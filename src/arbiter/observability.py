"""Content-free logging and bounded process metrics; never an admission authority."""

import json
import logging
import logging.config
import math
import os
import socket
import socketserver
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from threading import Lock, Thread
from time import monotonic
from typing import ParamSpec, TypeVar

SOCKET_PATH = Path("/tmp/arbiter-observability/metrics.sock")  # noqa: S108 -- private directory
P = ParamSpec("P")
T = TypeVar("T")
_OPERATIONS = frozenset({"execution", "provider", "provider_validation", "maintenance"})
_OUTCOMES = frozenset(
    {
        "success",
        "denied",
        "unavailable",
        "rejected_input",
        "definite_failure",
        "deadline",
        "invalid_response",
        "unknown",
        "failure",
    }
)
_FALLBACK_LOG = (
    '{"component": "other", "event": "runtime_log", "exception": true, "level": "OTHER"}'
)


class SafeFormatter(logging.Formatter):
    """Discard message, arguments, extras, stack and traceback instead of redacting text."""

    def __init__(self) -> None:
        super().__init__()
        # Also protect warning output during Uvicorn's subsequent app import/startup.
        logging.captureWarnings(True)

    def format(self, record: logging.LogRecord) -> str:
        try:
            fields = object.__getattribute__(record, "__dict__")
            if type(fields) is not dict:
                return _FALLBACK_LOG
            name: object = None
            level_name: object = None
            exception = False
            # Do not stringify values, use subclass methods or hash/equal arbitrary
            # field keys. Malformed ignored fields never enter serialization.
            for key, value in fields.items():
                if type(key) is not str:
                    continue
                if key == "name":
                    name = value
                elif key == "levelname":
                    level_name = value
                elif key == "exc_info":
                    exception = value is not None
            component = name.split(".", 1)[0] if type(name) is str and len(name) <= 256 else "other"
            if component not in {
                "arbiter",
                "uvicorn",
                "httpx",
                "httpcore",
                "sqlalchemy",
                "alembic",
            }:
                component = "other"
            level = (
                level_name
                if type(level_name) is str
                and len(level_name) <= 8
                and level_name in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
                else "OTHER"
            )
            return json.dumps(
                {
                    "event": "runtime_log",
                    "component": component,
                    "level": level,
                    "exception": exception,
                },
                sort_keys=True,
            )
        except BaseException:
            # Formatter failure must never reach Handler.handleError, which can
            # print the original message/args/traceback. No untrusted text here.
            return _FALLBACK_LOG


def configure_logging() -> None:
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": True,
            "formatters": {"safe": {"()": SafeFormatter}},
            "handlers": {"safe": {"class": "logging.StreamHandler", "formatter": "safe"}},
            "root": {"level": "INFO", "handlers": ["safe"]},
            "loggers": {
                name: {"handlers": [], "propagate": True}
                for name in (
                    "uvicorn",
                    "uvicorn.error",
                    "uvicorn.access",
                    "httpx",
                    "httpcore",
                    "sqlalchemy",
                    "alembic",
                    "py.warnings",
                )
            },
        }
    )


class OperationalMetrics:
    """Fixed dimension sets. No identifiers, caller strings or exception text accepted."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._counts = {(op, outcome): 0 for op in _OPERATIONS for outcome in _OUTCOMES}
        self._seconds = {op: 0.0 for op in _OPERATIONS}
        self._redis = "unobserved"

    def record(self, operation: str, outcome: str, seconds: float = 0.0) -> None:
        if operation not in _OPERATIONS or outcome not in _OUTCOMES:
            raise ValueError("unsupported operational dimension")
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("invalid operational duration")
        with self._lock:
            self._counts[operation, outcome] += 1
            self._seconds[operation] += max(0.0, min(seconds, 86400.0))

    def redis(self, state: str) -> None:
        if state not in {"healthy", "unavailable", "barrier", "denied"}:
            raise ValueError("unsupported Redis state")
        with self._lock:
            self._redis = state

    def output(self) -> dict[str, object]:
        with self._lock:
            return {
                "operations": [
                    {"operation": op, "outcome": outcome, "count": count}
                    for (op, outcome), count in sorted(self._counts.items())
                ],
                "elapsed_seconds": dict(sorted(self._seconds.items())),
                "redis_last_observation": self._redis,
            }


metrics = OperationalMetrics()


def observed(operation: str) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Observe an existing call; exceptions and lifecycle decisions are unchanged."""
    if operation not in _OPERATIONS:
        raise ValueError("unsupported operation")

    def decorate(function: Callable[P, T]) -> Callable[P, T]:
        @wraps(function)
        def call(*args: P.args, **kwargs: P.kwargs) -> T:
            started = monotonic()
            outcome = "success"
            try:
                result = function(*args, **kwargs)
                if operation == "execution":
                    outcome = {
                        "succeeded": "success",
                        "failed": "failure",
                        "unknown": "unknown",
                    }.get(getattr(result, "state", ""), "failure")
                return result
            except BaseException as error:
                name = type(error).__name__
                if name in {"InferenceDeadline", "ProviderDeadline"}:
                    outcome = "deadline"
                elif name in {
                    "InvalidKey",
                    "MissingScope",
                    "ModelDenied",
                    "RateDenied",
                    "ReservationDenied",
                    "RequestAlreadyAdmitted",
                    "IdempotencyConflict",
                    "CapacityUnavailable",
                    "DispatchRejected",
                }:
                    outcome = "denied"
                elif name in {
                    "ReservationUnavailable",
                    "RateUnavailable",
                    "MaintenanceUnavailable",
                    "DispatchUnavailable",
                    "TerminalUnavailable",
                    "ProviderBindingUnavailable",
                }:
                    outcome = "unavailable"
                else:
                    outcome = "failure"
                raise
            finally:
                metrics.record(operation, outcome, monotonic() - started)

        return call

    return decorate


@contextmanager
def metrics_server(
    snapshot: Callable[[], dict[str, object]], path: Path = SOCKET_PATH
) -> Iterator[None]:
    """Local same-UID operator diagnostics only; no TCP/public route or credentials."""

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(2)
            try:
                self.request.sendall(json.dumps(snapshot(), sort_keys=True).encode() + b"\n")
            except (OSError, RuntimeError):
                return

    class Server(socketserver.UnixStreamServer):
        def handle_error(self, request: object, client_address: object) -> None:
            # socketserver's default prints a raw traceback to stderr.
            logging.getLogger("arbiter").error("operational export failed")

    created_directory = False
    if not path.parent.exists():
        path.parent.mkdir(mode=0o700)
        created_directory = True
    directory = path.parent.lstat()
    if (
        not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != os.getuid()
        or stat.S_IMODE(directory.st_mode) & 0o077
    ):
        raise PermissionError("private operational directory required")
    # Refuse an existing path; never remove an unknown socket or follow a symlink.
    with Server(str(path), Handler) as server:
        os.chmod(path, 0o600)
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        thread.start()
        try:
            yield
        finally:
            server.shutdown()
            thread.join(timeout=3)
            path.unlink()
            if created_directory:
                path.parent.rmdir()


def read_metrics(path: Path = SOCKET_PATH) -> dict[str, object]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(str(path))
        body = bytearray()
        while b"\n" not in body:
            part = client.recv(4096)
            if not part or len(body) + len(part) > 65536:
                raise ValueError("invalid operational reply")
            body.extend(part)
    value: object = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError("invalid operational reply")
    return value
