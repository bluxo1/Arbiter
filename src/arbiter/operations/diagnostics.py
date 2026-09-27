"""Local, read-only foundation checks. Connectivity never authorizes admission.

Only the runtime secret is needed. No tenant data, version-marker privilege,
Redis mutation, identity/provider call, or HTTP diagnostic surface is introduced.
"""

import json
import socket
from dataclasses import asdict, dataclass
from time import monotonic

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from arbiter.config import DatabaseSettings, RedisSettings
from arbiter.persistence.tenant import runtime_engine


@dataclass(frozen=True)
class FoundationReport:
    postgres: bool
    redis: bool

    @property
    def foundation_ready(self) -> bool:
        return self.postgres and self.redis

    def output(self) -> dict[str, object]:
        return {
            **asdict(self),
            "foundation_ready": self.foundation_ready,
            "ready": False,
            "unimplemented_gates": ["identity", "enforcement", "recovery", "model_readiness"],
        }


def postgres_foundation(engine: Engine) -> bool:
    """Inspect catalogs with runtime authority, without establishing tenant context."""
    try:
        with engine.begin() as connection:
            role: bool = connection.execute(
                text("""
                SELECT current_user = 'arbiter_runtime' AND session_user = current_user
                    AND NOT (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole
                             OR rolreplication OR rolinherit)
                    AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member = r.oid)
                    AND NOT has_database_privilege(current_user, current_database(), 'CREATE')
                    AND NOT has_schema_privilege(current_user, 'public', 'CREATE')
                FROM pg_roles r WHERE rolname = current_user
            """)
            ).scalar_one()
            context: str | None = connection.execute(
                text("SELECT NULLIF(current_setting('arbiter.tenant_id', true), '')")
            ).scalar_one()
            if context is not None:
                connection.invalidate()
                return False
            schema: bool | None = connection.execute(
                text("""
                SELECT count(*) = 4 AND bool_and(
                    c.relrowsecurity AND c.relforcerowsecurity AND a.attnotnull
                    AND pg_get_userbyid(c.relowner) = 'arbiter_migration'
                    AND has_table_privilege(current_user, c.oid, 'SELECT')
                    AND NOT has_table_privilege(current_user, c.oid, 'TRUNCATE')
                    AND (c.relname <> 'tenant_policies' OR
                        NOT has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE'))
                )
                FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id'
                WHERE n.nspname = 'arbiter'
                    AND c.relname IN ('tenants', 'memberships', 'audit_events', 'tenant_policies')
                    AND c.relkind = 'r' AND NOT a.attisdropped
            """)
            ).scalar_one()
            policies: bool = connection.execute(
                text("""
                SELECT count(*) FILTER (WHERE policyname = 'tenant_ownership'
                    AND permissive = 'RESTRICTIVE' AND cmd = 'ALL'
                    AND qual IS NOT NULL AND with_check IS NOT NULL) = 5
                    AND count(*) FILTER (WHERE tablename = 'audit_events'
                    AND policyname = 'runtime_audit_actor' AND permissive = 'RESTRICTIVE'
                    AND cmd = 'INSERT' AND with_check IS NOT NULL) = 1
                FROM pg_policies WHERE schemaname = 'arbiter'
            """)
            ).scalar_one()
            return role is True and schema is True and policies is True
    except SQLAlchemyError:
        return False


def _receive(sock: socket.socket, length: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < length:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("diagnostic deadline exceeded")
        sock.settimeout(min(2.0, remaining))
        chunk = sock.recv(length - len(result))
        if not chunk:
            raise ValueError("incomplete Redis reply")
        result.extend(chunk)
    return bytes(result)


def _reply(sock: socket.socket, deadline: float) -> bytes:
    header = bytearray()
    while not header.endswith(b"\r\n"):
        if len(header) >= 128:
            raise ValueError("oversized Redis header")
        header.extend(_receive(sock, 1, deadline))
    if header[:1] == b"+":
        return bytes(header[1:-2])
    if header[:1] != b"$":
        raise ValueError("unexpected Redis reply")
    length = int(header[1:-2])
    if not 0 <= length <= 65536:
        raise ValueError("oversized Redis reply")
    body = _receive(sock, length + 2, deadline)
    if body[-2:] != b"\r\n":
        raise ValueError("invalid Redis terminator")
    return body[:-2]


def redis_foundation(settings: RedisSettings) -> bool:
    """Bounded PING/INFO checks, not limiter state or its future recovery barrier."""
    try:
        with socket.create_connection((settings.host, settings.port), timeout=2) as sock:
            deadline = monotonic() + 4
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            if _reply(sock, deadline) != b"PONG":
                return False
            sock.sendall(b"*2\r\n$4\r\nINFO\r\n$3\r\nall\r\n")
            fields = dict(
                line.split(":", 1)
                for line in _reply(sock, deadline).decode("ascii").splitlines()
                if line and not line.startswith("#") and ":" in line
            )
            return all(
                fields.get(key) == value
                for key, value in {
                    "redis_version": "7.2.16",
                    "role": "master",
                    "loading": "0",
                    "aof_enabled": "1",
                    "aof_last_write_status": "ok",
                    "aof_last_bgrewrite_status": "ok",
                    "maxmemory": "67108864",
                    "maxmemory_policy": "noeviction",
                }.items()
            )
    except (OSError, ValueError):
        return False


def diagnose() -> FoundationReport:
    postgres = False
    try:
        engine = runtime_engine(DatabaseSettings())
        try:
            postgres = postgres_foundation(engine)
        finally:
            engine.dispose()
    except (OSError, ValueError):
        # Secret/config errors fail closed without echoing values or driver details.
        pass
    return FoundationReport(postgres=postgres, redis=redis_foundation(RedisSettings()))


def main() -> None:
    try:
        report = diagnose()
    except Exception:
        raise SystemExit("foundation diagnostics failed") from None
    print(json.dumps(report.output(), sort_keys=True))
    raise SystemExit(0 if report.foundation_ready else 1)


if __name__ == "__main__":
    main()
