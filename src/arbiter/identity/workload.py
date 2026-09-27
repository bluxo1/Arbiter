"""Fresh workload verification then scoped execution; never dispatch authority."""

from collections.abc import Callable
from typing import TypeVar

from anyio import CapacityLimiter, to_thread
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from arbiter.identity.context import TenantContext
from arbiter.identity.keys import KeyVerifier
from arbiter.persistence.tenant import TenantTransaction, bind_tenant_transaction
from arbiter.persistence.workload import KeyBinding, KeyScope, resolve_key

T = TypeVar("T")


class MissingScope(Exception):
    def __init__(self) -> None:
        super().__init__("permission denied")


class WorkloadUnavailable(Exception):
    def __init__(self) -> None:
        super().__init__("workload verification unavailable")


class WorkloadAccess:
    def __init__(self, verifier: KeyVerifier, engine: Engine) -> None:
        self._verifier = verifier
        self._engine = engine
        self._slots = CapacityLimiter(2)

    async def run(
        self,
        credential: SecretStr,
        operation: Callable[[KeyBinding, TenantTransaction], T],
        *,
        required_scope: KeyScope | None = None,
    ) -> T:
        if required_scope not in {None, "inference:write", "usage:read"}:
            raise ValueError("invalid server scope")
        return await to_thread.run_sync(
            self._run_scoped, credential, operation, required_scope, limiter=self._slots
        )

    def _run_scoped(
        self,
        credential: SecretStr,
        operation: Callable[[KeyBinding, TenantTransaction], T],
        required_scope: KeyScope | None,
    ) -> T:
        candidate = self._verifier.candidate(credential)
        try:
            with self._engine.connect() as connection, connection.begin() as transaction:
                inherited: str | None = connection.execute(
                    text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                ).scalar_one()
                if inherited is not None:
                    connection.invalidate()
                    raise WorkloadUnavailable()
                binding = resolve_key(connection, candidate)
                if required_scope is not None and required_scope not in binding.scopes:
                    raise MissingScope()
                scoped = bind_tenant_transaction(
                    connection, transaction, TenantContext(binding.tenant_id)
                )
                return operation(binding, scoped)
        except SQLAlchemyError:
            raise WorkloadUnavailable() from None
