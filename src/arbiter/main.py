"""Composition root: health, audit and key administration; no inference."""

import os
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from anyio import to_thread
from fastapi import FastAPI
from sqlalchemy.engine import Engine

from arbiter.config import AuditSettings, DatabaseSettings, KeySettings, OidcSettings
from arbiter.identity.access import ManagementAccess
from arbiter.identity.audit_cursor import AuditCursor
from arbiter.identity.key_cursor import KeyCursor
from arbiter.identity.keys import KeyIssuer, KeyVerifier
from arbiter.identity.oidc import OidcVerifier
from arbiter.identity.workload import WorkloadAccess
from arbiter.operations.audit import AuditService
from arbiter.operations.key_listing import KeyListService
from arbiter.operations.key_revocation import KeyRevocationService
from arbiter.operations.keys import KeyService
from arbiter.persistence.tenant import runtime_engine
from arbiter.transport.audit import router as audit_router
from arbiter.transport.health import router as health_router
from arbiter.transport.keys import router as key_router


def _resources() -> tuple[
    Engine, OidcSettings, ssl.SSLContext, AuditCursor, KeyIssuer, KeyCursor, KeyVerifier
]:
    # Configuration, certificate and secret-file IO are outside the event loop.
    settings = OidcSettings(
        issuer=os.environ.get("ARBITER_OIDC_ISSUER", ""),
        audience=os.environ.get("ARBITER_OIDC_AUDIENCE", ""),
        jwks_url=os.environ.get("ARBITER_OIDC_JWKS_URL", ""),
    )
    trust = ssl.create_default_context(cafile=settings.ca_file)
    cursor_key = AuditSettings().key()
    cursors = AuditCursor(cursor_key)
    keys = KeySettings()
    pepper = keys.pepper()
    issuer = KeyIssuer(pepper, keys.pepper_version)
    return (
        runtime_engine(DatabaseSettings()),
        settings,
        trust,
        cursors,
        issuer,
        KeyCursor(cursor_key),
        KeyVerifier(pepper, keys.pepper_version),
    )


def create_app(
    *,
    audit_service: AuditService | None = None,
    key_service: KeyService | None = None,
    key_list_service: KeyListService | None = None,
    key_revocation_service: KeyRevocationService | None = None,
    workload_access: WorkloadAccess | None = None,
) -> FastAPI:
    """Optional explicit service wiring is for host-side tests, never request input."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if any(
            service is not None
            for service in (
                audit_service,
                key_service,
                key_list_service,
                key_revocation_service,
                workload_access,
            )
        ):
            app.state.audit_service = audit_service
            app.state.key_service = key_service
            app.state.key_list_service = key_list_service
            app.state.key_revocation_service = key_revocation_service
            app.state.workload_access = workload_access
            yield
            return
        (
            engine,
            settings,
            trust,
            cursors,
            issuer,
            key_cursors,
            key_verifier,
        ) = await to_thread.run_sync(_resources)
        try:
            async with OidcVerifier(settings, trust=trust) as verifier:
                access = ManagementAccess(verifier, engine)
                app.state.audit_service = AuditService(access, cursors)
                app.state.key_service = KeyService(access, issuer)
                app.state.key_list_service = KeyListService(access, key_cursors)
                app.state.key_revocation_service = KeyRevocationService(access)
                app.state.workload_access = WorkloadAccess(key_verifier, engine)
                yield
        finally:
            await to_thread.run_sync(engine.dispose)
            if hasattr(app.state, "audit_service"):
                del app.state.audit_service
            if hasattr(app.state, "key_service"):
                del app.state.key_service
            if hasattr(app.state, "key_list_service"):
                del app.state.key_list_service
            if hasattr(app.state, "key_revocation_service"):
                del app.state.key_revocation_service
            if hasattr(app.state, "workload_access"):
                del app.state.workload_access

    app = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.include_router(health_router)
    app.include_router(audit_router)
    app.include_router(key_router)
    return app
