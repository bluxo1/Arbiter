"""Composition root: health and authenticated audit reads; inference stays unavailable."""

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
from arbiter.identity.keys import KeyIssuer
from arbiter.identity.oidc import OidcVerifier
from arbiter.operations.audit import AuditService
from arbiter.operations.keys import KeyService
from arbiter.persistence.tenant import runtime_engine
from arbiter.transport.audit import router as audit_router
from arbiter.transport.health import router as health_router
from arbiter.transport.keys import router as key_router


def _resources() -> tuple[Engine, OidcSettings, ssl.SSLContext, AuditCursor, KeyIssuer]:
    # Configuration, certificate and secret-file IO are outside the event loop.
    settings = OidcSettings(
        issuer=os.environ.get("ARBITER_OIDC_ISSUER", ""),
        audience=os.environ.get("ARBITER_OIDC_AUDIENCE", ""),
        jwks_url=os.environ.get("ARBITER_OIDC_JWKS_URL", ""),
    )
    trust = ssl.create_default_context(cafile=settings.ca_file)
    cursors = AuditCursor(AuditSettings().key())
    keys = KeySettings()
    issuer = KeyIssuer(keys.pepper(), keys.pepper_version)
    return runtime_engine(DatabaseSettings()), settings, trust, cursors, issuer


def create_app(
    *, audit_service: AuditService | None = None, key_service: KeyService | None = None
) -> FastAPI:
    """Optional explicit service wiring is for host-side tests, never request input."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if audit_service is not None or key_service is not None:
            app.state.audit_service = audit_service
            app.state.key_service = key_service
            yield
            return
        engine, settings, trust, cursors, issuer = await to_thread.run_sync(_resources)
        try:
            async with OidcVerifier(settings, trust=trust) as verifier:
                access = ManagementAccess(verifier, engine)
                app.state.audit_service = AuditService(access, cursors)
                app.state.key_service = KeyService(access, issuer)
                yield
        finally:
            await to_thread.run_sync(engine.dispose)
            if hasattr(app.state, "audit_service"):
                del app.state.audit_service
            if hasattr(app.state, "key_service"):
                del app.state.key_service

    app = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.include_router(health_router)
    app.include_router(audit_router)
    app.include_router(key_router)
    return app
