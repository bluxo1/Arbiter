"""Composition root for management and governed, non-streaming inference."""

import os
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from anyio import create_task_group, sleep, to_thread
from fastapi import FastAPI
from sqlalchemy.engine import Engine

from arbiter.config import (
    AuditSettings,
    DatabaseSettings,
    FingerprintSettings,
    KeySettings,
    OidcSettings,
    RedisSettings,
)
from arbiter.governance.execution import GovernedExecutionService
from arbiter.governance.fingerprint import Fingerprinter
from arbiter.governance.rate import RateGate
from arbiter.identity.access import ManagementAccess
from arbiter.identity.audit_cursor import AuditCursor
from arbiter.identity.key_cursor import KeyCursor
from arbiter.identity.keys import KeyIssuer, KeyVerifier
from arbiter.identity.model_cursor import ModelCursor
from arbiter.identity.oidc import OidcVerifier
from arbiter.identity.workload import WorkloadAccess
from arbiter.operations.audit import AuditService
from arbiter.operations.key_listing import KeyListService
from arbiter.operations.key_revocation import KeyRevocationService
from arbiter.operations.keys import KeyService
from arbiter.operations.maintenance import (
    CADENCE_SECONDS,
    MaintenanceService,
    MaintenanceUnavailable,
)
from arbiter.operations.models import ManagementModels, ModelCatalog
from arbiter.operations.usage import ManagementUsage
from arbiter.persistence.maintenance import maintenance_engine
from arbiter.persistence.tenant import runtime_engine
from arbiter.transport.audit import router as audit_router
from arbiter.transport.chat import router as chat_router
from arbiter.transport.health import router as health_router
from arbiter.transport.keys import router as key_router
from arbiter.transport.models import router as model_router
from arbiter.transport.usage import router as usage_router


def _resources() -> tuple[
    Engine,
    Engine,
    OidcSettings,
    ssl.SSLContext,
    AuditCursor,
    KeyIssuer,
    KeyCursor,
    KeyVerifier,
    ModelCatalog,
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
        maintenance_engine(DatabaseSettings()),
        settings,
        trust,
        cursors,
        issuer,
        KeyCursor(cursor_key),
        KeyVerifier(pepper, keys.pepper_version),
        ModelCatalog(ModelCursor(cursor_key)),
    )


def create_app(
    *,
    audit_service: AuditService | None = None,
    key_service: KeyService | None = None,
    key_list_service: KeyListService | None = None,
    key_revocation_service: KeyRevocationService | None = None,
    workload_access: WorkloadAccess | None = None,
    management_models: ManagementModels | None = None,
    model_catalog: ModelCatalog | None = None,
    chat_service: GovernedExecutionService | None = None,
) -> FastAPI:
    """Optional explicit service wiring is for host-side tests, never request input."""

    async def maintain(service: MaintenanceService) -> None:
        while True:
            await sleep(CADENCE_SECONDS)
            try:
                await to_thread.run_sync(service.run_once)
            except MaintenanceUnavailable:
                # The service has closed recovery admission and retries next cycle.
                pass

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
                management_models,
                model_catalog,
                chat_service,
            )
        ):
            app.state.audit_service = audit_service
            app.state.key_service = key_service
            app.state.key_list_service = key_list_service
            app.state.key_revocation_service = key_revocation_service
            app.state.workload_access = workload_access
            app.state.management_models = management_models
            app.state.model_catalog = model_catalog
            app.state.chat_service = chat_service
            yield
            return
        (
            engine,
            discovery,
            settings,
            trust,
            cursors,
            issuer,
            key_cursors,
            key_verifier,
            catalog,
        ) = await to_thread.run_sync(_resources)
        try:
            async with OidcVerifier(settings, trust=trust) as verifier:
                access = ManagementAccess(verifier, engine)
                app.state.audit_service = AuditService(access, cursors)
                app.state.key_service = KeyService(access, issuer)
                app.state.key_list_service = KeyListService(access, key_cursors)
                app.state.key_revocation_service = KeyRevocationService(access)
                app.state.workload_access = WorkloadAccess(key_verifier, engine)
                fingerprint_settings = FingerprintSettings()
                app.state.chat_service = GovernedExecutionService(
                    engine,
                    key_verifier,
                    Fingerprinter(fingerprint_settings.key(), fingerprint_settings.version),
                    RateGate(RedisSettings()),
                    None,
                )
                app.state.model_catalog = catalog
                app.state.management_models = ManagementModels(access, catalog)
                app.state.management_usage = ManagementUsage(access)
                maintenance = MaintenanceService(engine, discovery)
                app.state.maintenance_service = maintenance
                try:
                    await to_thread.run_sync(maintenance.run_once)
                except MaintenanceUnavailable:
                    pass
                async with create_task_group() as tasks:
                    tasks.start_soon(maintain, maintenance)
                    try:
                        yield
                    finally:
                        tasks.cancel_scope.cancel()
        finally:
            await to_thread.run_sync(engine.dispose)
            await to_thread.run_sync(discovery.dispose)
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
            if hasattr(app.state, "model_catalog"):
                del app.state.model_catalog
            if hasattr(app.state, "management_models"):
                del app.state.management_models
            if hasattr(app.state, "management_usage"):
                del app.state.management_usage
            if hasattr(app.state, "maintenance_service"):
                del app.state.maintenance_service
            if hasattr(app.state, "chat_service"):
                del app.state.chat_service

    app = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.include_router(health_router)
    app.include_router(audit_router)
    app.include_router(key_router)
    app.include_router(model_router)
    app.include_router(usage_router)
    app.include_router(chat_router)
    return app
