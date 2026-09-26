"""Composition root. No identity, tenant or inference routes are enabled yet."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from anyio import to_thread
from fastapi import FastAPI

from arbiter.config import DatabaseSettings
from arbiter.transport.health import router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Secret-file IO belongs off the event loop. No database mutation occurs here.
    await to_thread.run_sync(lambda: DatabaseSettings().password("runtime"))
    yield


def create_app() -> FastAPI:
    app = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.include_router(router)
    return app
