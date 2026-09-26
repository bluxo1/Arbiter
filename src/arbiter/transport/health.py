"""Minimal health responses; this scaffold cannot admit work."""

from typing import Literal

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

router = APIRouter()


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    status: Literal["ok", "not_ready"]


@router.get("/health/live", response_model=HealthResponse)
async def liveness() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/health/ready", response_model=HealthResponse, status_code=503)
async def readiness() -> JSONResponse:
    # Never substitute connectivity for the unimplemented security/readiness gates.
    return JSONResponse(status_code=503, content=HealthResponse(status="not_ready").model_dump())
