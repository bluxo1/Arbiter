"""Fixed public management errors; no rejected values or exception messages."""

from uuid import uuid4

from fastapi.responses import JSONResponse


def error_response(status: int, code: str, message: str) -> JSONResponse:
    headers = {"Cache-Control": "no-store"}
    if status == 401:
        headers["WWW-Authenticate"] = "Bearer"
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message}, "request_id": str(uuid4())},
        headers=headers,
    )
