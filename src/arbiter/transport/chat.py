"""Bounded public chat transport into the existing governed execution service."""

import json
from typing import Any, Literal
from uuid import UUID

from anyio import fail_after, to_thread
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.requests import ClientDisconnect

from arbiter.governance.capacity import CapacityUnavailable
from arbiter.governance.dispatch import (
    DispatchConflict,
    DispatchNotFound,
    DispatchRejected,
    DispatchUnavailable,
    ProviderCompletion,
    TerminalUnavailable,
)
from arbiter.governance.execution import GovernedExecutionService, InferenceDeadline
from arbiter.governance.fingerprint import (
    InvalidReservation,
    Message,
    ReservationInput,
    validate_idempotency,
)
from arbiter.governance.rate import RateDenied, RateUnavailable
from arbiter.governance.release import ReleaseUnavailable
from arbiter.governance.reservation import (
    IdempotencyConflict,
    ModelDenied,
    RequestAlreadyAdmitted,
    ReservationDenied,
    ReservationUnavailable,
)
from arbiter.identity.keys import InvalidKey
from arbiter.identity.workload import MissingScope
from arbiter.persistence.provider_binding import ProviderBindingUnavailable
from arbiter.transport.errors import error_response
from arbiter.transport.workload import workload_bearer

router = APIRouter()
_BODY_LIMIT = 65536


class _InvalidChat(Exception):
    pass


class _BodyTooLarge(Exception):
    pass


class _BodyReceiveTimeout(Exception):
    pass


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    role: Literal["system", "user", "assistant"]
    content: str


class ChatInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    model: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    messages: list[ChatMessage] = Field(min_length=1, max_length=32)
    max_output_tokens: int = Field(default=256, ge=1, le=1024)

    def reservation(self) -> ReservationInput:
        return ReservationInput(
            self.model,
            tuple(Message(item.role, item.content) for item in self.messages),
            self.max_output_tokens,
        )


class AssistantMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    role: Literal["assistant"] = "assistant"
    content: str


class ChatResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    request_id: UUID
    model: str
    message: AssistantMessage
    input_tokens: int | None
    output_tokens: int | None
    charged_credits: int = Field(ge=1)


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in values:
        if name in result:
            raise ValueError("duplicate JSON member")
        result[name] = value
    return result


def _constant(_: str) -> None:
    raise ValueError("non-finite JSON value")


async def _input(request: Request) -> tuple[str, ReservationInput]:
    if request.query_params:
        raise _InvalidChat()
    headers = request.scope["headers"]
    content_types = [value for name, value in headers if name.lower() == b"content-type"]
    lengths = [value for name, value in headers if name.lower() == b"content-length"]
    encodings = [value for name, value in headers if name.lower() == b"content-encoding"]
    keys = [value for name, value in headers if name.lower() == b"idempotency-key"]
    if (
        len(content_types) != 1
        or b"," in content_types[0]
        or content_types[0].split(b";", 1)[0].strip().lower() != b"application/json"
        or len(lengths) > 1
        or encodings
        or len(keys) != 1
    ):
        raise _InvalidChat()
    try:
        idempotency = keys[0].decode("ascii")
        validate_idempotency(idempotency)
        if lengths:
            length = int(lengths[0])
            if length < 0:
                raise _InvalidChat()
            if length > _BODY_LIMIT:
                raise _BodyTooLarge()
        body = bytearray()
        try:
            with fail_after(5):
                async for chunk in request.stream():
                    if len(body) + len(chunk) > _BODY_LIMIT:
                        raise _BodyTooLarge()
                    body.extend(chunk)
        except TimeoutError:
            raise _BodyReceiveTimeout() from None
        decoded = json.loads(
            body.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant
        )
        public = ChatInput.model_validate(decoded)
        return idempotency, public.reservation()
    except (UnicodeError, ValueError, ValidationError, InvalidReservation):
        raise _InvalidChat() from None


def _duplicate(error: RequestAlreadyAdmitted) -> JSONResponse:
    return JSONResponse(
        status_code=409,
        content={
            "error": {"code": error.code, "message": "Request already admitted"},
            "request_id": str(error.request_id),
            "state": error.state,
            "status_url": error.status_url,
        },
        headers={"Cache-Control": "no-store"},
    )


def _completion(value: ProviderCompletion) -> JSONResponse:
    if value.state == "succeeded" and value.assistant_text is not None:
        if value.model_alias is None or value.charged_credits is None:
            return error_response(503, "unavailable", "Service unavailable")
        result = ChatResponse(
            request_id=value.request_id,
            model=value.model_alias,
            message=AssistantMessage(content=value.assistant_text),
            input_tokens=value.input_tokens,
            output_tokens=value.output_tokens,
            charged_credits=value.charged_credits,
        )
        return JSONResponse(result.model_dump(mode="json"), headers={"Cache-Control": "no-store"})
    mapping = {
        "model_unavailable": (502, "model_unavailable", "Model unavailable"),
        "provider_failure": (502, "provider_failure", "Provider failure"),
        "provider_unavailable": (503, "unavailable", "Service unavailable"),
        "provider_deadline": (504, "provider_deadline", "Provider deadline exceeded"),
        "provider_malformed": (502, "provider_malformed", "Provider response invalid"),
        "provider_oversized": (502, "provider_oversized", "Provider response invalid"),
        "provider_outcome_unknown": (503, "unavailable", "Provider outcome unknown"),
    }
    status, code, message = mapping.get(
        value.public_error or "provider_outcome_unknown",
        (503, "unavailable", "Provider outcome unknown"),
    )
    return JSONResponse(
        status_code=status,
        content={
            "error": {"code": code, "message": message},
            "request_id": str(value.request_id),
        },
        headers={"Cache-Control": "no-store"},
    )


@router.post("/v1/chat/completions", response_model=ChatResponse)
async def chat_completion(request: Request) -> JSONResponse:
    try:
        credential = workload_bearer(request)
        idempotency, content = await _input(request)
        service: GovernedExecutionService | None = getattr(request.app.state, "chat_service", None)
        if service is None:
            return error_response(503, "unavailable", "Service unavailable")
        # AnyIO shields the worker on HTTP cancellation. Once dispatch commits,
        # the owned worker continues terminalization; no second worker is started.
        completed = await to_thread.run_sync(service.execute, credential, idempotency, content)
        return _completion(completed)
    except InvalidKey:
        return error_response(401, "invalid_credentials", "Invalid credentials")
    except MissingScope:
        return error_response(403, "permission_denied", "Permission denied")
    except ModelDenied:
        return error_response(403, "model_denied", "Model denied")
    except RequestAlreadyAdmitted as error:
        return _duplicate(error)
    except IdempotencyConflict:
        return error_response(409, "idempotency_conflict", "Idempotency conflict")
    except (InvalidReservation, _InvalidChat, ClientDisconnect):
        return error_response(422, "invalid_fields", "Invalid chat request")
    except _BodyTooLarge:
        return error_response(413, "body_too_large", "Request body too large")
    except _BodyReceiveTimeout:
        return error_response(503, "unavailable", "Service unavailable")
    except ReservationDenied as error:
        return error_response(error.status_code, error.code, "Request denied")
    except RateDenied:
        return error_response(429, "rate_exhausted", "Rate limit exceeded")
    except (
        CapacityUnavailable,
        ProviderBindingUnavailable,
        ReservationUnavailable,
        RateUnavailable,
        DispatchUnavailable,
        TerminalUnavailable,
        ReleaseUnavailable,
    ):
        return error_response(503, "unavailable", "Service unavailable")
    except InferenceDeadline:
        return error_response(504, "provider_deadline", "Provider deadline exceeded")
    except (DispatchRejected, DispatchConflict):
        return error_response(409, "authorization_changed", "Authorization changed")
    except DispatchNotFound:
        return error_response(404, "not_found", "Resource not found")
