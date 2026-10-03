"""Local verified configuration provisioning; no provider clients or HTTP authority."""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from arbiter.persistence.registry import RegistryRepository, registry_transaction

MAX_INTEGER = 9223372036854775807
DIGEST = r"^sha256:[0-9a-f]{64}$"


class ModelApproval(BaseModel):
    """Operator attestation to prior runtime/cap/license verification, never a license action."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    adapter: str = Field(pattern="^ollama$")
    model_digest: str = Field(pattern=DIGEST)
    runtime_digest: str = Field(pattern=DIGEST)
    verification_digest: str = Field(pattern=DIGEST)
    context_cap: int = Field(ge=1, le=MAX_INTEGER)
    output_cap: int = Field(ge=1, le=1024)
    verified_text: bool
    license_accepted: bool

    @model_validator(mode="after")
    def verified(self) -> "ModelApproval":
        if (
            not self.verified_text
            or not self.license_accepted
            or self.output_cap > self.context_cap
        ):
            raise ValueError("model approval required")
        return self

    def digest(self) -> str:
        encoded = json.dumps(self.model_dump(), sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate approval field")
        result[name] = value
    return result


def read_approval(path: Path) -> ModelApproval:
    # Explicit operator-controlled read-only file; no request body or approval boolean option.
    with path.open("rb") as stream:
        raw = stream.read(8193)
    if len(raw) > 8192:
        raise ValueError("invalid model approval")
    try:
        values = json.loads(raw, object_pairs_hook=_unique_fields)
        return ModelApproval.model_validate(values)
    except ValueError:
        raise ValueError("invalid model approval") from None


@dataclass(frozen=True, slots=True)
class ModelInput:
    alias: str
    adapter: str
    model_digest: str
    context_cap: int
    output_cap: int
    credit_charge: int
    active: bool

    def __post_init__(self) -> None:
        if (
            not isinstance(self.alias, str)
            or re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", self.alias) is None
        ):
            raise ValueError("invalid model alias")
        if (
            self.adapter != "ollama"
            or not isinstance(self.model_digest, str)
            or re.fullmatch(DIGEST, self.model_digest) is None
        ):
            raise ValueError("invalid model reference")
        for value in (self.context_cap, self.output_cap, self.credit_charge):
            if type(value) is not int or not 1 <= value <= MAX_INTEGER:
                raise ValueError("invalid model limit")
        if (
            self.output_cap > 1024
            or self.output_cap > self.context_cap
            or type(self.active) is not bool
        ):
            raise ValueError("invalid model configuration")


@dataclass(frozen=True, slots=True)
class RegistryResult:
    model_id: UUID
    revision: int
    journal_id: UUID
    correlation_id: UUID


class RegistryConflict(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class NativeBindingInput:
    """Local operator selection by registered UUID, never by a public alias."""

    model_id: UUID
    expected_revision: int
    provider_kind: str
    native_name: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.model_id, UUID)
            or type(self.expected_revision) is not int
            or not 1 <= self.expected_revision < MAX_INTEGER
            or self.provider_kind != "ollama"
            or type(self.native_name) is not str
            or re.fullmatch(
                r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}:[A-Za-z0-9_.-]{1,80}", self.native_name
            )
            is None
            or self.native_name.lower().endswith((":cloud", "-cloud"))
        ):
            raise ValueError("invalid native model binding")


class RegistryService:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def provision(
        self, model: ModelInput, approval: ModelApproval, *, expected_revision: int | None = None
    ) -> RegistryResult:
        if not isinstance(model, ModelInput) or not isinstance(approval, ModelApproval):
            raise TypeError("validated model and approval required")
        if (
            (model.adapter, model.model_digest) != (approval.adapter, approval.model_digest)
            or model.context_cap > approval.context_cap
            or model.output_cap > approval.output_cap
        ):
            raise ValueError("unapproved model configuration")
        if expected_revision is not None and (
            type(expected_revision) is not int or not 1 <= expected_revision < MAX_INTEGER
        ):
            raise ValueError("invalid expected revision")
        correlation = uuid4()
        try:
            with registry_transaction(self._engine) as connection:
                result = RegistryRepository(connection).provision(
                    alias=model.alias,
                    adapter=model.adapter,
                    digest=model.model_digest,
                    context=model.context_cap,
                    output=model.output_cap,
                    charge=model.credit_charge,
                    active=model.active,
                    approval=approval.digest(),
                    expected=expected_revision,
                    object_id=uuid4(),
                    journal_id=uuid4(),
                    correlation=correlation,
                )
        except IntegrityError:
            raise RegistryConflict("registry conflict") from None
        return RegistryResult(result.model_id, result.revision, result.journal_id, correlation)

    def bind_native_model(
        self, binding: NativeBindingInput, approval: ModelApproval
    ) -> RegistryResult:
        if not isinstance(binding, NativeBindingInput) or not isinstance(approval, ModelApproval):
            raise TypeError("validated binding and approval required")
        correlation = uuid4()
        try:
            with registry_transaction(self._engine) as connection:
                result = RegistryRepository(connection).bind_native_model(
                    model_id=binding.model_id,
                    expected=binding.expected_revision,
                    provider_kind=binding.provider_kind,
                    native_name=binding.native_name,
                    digest=approval.model_digest,
                    context=approval.context_cap,
                    output=approval.output_cap,
                    approval=approval.digest(),
                    journal_id=uuid4(),
                    correlation=correlation,
                )
        except IntegrityError:
            raise RegistryConflict("registry conflict") from None
        return RegistryResult(result.model_id, result.revision, result.journal_id, correlation)
