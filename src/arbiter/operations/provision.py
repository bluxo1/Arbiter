"""Local operator commands. No HTTP registration, identity provider or inference path."""

import argparse
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal, Never
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import psycopg
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from arbiter.config import DatabaseSettings
from arbiter.operations.policy import PolicyInput, PolicyService
from arbiter.operations.registry import (
    ModelInput,
    NativeBindingInput,
    RegistryService,
    read_approval,
)
from arbiter.operations.retention import RetentionService
from arbiter.persistence.operator import OperatorRepository, operator_engine, operator_transaction

TenantStatus = Literal["active", "suspended"]
MemberRole = Literal["member", "admin"]


class ProvisioningConflict(ValueError):
    pass


class OperatorParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        # argparse normally echoes rejected values. Keep possible accidental secrets private.
        raise SystemExit("operator command failed (invalid arguments)")


@dataclass(frozen=True, slots=True)
class MemberInput:
    issuer: str
    subject: str
    role: MemberRole = "member"

    def __post_init__(self) -> None:
        parsed = urlsplit(self.issuer)
        if (
            not 1 <= len(self.issuer) <= 2048
            or self.issuer != self.issuer.strip()
            or any(
                character.isspace() or ord(character) < 32 or 127 <= ord(character) <= 159
                for character in self.issuer
            )
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("invalid public issuer URL")
        # Validate the port without fetching discovery/JWKS or normalizing the identity.
        if parsed.port is not None and parsed.port < 1:
            raise ValueError("invalid public issuer URL")
        if (
            not 1 <= len(self.subject) <= 255
            or any(
                ord(character) < 32 or 127 <= ord(character) <= 159 for character in self.subject
            )
            or self.role not in ("member", "admin")
        ):
            raise ValueError("invalid member binding")


@dataclass(frozen=True, slots=True)
class ProvisioningResult:
    tenant_id: UUID
    object_id: UUID
    audit_id: UUID | None
    correlation_id: UUID
    changed: bool


class ProvisioningService:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def create_tenant(self) -> ProvisioningResult:
        tenant_id, correlation = uuid4(), uuid4()
        try:
            with operator_transaction(self._engine, tenant_id) as transaction:
                repository = OperatorRepository(transaction)
                repository.create_tenant()
                tenant = repository.lock_tenant()
                audit = repository.append_audit(
                    action="tenant_created",
                    target_id=tenant.id,
                    revision=tenant.policy_revision,
                    correlation=correlation,
                )
        except IntegrityError as error:
            self._conflict(error)
            raise
        return ProvisioningResult(tenant_id, tenant_id, audit, correlation, True)

    def set_tenant_status(self, tenant_id: UUID, status: TenantStatus) -> ProvisioningResult:
        if status not in ("active", "suspended"):
            raise ValueError("invalid tenant status")
        correlation = uuid4()
        with operator_transaction(self._engine, tenant_id) as transaction:
            repository = OperatorRepository(transaction)
            tenant = repository.lock_tenant()
            changed = tenant.status != status
            audit = None
            if changed:
                repository.set_status(status)
                audit = repository.append_audit(
                    action=f"tenant_{status}",
                    target_id=tenant.id,
                    revision=tenant.policy_revision,
                    correlation=correlation,
                )
        return ProvisioningResult(tenant_id, tenant_id, audit, correlation, changed)

    def create_member(self, tenant_id: UUID, member: MemberInput) -> ProvisioningResult:
        object_id, correlation = uuid4(), uuid4()
        try:
            with operator_transaction(self._engine, tenant_id) as transaction:
                repository = OperatorRepository(transaction)
                tenant = repository.lock_tenant()
                repository.create_member(
                    issuer=member.issuer,
                    subject=member.subject,
                    role=member.role,
                    object_id=object_id,
                )
                audit = repository.append_audit(
                    action="member_created",
                    target_id=object_id,
                    revision=tenant.policy_revision,
                    correlation=correlation,
                )
        except IntegrityError as error:
            self._conflict(error)
            raise
        return ProvisioningResult(tenant_id, object_id, audit, correlation, True)

    @staticmethod
    def _conflict(error: IntegrityError) -> None:
        if isinstance(error.orig, psycopg.Error) and error.orig.sqlstate == "23505":
            raise ProvisioningConflict("provisioning conflict") from None


def main(argv: Sequence[str] | None = None) -> None:
    parser = OperatorParser(description="Local, separately credentialed Arbiter operator")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("create-tenant")
    retention_parser = commands.add_parser("retire-requests")
    retention_parser.add_argument("--tenant", required=True, type=UUID)
    retention_parser.add_argument("--key", required=True, type=UUID)
    retention_parser.add_argument("--limit", type=int, default=100)
    status_parser = commands.add_parser("set-tenant-status")
    status_parser.add_argument("--tenant", required=True, type=UUID)
    status_parser.add_argument("--status", required=True, choices=("active", "suspended"))
    member_parser = commands.add_parser("create-member")
    member_parser.add_argument("--tenant", required=True, type=UUID)
    member_parser.add_argument("--issuer", required=True)
    member_parser.add_argument("--subject", required=True)
    member_parser.add_argument("--role", choices=("member", "admin"), default="member")
    policy_parser = commands.add_parser("set-tenant-policy")
    policy_parser.add_argument("--tenant", required=True, type=UUID)
    policy_parser.add_argument("--tenant-rate", type=int, required=True)
    policy_parser.add_argument("--key-rate", type=int, required=True)
    policy_parser.add_argument("--daily-quota", type=int, required=True)
    policy_parser.add_argument("--monthly-budget", type=int, required=True)
    policy_parser.add_argument("--concurrency", type=int, required=True)
    policy_parser.add_argument("--model-alias", action="append", default=[])
    for name in ("register-model", "update-model"):
        model_parser = commands.add_parser(name)
        model_parser.add_argument("--alias", required=True)
        model_parser.add_argument("--adapter", choices=("ollama",), required=True)
        model_parser.add_argument("--digest", required=True)
        model_parser.add_argument("--context-cap", type=int, required=True)
        model_parser.add_argument("--output-cap", type=int, required=True)
        model_parser.add_argument("--credit-charge", type=int, required=True)
        model_parser.add_argument("--state", choices=("active", "inactive"), required=True)
        model_parser.add_argument("--approval", type=Path, required=True)
        if name == "update-model":
            model_parser.add_argument("--expected-revision", type=int, required=True)
    binding_parser = commands.add_parser("bind-native-model")
    binding_parser.add_argument("--model-id", type=UUID, required=True)
    binding_parser.add_argument("--expected-revision", type=int, required=True)
    binding_parser.add_argument("--provider-kind", choices=("ollama",), required=True)
    binding_parser.add_argument("--native-name", required=True)
    binding_parser.add_argument("--approval", type=Path, required=True)
    engine: Engine | None = None
    try:
        args = parser.parse_args(argv)
        member = (
            MemberInput(args.issuer, args.subject, args.role)
            if args.command == "create-member"
            else None
        )
        policy = (
            PolicyInput(
                args.tenant_rate,
                args.key_rate,
                args.daily_quota,
                args.monthly_budget,
                args.concurrency,
                tuple(args.model_alias),
            )
            if args.command == "set-tenant-policy"
            else None
        )
        engine = operator_engine(DatabaseSettings())
        service = ProvisioningService(engine)
        if args.command == "retire-requests":
            result_retention = RetentionService(engine).run_once(
                args.tenant, args.key, limit=args.limit
            )
            print(json.dumps(asdict(result_retention), default=str))
            return
        elif args.command == "bind-native-model":
            registry_result = RegistryService(engine).bind_native_model(
                NativeBindingInput(
                    args.model_id, args.expected_revision, args.provider_kind, args.native_name
                ),
                read_approval(args.approval),
            )
            print(json.dumps(asdict(registry_result), default=str))
            return
        elif args.command in ("register-model", "update-model"):
            model = ModelInput(
                args.alias,
                args.adapter,
                args.digest,
                args.context_cap,
                args.output_cap,
                args.credit_charge,
                args.state == "active",
            )
            registry_result = RegistryService(engine).provision(
                model,
                read_approval(args.approval),
                expected_revision=args.expected_revision
                if args.command == "update-model"
                else None,
            )
            print(json.dumps(asdict(registry_result), default=str))
            return
        elif args.command == "create-tenant":
            result = service.create_tenant()
        elif args.command == "set-tenant-status":
            result = service.set_tenant_status(args.tenant, args.status)
        elif args.command == "create-member":
            if member is None:
                raise ValueError("member binding required")
            result = service.create_member(args.tenant, member)
        else:
            if policy is None:
                raise ValueError("validated policy required")
            policy_result = PolicyService(engine).set_policy(args.tenant, policy)
            print(json.dumps(asdict(policy_result), default=str))
            return
        print(json.dumps(asdict(result), default=str))
    except Exception as error:
        # Never expose subject, input values, SQL/driver bodies or credential details.
        raise SystemExit(f"operator command failed ({type(error).__name__})") from None
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    main()
