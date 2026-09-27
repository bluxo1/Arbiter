"""Local policy configuration only; no admission or inference authority."""

import re
from dataclasses import dataclass
from uuid import UUID, uuid4

from sqlalchemy.engine import Engine

from arbiter.persistence.operator import OperatorRepository, operator_transaction
from arbiter.persistence.policy import PolicyRepository

MAX_INTEGER = 9223372036854775807
VALIDATED_CONCURRENCY = 2


@dataclass(frozen=True, slots=True)
class PolicyInput:
    tenant_rate: int = 60
    key_rate: int = 30
    daily_quota: int = 1000
    monthly_budget: int = 10000
    concurrency: int = 1
    aliases: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value in (
            self.tenant_rate,
            self.key_rate,
            self.daily_quota,
            self.monthly_budget,
            self.concurrency,
        ):
            if type(value) is not int or not 0 <= value <= MAX_INTEGER:
                raise ValueError("invalid policy limit")
        if self.concurrency > VALIDATED_CONCURRENCY:
            raise ValueError("unvalidated deployment concurrency")
        if (
            type(self.aliases) is not tuple
            or len(self.aliases) > 32
            or any(
                not isinstance(alias, str) or re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", alias) is None
                for alias in self.aliases
            )
            or len(set(self.aliases)) != len(self.aliases)
        ):
            raise ValueError("invalid model aliases")


@dataclass(frozen=True, slots=True)
class PolicyResult:
    tenant_id: UUID
    policy_id: UUID
    revision: int
    audit_id: UUID
    correlation_id: UUID


class PolicyService:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def set_policy(self, tenant_id: UUID, policy: PolicyInput) -> PolicyResult:
        if not isinstance(policy, PolicyInput):
            raise TypeError("validated policy required")
        policy_id, correlation = uuid4(), uuid4()
        with operator_transaction(self._engine, tenant_id) as transaction:
            operator = OperatorRepository(transaction)
            tenant = operator.lock_tenant()
            if tenant.policy_revision >= MAX_INTEGER:
                raise ValueError("policy revision exhausted")
            repository = PolicyRepository(transaction)
            repository.validate_aliases(policy.aliases)
            revision = tenant.policy_revision + 1
            repository.advance_revision(tenant.policy_revision, revision)
            audit = operator.append_audit(
                action="tenant_policy_set",
                target_id=policy_id,
                revision=revision,
                correlation=correlation,
            )
            repository.insert(
                policy_id=policy_id,
                revision=revision,
                audit_id=audit,
                limits=(
                    policy.tenant_rate,
                    policy.key_rate,
                    policy.daily_quota,
                    policy.monthly_budget,
                    policy.concurrency,
                ),
                aliases=policy.aliases,
            )
        return PolicyResult(tenant_id, policy_id, revision, audit, correlation)
