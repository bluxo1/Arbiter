"""Synthetic persistence fixtures on real PostgreSQL; no runtime writer or provider."""

import os
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from psycopg import sql
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.sql.elements import TextClause
from test_tenant_isolation import credential_engine, postgres_error, set_context

from arbiter.identity.context import TenantContext
from arbiter.operations.policy import PolicyInput, PolicyService
from arbiter.operations.provision import MemberInput, ProvisioningService
from arbiter.persistence.accounting import AccountingRepository
from arbiter.persistence.policy import PolicyRepository
from arbiter.persistence.tenant import tenant_transaction

pytestmark = pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_DATABASE") != "1", reason="requires real PostgreSQL"
)
TABLES = ("quota_windows", "budget_windows", "requests", "reservations", "accounting_events")
MAXIMUM = 9223372036854775807


def table_statement(template: str, table: str, column: str = "id") -> TextClause:
    if table not in TABLES or column not in {
        "id",
        "committed",
        "reserved",
        "credit_charge",
        "fingerprint_version",
        "output_tokens",
        "credits",
        "request_count",
    }:
        raise ValueError("invalid fixture identifier")
    return text(
        sql.SQL(template)
        .format(table=sql.Identifier("arbiter", table), column=sql.Identifier(column))
        .as_string()
    )


def bundle_values(
    tenant: UUID, key: UUID, quota: UUID, budget: UUID, day: datetime, month: datetime
) -> dict[str, object]:
    return {
        "tenant": tenant,
        "key": key,
        "quota": quota,
        "budget": budget,
        "day": day,
        "month": month,
        "request": uuid4(),
        "reservation": uuid4(),
        "event": uuid4(),
        "idem": uuid4().hex,
        "hmac": b"x" * 32,
        "model": uuid4(),
    }


def insert_request(connection: Connection, values: dict[str, object]) -> None:
    connection.execute(
        text("""
        INSERT INTO arbiter.requests
        (id,tenant_id,key_id,idempotency_key,payload_hmac,fingerprint_version,policy_revision,
         model_id,model_revision,model_alias,model_adapter,model_digest,context_cap,output_cap,
         credit_charge,quota_window_id,budget_window_id,quota_start,budget_start,
         reservation_id,reserve_event_id)
        VALUES (:request,:tenant,:key,:idem,:hmac,1,2,:model,1,:alias,'ollama',
            :digest,4096,256,:charge,:quota,:budget,:day,:month,:reservation,:event)
    """),
        {**values, "digest": "sha256:" + "a" * 64, "charge": values.get("charge", 10)},
    )


def insert_reservation(connection: Connection, values: dict[str, object]) -> None:
    connection.execute(
        text("""
        INSERT INTO arbiter.reservations
        (id,tenant_id,request_id,quota_window_id,budget_window_id,request_count,credits)
        VALUES (:reservation,:tenant,:request,:quota,:budget,:count,:charge)
    """),
        {**values, "count": values.get("count", 1), "charge": values.get("charge", 10)},
    )


def insert_event(connection: Connection, values: dict[str, object], kind: str = "reserve") -> None:
    connection.execute(
        text("""
        INSERT INTO arbiter.accounting_events
        (id,tenant_id,request_id,reservation_id,quota_window_id,budget_window_id,
         request_count,credits,kind)
        VALUES (:event,:tenant,:request,:reservation,:quota,:budget,1,:charge,:kind)
    """),
        {**values, "kind": kind, "charge": values.get("charge", 10)},
    )


def insert_bundle(connection: Connection, values: dict[str, object]) -> None:
    insert_request(connection, values)
    insert_reservation(connection, values)
    insert_event(connection, values)


@dataclass
class Ledger:
    runtime: Engine
    operator: Engine
    migration: Engine
    tenants: list[UUID]
    keys: list[UUID]
    quotas: list[UUID]
    budgets: list[UUID]
    requests: list[UUID]
    day: datetime
    month: datetime
    model: UUID
    alias: str

    def values(self, index: int = 0) -> dict[str, object]:
        return {
            **bundle_values(
                self.tenants[index],
                self.keys[index],
                self.quotas[index],
                self.budgets[index],
                self.day,
                self.month,
            ),
            "model": self.model,
            "alias": self.alias,
        }


@pytest.fixture(scope="module")
def ledger() -> Iterator[Ledger]:
    runtime, operator, migration = (
        credential_engine(role) for role in ("runtime", "operator", "migration")
    )
    with migration.begin() as connection:
        day, month = connection.execute(
            text("""
            SELECT date_trunc('day',CURRENT_TIMESTAMP AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
                date_trunc('month',CURRENT_TIMESTAMP AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
        """)
        ).one()
    model, alias = uuid4(), "persistence-fixture-" + uuid4().hex
    value = Ledger(runtime, operator, migration, [], [], [], [], [], day, month, model, alias)
    try:
        with migration.begin() as connection:
            connection.execute(
                text("""
                INSERT INTO arbiter.provider_models
                (id,alias,adapter,model_digest,context_cap,output_cap,credit_charge,revision,active)
                VALUES (:id,:alias,'ollama',:digest,4096,256,10,1,true)
            """),
                {"id": model, "alias": alias, "digest": "sha256:" + "a" * 64},
            )
        service = ProvisioningService(operator)
        for _ in range(2):
            tenant = service.create_tenant().tenant_id
            member = service.create_member(
                tenant, MemberInput("https://persistence.fixture.invalid", uuid4().hex, "admin")
            ).object_id
            PolicyService(operator).set_policy(tenant, PolicyInput(concurrency=2, aliases=(alias,)))
            key, audit, quota, budget = (uuid4() for _ in range(4))
            values = bundle_values(tenant, key, quota, budget, day, month)
            values.update({"model": model, "alias": alias})
            with migration.begin() as connection:
                set_context(connection, tenant)
                connection.execute(
                    text("""
                    INSERT INTO arbiter.audit_events
                    (id,tenant_id,actor_type,actor_reference,actor_membership_id,action,
                     target_id,policy_revision,outcome)
                    VALUES (:audit,:tenant,'member',:reference,:member,
                        'api_key_created',:key,2,'succeeded')
                """),
                    {
                        "audit": audit,
                        "tenant": tenant,
                        "reference": str(member),
                        "member": member,
                        "key": key,
                    },
                )
                connection.execute(
                    text("""
                    INSERT INTO arbiter.api_keys
                    (id,tenant_id,public_id,label,verifier,pepper_version,scopes,created_at,
                     expires_at,created_by_membership_id,creation_audit_id)
                    VALUES (:key,:tenant,:public,'fixture',:verifier,1,ARRAY['usage:read'],
                        CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+interval '1 day',:member,:audit)
                """),
                    {
                        "key": key,
                        "tenant": tenant,
                        "public": uuid4().hex,
                        "verifier": b"v" * 32,
                        "member": member,
                        "audit": audit,
                    },
                )
                for table, identifier, start, amount in (
                    ("quota_windows", quota, day, 1),
                    ("budget_windows", budget, month, 10),
                ):
                    connection.execute(
                        table_statement(
                            """
                        INSERT INTO {table}(id,tenant_id,window_start,reserved)
                        VALUES (:id,:tenant,:start,:amount)
                    """,
                            table,
                        ),
                        {"id": identifier, "tenant": tenant, "start": start, "amount": amount},
                    )
                insert_bundle(connection, values)
            value.tenants.append(tenant)
            value.keys.append(key)
            value.quotas.append(quota)
            value.budgets.append(budget)
            assert isinstance(values["request"], UUID)
            value.requests.append(values["request"])
        yield value
    finally:
        # Accepted evidence is immutable: retain this entire synthetic fixture in the isolated DB.
        # No table-owner trigger bypass or unlogged deletion of accounting history.
        for engine in (runtime, operator, migration):
            engine.dispose()


@pytest.mark.parametrize("role", ["runtime", "operator", "migration"])
def test_missing_context_and_forced_owner_reads(ledger: Ledger, role: str) -> None:
    with getattr(ledger, role).begin() as connection:
        for table in TABLES:
            assert connection.execute(table_statement("SELECT id FROM {table}", table)).all() == []


@pytest.mark.parametrize("role", ["runtime", "operator", "migration"])
def test_scoped_reads_and_cross_tenant_joins(ledger: Ledger, role: str) -> None:
    with tenant_transaction(getattr(ledger, role), TenantContext(ledger.tenants[0])) as tx:
        repo = AccountingRepository(tx)
        assert repo.request(ledger.requests[0]) is not None
        assert repo.request(ledger.requests[1]) is None
        assert len(repo.evidence(ledger.requests[0])) == 1
        assert repo.evidence(ledger.requests[1]) == ()
        assert repo.window("quota", ledger.day) is not None
        assert repo.window("budget", ledger.month) is not None
        assert repo.window("quota", ledger.day - timedelta(days=1)) is None
        for table in TABLES:
            assert (
                tx.connection()
                .execute(
                    table_statement("SELECT count(*) FROM {table} WHERE tenant_id=:other", table),
                    {"other": ledger.tenants[1]},
                )
                .scalar_one()
                == 0
            )
        assert (
            tx.connection()
            .execute(
                text("""
            SELECT r.id FROM arbiter.requests r JOIN arbiter.reservations s
                ON s.tenant_id=:other WHERE r.tenant_id=:tenant
        """),
                {"other": ledger.tenants[1], "tenant": ledger.tenants[0]},
            )
            .all()
            == []
        )


@pytest.mark.parametrize("table", TABLES)
def test_missing_context_and_cross_tenant_owner_writes(ledger: Ledger, table: str) -> None:
    for context in (None, ledger.tenants[0]):
        with pytest.raises(DBAPIError) as failure, ledger.migration.begin() as connection:
            if context is not None:
                set_context(connection, context)
            if table in {"quota_windows", "budget_windows"}:
                connection.execute(
                    table_statement(
                        """
                        INSERT INTO {table}(id,tenant_id,window_start)
                        VALUES (:id,:tenant,:start)
                    """,
                        table,
                    ),
                    {
                        "id": uuid4(),
                        "tenant": ledger.tenants[1],
                        "start": ledger.day if table == "quota_windows" else ledger.month,
                    },
                )
            else:
                {
                    "requests": insert_request,
                    "reservations": insert_reservation,
                    "accounting_events": insert_event,
                }[table](connection, ledger.values(1))
        assert postgres_error(failure.value).sqlstate == "42501"
    with ledger.migration.begin() as connection:
        set_context(connection, ledger.tenants[0])
        assert (
            connection.execute(
                text("UPDATE arbiter.requests SET state=state WHERE id=:id"),
                {"id": ledger.requests[1]},
            ).rowcount
            == 0
        )


@pytest.mark.parametrize("target", ["key", "quota", "budget"])
def test_mixed_tenant_request_parents(ledger: Ledger, target: str) -> None:
    values = ledger.values()
    values[target] = {
        "key": ledger.keys[1],
        "quota": ledger.quotas[1],
        "budget": ledger.budgets[1],
    }[target]
    with pytest.raises(DBAPIError) as failure, ledger.migration.begin() as connection:
        set_context(connection, ledger.tenants[0])
        insert_bundle(connection, values)
    assert postgres_error(failure.value).sqlstate == "23503"


@pytest.mark.parametrize("table", ["quota_windows", "budget_windows"])
def test_duplicate_and_timezone_window_identity(ledger: Ledger, table: str) -> None:
    start = ledger.day if table == "quota_windows" else ledger.month
    for equivalent in (start, start.astimezone(timezone(timedelta(hours=5, minutes=30)))):
        with pytest.raises(DBAPIError) as failure, ledger.migration.begin() as connection:
            set_context(connection, ledger.tenants[0])
            connection.execute(
                table_statement(
                    """
                INSERT INTO {table}(id,tenant_id,window_start) VALUES (:id,:tenant,:start)
            """,
                    table,
                ),
                {"id": uuid4(), "tenant": ledger.tenants[0], "start": equivalent},
            )
        assert postgres_error(failure.value).sqlstate == "23505"
    with pytest.raises(DBAPIError) as failure, ledger.migration.begin() as connection:
        set_context(connection, ledger.tenants[0])
        connection.execute(
            table_statement(
                """
            INSERT INTO {table}(id,tenant_id,window_start) VALUES (:id,:tenant,:start)
        """,
                table,
            ),
            {"id": uuid4(), "tenant": ledger.tenants[0], "start": start + timedelta(hours=1)},
        )
    assert postgres_error(failure.value).sqlstate == "23514"


@pytest.mark.parametrize("table", ["quota_windows", "budget_windows"])
@pytest.mark.parametrize(
    "column,value",
    [("committed", -1), ("reserved", -1), ("committed", MAXIMUM), ("reserved", MAXIMUM + 1)],
)
def test_negative_and_overflow_window_totals(
    ledger: Ledger, table: str, column: str, value: int
) -> None:
    with pytest.raises(DBAPIError) as failure, ledger.migration.begin() as connection:
        set_context(connection, ledger.tenants[0])
        connection.execute(
            table_statement(
                "UPDATE {table} SET {column}=:value WHERE tenant_id=:tenant", table, column
            ),
            {"value": value, "tenant": ledger.tenants[0]},
        )
    assert postgres_error(failure.value).sqlstate in {"23514", "22003"}


def test_idempotency_uniqueness_is_per_tenant_and_key(ledger: Ledger) -> None:
    with tenant_transaction(ledger.runtime, TenantContext(ledger.tenants[0])) as tx:
        existing: str = (
            tx.connection()
            .execute(
                text(
                    "SELECT idempotency_key FROM arbiter.requests "
                    "WHERE id=:id AND tenant_id=:tenant"
                ),
                {"id": ledger.requests[0], "tenant": ledger.tenants[0]},
            )
            .scalar_one()
        )
    values = ledger.values()
    values["idem"] = existing
    with pytest.raises(DBAPIError) as failure, ledger.migration.begin() as connection:
        set_context(connection, ledger.tenants[0])
        insert_bundle(connection, values)
    assert postgres_error(failure.value).sqlstate == "23505"
    # Same string on the other tenant's independently bound key is legal; rollback test data.
    with ledger.migration.connect() as connection, connection.begin() as transaction:
        set_context(connection, ledger.tenants[1])
        values = ledger.values(1)
        values["idem"] = existing
        insert_bundle(connection, values)
        connection.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
        transaction.rollback()
    # The same tenant with a different key also has an independent idempotency namespace.
    with ledger.migration.connect() as connection, connection.begin() as transaction:
        set_context(connection, ledger.tenants[0])
        new_key, audit = uuid4(), uuid4()
        connection.execute(
            text("""
            INSERT INTO arbiter.audit_events
            (id,tenant_id,actor_type,actor_reference,actor_membership_id,action,
             target_id,policy_revision,outcome)
            SELECT :audit,tenant_id,actor_type,actor_reference,actor_membership_id,
                action,:new_key,policy_revision,outcome FROM arbiter.audit_events
            WHERE tenant_id=:tenant AND target_id=:old_key AND action='api_key_created'
        """),
            {
                "audit": audit,
                "new_key": new_key,
                "tenant": ledger.tenants[0],
                "old_key": ledger.keys[0],
            },
        )
        connection.execute(
            text("""
            INSERT INTO arbiter.api_keys
            (id,tenant_id,public_id,label,verifier,pepper_version,scopes,created_at,
             expires_at,created_by_membership_id,creation_audit_id)
            SELECT :new_key,tenant_id,:public,label,verifier,pepper_version,scopes,
                created_at,expires_at,created_by_membership_id,:audit
            FROM arbiter.api_keys WHERE tenant_id=:tenant AND id=:old_key
        """),
            {
                "new_key": new_key,
                "public": uuid4().hex,
                "audit": audit,
                "tenant": ledger.tenants[0],
                "old_key": ledger.keys[0],
            },
        )
        insert_bundle(connection, {**ledger.values(), "key": new_key, "idem": existing})
        connection.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
        transaction.rollback()


@pytest.mark.parametrize("missing", ["reservation", "event"])
def test_no_request_without_matching_atomic_evidence(ledger: Ledger, missing: str) -> None:
    values = ledger.values()
    with pytest.raises(DBAPIError) as failure, ledger.migration.begin() as connection:
        set_context(connection, ledger.tenants[0])
        insert_request(connection, values)
        if missing != "reservation":
            insert_reservation(connection, values)
    assert postgres_error(failure.value).sqlstate in {"23503", "23514"}
    with tenant_transaction(ledger.runtime, TenantContext(ledger.tenants[0])) as tx:
        assert isinstance(values["request"], UUID)
        assert AccountingRepository(tx).request(values["request"]) is None


@pytest.mark.parametrize("target", ["reservation", "event"])
def test_cross_tenant_reservation_and_event_bindings(ledger: Ledger, target: str) -> None:
    values = ledger.values()
    with pytest.raises(DBAPIError) as failure, ledger.migration.begin() as connection:
        set_context(connection, ledger.tenants[0])
        if target == "reservation":
            values["request"] = ledger.requests[1]
            insert_reservation(connection, values)
        else:
            values["reservation"] = tx_reservation(ledger, 1)
            insert_event(connection, values)
    assert postgres_error(failure.value).sqlstate == "23503"


def tx_reservation(ledger: Ledger, index: int) -> UUID:
    with tenant_transaction(ledger.runtime, TenantContext(ledger.tenants[index])) as tx:
        result: UUID = (
            tx.connection()
            .execute(
                text(
                    "SELECT reservation_id FROM arbiter.requests WHERE tenant_id=:tenant AND id=:id"
                ),
                {"tenant": ledger.tenants[index], "id": ledger.requests[index]},
            )
            .scalar_one()
        )
        return result


@pytest.mark.parametrize(
    "table,column,value",
    [
        ("requests", "credit_charge", -1),
        ("requests", "credit_charge", MAXIMUM + 1),
        ("requests", "fingerprint_version", 0),
        ("requests", "output_tokens", -1),
        ("reservations", "credits", -1),
        ("reservations", "credits", MAXIMUM + 1),
        ("reservations", "request_count", 2),
    ],
)
def test_invalid_amounts_and_snapshots(ledger: Ledger, table: str, column: str, value: int) -> None:
    with pytest.raises(DBAPIError) as failure, ledger.migration.begin() as connection:
        set_context(connection, ledger.tenants[0])
        connection.execute(
            table_statement(
                "UPDATE {table} SET {column}=:value WHERE tenant_id=:tenant", table, column
            ),
            {"value": value, "tenant": ledger.tenants[0]},
        )
    assert postgres_error(failure.value).sqlstate in {"23514", "23503", "22003"}


@pytest.mark.parametrize("role", ["runtime", "operator", "migration"])
@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE arbiter.accounting_events SET credits=credits",
        "DELETE FROM arbiter.accounting_events",
        "TRUNCATE arbiter.accounting_events CASCADE",
    ],
)
def test_accounting_evidence_immutable_even_for_owner(
    ledger: Ledger, role: str, statement: str
) -> None:
    with pytest.raises(DBAPIError) as failure, getattr(ledger, role).begin() as connection:
        set_context(connection, ledger.tenants[0])
        connection.execute(text(statement))
    assert postgres_error(failure.value).sqlstate == "42501"


@pytest.mark.parametrize("table", TABLES)
@pytest.mark.parametrize("role", ["runtime", "operator"])
def test_restricted_runtime_and_operator_write_grants(
    ledger: Ledger, table: str, role: str
) -> None:
    with getattr(ledger, role).begin() as connection:
        assert (
            connection.execute(
                text("SELECT has_table_privilege(current_user,:table,'SELECT')"),
                {"table": "arbiter." + table},
            ).scalar_one()
            is True
        )
        assert (
            connection.execute(
                text("""
            SELECT has_table_privilege(current_user,:table,
                'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
        """),
                {"table": "arbiter." + table},
            ).scalar_one()
            is False
        )
    with pytest.raises(DBAPIError) as failure, getattr(ledger, role).begin() as connection:
        set_context(connection, ledger.tenants[0])
        connection.execute(
            table_statement("UPDATE {table} SET id=id WHERE tenant_id=:tenant", table),
            {"tenant": ledger.tenants[0]},
        )
    assert postgres_error(failure.value).sqlstate == "42501"


def test_pool_context_reset_and_repository_guard(ledger: Ledger) -> None:
    for index in (0, 1, 0):
        with tenant_transaction(ledger.runtime, TenantContext(ledger.tenants[index])) as tx:
            assert AccountingRepository(tx).request(ledger.requests[index]) is not None
            assert AccountingRepository(tx).request(ledger.requests[1 - index]) is None
        with ledger.runtime.begin() as connection:
            assert (
                connection.execute(
                    text("SELECT NULLIF(current_setting('arbiter.tenant_id',true),'')")
                ).scalar_one()
                is None
            )
            assert connection.execute(text("SELECT id FROM arbiter.accounting_events")).all() == []
    with tenant_transaction(ledger.runtime, TenantContext(ledger.tenants[0])) as tx:
        set_context(tx.connection(), ledger.tenants[1])
        with pytest.raises(RuntimeError, match="context changed"):
            AccountingRepository(tx).request(ledger.requests[0])


def test_state_and_settlement_evidence_must_match(ledger: Ledger) -> None:
    values = ledger.values()
    with pytest.raises(DBAPIError) as failure, ledger.migration.begin() as connection:
        set_context(connection, ledger.tenants[0])
        insert_bundle(connection, values)
        insert_event(connection, {**values, "event": uuid4()}, "commit")
    assert postgres_error(failure.value).sqlstate == "23514"


@pytest.mark.parametrize("charge", [-1, 0, MAXIMUM + 1])
def test_insert_negative_overflow_credits_are_rejected(ledger: Ledger, charge: int) -> None:
    with pytest.raises(DBAPIError) as failure, ledger.migration.begin() as connection:
        set_context(connection, ledger.tenants[0])
        insert_request(connection, {**ledger.values(), "charge": charge})
    assert postgres_error(failure.value).sqlstate in {"23514", "22003"}


@pytest.mark.parametrize("kind", ["reserve", "commit", "release"])
def test_duplicate_event_kind_and_exclusive_settlement(ledger: Ledger, kind: str) -> None:
    with pytest.raises(DBAPIError) as failure, ledger.migration.begin() as connection:
        set_context(connection, ledger.tenants[0])
        values = ledger.values()
        values["request"] = ledger.requests[0]
        values["reservation"] = tx_reservation(ledger, 0)
        insert_event(connection, values, kind)
        if kind != "reserve":
            insert_event(
                connection,
                {**values, "event": uuid4()},
                "release" if kind == "commit" else "commit",
            )
    assert postgres_error(failure.value).sqlstate == "23505"


def test_reservation_amount_must_match_request_charge(ledger: Ledger) -> None:
    values = ledger.values()
    with pytest.raises(DBAPIError) as failure, ledger.migration.begin() as connection:
        set_context(connection, ledger.tenants[0])
        insert_bundle(connection, values)
        connection.execute(
            text("UPDATE arbiter.reservations SET credits=11 WHERE id=:id"),
            {"id": values["reservation"]},
        )
    assert postgres_error(failure.value).sqlstate == "23503"


def test_policy_cannot_lower_below_current_consumption_or_occupancy(ledger: Ledger) -> None:
    for policy in (
        PolicyInput(daily_quota=0),
        PolicyInput(monthly_budget=0),
        PolicyInput(concurrency=0),
    ):
        with pytest.raises(DBAPIError) as failure:
            PolicyService(ledger.operator).set_policy(ledger.tenants[0], policy)
        assert postgres_error(failure.value).sqlstate == "23514"
    result = PolicyService(ledger.operator).set_policy(
        ledger.tenants[0], PolicyInput(concurrency=2)
    )
    assert result.revision == 3


def test_runtime_cannot_use_operator_limit_checker(ledger: Ledger) -> None:
    with pytest.raises(DBAPIError) as failure, ledger.runtime.begin() as connection:
        set_context(connection, ledger.tenants[0])
        connection.execute(
            text("SELECT arbiter.assert_policy_limits(:tenant,1000,10000,1)"),
            {"tenant": ledger.tenants[0]},
        )
    assert postgres_error(failure.value).sqlstate == "42501"


def test_no_content_columns_or_public_internal_projection(ledger: Ledger) -> None:
    with ledger.migration.begin() as connection:
        columns: set[str] = set(
            connection.execute(
                text("""
            SELECT column_name FROM information_schema.columns
            WHERE table_schema='arbiter' AND table_name=ANY(:tables)
        """),
                {"tables": list(TABLES)},
            ).scalars()
        )
    assert not columns.intersection(
        {"prompt", "completion", "messages", "secret", "verifier", "provider_url", "native_model"}
    )
    with tenant_transaction(ledger.runtime, TenantContext(ledger.tenants[0])) as tx:
        result = AccountingRepository(tx).request(ledger.requests[0])
        assert result is not None and result.input_tokens is None and result.output_tokens is None
        assert not hasattr(result, "payload_hmac") and not hasattr(result, "model_digest")


@pytest.mark.parametrize("table", ["quota_windows", "budget_windows"])
def test_window_identity_and_checked_maximum(ledger: Ledger, table: str) -> None:
    with ledger.migration.connect() as connection, connection.begin() as transaction:
        set_context(connection, ledger.tenants[0])
        connection.execute(
            table_statement(
                """
            UPDATE {table} SET committed=:maximum,reserved=0 WHERE tenant_id=:tenant
        """,
                table,
            ),
            {"maximum": MAXIMUM, "tenant": ledger.tenants[0]},
        )
        assert (
            connection.execute(
                table_statement(
                    """
            SELECT committed+reserved FROM {table} WHERE tenant_id=:tenant
        """,
                    table,
                ),
                {"tenant": ledger.tenants[0]},
            ).scalar_one()
            == MAXIMUM
        )
        transaction.rollback()
    with pytest.raises(DBAPIError) as failure, ledger.migration.begin() as connection:
        set_context(connection, ledger.tenants[0])
        connection.execute(
            table_statement(
                """
            UPDATE {table} SET window_start=window_start-interval '1 month'
            WHERE tenant_id=:tenant
        """,
                table,
            ),
            {"tenant": ledger.tenants[0]},
        )
    assert postgres_error(failure.value).sqlstate == "23514"


@pytest.mark.parametrize("table", TABLES)
def test_tenant_ownership_is_immutable(ledger: Ledger, table: str) -> None:
    with pytest.raises(DBAPIError) as failure, ledger.migration.begin() as connection:
        set_context(connection, ledger.tenants[0])
        connection.execute(
            table_statement(
                """
            UPDATE {table} SET tenant_id=:other WHERE tenant_id=:tenant
        """,
                table,
            ),
            {"other": ledger.tenants[1], "tenant": ledger.tenants[0]},
        )
    assert postgres_error(failure.value).sqlstate in {"23514", "42501"}


@pytest.mark.parametrize(
    "state", ["dispatched", "succeeded", "failed", "unknown", "released", "rejected_capacity"]
)
def test_future_settlement_shapes_with_matching_evidence(ledger: Ledger, state: str) -> None:
    # Validate schema shapes only, in a rolled-back fixture transaction. No writer or dispatch.
    values = ledger.values()
    undispatched = state in {"released", "rejected_capacity"}
    kind, disposition = ("release", "released") if undispatched else ("commit", "committed")
    terminal = state in {"succeeded", "failed", "unknown"}
    outcome = {
        "dispatched": None,
        "succeeded": "succeeded",
        "failed": "provider_failure",
        "unknown": "unknown",
        "released": "cancelled",
        "rejected_capacity": "rejected_capacity",
    }[state]
    with ledger.migration.connect() as connection, connection.begin() as transaction:
        set_context(connection, ledger.tenants[0])
        insert_bundle(connection, values)
        settlement = uuid4()
        insert_event(connection, {**values, "event": settlement}, kind)
        connection.execute(
            text("""
            UPDATE arbiter.reservations SET disposition=:disposition,settlement_event_id=:event
            WHERE tenant_id=:tenant AND id=:id
        """),
            {
                "disposition": disposition,
                "event": settlement,
                "tenant": ledger.tenants[0],
                "id": values["reservation"],
            },
        )
        if not undispatched:
            dispatch_audit = uuid4()
            connection.execute(
                text("""
                INSERT INTO arbiter.audit_events
                    (id,tenant_id,actor_type,actor_reference,actor_api_key_id,action,
                     target_id,policy_revision,request_id,occurred_at,outcome)
                SELECT :audit,r.tenant_id,'api_key',r.key_id::text,r.key_id,
                    'request_dispatched',r.id,r.policy_revision,r.id,
                    CURRENT_TIMESTAMP,'succeeded'
                FROM arbiter.requests r WHERE r.tenant_id=:tenant AND r.id=:request
            """),
                {**values, "audit": dispatch_audit},
            )
            connection.execute(
                text("""
                UPDATE arbiter.requests SET state='dispatched',
                    dispatched_at=CURRENT_TIMESTAMP,dispatch_audit_id=:audit
                WHERE tenant_id=:tenant AND id=:request
            """),
                {**values, "audit": dispatch_audit},
            )
        if terminal and not undispatched:
            terminal_audit = uuid4()
            connection.execute(
                text("""
                INSERT INTO arbiter.audit_events
                    (id,tenant_id,actor_type,actor_reference,actor_api_key_id,action,
                     target_id,policy_revision,request_id,occurred_at,outcome)
                SELECT :audit,r.tenant_id,'api_key',r.key_id::text,r.key_id,
                    'request_finalized',r.id,r.policy_revision,r.id,
                    CURRENT_TIMESTAMP,'succeeded'
                FROM arbiter.requests r WHERE r.tenant_id=:tenant AND r.id=:request
            """),
                {**values, "audit": terminal_audit},
            )
            connection.execute(
                text("""
                UPDATE arbiter.requests SET state=:state,outcome=:outcome,
                    finished_at=CASE WHEN :finished THEN CURRENT_TIMESTAMP ELSE NULL END,
                    terminal_audit_id=:audit
                WHERE tenant_id=:tenant AND id=:request
            """),
                {
                    **values,
                    "state": state,
                    "outcome": outcome,
                    "finished": state != "unknown",
                    "audit": terminal_audit,
                },
            )
        elif undispatched:
            connection.execute(
                text("""
                UPDATE arbiter.requests SET state=:state,outcome=:outcome,
                    finished_at=CURRENT_TIMESTAMP
                WHERE tenant_id=:tenant AND id=:request
            """),
                {**values, "state": state, "outcome": outcome},
            )
        connection.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
        transaction.rollback()


def test_policy_database_guard_and_atomic_rollback(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch
) -> None:
    def snapshot() -> tuple[int, int]:
        with tenant_transaction(ledger.runtime, TenantContext(ledger.tenants[0])) as tx:
            revision: int = (
                tx.connection()
                .execute(
                    text("""
                SELECT policy_revision FROM arbiter.tenants WHERE tenant_id=:tenant
            """),
                    {"tenant": ledger.tenants[0]},
                )
                .scalar_one()
            )
            audits: int = (
                tx.connection()
                .execute(
                    text("""
                SELECT count(*) FROM arbiter.audit_events WHERE tenant_id=:tenant
            """),
                    {"tenant": ledger.tenants[0]},
                )
                .scalar_one()
            )
            return revision, audits

    def bypass_application_check(
        self: PolicyRepository, quota: int, budget: int, concurrency: int
    ) -> None:
        pass

    before = snapshot()
    monkeypatch.setattr(PolicyRepository, "validate_limits", bypass_application_check)
    with pytest.raises(DBAPIError) as failure:
        PolicyService(ledger.operator).set_policy(ledger.tenants[0], PolicyInput(daily_quota=0))
    assert postgres_error(failure.value).sqlstate == "23514"
    assert snapshot() == before
