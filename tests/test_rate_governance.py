"""Real Redis paired decisions and full-duration recovery checks."""

import os
import socket
from concurrent.futures import ThreadPoolExecutor
from time import monotonic, sleep
from uuid import UUID, uuid4

import pytest

from arbiter.config import RedisSettings
from arbiter.governance import rate
from arbiter.governance.rate import RateDenied, RateGate, RateUnavailable
from arbiter.persistence.workload import KeyBinding

pytestmark = pytest.mark.skipif(os.environ.get("ARBITER_TEST_REDIS") != "1", reason="real Redis")
SETTINGS = RedisSettings()
GATE = RateGate(SETTINGS)


def binding(tenant: UUID | None = None, key: UUID | None = None) -> KeyBinding:
    return KeyBinding(key or uuid4(), tenant or uuid4(), ("inference:write",))


def redis_int(script: str, keys: tuple[str, ...] = (), args: tuple[str, ...] = ()) -> int:
    command = (
        b"EVAL",
        script.encode("ascii"),
        str(len(keys)).encode("ascii"),
        *(value.encode("ascii") for value in keys),
        *(value.encode("ascii") for value in args),
    )
    with socket.create_connection((SETTINGS.host, SETTINGS.port), timeout=2) as sock:
        sock.settimeout(3)
        sock.sendall(rate._command(command))
        return rate._integer_reply(sock)


def tenant_key(actor: KeyBinding) -> str:
    return f"arbiter:rate:tenant:{actor.tenant_id.hex}"


def api_key(actor: KeyBinding) -> str:
    return f"arbiter:rate:key:{actor.tenant_id.hex}:{actor.key_id.hex}"


def count(name: str) -> int:
    return redis_int("return redis.call('ZCARD',KEYS[1])", (name,))


def test_administrative_commands_and_other_keyspace_are_denied() -> None:
    for command in (
        (b"CONFIG", b"GET", b"maxmemory-policy"),
        (b"FLUSHALL",),
        (b"SET", b"unrelated:key", b"value"),
    ):
        with socket.create_connection((SETTINGS.host, SETTINGS.port), timeout=2) as sock:
            sock.settimeout(3)
            sock.sendall(rate._command(command))
            assert sock.recv(128).startswith(b"-NOPERM")


def wait_ready() -> None:
    actor = binding()
    end = monotonic() + 65
    while monotonic() < end:
        try:
            GATE.admit(actor, 0, 0)
        except RateDenied:
            return
        except RateUnavailable:
            sleep(0.2)
    pytest.fail("Redis recovery barrier did not become ready after 60 seconds")


def test_paired_limits_independence_and_zero() -> None:
    wait_ready()
    first = binding()
    second_key = binding(first.tenant_id)
    other_tenant = binding()
    GATE.admit(first, 2, 1)
    assert (count(tenant_key(first)), count(api_key(first))) == (1, 1)
    with pytest.raises(RateDenied):
        GATE.admit(first, 2, 1)
    assert (count(tenant_key(first)), count(api_key(first))) == (1, 1)
    GATE.admit(second_key, 2, 1)
    with pytest.raises(RateDenied):
        GATE.admit(binding(first.tenant_id), 2, 1)
    assert count(tenant_key(first)) == 2
    assert count(api_key(second_key)) == 1
    GATE.admit(other_tenant, 1, 1)
    assert count(tenant_key(other_tenant)) == 1
    zero = binding()
    with pytest.raises(RateDenied):
        GATE.admit(zero, 0, 30)
    with pytest.raises(RateDenied):
        GATE.admit(zero, 60, 0)
    assert (count(tenant_key(zero)), count(api_key(zero))) == (0, 0)


def test_concurrent_paired_decisions_never_overshoot() -> None:
    wait_ready()
    tenant = uuid4()
    keys = [binding(tenant) for _ in range(5)]

    def attempt(index: int) -> bool:
        try:
            GATE.admit(keys[index % len(keys)], 10, 3)
            return True
        except RateDenied:
            return False

    with ThreadPoolExecutor(max_workers=32) as workers:
        outcomes = list(workers.map(attempt, range(100)))
    assert sum(outcomes) == 10
    assert count(tenant_key(keys[0])) == 10
    assert all(count(api_key(key)) <= 3 for key in keys)
    assert sum(count(api_key(key)) for key in keys) == 10


def test_redis_server_time_boundary_pruning_and_expiry() -> None:
    wait_ready()
    actor = binding()
    GATE.admit(actor, 1, 1)
    tenant, key = tenant_key(actor), api_key(actor)
    script = """
        local t=redis.call('TIME')
        local now=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)
        local member=redis.call('ZRANGE',KEYS[1],0,0)[1]
        if not member or not string.match(member,'^[0-9a-f]+$')
            or string.len(member) ~= 32 then return -1 end
        redis.call('ZADD',KEYS[1],now-60000,member)
        redis.call('ZADD',KEYS[2],now-60000,member)
        return redis.call('PTTL',KEYS[1])
    """
    ttl = redis_int(script, (tenant, key))
    assert 60_000 <= ttl <= 61_000
    # The exact 60-second-old entry is pruned on the next server-time decision.
    GATE.admit(actor, 1, 1)
    assert (count(tenant), count(key)) == (1, 1)
    assert redis_int("return redis.call('PTTL',KEYS[1])", (tenant,)) > 60_000


def test_unavailable_and_script_failure_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    with socket.socket() as unused:
        unused.bind(("127.0.0.1", 0))
        unreachable = RateGate(RedisSettings(host="127.0.0.1", port=unused.getsockname()[1]))
        with pytest.raises(RateUnavailable):
            unreachable.admit(binding(), 1, 1)
    actor = binding()
    monkeypatch.setattr(rate, "RATE_SCRIPT", "return redis.call('NONEXISTENT_COMMAND')")
    with pytest.raises(RateUnavailable):
        GATE.admit(actor, 1, 1)
    assert count(tenant_key(actor)) == count(api_key(actor)) == 0


def test_missing_sentinel_and_concurrent_probes_keep_full_barrier() -> None:
    wait_ready()
    sentinel = "arbiter:rate:sentinel"
    barrier = "arbiter:rate:barrier"
    # Erase both markers to model a complete limiter reset, not just one lost key.
    assert (
        redis_int("return redis.call('DEL',KEYS[1],KEYS[2])", (sentinel, "arbiter:rate:index")) == 2
    )
    actor = binding()
    with ThreadPoolExecutor(max_workers=16) as workers:
        outcomes = list(workers.map(lambda _: _unavailable(actor), range(32)))
    assert all(outcomes)
    assert redis_int("return redis.call('EXISTS',KEYS[1])", ("arbiter:rate:incident",)) == 1
    assert redis_int("return redis.call('PING').ok == 'PONG' and 1 or 0") == 1
    assert _unavailable(actor)
    deadline = redis_int(
        "return tonumber(string.match(redis.call('GET',KEYS[1]),':([0-9]+)$'))", (barrier,)
    )
    sleep(1)
    assert _unavailable(actor)
    assert (
        redis_int(
            "return tonumber(string.match(redis.call('GET',KEYS[1]),':([0-9]+)$'))", (barrier,)
        )
        == deadline
    )
    server_now = redis_int(
        "local t=redis.call('TIME'); return tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000)"
    )
    assert server_now < deadline
    wait_ready()
    GATE.admit(actor, 1, 1)


def _unavailable(actor: KeyBinding) -> bool:
    try:
        GATE.admit(actor, 1, 1)
    except RateUnavailable:
        return True
    return False


def test_detected_limiter_state_loss_blocks_and_records_incident() -> None:
    wait_ready()
    actor = binding()
    GATE.admit(actor, 2, 2)
    assert redis_int("return redis.call('DEL',KEYS[1])", (tenant_key(actor),)) == 1
    assert _unavailable(actor)
    assert redis_int("return redis.call('EXISTS',KEYS[1])", ("arbiter:rate:incident",)) == 1
    assert count(api_key(actor)) == 1
    wait_ready()
    GATE.admit(actor, 2, 2)


def test_interrupted_paired_write_marker_requires_recovery() -> None:
    wait_ready()
    marker = "arbiter:rate:write_marker"
    assert redis_int("redis.call('SET',KEYS[1],'interrupted'); return 1", (marker,)) == 1
    actor = binding()
    assert _unavailable(actor)
    assert count(tenant_key(actor)) == count(api_key(actor)) == 0
    wait_ready()
    assert redis_int("return redis.call('EXISTS',KEYS[1])", (marker,)) == 0
    GATE.admit(actor, 1, 1)


@pytest.mark.skipif(
    os.environ.get("ARBITER_TEST_REDIS_RESTARTED") != "1"
    and os.environ.get("ARBITER_TEST_EXIT_HOST") != "1",
    reason="requires host restart step",
)
def test_process_restart_requires_new_full_barrier() -> None:
    if os.environ.get("ARBITER_TEST_EXIT_HOST") == "1":
        from phase3_exit_host import request_host

        request_host("redis_restart")
    # Run only immediately after the host has restarted this test Redis process.
    actor = binding()
    assert _unavailable(actor)
    wait_ready()
    GATE.admit(actor, 1, 1)
