"""Atomic Redis tenant/key rate admission and process-incarnation recovery barrier.

This synchronous component is called only from an off-event-loop admission service.
Redis contains opaque UUID-derived keys and request IDs, never request content.
"""

import socket
from dataclasses import dataclass
from uuid import UUID, uuid4

from arbiter.config import RedisSettings
from arbiter.observability import metrics
from arbiter.persistence.workload import KeyBinding

WINDOW_MS = 60_000
KEY_TTL_MS = 61_000
_MAX_REPLY = 64

# The one script owns the process epoch, recovery barrier, reset detection and
# paired decision. INFO/TIME are executed by Redis in the same atomic invocation.
RATE_SCRIPT = r"""
local function field(info, name)
    return string.match(info, '[\r\n]' .. name .. ':([^\r\n]+)')
end
local server = redis.call('INFO', 'server')
local persistence = redis.call('INFO', 'persistence')
local memory = redis.call('INFO', 'memory')
local run = field(server, 'run_id')
local maxmemory = tonumber(field(memory, 'maxmemory'))
local usedmemory = tonumber(field(memory, 'used_memory'))
if not run or not string.match(run, '^[0-9a-f]+$')
    or field(persistence, 'aof_enabled') ~= '1'
    or field(persistence, 'aof_last_write_status') ~= 'ok'
    or field(persistence, 'aof_last_bgrewrite_status') ~= 'ok'
    or field(memory, 'maxmemory_policy') ~= 'noeviction'
    or not maxmemory or not usedmemory or maxmemory - usedmemory < 4194304 then
    return -4
end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local pending = redis.call('GET', KEYS[2])
local sentinel = redis.call('GET', KEYS[1])
local anchor = '__epoch:' .. run
local function begin_barrier(incident)
    if incident then redis.call('SET', KEYS[4], 'limiter_state_lost') end
    redis.call('SET', KEYS[2], run .. ':' .. string.format('%.0f', now + 60000))
    return -3
end
if pending then
    local pending_run, pending_until = string.match(pending, '^([0-9a-f]+):([0-9]+)$')
    local until_ms = tonumber(pending_until)
    if not pending_run or not until_ms or until_ms > now + 60000 then
        -- A malformed or implausible barrier never grants admission.
        return -4
    end
    if pending_run ~= run then return begin_barrier(true) end
    if now < until_ms then return -3 end
    -- The original 60-second deadline has elapsed. Old windows are expired.
    redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', '+inf')
    redis.call('ZADD', KEYS[3], 9007199254740991, anchor)
    redis.call('SET', KEYS[1], run)
    redis.call('DEL', KEYS[7])
    redis.call('DEL', KEYS[2])
elseif sentinel ~= run then
    -- A complete reset can erase both sentinel and index; conservatively
    -- record every missing epoch as an incident, including a virgin startup.
    return begin_barrier(true)
elseif redis.call('ZSCORE', KEYS[3], anchor) == false then
    return begin_barrier(true)
end
if redis.call('GET', KEYS[7]) then return begin_barrier(true) end
local limit_tenant = tonumber(ARGV[1])
local limit_key = tonumber(ARGV[2])
if not limit_tenant or not limit_key or limit_tenant < 0 or limit_key < 0
    or limit_tenant > 9223372036854775807 or limit_key > 9223372036854775807
    or ARGV[3] == nil or not string.match(ARGV[3], '^[0-9a-f]+$') then
    return -4
end
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
for i = 5, 6 do
    local expected = redis.call('ZSCORE', KEYS[3], KEYS[i])
    local kind = redis.call('TYPE', KEYS[i]).ok
    if expected and kind ~= 'zset' then return begin_barrier(true) end
    if not expected and kind ~= 'none' then
        if kind ~= 'zset' then return begin_barrier(true) end
        redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', now - 60000)
        if redis.call('ZCARD', KEYS[i]) > 0 then return begin_barrier(true) end
    end
end
redis.call('ZREMRANGEBYSCORE', KEYS[5], '-inf', now - 60000)
redis.call('ZREMRANGEBYSCORE', KEYS[6], '-inf', now - 60000)
local tenant_count = redis.call('ZCARD', KEYS[5])
local key_count = redis.call('ZCARD', KEYS[6])
if tenant_count >= limit_tenant then return -1 end
if key_count >= limit_key then return -2 end
-- If a Redis command fails after the first write, this marker survives. Every
-- later attempt enters a full barrier instead of trusting a partial decision.
redis.call('SET', KEYS[7], ARGV[3])
redis.call('ZADD', KEYS[5], now, ARGV[3])
redis.call('ZADD', KEYS[6], now, ARGV[3])
redis.call('PEXPIRE', KEYS[5], 61000)
redis.call('PEXPIRE', KEYS[6], 61000)
redis.call('ZADD', KEYS[3], now + 60000, KEYS[5], now + 60000, KEYS[6])
redis.call('DEL', KEYS[7])
return 1
"""


class RateDenied(Exception):
    code = "rate_exhausted"
    status_code = 429


class RateUnavailable(Exception):
    code = "unavailable"
    status_code = 503


def _command(parts: tuple[bytes, ...]) -> bytes:
    return (
        b"*"
        + str(len(parts)).encode()
        + b"\r\n"
        + b"".join(b"$" + str(len(part)).encode() + b"\r\n" + part + b"\r\n" for part in parts)
    )


def _integer_reply(sock: socket.socket) -> int:
    reply = bytearray()
    while not reply.endswith(b"\r\n"):
        if len(reply) >= _MAX_REPLY:
            raise RateUnavailable()
        part = sock.recv(1)
        if not part:
            raise RateUnavailable()
        reply.extend(part)
    if reply[:1] != b":" or not reply[1:-2].lstrip(b"-").isdigit():
        raise RateUnavailable()
    return int(reply[1:-2])


@dataclass(frozen=True, slots=True)
class RateGate:
    settings: RedisSettings

    def admit(self, binding: KeyBinding, tenant_limit: int, key_limit: int) -> None:
        if (
            not isinstance(binding.tenant_id, UUID)
            or not isinstance(binding.key_id, UUID)
            or type(tenant_limit) is not int
            or type(key_limit) is not int
            or not 0 <= tenant_limit <= 9223372036854775807
            or not 0 <= key_limit <= 9223372036854775807
        ):
            raise RateUnavailable()
        prefix = b"arbiter:rate:"
        tenant = binding.tenant_id.hex.encode("ascii")
        key = binding.key_id.hex.encode("ascii")
        keys = (
            prefix + b"sentinel",
            prefix + b"barrier",
            prefix + b"index",
            prefix + b"incident",
            prefix + b"tenant:" + tenant,
            prefix + b"key:" + tenant + b":" + key,
            prefix + b"write_marker",
        )
        request_id = uuid4().hex.encode("ascii")
        parts = (
            b"EVAL",
            RATE_SCRIPT.encode("ascii"),
            b"7",
            *keys,
            str(tenant_limit).encode("ascii"),
            str(key_limit).encode("ascii"),
            request_id,
        )
        try:
            with socket.create_connection(
                (self.settings.host, self.settings.port), timeout=2
            ) as sock:
                sock.settimeout(3)
                sock.sendall(_command(parts))
                decision = _integer_reply(sock)
        except (OSError, ValueError, OverflowError, RateUnavailable):
            metrics.redis("unavailable")
            raise RateUnavailable() from None
        if decision == 1:
            metrics.redis("healthy")
            return
        if decision in {-1, -2}:
            metrics.redis("denied")
            raise RateDenied()
        metrics.redis("barrier" if decision == -3 else "unavailable")
        raise RateUnavailable()
