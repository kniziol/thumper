"""HMAC signing for the public /api/trigger callback.

The trigger endpoint is reachable by every managed endpoint, so it is effectively
public. Each tripwire carries a unique secret; the agent signs its callback body
with it and the server verifies. The secret never appears in the planted bait
file, so an attacker who finds the token (and the callback URL) still cannot
forge a trigger.

Signature is computed over the EXACT request body bytes - no canonicalization,
no room for an encoding mismatch between agent and server.
"""
import hashlib
import hmac

_PREFIX = "sha256="


def sign(secret: str, body: bytes) -> str:
    return _PREFIX + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def verify(secret: str, body: bytes, signature: str | None) -> bool:
    if not signature:
        return False
    return hmac.compare_digest(sign(secret, body), signature)


def _signed_material(ts: int, body: bytes) -> bytes:
    """The bytes covered by a timestamped signature: "<ts>." then the raw body.
    Binding the timestamp in is what makes a captured payload non-replayable.
    `ts` is an integer unix-seconds and `body` is JSON (always starts with `{`),
    so the "<ts>." prefix is unambiguous - no (ts, body) pair can collide."""
    return f"{ts}.".encode() + body


def sign_timestamped(secret: str, ts: int, body: bytes) -> str:
    """Sign send-time `ts` (unix seconds) together with the body."""
    return sign(secret, _signed_material(ts, body))


def verify_timestamped(secret: str, ts: int, body: bytes, signature: str | None,
                       *, now: int, max_age: int = 300, max_skew: int = 60) -> bool:
    """True iff `signature` matches and `ts` is recent.

    The window is ASYMMETRIC on purpose. A captured payload is only replayable
    inside the accept window, so the backward tolerance (`max_age`, default 300s)
    is the real exposure and stays generous for slow/queued delivery. The forward
    tolerance (`max_skew`, default 60s) exists ONLY to absorb clock drift: a
    symmetric window would let an attacker mint a future-dated `ts` and stretch
    the effective replay window to `max_age + max_skew` past that future instant.
    Capping forward skew keeps the worst-case acceptance at ~`max_age`."""
    if ts > now + max_skew:   # too far in the future - drift cap
        return False
    if now - ts > max_age:    # too old - stale replay
        return False
    return verify(secret, _signed_material(ts, body), signature)
