"""Custodian — scoped credential lifecycle: issue, verify, rotate, revoke, audit.

Pure Python, no network. Secrets are hashed (SHA-256 + per-key salt) and never
stored or logged in plaintext.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

VALID_SCOPES = frozenset({"read", "write", "admin"})
GRACE_PERIOD_S = 300  # old secret stays valid for 5 minutes after rotation


class CustodianError(Exception):
    """Base error for Custodian operations."""


class UnknownKeyError(CustodianError):
    """Raised when an operation references a key id that does not exist."""


class ScopeError(CustodianError):
    """Raised when an invalid scope is requested."""


@dataclass
class AuditEvent:
    ts: float
    action: str
    key_id: str
    detail: str = ""

    def as_dict(self) -> dict:
        return {"ts": self.ts, "action": self.action, "key_id": self.key_id, "detail": self.detail}


@dataclass
class KeyRecord:
    key_id: str
    subject: str
    scopes: frozenset
    secret_hash: str
    salt: str
    created_at: float
    expires_at: float
    revoked: bool = False
    revoked_at: Optional[float] = None
    # Previous secret hash kept during rotation grace window.
    prev_secret_hash: Optional[str] = None
    prev_salt: Optional[str] = None
    grace_ends_at: Optional[float] = None


def _hash_secret(secret: str, salt: str) -> str:
    return hashlib.sha256((salt + secret).encode("utf-8")).hexdigest()


def _check_secret(secret: str, salt: str, expected_hash: str) -> bool:
    return hmac.compare_digest(_hash_secret(secret, salt), expected_hash)


class Custodian:
    """In-memory credential custodian."""

    def __init__(self, grace_period_s: int = GRACE_PERIOD_S, now=None) -> None:
        self._grace_period_s = grace_period_s
        self._now = now or time.time
        self._keys: Dict[str, KeyRecord] = {}
        self._audit: List[AuditEvent] = []

    # -- internals ---------------------------------------------------------

    def _log(self, action: str, key_id: str, detail: str = "") -> None:
        self._audit.append(AuditEvent(ts=self._now(), action=action, key_id=key_id, detail=detail))

    @staticmethod
    def _new_secret() -> str:
        return secrets.token_urlsafe(32)

    # -- public API --------------------------------------------------------

    def issue(self, subject: str, scopes: List[str], ttl_s: int) -> tuple[str, str]:
        """Issue a key. Returns (key_id, plaintext_secret). The secret is shown
        exactly once; only its salted hash is stored."""
        if not subject:
            raise ValueError("subject must be non-empty")
        if ttl_s <= 0:
            raise ValueError("ttl_s must be positive")
        bad = set(scopes) - VALID_SCOPES
        if bad:
            raise ScopeError(f"invalid scopes: {sorted(bad)}")
        if not scopes:
            raise ScopeError("at least one scope required")

        key_id = "key_" + secrets.token_hex(8)
        secret = self._new_secret()
        salt = secrets.token_hex(16)
        now = self._now()
        rec = KeyRecord(
            key_id=key_id,
            subject=subject,
            scopes=frozenset(scopes),
            secret_hash=_hash_secret(secret, salt),
            salt=salt,
            created_at=now,
            expires_at=now + ttl_s,
        )
        self._keys[key_id] = rec
        self._log("issue", key_id, f"subject={subject} scopes={sorted(rec.scopes)} ttl_s={ttl_s}")
        return key_id, secret

    def verify(self, key_id: str, secret: str, required_scope: str) -> bool:
        """Verify a key against its id, secret and a required scope.

        Fails on unknown key, wrong secret, expiry, revocation, or missing scope.
        During a rotation grace window the previous secret is also accepted.
        """
        rec = self._keys.get(key_id)
        if rec is None:
            self._log("verify_fail", key_id, "unknown key")
            return False
        now = self._now()

        if rec.revoked:
            self._log("verify_fail", key_id, "revoked")
            return False
        if now >= rec.expires_at:
            self._log("verify_fail", key_id, "expired")
            return False

        if _check_secret(secret, rec.salt, rec.secret_hash):
            matched = True
        elif (
            rec.prev_secret_hash is not None
            and rec.grace_ends_at is not None
            and now < rec.grace_ends_at
            and _check_secret(secret, rec.prev_salt, rec.prev_secret_hash)
        ):
            matched = True  # old secret valid during grace window
        else:
            matched = False

        if not matched:
            self._log("verify_fail", key_id, "bad secret")
            return False
        if required_scope not in rec.scopes:
            self._log("verify_fail", key_id, f"missing scope {required_scope}")
            return False

        self._log("verify_ok", key_id)
        return True

    def rotate(self, key_id: str) -> str:
        """Rotate a key: new secret, old secret stays valid until grace ends."""
        rec = self._keys.get(key_id)
        if rec is None:
            raise UnknownKeyError(f"unknown key: {key_id}")
        if rec.revoked:
            raise CustodianError("cannot rotate a revoked key")
        now = self._now()
        if now >= rec.expires_at:
            raise CustodianError("cannot rotate an expired key")

        new_secret = self._new_secret()
        rec.prev_secret_hash = rec.secret_hash
        rec.prev_salt = rec.salt
        rec.grace_ends_at = now + self._grace_period_s
        rec.salt = secrets.token_hex(16)
        rec.secret_hash = _hash_secret(new_secret, rec.salt)
        self._log("rotate", key_id, f"grace_ends_at={rec.grace_ends_at}")
        return new_secret

    def revoke(self, key_id: str) -> None:
        """Revoke immediately; the key is tombstoned, never deleted."""
        rec = self._keys.get(key_id)
        if rec is None:
            raise UnknownKeyError(f"unknown key: {key_id}")
        rec.revoked = True
        rec.revoked_at = self._now()
        self._log("revoke", key_id)

    def audit(self) -> List[dict]:
        """Audit trail of every event. Never contains secrets."""
        return [e.as_dict() for e in self._audit]

    def get_record(self, key_id: str) -> Optional[KeyRecord]:
        return self._keys.get(key_id)
