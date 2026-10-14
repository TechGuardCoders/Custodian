import pytest

from custodian import Custodian, CustodianError, ScopeError, UnknownKeyError


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def c(clock):
    return Custodian(now=clock)


# --- issue -----------------------------------------------------------------

def test_issue_returns_key_id_and_secret(c):
    key_id, secret = c.issue("svc-a", ["read"], 60)
    assert key_id.startswith("key_")
    assert isinstance(secret, str) and len(secret) >= 32


def test_issue_never_stores_plaintext_secret(c):
    key_id, secret = c.issue("svc-a", ["read"], 60)
    rec = c.get_record(key_id)
    assert secret not in str(rec)
    assert rec.secret_hash != secret


def test_issue_rejects_invalid_scope(c):
    with pytest.raises(ScopeError):
        c.issue("svc-a", ["root"], 60)


def test_issue_rejects_empty_scopes(c):
    with pytest.raises(ScopeError):
        c.issue("svc-a", [], 60)


def test_issue_rejects_bad_ttl(c):
    with pytest.raises(ValueError):
        c.issue("svc-a", ["read"], 0)


# --- verify ----------------------------------------------------------------

def test_verify_ok(c):
    key_id, secret = c.issue("svc-a", ["read", "write"], 60)
    assert c.verify(key_id, secret, "read") is True
    assert c.verify(key_id, secret, "write") is True


def test_verify_wrong_secret(c):
    key_id, _ = c.issue("svc-a", ["read"], 60)
    assert c.verify(key_id, "nope", "read") is False


def test_verify_unknown_key(c):
    assert c.verify("key_missing", "s", "read") is False


def test_verify_missing_scope(c):
    key_id, secret = c.issue("svc-a", ["read"], 60)
    assert c.verify(key_id, secret, "admin") is False


def test_verify_expired(clock):
    c = Custodian(now=clock)
    key_id, secret = c.issue("svc-a", ["read"], 60)
    clock.advance(61)
    assert c.verify(key_id, secret, "read") is False


def test_verify_before_expiry_ok(clock):
    c = Custodian(now=clock)
    key_id, secret = c.issue("svc-a", ["read"], 60)
    clock.advance(59)
    assert c.verify(key_id, secret, "read") is True


# --- rotate ----------------------------------------------------------------

def test_rotate_new_secret_works_old_rejected_after_grace(clock):
    c = Custodian(now=clock)
    key_id, old = c.issue("svc-a", ["read"], 1000)
    new = c.rotate(key_id)
    assert new != old
    # both valid immediately after rotation
    assert c.verify(key_id, new, "read") is True
    assert c.verify(key_id, old, "read") is True
    clock.advance(301)  # grace (default 300s) has ended
    assert c.verify(key_id, old, "read") is False
    assert c.verify(key_id, new, "read") is True


def test_rotate_old_valid_during_grace(clock):
    c = Custodian(now=clock)
    key_id, old = c.issue("svc-a", ["read"], 1000)
    c.rotate(key_id)
    clock.advance(299)
    assert c.verify(key_id, old, "read") is True


def test_rotate_unknown_key(c):
    with pytest.raises(UnknownKeyError):
        c.rotate("key_missing")


def test_rotate_revoked_key(c):
    key_id, _ = c.issue("svc-a", ["read"], 60)
    c.revoke(key_id)
    with pytest.raises(CustodianError):
        c.rotate(key_id)


# --- revoke ----------------------------------------------------------------

def test_revoke_is_immediate(c):
    key_id, secret = c.issue("svc-a", ["read"], 60)
    c.revoke(key_id)
    assert c.verify(key_id, secret, "read") is False


def test_revoke_tombstones_record(c):
    key_id, _ = c.issue("svc-a", ["read"], 60)
    c.revoke(key_id)
    rec = c.get_record(key_id)
    assert rec is not None and rec.revoked is True and rec.revoked_at is not None


def test_revoke_unknown_key(c):
    with pytest.raises(UnknownKeyError):
        c.revoke("key_missing")


# --- audit -----------------------------------------------------------------

def test_audit_records_every_event(c):
    key_id, secret = c.issue("svc-a", ["read"], 60)
    c.verify(key_id, secret, "read")
    c.verify(key_id, "bad", "read")
    c.rotate(key_id)
    c.revoke(key_id)
    actions = [e["action"] for e in c.audit()]
    assert actions == ["issue", "verify_ok", "verify_fail", "rotate", "revoke"]


def test_audit_never_contains_secrets(c):
    key_id, secret = c.issue("svc-a", ["read"], 60)
    c.verify(key_id, secret, "read")
    c.rotate(key_id)
    blob = repr(c.audit())
    assert secret not in blob
