# Custodian

Scoped credential lifecycle in pure Python: issue keys with scopes and a TTL, verify them, rotate with a grace window, revoke immediately, and keep an audit trail of every event. No network, no dependencies beyond `pytest` for tests.

## What it does

- **`issue(subject, scopes, ttl_s)`** → returns `(key_id, secret)` once. Only a salted SHA-256 hash of the secret is stored; the plaintext is never persisted or logged.
- **`verify(key_id, secret, required_scope)`** → `bool`. Checks existence, revocation, expiry, secret match, and scope.
- **`rotate(key_id)`** → new secret; the old secret stays valid until the grace window ends (default 300s), so rotation is zero-downtime.
- **`revoke(key_id)`** → immediate; the record is tombstoned, never deleted.
- **`audit()`** → ordered list of every event (`issue`, `verify_ok`, `verify_fail`, `rotate`, `revoke`), timestamps included, secrets excluded.

## Architecture

```
custodian.py
├── Custodian          # state: key_id → KeyRecord, append-only audit list
├── KeyRecord          # subject, scopes, secret_hash + salt, expiry,
│                      # revoked flag, previous hash for grace window
├── AuditEvent         # ts, action, key_id, detail
└── errors             # CustodianError / UnknownKeyError / ScopeError
```

Secrets are hashed with `hashlib.sha256(salt + secret)` and compared with `hmac.compare_digest`. Rotation keeps the previous hash alongside the new one; `verify` accepts either until `grace_ends_at`.

## Why

Most toy key stores either store plaintext secrets, lose the audit trail, or make rotation a breaking change. Custodian keeps all three correct in ~200 lines with no dependencies: hashed secrets, tombstoned revocation, and a grace window so rotation never locks out a live client mid-deploy.

## Usage

```python
from custodian import Custodian

c = Custodian()
key_id, secret = c.issue("svc-a", ["read", "write"], ttl_s=3600)

c.verify(key_id, secret, "read")        # True
c.verify(key_id, secret, "admin")       # False — scope not granted

new_secret = c.rotate(key_id)           # old secret valid for 5 more minutes
c.revoke(key_id)                        # immediate, tombstoned
c.audit()                               # every event, no secrets
```

## Tests

```bash
uv venv && . .venv/bin/Scripts/activate  # or source .venv/bin/activate
uv pip install pytest
pytest -q
```

## License

MIT
