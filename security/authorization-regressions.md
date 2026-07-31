# Review and executed checks

The security boundary was reviewed as a **local symmetric capability system**, not user login, public signatures, or a remote authorization service. Every action passes through the typed operation contract and a SQLite transaction; cryptographic verification alone is deliberately insufficient.

## Adversarial evidence

The standard-library suite passes **17 tests**, including:

- Valid-MAC malformed/duplicate/noncanonical/unknown claims, forged MACs, changed budgets, unknown keys, and unregistered MAC-valid credentials.
- Exact expiry/future boundaries, wrong audience, issuer-controlled non-widening attenuation, shared ancestor quotas, descendant revocation, and key rotation/revocation.
- Concurrent unique-nonce requests with a shared quota and concurrent replay of one nonce: the committed counts equal the authorized bound, not the number of contenders.
- Revocation between MAC verification and effect transaction; a request blocked behind a write lock observes the revocation committed before it proceeds.
- Expiry is reread after waiting for the transaction. A stale earlier verification time cannot extend a grant.
- An injected SQLite effect failure rolls back nonce and all quota updates; the same nonce then succeeds after the fault is removed.
- UTF-8 byte accounting and truncation. A reproduced malformed-surrogate input originally escaped as `UnicodeEncodeError`; it now raises `AuthorizationError` with zero usage/effect.

The demo initially used a payload one byte larger than its deliberately small cap; the fixture was corrected and its actual CLI plus invariants are now checked. The authorization limit was retained.

## Targeted mutation checks

`python scripts/review_mutations.py` copies the repository into temporary directories and introduces three regressions: bypassing MAC comparison, charging only the leaf instead of all ancestors, and reusing the stale expiry clock. All three are killed by tests. [mutation-results.json](mutation-results.json) records outcomes and failure evidence. This focused check is not an exhaustive mutation score or security certification.

Executed commands:

```bash
PYTHONPATH=src python -m unittest discover -s adversarial -v
python -m capability_guard demo --output receipts/demo.json
python -m capability_guard evaluate --output receipts/evaluation.json
python scripts/review_mutations.py
```

Ruff checks/formatting pass. All runtime and test dependencies are standard-library modules; no credentials, network services, model downloads, or paid calls were used. Keys and bearers are generated temporarily and omitted from persisted reports.

## Limits

The host, issuer keys, clock, SQLite store/filesystem, and API integration are trusted. There was no OS sandboxing, network deployment, multi-host failure campaign, cryptographic primitive audit, formal proof, or high-load service benchmark. `verify()` may return claims for a revoked/used credential; only `execute()` authorizes under live transactional state. See the threat model in the README and [DESIGN](credential-and-quota-rules.md).
