# Changing a permission boundary

For an authorization change, add the rejected request first in `adversarial/test_authority.py`. Check usage and the local note effect after denial, not just the exception. Races should coordinate the competing operations with an event or a held SQLite transaction rather than relying on a sleep.

The [credential rules](security/credential-and-quota-rules.md) distinguish MAC verification from transactional authorization. A new claim needs canonical encoding, duplicate-field rejection, attenuation ordering, and live enforcement. Preserve byte-based UTF-8 quotas and ancestor charging. New tool operations belong in the explicit allowlist; issuer methods must stay host-only.

```bash
PYTHONPATH=src python -m unittest discover -s adversarial -v
python scripts/review_mutations.py
```

Use runtime-generated keys and temporary databases in tests. Save credential-free receipts when an experiment changes, together with the scenario and expected decision. The [sharing procedure](security/sharing-without-credentials.md) covers the repository checks and which artifacts may be included.
