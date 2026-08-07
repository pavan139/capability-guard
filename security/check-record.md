# Authorization check record

The behavioral suite contains 17 tests covering MAC/claim rejection, attenuation, replay, quota sharing, key and token revocation, UTF-8 accounting, blocked transactions, and rollback after an effect fault. Run it with `python -m unittest discover -s adversarial -v`.

The [machine-readable check record](../reports/verification.json) records the current test count, skips, source/configuration digest, lint results, and cold-wheel CLI checks. It is refreshed by `scripts/check_authority.py`. The [replay trials](replay-and-quota-trials.md) and [regression notes](authorization-regressions.md) explain what those tests actually exercise.

These are local file-backed SQLite checks. The report is not a claim about remote effects, key provisioning, OS isolation, or a deployed authorization service.
