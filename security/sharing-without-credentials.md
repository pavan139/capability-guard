# Sharing a credential-free example

Publish the library, adversarial cases, host-policy notes, and synthetic receipts. Keep issuer keys, bearer tokens, private note contents, and SQLite database files outside the repository. The demo creates its own temporary state, so reproducing it requires no shared secret from a previous run.

Run the repository checker from a Python 3.11+ environment with the development requirements installed:

```bash
python -m pip install -e . -r requirements-dev.txt
python scripts/check_authority.py --require-lint --wheel
```

Review `reports/verification.json` and the [authorization regressions](authorization-regressions.md). A receipt should describe the operation and observed quota/effect, not contain the credential used to authorize it. The tests establish local transactional behavior under the stated trusted-host assumptions; keep those assumptions with the artifact.

When uploading to a repository you own, retain the license and actual check record. If distributing a source archive, include `security/`, `adversarial/`, and `receipts/` with the package. The workflow in `.github/workflows/ci.yml` runs the same checker after a push.
