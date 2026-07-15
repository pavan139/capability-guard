"""Targeted mutation spot checks in temporary copies; stdlib only."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = [
    (
        "bypass-mac",
        "src/capability_guard/authority.py",
        'hmac.compare_digest(hmac.digest(key, body, "sha256"), mac)',
        "True",
    ),
    (
        "skip-ancestor-charging",
        "src/capability_guard/authority.py",
        "for ancestor, _, _ in chain:",
        "for ancestor, _, _ in chain[-1:]:",
    ),
    (
        "reuse-stale-expiry-clock",
        "src/capability_guard/authority.py",
        "self._check_chain(connection, claims, self._now(now))",
        "self._check_chain(connection, claims, current)",
    ),
]


def main():
    results = []
    for name, relative, old, new in MUTATIONS:
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "project"
            shutil.copytree(
                ROOT,
                copied,
                ignore=shutil.ignore_patterns(
                    ".git",
                    ".venv",
                    "__pycache__",
                    "*.egg-info",
                    "artifacts",
                    "dist",
                    "build",
                    "*.db",
                    "*.db-wal",
                    "*.db-shm",
                ),
            )
            target = copied / relative
            source = target.read_text()
            if old not in source:
                raise RuntimeError(f"Mutation target missing: {name}")
            target.write_text(source.replace(old, new))
            run = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", "adversarial", "-q"],
                cwd=copied,
                env=dict(os.environ, PYTHONPATH=str(copied / "src")),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=90,
            )
            results.append(
                {
                    "mutation": name,
                    "killed": run.returncode != 0 and ("FAIL:" in run.stdout or "ERROR:" in run.stdout),
                    "returncode": run.returncode,
                    "evidence": run.stdout[-1800:],
                }
            )
    print(
        json.dumps({"method": "temporary source mutations; working source unchanged", "mutations": results}, indent=2)
    )
    if not all(result["killed"] for result in results):
        raise SystemExit("A targeted mutation survived; inspect evidence.")


if __name__ == "__main__":
    main()
