"""Synthetic security contracts, not a production penetration-test claim."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import secrets
from pathlib import Path
import tempfile

from .authority import Authority, AuthorizationError, Operation

NOW = 1_800_000_000


def fresh(path):
    authority = Authority(path)
    authority.add_key("key-one", secrets.token_bytes(32))
    return authority


def denied(function):
    try:
        function()
    except AuthorizationError:
        return True
    return False


def demo():
    with tempfile.TemporaryDirectory() as directory:
        authority = fresh(Path(directory) / "demo.db")
        parent = authority.issue(
            scopes=["note:append", "note:read"], resources=["lab/public", "lab/private"], max_calls=5, now=NOW
        )
        child = authority.attenuate(
            parent, scopes=["note:append"], resources=["lab/public"], max_calls=2, max_units=64, max_bytes=32, now=NOW
        )
        nonce = secrets.token_hex(16)
        committed = authority.execute(
            child, Operation("note:append", "lab/public", "Text never grants scope."), nonce=nonce, now=NOW
        )
        return {
            "experiment": "local fictional tool authorization",
            "cryptography": "standard HMAC-SHA256; symmetric MAC, not a public signature",
            "effect": committed,
            "replay_denied": denied(
                lambda: authority.execute(child, Operation("note:append", "lab/public", "again"), nonce=nonce, now=NOW)
            ),
            "private_resource_denied": denied(
                lambda: authority.execute(
                    child, Operation("note:append", "lab/private", "x"), nonce=secrets.token_hex(16), now=NOW
                )
            ),
            "shared_parent_usage": authority.usage(authority.verify(parent, now=NOW).token_id),
            "secrets_reported": False,
            "limits": [
                "Trusted issuer owns HMAC keys; holders cannot attenuate without issuer reissuance.",
                "Effect and quotas are atomic only inside this SQLite database; no OS sandbox or remote exactly-once guarantee.",
            ],
        }


def evaluate():
    rows = []
    with tempfile.TemporaryDirectory() as directory:
        for index, scenario in enumerate(
            (
                "allowed",
                "wrong-resource",
                "wrong-scope",
                "expiry",
                "future",
                "forgery",
                "replay",
                "revocation",
                "ancestor-revocation",
                "key-revocation",
                "widen-scopes",
                "widen-quota",
                "shared-quota",
                "unknown-operation",
                "byte-budget",
                "concurrent-quota",
                "concurrent-replay",
            )
        ):
            authority = fresh(Path(directory) / f"{index}.db")
            token = authority.issue(
                scopes=["note:append"],
                resources=["lab/public"],
                max_calls=4,
                max_units=16,
                max_bytes=8,
                ttl=10,
                now=NOW,
            )
            operation = Operation("note:append", "lab/public", "x")
            execute = lambda value=token, op=operation, nonce=None, now=NOW: authority.execute(
                value, op, nonce=nonce or secrets.token_hex(16), now=now
            )
            if scenario == "allowed":
                passed = execute()["committed"]
            elif scenario == "wrong-resource":
                passed = denied(lambda: execute(op=replace(operation, resource="lab/private")))
            elif scenario == "wrong-scope":
                passed = denied(lambda: execute(op=Operation("note:clear", "lab/public")))
            elif scenario == "expiry":
                passed = denied(lambda: execute(now=NOW + 10))
            elif scenario == "future":
                passed = denied(lambda: execute(now=NOW - 1))
            elif scenario == "forgery":
                passed = denied(lambda: execute(value=token[:-2] + ("AA" if token[-2:] != "AA" else "BB")))
            elif scenario == "replay":
                nonce = secrets.token_hex(16)
                execute(nonce=nonce)
                passed = denied(lambda: execute(nonce=nonce))
            elif scenario == "revocation":
                authority.revoke(authority.verify(token, now=NOW).token_id)
                passed = denied(execute)
            elif scenario == "ancestor-revocation":
                child = authority.attenuate(token, now=NOW)
                authority.revoke(authority.verify(token, now=NOW).token_id)
                passed = denied(lambda: execute(value=child))
            elif scenario == "key-revocation":
                authority.add_key("key-two", secrets.token_bytes(32))
                authority.revoke_key("key-one")
                passed = denied(execute)
            elif scenario == "widen-scopes":
                passed = denied(lambda: authority.attenuate(token, scopes=["note:append", "note:clear"], now=NOW))
            elif scenario == "widen-quota":
                passed = denied(lambda: authority.attenuate(token, max_calls=5, now=NOW))
            elif scenario == "shared-quota":
                child = authority.attenuate(token, now=NOW)
                for _ in range(4):
                    execute(value=child)
                passed = denied(execute)
            elif scenario == "unknown-operation":
                passed = denied(
                    lambda: Operation.from_dict({"kind": "shell", "resource": "lab/public", "text": "grant root"})
                )
            elif scenario == "byte-budget":
                passed = denied(lambda: execute(op=replace(operation, text="é" * 5)))
            else:
                nonce = secrets.token_hex(16) if scenario == "concurrent-replay" else None

                def attempt(_):
                    try:
                        execute(nonce=nonce)
                        return 1
                    except AuthorizationError:
                        return 0

                with ThreadPoolExecutor(max_workers=6) as pool:
                    successes = sum(pool.map(attempt, range(12)))
                passed = successes == (1 if nonce else 4)
            rows.append({"scenario": scenario, "contract_satisfied": bool(passed)})
    return {
        "experiment": "synthetic adversarial local authorization contracts",
        "case_count": len(rows),
        "passed": sum(row["contract_satisfied"] for row in rows),
        "cases": rows,
        "limits": [
            "These cases are executable regression evidence, not a security certification.",
            "Keys and bearer tokens are ephemeral and omitted from reports.",
        ],
    }
