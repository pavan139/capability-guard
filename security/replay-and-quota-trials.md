# Executed experiments

Run the exact standard-library experiment:

```bash
python -m capability_guard evaluate --output receipts/evaluation.json
```

The checked-in [report](../receipts/evaluation.json) contains **17/17 satisfied synthetic contracts**: allowed operation, wrong resource/scope, expiry, future issuance, forgery, replay, token/ancestor/key revocation, widening scope/quota attempts, shared quotas, unknown operation, UTF-8 byte limits, concurrent quota consumption, and concurrent replay. These are deterministic scenario expectations; the ephemeral keys/nonces are intentionally random and never reported.

The concurrency scenarios launch 12 contenders with six worker threads. Four unique-nonce effects commit under a four-call quota; one effect commits when all contenders replay a single nonce. Unit tests separately use 30 contenders and 12 threads. This measures local state invariants, not transactions/second, external tool isolation, or remote exactly-once behavior.

The [demo](../receipts/demo.json) commits one 24-byte append under an attenuated capability, rejects its replay and an ungranted resource, and shows one call/24 units charged to the parent. The report contains no MAC key or bearer credential. Its clock is a fixed synthetic timestamp; it does not represent a live deployed grant.

The three targeted mutation outcomes are in [mutation-results.json](mutation-results.json). Full checks were executed on Python 3.12 using SQLite from the interpreter. The code targets Python 3.11+, but other operating systems, SQLite builds, filesystems, and long-duration production loads were not benchmarked. No security-certification percentage or cryptographic strength measurement is inferred from the pass count.
