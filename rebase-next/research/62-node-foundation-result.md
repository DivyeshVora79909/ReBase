# N0 — independent Node and native foundation review

Status: **N0 review complete; N1–N6 implementation and acceptance remain pending.**
This review checks the N0 ledger, Node dependency witness, frozen native wire
fixtures, and provenance of the reused native binary. It does not accept a Node
API or native host implementation.

The migration ledger has exactly 60 unique rows: all 50 current `tools/*.py`
files and all 10 `research/experiments/*.py` files. Every row has a nonempty
path, capability, future Node group, checkpoint, disposition, semantic controls,
and earliest deletion checkpoint; each referenced file exists.

The proposed composition example in paper 57 passes `node --check
--input-type=module` after extracting the fenced JavaScript block. This is a
syntax-only check: modules and types are intentionally not implemented, so it
does not validate names against future exports or perform a TypeScript check.

The scoped Node package and lockfile agree on the four direct dependencies and
the `node >=24` engine. The lock resolves exact versions and integrity hashes for
all nine package records (four direct and five transitive). The bounded witness
was installed with `npm ci --ignore-scripts --no-audit --no-fund` outside the
checkout, then ran `npm run test:n0` under official Node 24.22.1 / npm 11.19.1;
the distribution SHA was checked against the official `SHASUMS256.txt`. The
recorded result is 3 passed, 0 failed. The witness checks Draft 2020-12 schema
validation with native string formats/ranges, deterministic per-instance faker
seeds, nested duplicate-key rejection, exact integer handling, invalid JSON,
fatal UTF-8 decoding, and escaped surrogate handling. It remains a dependency
feasibility witness, not complete production codec coverage.

The configuration registry now records owner, default, unit, allowed range,
override policy, source, and secret status for every setting; it also describes
the target, server, client, child-process, workload, and release configuration
families. Hard limits are native-owned and cannot be overridden.

The native protocol fixture parses and matches the v1 envelope described in
paper 60: four valid-session scenarios and eight malformed-frame examples use
the documented protocol, ID, and result/error envelope shape. The fixture
freezes six N1 methods and explicitly labels later methods N2/N5. The actual
reused binary at `target/verification-build/release/rebase-next` hashes to
`cf9a5ccf864f362f717da9e441d62845981b4e4c7276de9349f43cb83e392b38`, matching
`target/g84-package-all/BUNDLE.json`, which records source commit
`8ddc88fa48ce5a9e1c9023ae2fd420e77e0d1502`. Read-only model exports produced
catalog bytes matching all six retained bundle hashes; no build, store open,
service start, or native host execution occurred for this trial.

The native trial confirms reusable exports and artifact identity only. Host
framing, process ownership, failure behavior, limits, and close semantics remain
N1 acceptance work. Node 24 dependency feasibility does not establish every
exported catalog or generation keyword, and no implementation is accepted here.
