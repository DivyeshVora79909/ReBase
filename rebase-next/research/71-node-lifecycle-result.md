# N5 — Node storage, lifecycle and release result

Status: **accepted within the bounds below**, 2026-10-26. Source
`6836c592abc99398d5e5440c18015b003859df49` produces verified redb-only and
all-feature releases. All **122 Node tests pass, with zero skips**, from the
extracted redb package outside Git. Extracted redb, standalone SurrealKV and
local FoundationDB lifecycle compositions pass. Exact source, build receipts,
logs, package inventories, failures and cleanup are in the
[release evidence](evidence/2026-10-26-n5-release.json),
[executed composition](evidence/2026-10-26-n5-adapter-run.mjs),
[adapter log](evidence/2026-10-26-n5-adapters.txt) and
[extracted test log](evidence/2026-10-26-n5-extracted-node.txt).

## Delivered functions and acceptance

N5 composes N2's scoped check/inspect/backup/restore/archive/reset, service and
identity functions. It adds independent `checkBackupStructure`, the durable
local `startFakeProvider`, explicit `openFdbEnvironment`, committed-source
export/build description, receipt-bound packaging, and `verifyRelease`.
See the [contract](70-node-lifecycle-contract.md). Production calculation and
storage semantics and dependency locks did not change.

Each release contains 1,067 checksummed files, six compiled model catalogs,
the native executable, Node ESM tools and locked dependencies, source and
deployment templates. The redb executable SHA-256 is
`57e0dbd7ea66e8340680c21ed85558f4e6057a4bca5b8e437014e17dd6a32b52`;
the FoundationDB/SurrealKV feature executable is
`eef38bdc5bbd830325cc4477d8e9c49d258831edd0dbd689b439ec2ea9a5a11e`.
Node is 24.22.1, Rust is 1.95.0 and FoundationDB is 7.3.77. The SDK remains an
explicit external build/runtime prerequisite. Package checksums and catalogs
were verified again after the tests and adapter runs.

The original full native builds ran from `8a723b7`. After test portability
repairs, 407 unchanged files retained timestamps only after content-hash
comparison. The actual locked Cargo commands ran again for `6836c59`, with
two jobs and incremental disabled, reused valid objects and produced identical
native hashes. The evidence distinguishes those cached builds from the
earlier full builds; no build receipt is inferred from an old artifact.

Every adapter passed ownership, authenticated fixture and original replay,
private-method rejection, winning CAS and stale-write rollback, independent
physical tree checking, restart/receipt recovery, wrong-backup rejection,
isolated restore, existing-destination rejection, archive expiry and reset
identity fencing. FoundationDB also passed a second host's reset fence.
Complete restored backup payloads stayed identical after rejected replacement.
The 122-test suite includes six-model physical snapshots and fake-effect
prestart backup, acceptance with a lost response, restart, quarantine and
reconciliation without a second provider submission.

## Independent checking and limits

Physical checking decodes bounded duplicate-free backup bytes and typed KV
rows, verifies envelope digest, tree links/reachability, heights, AVL balance,
spans, full key order and independently folded Financial, Quote and Statistics
summaries. It does not call the native checker. Non-tree values receive strict
UTF-8/JSON validation, not a complete independent model codec. Source membership
is checked only when supplied; these N5 lifecycle runs report it as
`not_evaluated`. N6 still owes the complete source-to-physical composition,
Measurement query payload/selected identity and equal-time mixed-sign Equipment
prefix checks. Native integrity is a separate check, never their substitute.

FoundationDB ran on one machine with one local server and single redundancy;
two native hosts tested shared transactional ownership. This establishes no
multi-host network latency, failover or general capacity result. Fake provider
durability is its documented local single-writer fixture contract. Python and
legacy CLI removal, and the standalone structured production bootstrap, remain
N6 work. Existing FoundationDB destination rejection currently maps native
`storage_exists` to the host's generic `internal` error; preservation is verified,
but specific diagnostic parity remains a known limitation.

## Failed trials and cleanup

The first extracted run exposed an absolute cloud npm-cache path, a historical
N2 binary hash and startup/cancellation timing assumptions. Commit `6836c59`
corrected them; the [portability log](evidence/2026-10-26-n5-portability.txt)
and final extracted run distinguish the two sources.

Three adapter composition failures are retained with their original hashes
and diagnostics: comparing an old receipt after its records changed, expecting
the embedded-adapter destination error on FDB, and using the operator method
name on a native handle. The final script checks old receipt identity plus
version-based redaction, latest-receipt recovery and complete restore-image
preservation. Native receipt disclosure follows `src/security.rs`; old record
payloads are not historical read snapshots.

All owned native hosts and the local FDB server stopped after the final run;
owned stores, backups and provider data were removed. No credentials or private
stores are included in evidence. Earlier [prebuild evidence](evidence/2026-10-26-n5-node-lifecycle.json)
and the [FDB ownership witness](evidence/2026-10-26-n5-fdb-owner-real.json)
remain dated evidence for their original executions.
