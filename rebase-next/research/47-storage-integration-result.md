# G7.2 shared application storage integration

**Accepted G7.2, 2026-10-24.** [Evidence](evidence/2026-10-24-g7-shared-persistence.json)
records the final source, dependencies, executable hashes, commands and results.
The raw suites pass 25 FoundationDB, 21 SurrealKV and 8 redb controls. Application
checks pass 19 controls on each optimistic adapter and 13 on redb. The shared
port passed 165 native tests across 26 harnesses; the two affected FoundationDB
classifier controls were rerun after the range/paging correction. Formatting
and final all-target Clippy pass. Fresh client processes reopen identical complete
table images on every backend, including after a FoundationDB server restart.
G7.3–G7.6 remain unaccepted.

The accepted baseline is [V1 source 0.15.0](44-workshop-verification-result.md),
followed by [G7.0 preparation](45-storage-adapter-plan.md) and the
[G7.1 runtime probe](46-storage-runtime-probe.md). This checkpoint connects the
existing synchronous engine to the shared byte facade. Model calculations,
settlement, authority repair and codecs remain engine-owned. A mutation stages
all native records, indexes, receipts and applicable effect state in one backend
transaction; the adapter owns the single atomic commit.

## Physical tables and protection

A secured application has exactly eleven logical application tables. An
unsecured application omits `authority` and `reader_records`. Adapter catalog,
namespace and SurrealKV guard keys are separate metadata; they do not replace
the business roots or belong to the privileged application-table observation.

In the table below, **point** means a tracked exact read, including absence.
**Range** means the entire requested half-open predicate, including an empty
range. Mutation reads and writes retain these obligations until commit.
Read-only responses use authority and values from their selected snapshot.

| Application table | Stored facts and protected predicate | Engine publication path |
| --- | --- | --- |
| `native_kv` | Model metadata; public/private records; linked roots, nodes and summaries; query descriptors; incoming/direct/subscriber routes; role bindings and reservations. Point reads protect identity absence, references, dependencies and root invariants. Linked searches protect each visited node/root; inventories use ranges. | `local::publish_native`, shared mutation settlement and effect domain application |
| `public_records` | UUID → public contract. Point updates protect exact index membership; ranges select complete ordered public candidates. | `local::publish_native` |
| `reader_records` | Reader/contract/UUID → public contract. Point updates protect old/new reader partitions; ranges select authorized candidates. | `security::update_reader_index`, native publication and authority repair |
| `authority` | Principal graph and prepared actor scopes, including grants, activity and credential epochs. Tracked scope/graph points protect write authorization, revocation and reader selection. | Secured initialization, `security::store_graph` and `Store::replace_access` |
| `operations` | Actor/operation UUID → content-bound result and original context. Point absence protects one operation identity; replay reads its original receipt. Archive uses complete inventory/cleanup. | `local::publish_receipt` and effect cancellation |
| `local_runtime` | Store/signing identity, operation epoch and retained-receipt population. Header point protects request context, retention and archive/reset boundaries. | Initialization, receipt publication and operator lifecycle |
| `effect_executions` | Exact execution identity, immutable request binding, phase, revision, lease and application state. Point validation protects fence/activation/CAS decisions and duplicate execution identity. | Intent publication, worker transitions, inbox consumption and domain application |
| `effect_due` | Ordered due-time/execution membership. Ranges protect worker candidate discovery; points maintain exact old/new scheduling entries. | Intent publication and execution replacement |
| `effect_facts` | Execution/outcome-bound immutable facts and application marker. Point absence/content checks protect deduplication, compatible facts and exactly one application marker. | Worker/inbox fact publication and effect domain application |
| `effect_inbox` | Canonical provider event identity, verified immutable event content and consumption revision. Point absence/content checks protect duplicate ingress; ranges discover bounded pending work. | Signed ingress acceptance and inbox consumption |
| `effect_runtime` | Effect activation, mode, quarantine, capacities, accounted bytes and bounded worker/inbox cursors. Header point protects activation/fences, capacity and scheduling decisions. | Every applicable effect transition and restore quarantine |

The adapters realize those same point/range obligations as follows:

| Adapter | Point and range protection | Atomicity and runtime |
| --- | --- | --- |
| FoundationDB 7.3.77 / Rust client 0.11.0 | Ordinary non-snapshot reads protect exact values and absent keys. Facade put/remove observes the previous value. Scans add an explicit read-conflict range for the complete requested predicate, independent of native page length. Table deletion protects the complete table range; catalog reads protect initialization and table identity. | One native transaction commits all logical spaces. The native network is booted once and outlives its database handles; no adapter retry loop. |
| Standalone SurrealKV 1.0.0 | Mutation reads use `get_for_update`, including absence. A scan protects all 256 hashed guard buckets for its logical table. Each point mutation changes its own bucket; catalog edits change their catalog guard. This conservatively protects phantoms and can reject unrelated writers in a shared bucket/table. | One transaction with `Durability::Immediate`. A persistent dedicated runtime drives its WAL; the tree closes before runtime shutdown. |
| redb 4.4.0 | One serialized writer protects mutation decisions; concurrent readers retain snapshots. Typed physical table codecs stay inside the adapter. | One redb write transaction spans all application tables. Optimistic overlapping-writer schedules are inapplicable. |

The FoundationDB correction matters: a limited native range page can cover only
part of the requested predicate. The portable scan now protects the full range
explicitly. The real multi-page overlay control also exposed short native Iterator batches:
`more=true` must continue before the facade can report range exhaustion. The
final adapter fills the requested bounded page and all affected controls pass.

## Runtime, limits and outcomes

The engine remains synchronous. Existing HTTP admission acquires a bounded
permit before `spawn_blocking`; the worker retains that permit through
completion, including after a response timeout. FoundationDB futures are driven
by its native network on that worker. SurrealKV enters its persistent runtime
to commit; no per-request or nested runtime is created. The check examples run
through the same Tokio blocking-worker context.

FoundationDB exposes a 10,000-byte complete physical key limit, a 100,000-byte
value limit, a 10,000,000-byte transaction limit and the approximately five-second
snapshot lifetime. The adapter selects a 4,500 ms client timeout and rejects an
expired attempt before commit submission. Namespace/table bytes count toward
key size. Final coalesced writes receive an early bound; immediately before
commit, the native approximate-size estimate includes conflict ranges and other
transaction overhead. Read values are not counted as written values. No raised
server limits or staged multi-transaction publication are used.

Embedded adapters report no analogous finite vendor transaction-size/lifetime
limit through this facade; that does not imply unlimited resources. Existing
engine work, population, request and effect bounds still apply.

| Normalized engine outcome | Meaning |
| --- | --- |
| Success | The one atomic commit returned success. |
| `transaction_conflict` | Confirmed optimistic conflict; the attempt aborted. No automatic fresh attempt is submitted. |
| `transaction_aborted` | Other confirmed retryable abort; replay policy remains a caller decision. |
| `transaction_limit` | Encoded key/value/transaction size or definite pre-submission lifetime rejection. |
| `outcome_unknown` | Commit acknowledgement cannot establish whether publication occurred. Retain the original operation ID and request context for receipt reconciliation. |

The shared facade returns the engine error type. `local::storage` preserves its
code instead of converting every failure into generic storage failure. Mutation
and effect commit paths preserve adapter classification instead of treating every
rejection as an unknown outcome. Ordinary network/API backend selection and
public error presentation belong to G7.4.

## Restore and executable checks

`restore_to_backend` first uses the existing create-only file restore in a
disposable redb store. It validates the supplied complete image before changing
effect activation, then quarantines restored unresolved effects and verifies
integrity. Only that validated image is imported into the target backend.
Target emptiness is read inside the importing write transaction; populated
destinations reject. All eleven applicable tables publish together. A final
backend open and integrity check verifies the imported image. Adapter limit
rejections abort the import. The operator must reconcile an unknown import
acknowledgement; the implementation does not resubmit it automatically.

The byte suite in `src/storage/conformance.rs` checks complete independent
dictionary images across six abstract families. It covers snapshots, partial
staging aborts, exact absence, range insertion/deletion, staged multi-page
overlay, root/no-op/protected-put decisions, reverse references, revocation,
disjoint point commits and backend limits. These abstract families are mapped
to the physical application inventory above; they do not replace application
publication evidence.

The application suite in `src/storage/application_checks.rs` uses EffectDemo,
Quantity and Calculation through ordinary mutation settlement. It compares
complete application observations and receipt absence after rejection; checks
intent publication/replay, stale CAS, response-loss reconciliation, reopen,
backend restore, exact quantity cascade and rollback, and root invariants.
Optimistic application schedules use a commit barrier: first stage the complete
attempt, commit the competitor, then release the first commit. Retained-snapshot
authorization is checked against a fresh read after revocation.

Reproduce using a disposable cluster namespace or fresh embedded paths. Set
`FDB_CLIENT_LIB_PATH` and `LD_LIBRARY_PATH` to the pinned native client directory
for the FoundationDB feature. One build owner runs the commands sequentially
against the existing `target/verification-build` cache:

```sh
CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=target/verification-build cargo test --locked
CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=target/verification-build cargo clippy --locked --all-targets --features foundationdb,surrealkv -- -D warnings
CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=target/verification-build cargo run --locked --features foundationdb,surrealkv --example g7_storage -- foundationdb target/g7-environment/fdb.cluster
CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=target/verification-build cargo run --locked --features foundationdb,surrealkv --example g7_application -- foundationdb target/g7-environment/fdb.cluster
```

Run the same two examples with `redb` and fresh file/directory arguments, then
`surrealkv` and fresh directory arguments. For `g7_storage`, redb takes a fresh
file; for `g7_application`, it takes a directory containing the family files.
The linked evidence records the executed counts, command outcomes, log/source
hashes, dependency/runtime versions and failed-trial corrections. Original logs
and complete private disposable observations remain under ignored `target`.

## Remaining acceptance

- **G7.3:** Exercise actual nonempty effect facts/inbox and domain application,
  with publication aborts and complete-table/reopen evidence. Cover authority
  replacement/reader-repair aborts, both reference-race directions and controlled
  concurrent initialization. Raw predicate schedules alone do not certify every
  application publication path.
- **G7.4:** Wire real backend selection into the ordinary server/API, retain
  default no retries, verify the uncertain outcome whose same-ID receipt is
  absent, and run real HTTP/process restart and bounded multi-client controls.
  In-process reopen is persistent-storage evidence, not process restart.
- **G7.5:** `native_kv` model metadata still combines global revision, contract
  populations and reservations. `local_runtime` still contains a global receipt
  counter written per mutation. These shared keys mask predicate-specific
  application conflict attribution and prevent a disjoint-root scalability
  claim. Replace them with verified scoped epochs/quotas and bounded receipt
  coordination; preserve business-root guards, explicit retention and original
  operation context. Effect runtime coordination remains a separately identified
  shared effect scope. Rerun affected application races after the change.
- **G7.6:** Run the complete shared semantic/application contract on all three
  pinned adapters, publish final identities/evidence and operational boundaries,
  and name unsupported cases. A single-process local FoundationDB deployment
  proves adapter transactions; it does not establish replicated fault tolerance
  or production capacity.

TiKV, G6 accounting expansion, G8 workload/release expansion, frontend,
automatic retries and implicit migration remain outside the selected G7 scope.
