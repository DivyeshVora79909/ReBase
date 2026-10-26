# Native M1/M2/M4: execution and acceptance

**Executed locally on 2026-10-22; S1–S5 complete for the bounded fixture.**
The native mutation path matches the independent source oracle across **68
cases and 93 operations: 53 commits and 40 rejections**. This establishes the
fixed authored-key calculation experiment from [paper 11](11-native-slice-plan.md).
It does not implement the proposed application runtime or public API.

[Dated evidence](evidence/2026-10-22-native-slice.json) records exact sources,
commands, operation outcomes, work counts and retained artifact hashes.
The earlier [S1 evidence](evidence/2026-10-22-native-s1.json) remains a separate
source-oracle/synthetic-checker result. Neither the planning evidence nor the
October 21 feasibility result was relabelled as native acceptance.

## 1. Implemented path

| Boundary | Implementation and purpose |
| --- | --- |
| Expected state | [Fixture](fixtures/native-slice.json) and [Python oracle/checker](https://github.com/DivyeshVora79909/ReBase/blob/0d0601187c79d430f8d7ed41674f53e9905af75f/rebase-next/research/experiments/native_slice.py): apply authored commands independently, scan quote facts, calculate values, derive every expected role and validate grouped account histories. |
| Native binding/model | [Native slice](../src/native_slice.rs): six fixed input types, strict command fields, exact native values, declared local field order, toy context, versions and state/work limits. |
| Persistence format | [Codec](../src/native_codec.rs): canonical decimal/UUID values, explicit key tags and slot codes, strict typed stored values. |
| Attempt state | The typed `Workspace` keeps original bytes, original typed values and one current value per touched key. It loads/decodes each touched key once and encodes final dirty values at the batch boundary. |
| Ordered roles | [Linked trees](../src/tree.rs): financial and quote AVL roots, stable source/slot identity, parent/child/neighbour links, insert/remove/revalue/latest and exact subtree summaries. |
| Settlement | `settle` stages source commands and routes, installs final quote positions, discovers old/new consumers, evaluates each surviving candidate once, reconciles both posting slots, validates complete account histories and assigns semantic revisions. |
| Embedded adapter | [redb harness](../examples/native_slice.rs): the same settlement entrypoint, one real write transaction, final batch application, known precommit abort hooks, complete raw observation and reopen checks. |

The adversarial local names remain `a_reporting` consuming `z_native`; actual
dependencies determine evaluation order. Discovery uses changed posting IDs and
old/new rule/curve routes. A curve edit conservatively considers all subscribers
on each affected curve. Zero amounts and equal selected rates preserve those
registrations. Minimal interval invalidation is not implemented.

Quote swaps remove moved old occurrences before installing their final
positions. Financial deletions transplant the successor's structural position
without copying another source into the deleted source's identity. Every tree
patch reloads the latest typed workspace node, preserving earlier patches in
the same operation. No whole-tree rebuild is used to hide a structural error.

Business validation occurs after settlement. A final-positive history with an
earlier complete-time deficit rejects; simultaneous cancelling deltas can pass.
Input/reference/authority checks still occur at their declared command boundary.
The adapter releases a successful result only after redb reports commit success.
Storage/internal errors are fatal to the harness; actual uncertain commit
errors are never labelled as domain rejection or automatically retried.

## 2. Independent acceptance

The checker derives expected records, empty roots, members, queries, incoming
references, direct users and curve subscribers from commands and declarations.
It does not use native descriptors to decide which roles should exist. It then
decodes the full raw table and walks actual links, checking ordering, parents,
neighbours, reachability, heights, AVL balance and every subtree/publication
against independent source scans. Alternative valid shapes are permitted.

The raw observer enumerates the application's normal and multimap table names,
rejects unexpected tables and scans every row in `native_kv`. A focused adapter
test proves that an unreachable unknown key is still exported and both kinds
of unexpected table reject. `complete` is earned by finishing the scan; it is
never taken from a stored root or manifest.

| Check | Observed result |
| --- | --- |
| Native source/role/structure/value comparison | 68 initial snapshots plus 93 post-operation snapshots passed. |
| Accepted operations | 53 commits; returned revision matched the independent command history. |
| Rejected operations | 40; every application key/value matched the preceding snapshot byte for byte, with no success result. |
| Late historical validation | The `+10, -15, +10` case rejected after 76 staged patches and three posting evaluations. |
| Work-limit failure | Limit 8 rejected at charged work 9 after one staged patch; no persistent change. |
| Storage abort controls | One abort after 2 of 10 final writes; one after all 17 final writes. Both restored the entire prior application map. |
| Snapshot/reopen | Old reads stayed unchanged across all 93 operations; all 68 databases matched after close/reopen. |
| Synthetic checker controls | Four valid images accepted; 20 invalid images rejected; two incomplete observations remained incomplete. |
| Integrated Rust suite | 13 tests passed: eight original semantic tests, two binding/workspace tests, two tree tests and one raw-observer test. |
| Static checks | Formatting and Clippy with warnings denied passed. |

The cases cover quote insert/edit/move/delete/swap, reparented quotes/postings,
empty-curve fallback, exact quote boundaries, coincident queries, zero-valued
dependencies, equal-rate provenance, no-op and stale versions, later UUID reuse,
parent-first deletion, staged/forward references, typed units, protected fields,
exact-value rejection, limits, same-time cancellation and separate checkpoints.
Tree tests cover all four rotation directions in both kinds, intrusive
leaf/one-child/two-child/root/last-node deletion and both `i64` timestamp limits.

The baseline is **33 application rows**: nine records, four root headers, six
nodes, two query descriptors, nine incoming-list headers, one direct-list
header, one subscriber-list header and metadata. Those lists contain ten
authored reference entries, two direct users and two subscribers. Counts include
the required empty account root and empty reverse lists.

## 3. Work observations and decisions

Counters describe these fixture operations, excluding store initialization and
baseline installation. They are observations, not latency or capacity results.

| Operation | Candidates / evaluations | Distinct key loads | Staged patches | Final dirty keys | Encoded value bytes |
| --- | --- | --- | --- | --- | --- |
| Coefficient edit | 2 / 2 | 16 | 23 | 10 | 4,411 |
| Quote-rate edit | 2 / 2 | 17 | 12 | 8 | 3,006 |
| Posting reparent | 1 / 1 | 17 | 16 | 8 | 2,596 |
| Semantic no-op | 1 / 1 | 12 | 1 | 1 | 260 |

A no-op still advances the store counter; it leaves the posting/root versions
unchanged. Equal-rate quote selection changes private query provenance without
changing the posting's calculated values or version. Zero-valued consumers are
still evaluated when their rule/curve changes; restoring units uses current
inputs. These are deliberate semantics, not missed opportunities to erase
dependency work.

`candidates` records the unique IDs when evaluation/reconciliation starts,
including deletions; failures before that point report zero. `evaluations`
counts surviving posting calculations. `node_visits` and `route_entries` count
repeated traversal work, while `key_loads` counts each first point load in an
attempt. `work_units` charges commands, route entries, node visits, loads and
typed patches. `encoded_bytes` counts final nondeleted value bytes, excluding
keys and redb internals. Final dirty counts on injected aborts describe the
prepared batch, not committed writes. Individual operation observations are
retained in the evidence; no comparison with the old engine has been performed.

The evidence supports keeping ordinary modules and bounded point-owned routes
for this experiment. It does not justify a generic scheduler, a minimal-range
invalidation framework or a throughput target. Those require a new workload and
a named correctness/cost question.

## 4. Reproduction and retained inputs

From `rebase-next/`:

```sh
CARGO_TARGET_DIR=target/native-slice/build cargo test --locked --all-targets
cargo fmt --all -- --check
CARGO_TARGET_DIR=target/native-slice/build cargo clippy --all-targets --locked -- -D warnings
CARGO_TARGET_DIR=target/native-slice/build cargo run --locked --example native_slice
# Replace run-... with the directory printed by the native example:
python3 -B research/experiments/native_slice.py --actual target/native-slice/run-.../native-observations.json
```

Each harness run creates a new directory under `target/native-slice/`, retains
its observation JSON and creates fresh per-case databases. Handles close before
owned database directories are removed on success or unwinding. Existing or
aliased run paths are refused. The Cargo cache is reusable and is not disposable
application state. The independent checker can also run without `--actual` to
exercise only its source oracle and synthetic controls.

The model identity is a SHA-256 fingerprint of embedded fixed-model/core,
Cargo and toolchain inputs; the Python checker independently derives it. Even
formatting changes those bytes. Rebuild and produce fresh observations after a
model-input change. This conservative experiment identity is not a semantic
model-upgrade protocol. The codec label is `native-slice-kv-1`; a requested
model/codec mismatch reaches the real store-header check and rejects unchanged.

UUID remains pinned at 1.23.1 and is now a normal dependency. SHA-256 adds pinned
`sha2` 0.10.9 and its lockfile dependencies. No old dependency was upgraded.
The original algebra, order, byte overlay and semantic tests remain unchanged;
Cargo manifests/lock and module exports changed. The October 21 eleven-input
fingerprint claim therefore remains historical. Earlier evidence files and the
M3/M5 and M6 Python programs were preserved. Original ReBase/MetaSol suites and
the old feasibility example were not rerun; the eight semantic tests ran as
part of the current integrated Rust suite.

## 5. Completion boundary

The authorized S1–S5 goal is complete. This is a small fixed model with one toy
actor/tenant, at most 64 records / 16 postings / 16 quotes, and serialized redb
writes. Finite fixtures establish the reported cases, not arbitrary workload
correctness, multi-tenant throughput or distributed conformance.

Native prefix consumers, required private outputs and general shape changes
remain behind the [M3/M5 contract](09-causal-settlement.md). A future packet must
first specify incremental discovery, detachment, final dependency ordering,
identity reservation and the corresponding independent lifecycle snapshots.
Its bounded source models must not be mistaken for an implemented scheduler.

General declaration/schema loading and build/explain/public catalogs remain
behind D1/D2; this experiment's strict decoder and raw checker are its developer
tools. Public RPC, query/cursor APIs, principal DAGs, authentication, receipts,
external effects, accounting/UI ports, migrations and distributed adapters keep
their [paper 8 gates](08-research-workflow.md). No additional production surface
was needed to answer this experiment's question.
