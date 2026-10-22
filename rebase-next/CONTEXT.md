# Compact context — 2026-10-22

**D1–D6 complete: deployable bounded backend plus composable developer tools; no frontend.**
The user has authorized autonomous implementation, breaking changes, checkpoint
commits on the existing `main` tree and direct pushes. The
[release checkpoints](research/17-deployable-backend.md) now own continuation.
Preserve ReBase's **power**, not its exact implementation or old APIs. Prefer
small, explicit, stateless functions and mature infrastructure libraries; do not
add a universal DSL/plugin framework or duplicate schemas between runtime/tools.
Carry context in this directory and checkpoint commit messages so another agent
can resume without another whole-repository audit. The [0.2 release result](research/18-release-result.md)
and [deployment guide](docs/deployment.md) own current acceptance. Enter a named
future capability gate when new work is requested; do not repeat completed stages.

D1/D2 are complete: pure principal/DAG scopes, per-operation actor sessions,
separate owner/reader, declared reader selection and atomic reader-index repair,
bounded indexed merging and revocation-aware receipt disclosure. D6 now accepts
the release build at 64 public sources: 128 writes, 1024 concurrent reads,
duplicate/CAS races, process-crash recovery and verified restore. Thirty-nine
release Rust tests and six Python client controls pass. The client avoids loading
TLS trust roots for plain HTTP while retaining normal HTTPS verification.
D5 adds model-driven
fixture plans, a stateless HTTP client, private durable mutation plans and a
real HTTP developer harness (39 Rust tests plus five client fault controls).
See [developer tools](docs/developer-tools.md). D4 adds current-state integrity,
verified backup/restore, reset, stable explicit data identity and fenced receipt
archiving (38 tests). Mutations/status now require the original `context` from
`session.describe`; never refresh an uncertain old request across an archive or
reset. See [storage lifecycle](docs/storage.md). D3 adds authenticated bounded
HTTP `/rpc`, Ed25519 JWT verification, offline issuance and real concurrency /
revocation / timeout tests (34 Rust tests; clean dependency audit). See the
[server guide](docs/server.md). The existing stdio interface remains a trusted
filesystem/operator interface, not an authentication bypass exposed over HTTP.

**Confirmed local-prototype finish line completed.** After `2109687`, the user
chose engine, model tooling, mutation/query API and a demonstrable workflow.
[P1–P4](research/13-local-prototype-plan.md) are complete. Start with the
[current result](research/16-local-prototype-result.md) and
[run/API guide](docs/local-prototype.md), not another whole-system audit.

The binary `rebase-next` provides a bundled prepared model, separate catalogs,
offline/live developer views, exact mutations, durable receipts, bounded public
pages/exists and root publications over redb. Its JSON-RPC transport is local
stdio with a fixed actor/tenant. `demo <new-directory>` runs the causal diamond,
rejections/replay and reopen; it creates a usable store and offline inspector.
The [interface contract](research/14-local-interface-contract.md) owns that scope.

P1–P4 acceptance included 27 Rust tests, 107 native cases / 148 operations and
nine local-adapter cases / 14 operations, plus the executable demo/browser view.
The independent checkers derive complete state and receipts from authored inputs
and explicit allocation history. [Final evidence](research/evidence/2026-10-22-local-prototype.json)
owns current fingerprints and counts. The [P1 result](research/15-causal-native-result.md)
and earlier evidence remain dated. D2/D3 subsequently added bounded transactional
DAG authorization and cryptographic network identity. Arbitrary models,
distributed adapters, effects and a full accounting/UI port remain future gates.

## Purpose and authority

ReBase is a calculation engine for connected, typed facts. The redesign changes
the implementation stack while preserving its mathematical and domain concepts.
The objective is the smallest amount of complex behavior the developer must own:
explicit contracts, composable functions, predictable work and narrow boundaries
that prevent maintenance changes from spreading across unrelated components.

The latest user corrections in the attachment take precedence over earlier
suggestions. Current source takes precedence over historical agent reports.
Sources, fingerprints and topic locations are in [sources.md](research/sources.md).
This review started at ReBase `e5d13b3`, which adds the isolated research to
`a963b25`; MetaSol is a separate repository at `28c6e7f`. Both trees were clean.
The prior GitHub/GitLab checks were October 21 observations, not a fresh pull.

The M3/M5 continuation started clean at `947cc25`, the committed context/audit
packet. It inspected the relevant current query/output sources without another
whole-project audit. Its changes and new research model remain inside this folder.

The October 22 request explicitly keeps work in **research, wireframes and
scenario design before implementation planning**. The [system review](research/06-system-audit.md)
maps documentation, hidden database responsibilities and past failures.
[Contract wireframes](research/07-contract-wireframes.md) define the API/tooling
seams, and the [research workflow](research/08-research-workflow.md) owns the
current gates. Earlier automatic “next: implement” wording is superseded. The
subsequent M contracts supported a bounded implementation plan. The later user
request authorized completing its S1–S5 stages autonomously; those stages are
now accepted. Deferred capabilities remain outside that bounded experiment.

## Meaning to preserve

1. **One stable record identity.** A fact can own roots, contribute through
   multiple slots, consume inputs and validate state. These roles are independent.
   A record can also have no tree role. Physical database tables are optional.
2. **A contract defines obligations.** Strict fields, allowed reference targets,
   immutable dimensions, required participation, calculations and invariants must
   be unambiguous. A compact schema code is the proposed selector; a full class
   hierarchy in a key is unnecessary. Sparse records and selected dimensions do
   not require all possible dimension combinations.
3. **References and memberships are distinct.** A currency reference does not
   imply a currency index. An invoice may validate children without reposting
   their amounts. A payment's contract can require treasury participation.
4. **A root is an ordered projection and publication boundary.** Its identity is
   `(owner record, root slot)`. A member is `(source record, member slot)` with a
   typed business key and deterministic tie breakers. One source may appear in
   several roots or several positions in the same root.
5. **Fixed-width associative summaries maintain rules efficiently.** Count,
   sum, extrema, ordered prefixes, complete-time boundaries, tags and interval
   endpoints are examples. Ordered combination need not commute or have inverses.
   Exact units, nanoseconds, rounding and missing-value semantics are contractual.
6. **Dependencies are declared.** Local fields follow actual dependency order;
   direct referenced fields use reverse routes; ordered reads declare source root,
   operation, bounds, consumed channel and fallback. Slots are fixed by the model;
   record inputs can change their activation, source and bounds.
7. **One dynamic principal DAG.** Tenant, user and group ancestry handles control
   and sharing. Domain reference graphs may have diamonds; each maintained index
   has tree topology, and active calculations must remain causally acyclic. These
   are different graphs, not a restriction that all business relations are trees.
8. **Access and calculation authority differ.** Requested writes and new links
   require client authority. Declared internal repairs and protected derived
   outputs use engine authority. Neither bypasses tenant or invariant checks.
9. **Retain the reader distinction.** The final discussion retracts removing
   `read_by`. Read visibility uses a selected immediate reader principal; write
   authority uses `owned_by`. Reader indexes must enumerate readable candidates.
10. **Execute against one transaction attempt.** Read a consistent snapshot,
    cache touched state, stage changes, settle dependencies, validate and commit
    final dirty values atomically. Retries discard the entire attempt and its
    authorization cache. Raw KV writes bypass the engine's guarantees.
11. **Effects have durable intent.** External delivery follows commit. Inline
    waiting and background dispatch can share the same intent/lifecycle; a due
    time supplies one-shot scheduling. Pure signing grants are a separate case.
12. **Declarations serve tools too.** Derive separate public contracts and full
    developer metadata from one loaded model. Private source/roles do not become
    public through a UI toggle. Keep fixture recipes and appearance/workflow
    choices explicit; bind artifacts and persisted state to model/codec identity.

## Corrections already resolved by the discussion and contracts

| Phrase or hypothesis | Precise meaning |
| --- | --- |
| Compiler becomes runtime | Load and validate declarations once; execute their prepared plans in Rust instead of generated SurrealQL. Compilation and runtime coexist. |
| Current writes commit repeatedly | Current synchronous events run inside an atomic transaction. They issue incremental maintenance statements; the redesign proposes a shared workspace and fewer final dirty writes. |
| Segment/rank/statistics tree are identical | An augmented balanced search tree supplies overlapping capabilities. Median amount needs amount ordering; date ordering supplies date rank. |
| Everything is `O(log n)` | Each balanced path is logarithmic; affected records, memberships, intervals, partitions and DAG closure add work. |
| Monoids remove validation | They preserve enough information to make a declared invariant cheap to check. A nonnegative final sum does not prove a nonnegative history. |
| Validate after every rotation | Check structural conditions immediately; business rules at a settled checkpoint or the final atomic-operation boundary. Incomplete construction can be temporarily invalid. |
| Shared blind write normalizes OCC | A portable guard must have a defined conflict contract, normally a tracked read plus changed write. FoundationDB does not reject concurrent blind writes solely for sharing a key. |
| Stateless token includes a wrapper | Token proves identity and may narrow capabilities. Server-owned plans enforce current authority. Client wrappers cannot enforce a boundary. |
| Request cache solves every revocation issue | Read current permissions in each attempt; protect those reads against concurrent edits. Session revocation remains a separate policy. |
| Fresh authority cancels any overlapping response | Read authorization has a snapshot boundary. FoundationDB read-only transactions do not commit/conflict; response-time revocation needs a separate protocol. |
| Owner partitions cover all reads | False when `read_by != owned_by`. Retain reader partitioning or another complete reader candidate source. |
| K-way merge everywhere | Use it only for several streams sharing the same full order. A single root needs one traversal. |
| A page limit bounds the whole query | Scope discovery and opening K streams require their own budget. An incomplete scope cannot establish a globally first page or exhausted search. |
| Unchanged index key means unchanged query | Residual-filter/projection or policy changes can invalidate a page without a rekey; cursor revisions must cover their promised consistency scope. |
| UUID includes tenant/owner/hierarchy | Keep mutable relationships out of canonical identity. Store a schema code and relations in the record/header; roots provide partitions. |
| Deterministic short hash means unique code | A persisted explicit codebook supplies stable uniqueness. A seed cannot losslessly compress arbitrary growing identities. |
| JSON is necessarily the bottleneck | Parse/validate at ingress, compute using native values and encode at egress/persistence. Profile before claiming a dominant cost. |
| Any ACID backend is interchangeable | Atomic multi-key commit, consistent reads, guard semantics and limits must conform. Raw write batches alone are insufficient. |

## Proposed smallest architecture

The shipped local subset is documented above. The broader architecture below
retains design direction; it does not add capabilities to the accepted prototype.

Use one Cargo package and ordinary modules. One loaded design combines authored
JSON Schemas with separate declarations for references, memberships, queries,
invariants and exposed operations. Ordinary trusted Rust functions supply behavior.
Do not invent a general query language, dependency capture framework, universal
middleware DSL or one package per feature.

Publish the new model's authored schemas unchanged from that model, but do not
assume today's schemas transfer byte-for-byte: current reference patterns contain
SurrealDB table prefixes. UUID-only transport requires an explicit contract edit,
while typed target obligations remain in the declarations.

Rust is the recommended execution core; Serde and `serde_json` handle values;
`jsonschema` compiles reusable validators. `jsonrpsee` plus Tokio can host the
eventual JSON-RPC server; Axum/Tower is optional when broader HTTP routes are
needed. Start storage proof with redb's ordinary serialized writer transactions.
FoundationDB is the proposed distributed adapter, conditional on conformance and
transaction budgets. TiKV and other engines are alternatives, not promised support.

Use stable 16-byte UUIDs and explicit `u16` schema/field/slot codes. Random UUIDv4
matches the latest observation that identity need not order records; UUIDv7 is
available for locality. Leave shorter custom IDs and principal dictionaries until
measurements justify their allocation/collision costs. Keep business payload and
structural slot storage separate without creating another business identity.

Public operations are structured `get`, `page`, `exists`, `mutate` and declared
root reads. An explicit mutation is one atomic unit; a JSON-RPC batch is not.
Queries select registered access paths, typed bounds, allowed predicates and
projections. Unsupported orderings reject. Optional residual filtering has a
visit budget and continuation; exhausted-budget `exists` is **unknown**.

## Production choices still open

- Local mutations now use final settled global validation. Any future independent
  command checkpoints require a separate declared operation. Early failure must
  be conclusive, not a transient deficit.
- Preserve current ordered scalar-reader selection initially. Its first-choice
  rule for incomparable principals is deliberate and is not a union or a universal
  lowest node. Multi-reader sharing requires a separately chosen policy.
- Start linked augmented indexes for the required mathematical operations.
  Ordinary ordered KV prefixes may implement simple enumeration later; they must
  not become undeclared default domain indexes or dictate the portable core.
- General decimal rounding, production timestamp policy and large cascades need
  their own decisions. The prototype fixes i64 time, exact bounded integers,
  revision-bound cursors and declared work/population limits.
- Distributed adapters, cryptographic identity verification, principal graph
  repair, ordered-result-driven topology and external delivery remain outside
  the local prototype. Authored-shape causal settlement is implemented.

## Work completed and continuation boundary

The [feasibility report](research/05-feasibility.md) records the executable Rust
checks and their scope. Standard AVL balance, heap merge and identity mathematics
are established algorithms; their proofs need no broad stress campaign here.
Unusual complete-time summary composition and transactional staging receive
focused checks against independent expectations. The initial October 22 review
verified all 11 executable-source fingerprints and reused the dated results;
that audit did not rerun or expand the proof. All 26 original repository source
fingerprints matched at that audit. Native execution below has since changed
the package.

The [bounded reference fixture](research/08-research-workflow.md#2-the-bounded-reference-scenario)
now specifies one source type, two memberships, a direct rule, dated quotes,
exact expected values and a historical invariant. The scenario register covers
API/tooling and future capabilities separately; its cases are not executed tests.

[M3/M5](research/09-causal-settlement.md) now defines the combined private-output
prefix fixture, a diamond and rejected feedback. Shape is resolved from authored
facts and acyclic direct-scalar inputs before ordered calculation. Old/new routes
discover invalidated work; only the final graph determines causality. Detachment
must cover affected managed outputs and pending predecessors, not just a moved
record's own slots. Query identity survives coincident bounds and zero amounts.

The bounded Python research model checked nine source states and all 36 valid
orders against grouped source arithmetic and literal expectations. It preserved
wrong-order and false-cycle counterexamples, logical inventory controls and
lifecycle rejection predicates. At that stage all 11 Rust proof inputs matched;
its suite was not rerun or expanded by M3/M5. This is not incremental, structural,
authority, UUID-allocation or storage-rollback evidence. General topology driven
by ordered results remains deferred.

[M6](research/10-independent-checker.md) now defines expected source/role
inventories separately from complete raw observation and actual tree walks.
Required empty roots, duplicate identities and disconnected slots are explicit
obligations; exact source scans check every subtree and publication. Valid
alternate shapes pass. Five valid synthetic snapshots passed, 28 invalid-state
controls rejected and two incomplete-scope/budget controls stayed incomplete.
The checker reuses the unchanged M3/M5 source oracle. It does not implement a
native writer, snapshot adapter, direct reverse routes or storage acceptance.

The [M1/M2/M4 plan](research/11-native-slice-plan.md) fixes six source types,
exact integer/UUID bindings, authored commands, separate record/root revisions,
final quote uniqueness and reference deletion rules. It uses linked quote and
financial trees with bounded point-owned reverse lists. A curve edit discovers
all old/new subscribers; minimal interval invalidation is deferred. The plan
separates independent expected state, real raw observation and all-key rejection
snapshots. The [execution report](research/12-native-slice.md) now verifies those
expectations against the actual native state.

**S1–S5 complete:** 68 cases / 93 operations passed the independent checker:
53 commits and 40 rejections. All source/role inventories, actual AVL links,
subtree caches and publications matched. Each rejected operation preserved all
application KV bytes; two controls aborted after actual writes. Old reads stayed
unchanged across all operations and all 68 stores matched after reopening.
Four valid checker controls, 20 corrupt images and two incomplete observations
also behaved as required. Thirteen integrated Rust tests, formatting and Clippy
passed. [Dated evidence](research/evidence/2026-10-22-native-slice.json) owns the
source hashes, commands, counts and limits.

The implementation is a fixed native calculation experiment with a toy actor,
point-owned reverse lists and one embedded writer. The baseline has 33 KV rows.
The original algebra/order/overlay and eight semantic tests are unchanged, but
`Cargo.toml`, `Cargo.lock` and module exports changed; the original 11-input
fingerprint claim is historical. Earlier evidence and Python programs remain
unchanged. No original ReBase/MetaSol code or acceptance suite was modified/run.

That bounded S1–S5 goal was complete at its dated evidence. The later P1–P4 goal
has now added native causal/output lifecycle, prepared tooling, a public local
API, replay receipts and a demo. Use paper 16 and the affected future gate for
new work; do not restart S1 or repeat the broad audit.
