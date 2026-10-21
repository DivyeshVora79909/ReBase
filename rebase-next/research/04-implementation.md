# A small implementation with explicit contracts

**Status:** recommended direction, 2026-10-21. This is a stack decision proposal
and implementation boundary, not a commitment to implement every listed feature.

**October 22 continuation:** implementation planning is gated by the current
[research workflow](08-research-workflow.md). The [system review](06-system-audit.md)
maps affected existing tools/APIs; [contract wireframes](07-contract-wireframes.md)
define the missing boundaries. Stack recommendations below remain proposals.

## 1. Optimize what must be maintained

The primary cost is complex behavior owned by the project, not dependency count
alone or fewest lines. Reuse infrastructure libraries whose scope matches the
need. Keep the custom engine centered on participation, augmented ordering,
declared reactive settlement and transaction correctness.

Logical decoupling does not require microservices. One Rust binary can host an
RPC adapter and import ordinary engine modules; the engine need not know HTTP,
token wire formats, frontend state or a backend vendor. Multiple server instances
may share a conforming distributed store later. This does not require a plugin
loader, global mutable registry or generic DSL for every action.

## 2. Stack choices and reasons

| Boundary | Recommendation | What remains ReBase's work |
| --- | --- | --- |
| Execution | Rust, ordinary typed values/functions | Mutation settlement, invariants and work budgets |
| Values | Serde + `serde_json` initially | Exact money/time binding, format versions and protected fields |
| Dynamic input contracts | Authored JSON Schema + Rust `jsonschema` | References, participation, authority and global rules |
| Static request types | Serde structs/enums; Schemars when export needed | Supported operations and exact scalars |
| RPC server | `jsonrpsee` + Tokio | Verified context, operation authorization and result semantics |
| Extra HTTP routes | Axum + Tower only when needed | Connecting those routes to the same engine |
| Embedded reference storage | redb normal writer transaction | Key codec, indexes and conformance checks |
| Distributed target | FoundationDB Rust binding | Guard coverage, transaction limits and cluster operation |
| Alternate distributed storage | TiKV TxnKV, conditional on conformance | Snapshot-isolation protection and client/deployment review |
| Authentication | Existing verifier / OIDC / standard crypto library | Session, tenant, role and revocation policy |
| Authorization | Existing principal DAG semantics | Candidate completeness and transactional graph/reader repair |
| Frontend | Solid/TanStack remains viable | Connected workflow and supported operation contracts |
| Effects | HTTP/provider libraries; durable intent + executor | Idempotency, leases, uncertain outcome and reconciliation |

Rust is recommended for the desired native index/calculation execution and exact
types. It is not mathematically necessary: JavaScript can implement the same
contract with exact values. No Rust speedup has been measured here. A second
TypeScript compiler/runtime would multiply maintenance without a demonstrated
need; use Rust for loading and preparing the new model initially.

FoundationDB's Rust bindings wrap its native C client and need a compatible client
installation/network lifecycle. TiKV's Rust client and transaction options need
review when selected. Their server language is not a reason to fork either engine
or write replication/consensus code. redb's serialized writer is useful for a local
proof and simple deployment; it is not evidence of distributed multiwriter scale.

The FoundationDB Record Layer provides mature records/indexes/rank/aggregate
patterns and is useful prior art. It is Java/FoundationDB-specific; adopting it
would change the Rust/portable-core goal. DataFusion, DBSP, Convex, GraphQL,
JSON:API, Cedar and OpenFGA each solve useful but different boundaries. Do not
stack them on the core merely because their names resemble a capability.
GraphQL/REST can be adapters later when clients need them. OpenRPC generation
must respect its schema dialect; JSON-RPC itself requires no OpenRPC implementation.

## 3. One design composed from standards and ordinary behavior

Keep JSON Schema files as input contracts. Refer to them from a small model
manifest rather than copying their validation rules into every index declaration.
Separate ordinary metadata by meaning without spreading one fact across competing
sources of truth:

```
design/
  model.json          # schema codes, root/member/query/operation declarations
  schemas/            # authored input JSON Schemas
  behavior.rs         # ordinary trusted formulas, projections and validators
  fixtures/           # optional design-owned input recipes/defaults
```

Reuse schema validation rules where their wire meaning matches. Current public
reference patterns include table-prefixed SurrealDB IDs (for example,
`account_entry.account`); switching to UUID-only references requires authored
schema/binding changes. “Unchanged schemas” means export the selected model's
schema faithfully, not promise byte-for-byte compatibility with the old API.

This is a suggested authoring shape, not a new interpreted language. The proof
uses one inline demo file to avoid establishing folders before concrete reuse.
Behavior is built/deployed with the application; hot-loading arbitrary executable
functions or client comparators is outside the initial model.
Schema composition needs deliberate closure rules: `allOf` does not merge property
allowlists from independently closed `additionalProperties: false` schemas. In
Draft 2020-12, a final `unevaluatedProperties: false` boundary can close a supported
composition, or the loader can flatten explicit fields. Do not duplicate every
primitive's field definitions just to make extensions validate.

At model load, resolve code/name references, compile input validators, check types,
permitted root/member pairs, operation shapes and dependency order. Each function
receives named/resolved declared inputs; a missing mutable dependency is an error,
not an invitation to capture arbitrary runtime reads. Calculated outputs and
structural fields are protected. A fixed declared slot count bounds possible
subscriptions while allowing their roots/bounds to vary per record.

Conceptually a declaration can say:

```
Posting(code=17, input_schema="posting.json")
  reference account → Account
  query quote = latest(exchange.rates, at)
  amount = calculate(quantity, quote.rate)
  member native → account.history, key=at, value=amount [required]
  member reporting → subsidiary.history, key=at, value=converted_amount [optional]
  invariant account.balance_floor → complete_time_min(history)
```

Names illustrate relationships, not a proposed parser syntax. Plain Rust/Serde
structs or JSON objects can represent the declarations. Flatten composition into
one loaded plan; do not create an evaluator layer for each primitive. Inputs,
references, activation and function outputs are checked at their defined boundary.
Untrusted functions/plugins would need an explicit sandbox/trust design later.

Generate public input schemas, operation/capability descriptions, typed bindings
where representable, and inspector metadata from that loaded model. Publish no
credentials, backend keys or executable privileged behavior. Keep source/rule
locations for explanation. Client validation improves feedback; the runtime
remains authoritative.

Produce distinct public and developer projections. The full authoring catalog
can describe private roles and source; that does not make it suitable for a
client-facing endpoint. JSON Schema `readOnly`/`default` annotations do not
enforce authority or install defaults. Model/store activation and stale artifact
handling follow the [lifecycle wireframe](07-contract-wireframes.md#2-model-and-artifact-lifecycle).

## 4. Identity and encoding

The latest discussion accepts stable random addresses and withdraws mutable
owner/tenant/hierarchy suffixes. Recommend 16-byte UUIDv4 initially; UUIDv7 can
supply creation locality when useful. Neither determines business effective order
or authority. Keep atomic create-if-absent for accidental collision/replay.

For `b` independent random bits and `N` IDs, the small-probability birthday
approximation is `N*(N-1)/2^(b+1)`. A 96-bit random space at one billion IDs is
about `6.3e-12`; reducing UUID bits has a real collision tradeoff. UUIDv4 has 122
random bits; UUIDv7 includes a timestamp and has a different within-time model.
ULID is also 128 bits. Short textual encoding changes presentation, not entropy.
Principal dictionaries or compact local IDs require allocation/mapping state;
skip those until the saved bytes justify that machinery.

Use explicit, unique `u16` codes for the few hundred or thousand schema/field/slot
names. Persist one model codebook, validate uniqueness and retain codes when names
move. Auto-assignment can fill unused codes and save them; array order or truncated
hash is not a stable storage identity after data exists. This is an internal
representation invariant even though legacy compatibility is not requested.
Design identity/fingerprint distinguishes codebooks across separate installations.

Color assignment and schema encoding solve different problems. Seeded hue spacing
can improve visualization; collisions there can be acceptable. Identity codes
require exact uniqueness and stable meaning. Do not use a visual distribution
algorithm as a storage codebook.

Recommended physical separation, with small namespace bytes:

```
record(UUID)                 → contract_code, tenant, owner, reader, payload
node(UUID, member_slot)      → root, order, links, summary
root(UUID, root_slot)        → node head, summary, protected version
other private namespaces    → graph, reverse dependencies, operations/effects
```

The demo uses byte prefixes and fixed fields for point addressing. For ordered KV
range keys use an order-preserving encoding library where possible; ordinary JSON,
Postcard/Bincode or Protobuf varints do not guarantee required lexicographic order.
Linked-node comparators can operate on typed values without ordered physical keys.
Keep codec choices confined to one engine boundary with a format identifier.

## 5. A file structure proportional to implementation

The present proof is one Cargo package:

```
rebase-next/
  CONTEXT.md                 # compact meaning and continuation boundary
  research/                  # topic papers, sources and evidence
  Cargo.toml, Cargo.lock
  src/
    lib.rs                   # explicit module exports
    algebra.rs               # ordered/complete-time summary
    plan.rs                  # declared local order and scalar-reader selection
    merge.rs                 # bounded merge/exists semantics
    staging.rs               # point-read transaction overlay
  examples/
    demo.json                # schema and fixed declarations
    feasibility.rs           # one real embedded transaction demonstration
  tests/
    semantics.rs             # unresolved semantic facts and counterexamples
```

Later add `model.rs`, `tree.rs`, `dependency.rs`, `access.rs`, `transaction.rs`,
`store/redb.rs` and `rpc.rs` when the corresponding slice exists. Split a module
when its actual responsibility outgrows a readable file. Split Cargo crates only
for real independent build/dependency needs; do not scaffold empty subsystems.
Server/provider libraries stay out of pure arithmetic modules. Storage-specific
errors and guards are normalized at the transaction boundary.

The coordinator is central by necessity, but it should order module calls rather
than contain every algorithm. Each module owns a contract: tree maintenance cannot
decide HTTP authorization; a validator cannot deliver an email; an RPC adapter
cannot patch nodes. Boundaries are explicit inputs/outputs, not a giant mutable
context passed to arbitrary hooks. Shared staging is the one state owner for
the attempt. Trusted behavior receives only the input/root reads it declares.

## 6. Fixtures and visualization

Current fixture shape/generation concepts are reusable, but their model loader,
native values, reference parsing, population and examples use SurrealDB/compiler
contracts. They are not already storage-agnostic. Preserve declarative inputs and
deterministic identities, then bind them through the new runtime operation API.
Shared fixture machinery should not install schemas or directly patch KV nodes.
Design-owned defaults, schemas, monoids and recipes can ship in build artifacts;
ordinary JSON Schema alone cannot declare all participation/execution semantics.

Current inspector architecture already separates common UI from catalog data.
Carry that pattern forward. Export possible references, roots, slots, queries,
channels, formula order and source locations; actual active participation needs
record data. Show whole topology first and details on selection. Deterministic
table/role colors and matching reference swatches remain presentation logic.
Layouts are ordinary selectable functions, independent of model interpretation.
There is no reason to build a frontend server merely to view a static catalog.

## 7. Next steps and stop conditions

1. **Completed October 21:** recovered meaning and recorded the bounded Rust
   mathematical/transaction proof. Its source fingerprints remain unchanged.
2. **Current research:** audit whole-system responsibilities, specify API/tooling
   wireframes and source-based scenarios. Paper 8 owns their status and decisions.
3. **Next causal review:** define M3/M5 before/after dependencies for a moved
   prefix consumer and required output, valid diamonds and rejected feedback.
   Use a tiny executable model only if a semantic question remains unresolved.
4. **Conditional implementation boundary:** after the relevant contracts are
   closed, plan one native mutation slice using paper 8's bounded fixture and
   independent oracle. A complete accounting port is not needed for that proof.
5. **Distributed gate:** implement one adapter and verify reads, absence,
   uniqueness, reverse-discovery phantoms, unchanged-output guards and revocation.
   Reject oversized cascades without partial publication.
6. **Performance gate:** compare the same bounded workload, counting decoded
   nodes, dirty keys, encoded bytes, evaluations, retries and I/O. Select measured
   optimizations such as multi-get, node layout or more native indexes.
7. **Application expansion:** add RPC/authentication and accounting capabilities
   only after these contracts hold. Generate bindings/tools from the loaded model.

This ordering limits token/context use too: read the compact reference, the topic
paper and the touched module, then consult original sources only for ambiguity.
Tests prove a boundary and stay small. Existing AVL/heap/UUID results provide
established foundations. New unusual algebra, settlement order or concurrency
coverage requires focused evidence. No broad stress campaign is justified before
the central semantics exist.
