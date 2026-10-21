# Source map and authority

Inspected 2026-10-21. [source-manifest.json](source-manifest.json) records SHA-256,
byte size, line count and revisions for the supplied discussion, export, relevant
repository files and historical memory references. Files were inspected by topic;
the manifest does not certify existing runtime behavior.

## October 22 continuation

The original manifest and executable evidence remain historical records.
The [new audit manifest](evidence/2026-10-22-context-audit.json) records this
review's source coverage and unchanged-proof verification. Start with the
[system map](06-system-audit.md) for current routing and known stale paragraphs.

The newly supplied discussion at
`/home/divyeshvora/.codex/attachments/122d5863-86ae-4960-a4ed-c1f3074a9760/Pasted text.txt`
has exactly the original attachment's bytes/hash. The second attachment at
`/home/divyeshvora/.codex/attachments/87730ad0-666f-42ec-93f3-75e433aecc4e/Pasted text.txt`
is 142,353 bytes / 1,689 lines, SHA-256
`3af127762ae82f0c214cdc405fb48beec4b3d7a26d3fcd5af532236dad804e53`.
It supplies inspector history and the previous research execution through
`e5d13b3`; its repeated prompts/tool calls are not a new task queue.

The latest direct request controls the phase: rebuild global context, learn
from failures, patch research and prepare scenario wireframes inside the
decoupled directory before implementation planning. The
[workflow](08-research-workflow.md) replaces prior automatic runtime-next steps.
All 26 original repository-source fingerprints and all 11 proof-input hashes
were checked unchanged. Git/MetaSol state and additional API/tooling seams were
inspected; old acceptance suites were not rerun.

One targeted external refresh checked the FoundationDB developer guide's
[conflict semantics](https://apple.github.io/foundationdb/developer-guide.html#how-foundationdb-detects-conflicts)
for the authority-time clarification in paper 7. This was not a storage/version
selection campaign or an executed distributed-adapter experiment.

## Supplied context

The attached file is
`/home/divyeshvora/.codex/attachments/819aa252-56c9-439f-a76a-a12f7b64463f/Pasted text.txt`:
264,513 bytes, 5,669 lines, SHA-256
`5056832017a9fb41c849bc70bfa6d783c8ab21a8b5c2047b0f6bc5e12aee0f45`.
It includes 30 original prompt/response pairs followed by an appended engineering
conversation with additional user corrections. Its last response marker therefore
contains more than that one original response.

The IDE's Downloads export is 175,198 bytes, SHA-256
`1bda931bd50bca3f9a65cce9c039baf0a28af0d8023bc29872ab902b5d2fce95`.
It ends after the original proposal. It is not byte-identical to the attachment;
the appended corrections are essential, particularly the restoration of `read_by`.
The October 21 direct request added the compact reference, independent directory,
small mathematical Rust check and limited testing scope.

The earlier conversation in this IDE supplies additional intent: common dev tools
consume build-owned design data; fixture schemas/defaults should be centralized;
visualization covers isolated entities, polymorphic references, roots/dependents,
channels and monoids; selectable layouts should compose as ordinary functions.
That work is already represented in current source at `a963b25`.

## Original prompts: coverage without transcript replay

| Prompts / attachment lines | Subject | Compressed location |
| --- | --- | --- |
| 1–2, L5–221 | Frontend server, backend responsibility, SolidStart/Next deployment | Paper 4 §§1–2; logical boundaries do not require extra deployments |
| 3–6, L222–845 | JSON Schema/API standards, OpenAPI, server signals and reactive databases | Papers 1 §§4–7 and 3 §8; schema, API and transactional reactivity differ |
| 7, L846–1131 | Minimal declarative engine over KV, internal indexes, parser need | Papers 3 §8 and 4 §3; structured operations and a prepared model |
| 8–12, L1132–1662 | Rust/distributed engines, TiKV internals, PostgreSQL/FDB and Snowflake | Papers 2 §4 and 4 §2; architectural fit and comparable evidence, no speed ranking |
| 13–21, L1658–2796 | Storage portability, isolation, blind writes, OCC and shared guards | Paper 2 §§4–6; protect facts, absences and predicates |
| 22–24, L2797–3156 | Standard schemas, runtime validators, manual invocation | Paper 4 §3; validators run when called, compilation prepares reuse |
| 25–26, L3157–3943 | Rust, schema/CRUD, GraphQL/JSON:API, heavy lifting | Papers 3 §8 and 4 §§2–3; reuse matching infrastructure, preserve engine semantics |
| 27–29, L3944–4362 | General RPC discovery, token-bound context, merge/bitmaps | Paper 3; server scope, named operations, ordered merge |
| 30, L4363–4484 | One DAG, trees, reactive intervals, RAM staging, effects, complexity | Papers 1–4; the central synthesis with qualified bounds |

The Snowflake/provider-use and old headline benchmark digressions establish the
user's concern for supported infrastructure. They do not choose a stack or prove
relative performance. Earlier assistant recommendations for three packages,
automatic dependency capture, multiple API/policy frameworks or unconditional
native indexes are not user requirements. The later direct clarifications and
current contracts select the narrow model.

## Appended user follow-ups: corrections that govern the proposal

| Attachment location | User meaning / correction | Consequence |
| --- | --- | --- |
| L4486–4488 | Separate redesign workspace and current checkout | Independent build inside `rebase-next/`; inspect/pull first |
| L4676 | Distinguish current interpretation from commit behavior | Existing writes are atomic; lower repeated execution is a hypothesis to measure |
| L4767 | Runtime authority, augmented tree capabilities, breaking scope | Preserve invariants, explain tree capabilities, no legacy migration requirement |
| L4845 | Global validation timing and portable OCC | Final settled checks plus explicit early checkpoints; guard semantics matter |
| L4890 | Both early and final validation | Early checks only when conclusive; transient global failures can be valid construction |
| L4913 | Rust serialization/schema/server choices and minimum plumbing | Mature crates; compile validators once; avoid raw HTTP implementation |
| L5016 | Indexed server authorization, wrapper/token ideas, linking from client perspective | Server scopes and current authority; client requests cannot bypass rules |
| L5110 | Sparse records compose roles without physical tables | Contract obligations separate from root/membership roles |
| L5154–5168 | Merge only where needed; identity versus hierarchy; invoice root and mandatory payment role | Stable ID, explicit contract selector, separate reference/participation information |
| L5304 | Deterministic compact schema codes and principal encoding | Small persisted codebook; no seed-only unique compression |
| L5401 | Retract mutable composite primary address; shorter IDs considered | UUID primary identity; dictionary only for schema/slot metadata |
| L5434 | Random ID permitted; community format and hash-store curiosity | Standard binary UUID baseline; transactional capability outranks hash lookup claims |
| L5536–5540 | Latest reader restoration, index inventory, ownership versus internal effects, bounded filters/exists | Keep scalar reader candidate index; declare supported paths; budget exhaustion is unknown |

## Current repository evidence

ReBase was clean at `a963b25` before this work. `git pull --ff-only origin main`
reported already current. The configured GitLab remote could not authenticate.
MetaSol was inspected separately at `28c6e7f`, one local commit ahead of its origin.
No frontend code or existing core source was changed by this research.

| Current source | Why it matters |
| --- | --- |
| [Developer blueprint](../../designs/rebase-system/developer-blueprint.md) | Record defaults, reader fold, roles, roots, membership and query authoring |
| [Ordered tree contract](../../designs/rebase-system/ordered-tree-contract.md) | Typed keys, uniqueness/coalescing, queries, interval and publication rules |
| [Declared queries](../../designs/rebase-system/function-reactivity.md) | Fixed descriptors, actual dependency order, source fences and settlement phases |
| [October 16 plan](../../designs/rebase-system/declarative-engine-plan.md) | Dynamic dependency capture was deliberately replaced by declarations |
| [October 16 evidence](../../designs/rebase-system/declarative-engine-verification.md) | Historical acceptance scope; not rerun for this research |
| [Tenant/authentication](../../designs/rebase-system/tenant-authentication.md) | Direct parents, roles, protected closure, graph conflicts and reader semantics |
| [Operations](../../designs/rebase-system/operations.md) | Grants versus committed intent, uncertain delivery, leases and scheduling |
| [Native auth](../../framework/auth.surql) | Exact `dominates`, `can_access`, `choose_reader` and graph metadata |
| [Tree algebra/storage](../../dev-tools/compiler/temporal.surql) | Complete-time boundary combine, sparse channels and incremental patches |
| [Security generator](../../dev-tools/compiler/generators/security.js) | Protected reader and same-tenant/owner rules; reverse reader repair |
| [Accounting context map](../../designs/all-in-accounting/context-map.md) | Sparse dimensions, independent native/reporting contributions and examples |
| [Frontend architecture](../../designs/frontend/architecture.md) | Session fences, exact values, index-based pages and unknown write outcomes |
| [Fixture model](../../dev-tools/fixtures/model.js) | Schema generation is reusable in concept; native binding remains SurrealDB-specific |
| [Inspector layout](../../dev-tools/inspector/layouts.js) | Small ordinary composition and independent common tooling |
| [Stress interpretation](../../research/rebase/authorization-stress-results.md) | Owner-merge completeness assumes `read_by = owned_by`; larger runs have stated limits |
| [Stress pagination](../../dev-tools/experiments/authorization-stress/paging.js) | Bounded heap merge/prefetch, revision and residual-filter examples |

Links above are reference routes, not dependencies for moving/building this folder.
The source manifest retains identities and fingerprints if those routes move.

## Historical memory: use and freshness

The registry guidance at `MEMORY.md:143–145` and `417–418` favors ordinary modules,
small reusable primitives and no speculative framework. The September 26 MetaSol
simplification records that preference (`01a0db77-3d3b-77e0-b8ae-9c8b47b8de44`).
The October 13 accounting recap reinforces sparse dimensions, independent roles,
linear constraints and reading source rather than trusting prior agents
(`01a134f5-2554-7173-a61f-1510a81fb41b`).

Those older notes describe authored impact selectors and partial accounting work.
The current October 16 source instead uses named fixed queries and contains its
later acceptance record. The research follows current contracts; it does not
present the older partial status or impact implementation as current.

The Rust/LMDB recap (`01a0e313-1018-7921-bf04-3f4ea470a23d`) records a bitmap/rank
experiment and workload-specific conclusions. No measured numbers from it are
used to select the new store or promise performance. It supplies a caution about
setup/memory costs and assuming parallel helpers always improve a query. Memory
was read as source guidance; no global Codex memory files were updated.

## Primary external references

Transaction, schema, server and UUID documentation was checked on 2026-10-21;
Serde, the canonical schema specification and Record Layer are additional
background references. Source versions and deployment constraints should be
rechecked when implementing an adapter.

| Reference | Fact used |
| --- | --- |
| [FoundationDB developer guide](https://apple.github.io/foundationdb/developer-guide.html) | Regular reads establish read-conflict ranges; concurrent blind writes alone need not conflict |
| [FoundationDB known limitations](https://apple.github.io/foundationdb/known-limitations.html) | Five-second/affected-data/key/value limits and large-operation constraints |
| [TiKV isolation](https://tikv.org/deep-dive/distributed-transaction/isolation-level/) | Snapshot isolation permits write skew; adapter protection must be defined |
| [FoundationDB Rust binding](https://github.com/foundationdb-rs/foundationdb-rs) | Futures-based binding around the native C client |
| [redb crate/source](https://docs.rs/redb/4.4.0/redb/) | Embedded ACID/MVCC and normal serialized writer transactions |
| [Rust JSON Schema](https://docs.rs/jsonschema/0.59.0/jsonschema/) | Reusable validators, explicit formats/offline reference construction |
| [Serde](https://serde.rs/) | Mature format-independent value serialization |
| [jsonrpsee](https://github.com/paritytech/jsonrpsee) | HTTP/WebSocket JSON-RPC server and middleware infrastructure |
| [JSON-RPC 2.0](https://www.jsonrpc.org/specification) | Transport-agnostic message contract, notifications and non-atomic batches |
| [OpenRPC specification](https://spec.open-rpc.org/) | Method discovery/description; schema objects currently use Draft-07 |
| [JSON Schema 2020-12](https://json-schema.org/draft/2020-12) | Portable input validation dialect, distinct from cross-record engine rules |
| [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html) | Binary UUIDv4/v7 structure and entropy/ordering distinction |
| [FoundationDB Record Layer](https://foundationdb.github.io/fdb-record-layer/) | Prior art for transactional record/index layers; not an imported Rust dependency |

No comparative throughput results or release/popularity ranking was verified in
this task. The choice is based on semantics and maintenance fit. Primary docs
support the listed requirements; the proof supports only the scope in
[05-feasibility.md](05-feasibility.md).
