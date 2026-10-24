# Compiled model authoring

G1 adds reusable model authoring through trusted Rust modules. The calculation
model and the independently checked [equipment model](equipment.md) use the same
`Prepared<B>`, `Store<B>`, mutation lifecycle, principal DAG authority, public
queries, receipts, HTTP server and storage tools. Select one compiled model per
store. Omitting the selector chooses `calculation`:

```sh
rebase-next --model equipment model public
rebase-next --model equipment model developer
rebase-next --model equipment model explain Reservation
rebase-next --model equipment fixture list
rebase-next --model equipment fixture plan equipment --namespace 00000000-0000-4000-8000-000000000100 > equipment-draft.json
```

The [invoicing model](invoicing.md) adds fractional pricing, chronological tax
reassessment, payments and linked refunds using the same interfaces, with typed
authored-parent parameters and explicit money memberships.
Select `--model invoicing`; its initial source/output/retained envelope is
64/256/512 rather than calculation/equipment's larger accepted workload profile.

The [effect-demo model](external-effects.md) adds immutable Dispatch requests
committed with Account changes. Optional `Binding::effect_action` and
`effect_template` hooks declare and freeze the model-owned native input; the
ordinary transaction publishes intent and receipt together. Preparation checks
the action's immutable source and required typed target reference and hashes its
versioned metadata. Action metadata contributes to the declaring model's identity;
shared semantic changes still require every affected behavior identity to change.

`--model` must precede the command. Use the same selector for initialization,
serving, checks, inspection, backup, restore and reset. There is no HTTP operation
that switches a store's model. A model or codec mismatch rejects opening a store;
this gate supplies no migration from earlier store formats. Use `version` with
the selector to inspect the selected model identity and current store format.

## Small compiled interfaces

A model owns its native `Input` and `Derived` types. It implements these ordinary
Rust traits, without adding variants to another model's input enum:

| Interface | Model responsibility |
| --- | --- |
| `NativeInput` | Bind a contract code and canonical JSON to native values; validate native bounds; enumerate typed references and managed producer/role identity. |
| `Binding` | Supply closed schemas and explicit declarations, model name and behavior revision, limits, published-field shape, model settlement/checking functions and optional fixture recipes. |
| `ReactiveBinding` | Resolve declared shape and authored parameters, project ready parent publications, evaluate native publication/query values, and construct managed contributions. |

`Prepared::<B>::load()` validates declaration identities, closed schemas, field
agreement, local calculation order, reference targets, roots, memberships,
queries and private output roles. It compiles validators once. The same prepared
schemas and mutable fields drive ingress validation, catalogs, predicates and
tools. Preparation validates structural agreement; it does not prove that a
trusted Rust formula matches its descriptive expression or that a model's
invariant checker is complete.

A direct membership can name `through: "self"` to participate in its source's
own root. Preparation requires `root_contract` to equal that source contract and
resolves the declared root/kind there. It adds no implicit reference or copied
output; Payment uses it for its own refund-capacity history.

`ReactiveBinding::Parameters` is an ordinary native type. `resolve` returns
`Resolved { shape, parameters }`; the shared engine builds the final dependency
graph from `shape`, then passes `&parameters` and ordered-query values into
`evaluate`. For example, a tax model can capture
`TaxParameters { rate: Rational, rounding: Rounding }` from an authored rule and
evaluate `parameters.rate.apply(basis, parameters.rounding)` without a workspace.
Existing calculation/equipment bindings use `Parameters = ()`.

Resolve only declared direct authored inputs. List the consumed parent fields in
`Reference.direct_fields` and maintain that reference's old/new direct routes in
settlement, just as existing bindings do. Parent edits then select the child;
retargeting removes the old registration. This is parent-level invalidation,
not a separate field-level index. All source commands are staged before
resolution, so a parent edit and child retarget observe the same final authored
values in either command order. The parameter bundle is attempt-local: it needs
no Serde schema, stored copy, global cache or `Default` value for deleted records.
Creating new reference targets still requires parents before children during
command staging. Final-graph calculation does not imply arbitrary creation order.

Keep published parent calculations out of authored parameters: a parent may
still be pending during resolution. Declare them through `Contract.publication_inputs`:
each `PublicationInput` names its own `PublicationSlot`, an authored reference
slot, a published field code and its native binding. Preparation checks the field
against every allowed reference target. `resolve` returns the pinned parent UUID
in `ResolvedShape.publications`; every declared slot is mandatory, including when
the formula multiplies it by zero.

`ReactiveBinding::Publication` is a model-owned native type without Clone or Serde
requirements. `project_publication(parent, field_code)` receives the ready parent's
current record. The engine passes slot-tagged `PublicationValue` entries into
`evaluate` between authored parameters and ordered query values. Invoicing uses
`Publication::IssueAmount(i128)` for IssueShare. One Direct registration per
reference covers both authored and published inputs; `Contract::uses_direct`
identifies that union. Publication edges participate in the same final graph as
financial reads, and original/staged routes only discover affected work.

Only declared parents using the shared causal scheduler are supported here.
Publication values cannot choose references, output activation or query bounds.
Undeclared reference chains and hidden reads remain unsupported. Keep database
handles out of evaluation. Model hooks remain trusted Rust code; the interface
does not enforce purity against malicious code.

`Store::<B>` supplies the shared adapter. The engine stages source commands,
checks schema and equality-only UUID CAS tokens, enforces current authority, and creates declared
headers. Model settlement maintains its direct memberships and reverse routes;
the shared reactive engine discovers affected work from old and new routes,
detaches old managed outputs, builds the final dependency graph, rejects cycles,
evaluates in dependency order and reconciles private output identities. Model
validation runs against the settled state before the shared transaction publishes
root/source tokens, reader indexes, query epochs, receipt allocations and receipts
atomically over the selected storage backend.

The native `Meta` contains immutable model/codec/tenant/bootstrap identity.
`Population` separately holds exact per-contract counts and retained reservation
counts. Settlement receives `&mut Population` and one fresh UUID mutation token;
it writes the population row only when counts actually change. Changed records
and roots receive the token, while unchanged state retains its prior token.
Declared roots still guard their shared invariants. New capacity reservations
and shared reader/contract query partitions can coordinate otherwise separate
updates; model hooks must not invent a global mutation sequence or a backend-
specific calculation path. [Storage contracts](storage.md#data-identity-and-upgrades)
distinguish these tokens from administration/execution counters.

Requested source writes and new links require client authority. Declared managed
outputs and repairs run under engine authority; the public API rejects writes
to private contracts. Owner and reader remain distinct. The model hooks are
trusted compiled code with workspace access, not a sandbox for untrusted authors.
They must preserve tenant, reference, routing and invariant obligations.

A declared sum reader can validate without private outputs. Pure validators
register ordinary dependencies and run after all final contributions settle;
they need no dummy output or formula. Calculation-only readers can publish
derived values without emissions. Whether a formula runs follows the contract's
declarations, so disabling an active query still recomputes its explicit fallback.
Reactive reads use exact typed `TimeRange` values. A validation-only read can
check a window after all outputs settle without creating calculation edges. The
shared validator remains a nonnegative aggregate sum; windows do not add
arbitrary predicates. See [exact time windows](reactive-windows.md) for the
wire form and public root read.

Native monetary/rate calculations can compose the pure
[`Rational` and `Rounding` primitives](exact-values.md). Their schema helpers
come from the same native types used by binding; tools need no duplicate schemas.
The bundled formula arithmetic remains unchanged; the format and behavior
revisions below record the new stored query/index identities.

Calculation and equipment provide independent checkers. The equipment checker derives
allocations and event histories from authored sources, then compares managed
outputs, publications, queries and memberships. Shared snapshot checking verifies
exact key inventory, role reservations, authority/reader indexes, real tree links,
caches, population counts, scoped epochs and the exact receipt/slot bijection.
A second fixture alone would not establish this boundary:
equipment uses separate native types and sparse contract, root, member, query and
role codes through the same engine.

## Supported shape and limits

The slot inventory is fixed and bounded by declarations. Authored input and
permitted direct scalar inputs can change query activation, source roots and
bounds, and output activation, root and time. Ordered query results supply
calculated values; they cannot create new slots or select new dependency topology.
Both zero amounts and coincident bounds retain their declared identities.

The shared ordered tree currently supports signed i128 quantity histories and
u16 dated quotes, using i64 time plus deterministic identity ties. Its summaries
support sum, prefix and latest reads, complete-time invariants, and exact
two-bound financial sum windows. This is not a facility for arbitrary monoids,
arbitrary query predicates or automatically discovered dependencies. Adding a
new aggregate or result type needs an explicit engine contract.

Calculation and equipment allow 4,096 public source records, 8,192 active private
outputs and 16,384 retained output identity reservations. Each active equipment
reservation consumes two outputs, including zero allocations. Calculation has
no separate 16-record Quote/Posting/Adjustment/Basis cap. Mutations allow 1–64
distinct source commands, at most 32 returning IDs and 200,000 charged engine
work units. Public pages, candidate visits, receipts and transport bytes have
separate limits published in the model catalog. A logarithmic tree path does
not bound an affected causal closure.

Tree insertion, removal and prefix lookup follow balanced paths. Point-addressed
reverse AVL routes retain subscriber ranges and select affected readers from
changed old/new member times. Prefix-only roots keep the earlier earliest-impact
suffix path; roots with bounded lower ends use interval stabbing against both
original and staged route state. Latest-quote invalidation respects successor
intervals. The final dependency graph uses prefix gates for lower-unbounded
reads and segment covers for bounded reads, preserving zero-output dependencies
and excluding out-of-window producers. For P producers, E distinct emission
times and R reads, the bounded graph has O(P + E) nodes and
O(P + E + R log E) edges; prefix-only graph edges retain the prior linear
construction. Building time indexes and locating read spans takes
O(E log E + R log E) comparisons, besides graph traversal and producer
evaluation. These bounds do not make mutations logarithmic: full fanout remains
finite work and may reject atomically at the unchanged budget. The independent
checker inventories the complete bounded store.
The [population result](../research/24-population-scaling-result.md) owns measured
workload evidence and its limits.

Model identity includes explicit behavior identity and resolved declarations;
source-file presentation paths do not define stored semantics. Bump behavior
identity when bindings, formulas, causality or invariants change, and codec/store
versions when those formats change. Earlier proof evidence remains dated.
Current source 0.16.0 uses store 10 /native codec 7 /effect codec 4 /API 4, with
calculation behavior `rebase-calculation-contract-7`, equipment
`equipment-reservations-6`, invoicing `invoice-assessments-6`, measurement
`dimensioned-measurements-4`, effect-demo `effect-demo-ingress-4` and quantity
`quantity-flow-2`. These identities reflect the shared token/coordination contract;
the declared business formulas remain unchanged. New-format stores are required.

Historically, 0.14.0 source used store 9 /native codec 6 /effect codec 3 /API 3,
calculation behavior `rebase-calculation-contract-6`, equipment behavior
`equipment-reservations-5` and measurement behavior `dimensioned-measurements-3`.
Invoicing used `invoice-assessments-5` for IssueShare. Only measurement's identity
changed from 0.13.0; effect-demo used `effect-demo-ingress-3`. Checked inbox
events and explicit worker modes required new format-9 stores. No implicit
migration from earlier stores was provided.
The [0.6 deployment result](../research/29-deployment-result.md) remains dated
evidence for that bundle. See [storage upgrades](storage.md#data-identity-and-upgrades).

## Existing client and tools

The [ordinary developer workflow](developer-tools.md) applies to either model;
its original D5 acceptance examples use calculation. Follow the [server
configuration](server.md) for issuer keys, tokens and HTTP settings, adding
`--model equipment` to model/store commands for equipment. Send its fixture draft
using the existing client:

```sh
python3 tools/client.py --url http://127.0.0.1:8080/rpc --token-file token.txt prepare equipment-draft.json equipment.plan.json
python3 tools/client.py --url http://127.0.0.1:8080/rpc --token-file token.txt apply equipment.plan.json
python3 tools/client.py --url http://127.0.0.1:8080/rpc --token-file token.txt status equipment.plan.json
```

The client takes no model selector: the draft and authenticated destination supply
model identity. A saved plan preserves the original operation context across
retries and status checks. It never refreshes an uncertain operation across a
reset or archive fence. The filesystem stdio/operator interface remains separate
from authenticated HTTP. No arbitrary JSON behavior loader, scripting runtime,
plugin registry, live-provider delivery or frontend is included. The selected
[transactional adapters](storage-backends.md) use the same model and mutation paths.

## Native index families

A binding selects `type Index: NativeIndex`. Its codebook, native key/leaf/summary/query-result
types, algebra and read schemas feed the shared tree, codec and model catalog.
Calculation, equipment and invoicing select `indexes::standard::Standard`;
measurement selects its independent statistics family. Balancing, point storage,
authority and receipts remain shared. Read [native indexes](native-indexes.md)
for the concrete authoring contract and independent source-check obligations.

`ReactiveBinding` receives `&[Index::QueryResult]` through the shared scheduler.
Standard retains scalar `i128` results and the fast financial prefix path.
Measurement's output-free ObservationReport consumes a native Summary, declaring
its Instrument, exact range and direct authored-unit dependency. LatestObservation
consumes an optional native selection from all authored observations at or before
its exact cutoff, including a persistent dependency when absent. Its source
checker reconstructs queries, routes and derived values without writer caches.
A custom root's `sum` field does not grant financial query semantics. Managed
output construction remains an explicit financial capability; authored-only
statistics consumption does not establish generic managed-emission readiness.


## Typed external results

Bindings without external actions set `type Outcome = ();`. The experimental
[effect-demo](external-effects.md) binding supplies a typed `Outcome`, its public
schema, pure frozen-request/outcome validation and a pure application command.
`ActionDeclaration::application_fields` lists the mutable target fields that
this command may update. Core validates those declarations and restricts both
pre-binding and post-binding authorization before ordinary settlement. Provider
I/O and configuration remain outside model calculation and transactions.

## Minimal ready-publication example

Select `--model quantity` for the [workshop](workshop.md). Source (101) publishes
an authored integer, Scale (205) applies an exact rational with explicit rounding,
and Join (309) adds two ready parent quantities. `fixture plan quantities
--namespace <uuid>` prepares Source 12, exact half/third scales and Join 10.
Its limit is 16 public records with absolute published quantities at most
`1000000000000000000`; it has no private outputs or custom index family.

Publication target declarations put even terminal Sources into the existing
shared scheduler. A parent must still use supported causal query operations.
The original 0.15.0 addition needed no fake root/query or second writer and changed
no existing model catalog or persisted format; its behavior identity was
`quantity-flow-1`. Source 0.16.0 uses `quantity-flow-2` for the shared UUID token
and coordination contract.
