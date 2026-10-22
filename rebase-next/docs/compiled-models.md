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
| `ReactiveBinding` | Resolve declared query/output shape and model-owned parameters, evaluate them with query values, construct managed output inputs and identify their tree memberships. |

`Prepared::<B>::load()` validates declaration identities, closed schemas, field
agreement, local calculation order, reference targets, roots, memberships,
queries and private output roles. It compiles validators once. The same prepared
schemas and mutable fields drive ingress validation, catalogs, predicates and
tools. Preparation validates structural agreement; it does not prove that a
trusted Rust formula matches its descriptive expression or that a model's
invariant checker is complete.

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

This seam does not make published parent calculations or undeclared reference
chains safe inputs. They need additional dependency contracts. Keep database
handles and hidden reads out of parameters/evaluation. Model hooks remain trusted
Rust code; the interface does not enforce purity against malicious code.

`Store::<B>` supplies the shared adapter. The engine stages source commands,
checks schema and CAS versions, enforces current authority, and creates declared
headers. Model settlement maintains its direct memberships and reverse routes;
the shared reactive engine discovers affected work from old and new routes,
detaches old managed outputs, builds the final dependency graph, rejects cycles,
evaluates in dependency order and reconciles private output identities. Model
validation runs against the settled state before the shared transaction publishes
root/source revisions, reader indexes and receipts atomically.

Requested source writes and new links require client authority. Declared managed
outputs and repairs run under engine authority; the public API rejects writes
to private contracts. Owner and reader remain distinct. The model hooks are
trusted compiled code with workspace access, not a sandbox for untrusted authors.
They must preserve tenant, reference, routing and invariant obligations.

Native monetary/rate calculations can compose the pure
[`Rational` and `Rounding` primitives](exact-values.md). Their schema helpers
come from the same native types used by binding; tools need no duplicate schemas.
The bundled models retain their existing formulas and identities.

Both bundled models provide an independent checker. The equipment checker derives
allocations and event histories from authored sources, then compares managed
outputs, publications, queries and memberships. Shared snapshot checking verifies
exact key inventory, role reservations, authority/reader indexes, real tree links,
caches and receipts. A second fixture alone would not establish this boundary:
equipment uses separate native types and sparse contract, root, member, query and
role codes through the same engine.

## Supported shape and limits

The slot inventory is fixed and bounded by declarations. Authored input and
permitted direct scalar inputs can change query activation, source roots and
bounds, and output activation, root and time. Ordered query results supply
calculated values; they cannot create new slots or select new dependency topology.
Both zero amounts and coincident bounds retain their declared identities.

The shared ordered tree currently supports signed i128 quantity histories and
u16 dated quotes, using i64 time plus deterministic identity ties. Its associative
summaries support the implemented sum/prefix/latest operations and complete-time
invariants. This is not a facility for arbitrary monoids, arbitrary query
predicates, general interval optimization or automatically discovered dependencies.
Adding a new aggregate or read operation needs an explicit engine contract.

Both bundled models allow 4,096 public source records, 8,192 active private
outputs and 16,384 retained output identity reservations. Each active equipment
reservation consumes two outputs, including zero allocations. Calculation has
no separate 16-record Quote/Posting/Adjustment/Basis cap. Mutations allow 1–64
distinct source commands, at most 32 returning IDs and 200,000 charged engine
work units. Public pages, candidate visits, receipts and transport bytes have
separate limits published in the model catalog. A logarithmic tree path does
not bound an affected causal closure.

Tree insertion, removal and prefix lookup follow balanced paths. Point-addressed
reverse AVL routes select read endpoints using changed old/new member times;
latest-quote invalidation respects successor intervals. Original and staged
routes preserve retargeting and moved-bound discovery. The final dependency
graph uses prefix gates to preserve producer reachability, including zero
outputs and feedback. For P producers, R resolved reads and E emissions, its
nodes and edges occupy O(P + R + E) space. Building the ordered emission indexes
and locating read prefixes takes O(E log E + R log E) CPU work, in addition to
graph traversal and producer evaluation; linear graph size is not linear CPU
time. Full fanout remains finite work and may reject atomically at the unchanged
budget. The independent checker inventories the complete bounded store.
The [population result](../research/24-population-scaling-result.md) owns measured
workload evidence and its limits.

Model identity includes explicit behavior identity and resolved declarations;
source-file presentation paths do not define stored semantics. Bump behavior
identity when bindings, formulas, causality or invariants change, and codec/store
versions when those formats change. Earlier proof evidence remains dated.
Release 0.4.0 uses store/codec format 4, calculation behavior
`rebase-calculation-contract-4` and equipment behavior `equipment-reservations-3`.
Those identities and the expanded declared limits differ from 0.3.0; no implicit
format 3 migration is supplied. See [storage upgrades](storage.md#data-identity-and-upgrades).

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
plugin registry, distributed adapter, external delivery or frontend is included.
