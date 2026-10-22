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
| `ReactiveBinding` | Resolve declared query/output shape, evaluate query values, construct managed output inputs and identify their tree memberships. |

`Prepared::<B>::load()` validates declaration identities, closed schemas, field
agreement, local calculation order, reference targets, roots, memberships,
queries and private output roles. It compiles validators once. The same prepared
schemas and mutable fields drive ingress validation, catalogs, predicates and
tools. Preparation validates structural agreement; it does not prove that a
trusted Rust formula matches its descriptive expression or that a model's
invariant checker is complete.

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

Both bundled models retain limits of 64 public source records, 48 active private
outputs and 256 retained output identity reservations. Each active equipment
reservation consumes two outputs, so the output limit can bind before the source
limit. Calculation also caps each Quote, Posting, Adjustment and Basis contract
at 16 records. Mutations allow 1–64 distinct source commands and have a work
budget; public pages, candidate visits, receipts and transport bytes have separate
limits published in the model catalog. A logarithmic tree path does not bound
an affected causal closure.

Tree insertion, removal and prefix lookup follow balanced paths. The current
reactive scheduler conservatively opens affected-root subscriber lists and
compares planned reads with planned emissions to build its final graph; with
fixed slots, that comparison can be quadratic in affected producers. The
independent checker inventories the complete bounded store. This gate establishes
model reuse and correctness within the envelope, not large-population scheduling
or constant-time validation. Those need a separate capacity gate.

Model identity includes explicit behavior identity and resolved declarations;
source-file presentation paths do not define stored semantics. Bump behavior
identity when bindings, formulas, causality or invariants change, and codec/store
versions when those formats change. Earlier proof evidence remains dated.

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
