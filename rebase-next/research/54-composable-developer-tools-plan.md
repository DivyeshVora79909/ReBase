# G9 composable population and experiment tools

Implementation explicitly assigned after G8 closeout, 2026-10-25. G9.0 is the
first checkpoint; this plan is not executable acceptance. Historical D5, G2,
V1 and G8 evidence remains dated evidence. The user permits breaking changes
and requests verified checkpoint commits/pushes on existing main.

## Goal and placement

Give developers reusable ways to construct related data, submit it through the
real mutation API, inspect the result and run their own measured experiments.
Preserve capability rather than legacy function names. Breaking tool changes
are allowed when they reduce total maintenance or make composition clearer.
Do not preserve a wrapper simply because it already exists.

| Existing gate | Coverage | Remaining tooling opportunity |
| --- | --- | --- |
| D5 | Shared model metadata, design-owned fixture drafts, ordinary stateless client | General generation from model metadata and explicit reference pools |
| G2 | Bounded population and indexed-selection acceptance | A developer-controlled population tool rather than another capacity campaign |
| V1 | Explained scenarios, independent expectations, exploration and replay | Reuse those expectations as checks, without forcing every experiment into workshop modes |
| G8 | Workload, resource, recovery and deployment acceptance | Separate scenario logic from scheduling/observations using actual second-profile reuse |
| G9 | This prepared goal | Composable population, runtime context and an example feeding existing workload/check tools |

G8 should not grow a general fake-data engine. G9 should not grow a second
stress runner, monitoring service, authentication client or storage writer.
G8 acceptance does not depend on completing G9. Its workload extraction is
specified in [paper 52](52-workload-deployment-plan.md#composition-contract).

## Current implementation facts

The prepared model owns public schemas, contract/reference metadata and native
validation. Model behavior is trusted compiled Rust; a catalog is not a loader
for arbitrary executable JSON. Developer metadata includes reference targets;
public catalog output does not currently expose all of that metadata. First
reuse explicit trusted CLI output, or narrowly expose public reference metadata
if a demonstrated use requires it. Do not export private roles to solve this.

Existing fixture recipes remap labelled authored IDs and declared references.
They do not provide general field faking, named reference pools, weighted
incremental counts or automatic global-constraint inference. Original ReBase's
fixture algorithms are useful references, but its SurrealDB parser, RecordId,
SQL and transaction ownership are not reusable storage-independent interfaces.

G8.0's observer, stream and resource-check functions already compose separately.
Its workload module still fixes equipment contracts, fixture state, source
oracle, CRUD cycle and reader query. That is a concrete extraction opportunity,
not evidence that the engine needs redesign.

## Small operation boundaries

The following are responsibilities, not mandatory names, classes or wrappers:

1. **Prepare:** consume one authoritative catalog plus ordinary generation
   settings. Prepare schema strategies/validators and reference-field metadata
   once, validate counts/options and initialize explicit state.
2. **Propose:** use that state and caller-supplied current context to produce
   authored inputs or a bounded mutation draft. Selection, value generation and
   context rules are ordinary replaceable functions.
3. **Accept:** advance reference pools, fulfilled counts and usage statistics
   only after confirmed commitment. Keep rejected and unresolved proposals
   distinct. Proposal/RNG progress is explicit so resume does not guess it.

Use the existing client's prepare/save/execute/status operations for submission.
A convenience population loop is justified only by repeated use; it must be
equivalent to explicit composition and expose accepted progress and failures.
No hidden sessions, global generator cache or automatic mutation retry.

Generation is stateful: remaining quotas, RNG state, available IDs and selection
statistics change. Make that state an explicit caller-owned value. Do not hide
it to claim statelessness, and do not require copying a complete dataset on each
iteration merely to make the API look functional.

## Configuration and runtime context

Settings should cover counts by public contract, seed/explicit clock, supplied
reference pools, field strategies and a small number of selection controls.
Existing pools identify IDs with their contracts explicitly; bare Next UUIDs
cannot be parsed as table names. Supplied records do not consume new-record
quotas. Detect incompatible IDs, duplicate identities and missing context.

Reuse declared target types for optional, nested, array and polymorphic
references. Select eligible contracts by remaining count and optional priority;
use equal per-record selection by default, with explicit bias/skew functions
when requested. Document whether polymorphic weighting is per record or per
contract. Unequal pool sizes must not silently change that interpretation.
Statistical skew is a tendency, not an exact cardinality guarantee.

References, chronological prerequisites and business feasibility are different
conditions. A nonempty parent pool does not prove that a chosen parent can
accept another child. Read the required current aggregate context before a
dependent proposal, or use an explicitly supplied independent scenario oracle.
For example, an equipment rule can choose an amount from its available capacity;
that rule is ordinary code, not an inferred consequence of JSON Schema.

Use declared relations plus explicit scenario ordering where needed. Do not
deduce insertion order solely from table names or require an aggregate to change
before allowing a legitimate empty/zero dependency. Distinguish reference
availability from the model's final-graph causal evaluation order. Required
cycles need valid supplied anchors or an explicitly model-valid same-operation
seed; never invent nonexistent committed parents. Report stalled remaining
quotas and their unavailable prerequisites without calling this a proof of
mathematical unsatisfiability.

Monotonic generated times are useful defaults, not a proof of all historical
invariants. An explicit clock/sequence makes replay meaningful; wall-clock time
and a random seed alone do not. Missing aggregates remain missing, never zero.
Simplex/Z3 cannot infer business rules or automatically supply graph validity.
Use ordinary range calculations first and direct optional solver calls when a
scenario has interacting constraints. Solver timeout/unknown differs from unsat.

## Transactions, progress and scale

Default dependent generation should observe confirmed state between batches.
If several dependent inputs share one operation, their rule needs a declared
valid construction or local oracle for that proposal; do not silently reuse
pre-batch aggregates as though previous proposals had already committed.
Read-then-submit context can become stale with other writers. The real server's
authority, OCC and invariant checks remain authoritative. Surface a conflict;
continuing with a newly authored proposal is explicit developer policy.

Every submitted mutation is atomic, not the whole multi-batch population job.
Respect 64 commands, 32 returning IDs, request bytes, engine work, receipt room
and the selected model's actual population bounds. Save original IDs/contexts
and reconcile uncertain operations before advancing or reauthoring. Receipt
archive is explicit maintenance, not an invisible way to keep a job running.

Support bounded streaming of proposals/results and caller-chosen retention of
full rows versus ID/contract/context summaries. Reference pools and statistics
still cost space proportional to the identities retained. Producing N records
requires at least proportional output work. Weighted trees can improve selection
costs; arbitrary callbacks, changing all weights, solvers and RPCs have their
own costs. Do not promise universal constant-time generation.

Cloning is an optional recipe over authored inputs: fresh IDs, internal-reference
remapping and explicit external anchors. Do not copy private outputs, version
tokens or stored tree links. It does not bypass the current u16/4,096-source
envelope; million-record engine expansion remains separate.

Preserve canonical integer/rational/decimal representations from the model.
Sampling a valid amount must not introduce floating-point rounding that changes
an exact business boundary. Accepted source identities do not imply a local
cache knows all resulting derived values; refresh the needed context explicitly.

## Dependencies and language decision

Keep orchestration in the existing scripting surface unless a bounded comparison
establishes lower total maintenance elsewhere. Do not assume Rust makes a native
solver faster, or introduce Rust/Python/Node implementations of the same logic.
Keep any new tooling dependencies inside this directory and optional for the
backend release where possible. Avoid a subprocess/FFI bridge solely to reach
a library already available in the orchestration language.

Relevant Rust options, not a required dependency list:

| Library | Capability | Boundary |
| --- | --- | --- |
| [fake](https://github.com/cksac/fake-rs) | Realistic values and seeded generation with an explicit RNG | Not a general JSON Schema or relationship validator |
| [rand](https://github.com/rust-random/rand) / [rand_distr](https://github.com/rust-random/rand_distr) | Sampling/distributions | Reproducibility also depends on versions, ordering and RNG choice |
| [jsonschema](https://github.com/Stranger6667/jsonschema) | Prepared schema validation, already used | Does not infer global constraints |
| [z3](https://github.com/prove-rs/z3.rs) | Community-maintained bindings to native Z3 | Optional native installation/build and solver limits |
| [good_lp](https://github.com/rust-or/good_lp) | Linear problem modelling with selectable solvers | Not itself a solver; avoid adding alongside Z3 without a distinct need |
| [proptest](https://github.com/proptest-rs/proptest) | Generated tests and shrinking | Not a realistic population engine |

The Rust crate named json-schema-faker is a small JavaScript wrapper, not evidence
of a mature native equivalent. Do not select a dependency by name similarity.

## Checkpoints and acceptance

### G9.0 — bounded feasibility and operation contract

Before building a general generator, exercise field generation, typed pool
selection and one fresh-aggregate rule with supported libraries. Compare the
existing scripting path with another language only when a concrete gap warrants
it. Record installation/build burden, schema support, seeded reproducibility,
unsupported keywords and actual integration code. Never silently ignore a schema
constraint. Prefer an explicit field strategy over a home-grown schema engine.
Select the smallest supported path; stop researching once the facts decide it.

### G9.1 — metadata, pools and accepted progress

Implement the minimal boundaries above, seeded counts/selection and existing-ID
pools. Test compatible/polymorphic references, optionals/arrays/nested fields,
unavailable prerequisites, cycle anchors, same-seed behavior, confirmed versus
rejected progress, unknown outcomes and bounded batch submission. Demonstrate
explicit composition and any justified convenience loop produce equivalent
accepted inputs. Do not require a new client or server endpoint.

### G9.2 — runtime constrained generation

Use equipment plus a second existing model with a different dependency shape.
Show refreshed context changes the next proposal's range and that valid inputs
pass the real API and independent source expectations. Include an explicit
chronological recipe and a missing-context negative control. Test a deliberate
concurrent conflict without silently retrying. Add a direct solver example only
if it closes an interacting-constraint case; no solver abstraction is mandatory.

### G9.3 — compose population with measured experiments

Feed generated inputs into G8's ordinary operation, observer and report tools.
Reuse the runner extraction made for its equipment/Quantity profiles; if G8 is
already accepted with scenario-specific code, extract here with affected controls
and keep historical acceptance accurately dated. A custom action iterator,
independent checker and caller-selected observations must work without modifying
the scheduler. Report generation, setup, RPC and verification costs separately.
Use existing JSON/JSONL/CSV and readable summaries; no dashboard is required.

### G9.4 — developer handoff

Provide short explicit-composition examples: existing references, mixed-contract
population, a fresh aggregate rule, stop/inspect/continue, cloning authored inputs
and a measured CRUD experiment. Name unsupported schema/constraint cases and the
actual model/receipt limits. Retain failing seeds and ordinary replay artifacts.
Update guides/continuation and verify extracted tooling if release contents
change. Reuse unchanged engine evidence; do not repeat G7 or a full scale campaign.

## Integration and continuation

G8.0–G8.5 are complete within their recorded bounds. G9 is now selected;
implementation in new owned files may overlap only after agreeing
ownership of shared clients, workload tools, package manifests and guides.
Never have two agents refactor the same runner. One owner integrates the G8
extraction. Continue G9.0–G9.4; no G6, TiKV, frontend,
new monitoring service or engine-capacity expansion is selected by this paper.
Use the existing main branch and verified checkpoint commits/pushes. Root owns
remote history and checks new upstream commits before pushing.
