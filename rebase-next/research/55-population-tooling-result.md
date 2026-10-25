# G9 composable population results

G9.0 is accepted on 2026-10-25; G9.1–G9.4 are implementation checkpoints, not
accepted by this paper yet. [Plan 54](54-composable-developer-tools-plan.md)
defines scope. G8 remains accepted and is not restarted. The user selected G9
and checkpoint pushes after the earlier G8-only stop/no-push handoff.

## G9.0 — bounded feasibility and operation contract

The [evidence](evidence/2026-10-25-g90-population-feasibility.json) records actual
library and native-validation trials. Keep Python orchestration and the existing
stateless client. Add an optional, replaceable Node schema-value provider only
for callers who want general schema-shaped base fields. Explicit Python field
strategies do not require Node. Do not implement another client or JSON Schema
generator, or introduce a persistent worker/FFI service.

| Trial for 1,024 values | Elapsed | Scope |
| --- | ---: | --- |
| Python Hypothesis JSON Schema via public test-generation API | 19.327 s | Value generation; no database |
| Node JSONSchemaFaker, batches of 32 | 1.365 s | Process startup, generation and JSON transfer |
| Node JSONSchemaFaker, batches of 128 | 0.419 s | Process startup, generation and JSON transfer |

The tested Node dependency is json-schema-faker 0.6.3, one production package
with no production transitive packages. The 26-line prototype establishes a
small boundary; production timeout, output bounds, schema-support checks and
cleanup still need their G9.1 controls. This timing does not establish RPC
throughput or justify making Node a backend dependency. Hypothesis remains a
property-testing tool rather than the chosen imperative population API.

The initial provider trial covers 28 distinct public contracts across five
catalogs. Actual SDK-free CLI exports then cover all six models and 31 public
contracts, including Quantity. Public catalogs expose schemas/fields/roots;
trusted developer catalogs additionally expose reference declarations/private
contracts. The generator must select public contracts from that metadata.

One schema-generated sample per model, with explicit reference/numeric/rational/
optional-field overlays, passes existing native model validation. Root reran all
six controls. The raw Equipment sample fails native binding because starts and
ends are equal despite the JSON property shapes being valid. In these six
native controls every field is explicitly overlaid: they demonstrate composition
and the validity boundary, not automatic native/global validity from the faker.
No transactional or aggregate proof follows from offline model validation.

Unknown assertion keywords must fail clearly in a provider that cannot honor
them. Standard annotations such as x-* are different: their native model meaning
can require explicit strategies even though they are not JSON Schema assertions.
Compile validators once and validate final values after reference/rule overlays.

## Selected operation boundary

The intended public module roles are prepare, propose, accept and reject, with
plain explicit state/proposal/pending records. Exact implementation signatures
and examples are recorded when G9.1 is accepted.

- Prepare uses authoritative metadata, quotas, typed supplied pools and explicit
  seed/clock/strategies. Supplied IDs do not fulfill new-record quotas.
- Propose selects available references and generates detached authored inputs.
  It can reserve pending work but cannot add committed parents or fulfill counts.
- The developer prepares/saves/submits the exact plan with the existing client.
  Accept verifies the saved proposal/request and the committed records receipt's
  operation ID before advancing accepted state. No second transaction path.
- Definite rejection may permit an explicit new proposal; unknown outcomes keep
  their original plan/context and block progress. Not-observed receipt status
  alone cannot prove a timed-out operation failed. No automatic retry/archive.

Runtime rules are ordinary functions using explicit fresh context. The Equipment
example will use a controlled chronological construction; prefix availability
alone is not sufficient for arbitrary interval histories. Quantity supplies a
different polymorphic graph/exact-arithmetic case. The server remains authority
for OCC, authorization, native/global invariants and final publication.

## Continuation

G9.1 core and optional-provider work have disjoint Luna owners, with independent
read-only review. After focused unit/native controls, root verifies the state,
receipt and provider boundaries before granting real G9.2/G9.3 workflow execution.
Keep model/receipt/work limits and matching G8 evidence. G9.4 documents explicit
composition and affected extracted tooling checks; no G6, TiKV, frontend, live
provider or million-record engine expansion is selected.
