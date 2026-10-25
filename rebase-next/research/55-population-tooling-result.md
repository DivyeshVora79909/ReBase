# G9 composable population results

G9.0–G9.1 are accepted on 2026-10-25; G9.2–G9.4 remain to be accepted.
[Plan 54](54-composable-developer-tools-plan.md)
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

**G9.1 contract correction before acceptance:** independent source review found
the initial G9.0 decision inferred internal ReceiptResult enum tagging rather
than following disclose_result and client.call. The real client response is
status=committed with result.operation_id/revision/records directly; it has no
result.kind or additional result nesting. The implementation and controls use
that actual wire shape. Original G9.0 trial evidence is retained as recorded;
its proposed receipt-binding nesting is superseded here, not an executed
transaction proof. No core/wire compatibility branch is introduced.

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

## G9.1 — metadata, pools and confirmed progress

The [G9.1 evidence](evidence/2026-10-25-g91-population-core.json) records 45
focused controls, independent adversarial review and root's actual Calculation
Basis native-validation witness. The public module operations are prepare,
propose, accept and reject. State, Proposal and Pending are explicit records;
there is no automatic client/session or alternate storage writer.

Prepared validators and detached public metadata drive generation. Typed pools
accept ID-only supplied anchors; supplied rows do not fulfill quotas. Required
references become available after committed parent acceptance, including indexed,
nested and polymorphic paths. Default selection samples compatible records
without scanning all stored parents. A caller selector and per-parent/path
usage ledger support custom bias; supplied ID-only anchors do not imply known
historical child counts. Known usage can be seeded explicitly.

An unbound preview can be explicitly cancelled. A bound plan is detached,
write-once and checked against proposal/model/target before execution. Accept
requires the actual operation ID and exact requested returning-ID sequence;
unknown/not-observed outcomes retain their original pending intent. Only a
confirmed no-commit result for the exact submission may release bound work.
Do not use a failed status query or a separate in-flight attempt as proof that
an earlier uncertain submission failed.

Optional schema values use bounded per-contract buffers, separate from database
batch size; a 64-command proposal works across two 32-value refills. Partial base
values are checked after reference/rule overlays. Python-only strategies bypass
Node. Node uses file/CPU/time/old-heap limits and disables core dumps; this is
not a whole-process RSS or arbitrary-code sandbox. Unknown assertions and
unsupported native formats fail clearly rather than being silently weakened.

## Continuation

G9.1 core and optional-provider work had disjoint Luna owners, with independent
read-only review. Real G9.2/G9.3 trajectories have run, but their final source
snapshot, evidence and handoff remain to be accepted separately.
Keep model/receipt/work limits and matching G8 evidence. G9.4 documents explicit
composition and affected extracted tooling checks; no G6, TiKV, frontend, live
provider or million-record engine expansion is selected.
