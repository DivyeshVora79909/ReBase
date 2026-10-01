# Accounting context map

This file is a reading route, not an alternate status ledger. Current domain
packet state, evidence, profiles, and limits are canonical in the
[implementation handoff](./implementation-handoff.md); architecture is in the
[blueprint](./blueprint.md). CRM and HRM remain future sibling domains.

## Read by task

| Need | Start here | Then consult |
|---|---|---|
| Current accounting invariants and proposed recipes | [Blueprint](./blueprint.md) | [Implementation handoff](./implementation-handoff.md), relevant module files |
| Exchange | [Blueprint §3](./blueprint.md#3-source-records-effects-and-exchange) | [Implementation handoff](./implementation-handoff.md) |
| Logistics and assembly | [Blueprint §8](./blueprint.md#8-logistics-services-work-and-manufacturing) | [Implementation handoff](./implementation-handoff.md) |
| Current packet status and exit evidence | [Implementation handoff](./implementation-handoff.md) | Evidence linked from the active packet |
| Current schema shape | [Core schema](./core/schema.surql) | `claims/*.surql`, `movements/*.surql`; probes in `dev-tools/accounting/` |
| Claims, invoices, allocation lifecycle | [Plan](./plan.md), sections 3, 4, 6 | `claims/standalone.surql`, `claims/adjustments.surql`, `claims/settlements.surql`, `claims/invoices.surql`; system [verification](../rebase-system/verification.md) |
| Temporal tree contract and C2 engine gates | System [plan](../rebase-system/plan.md), C2a–d | System [verification](../rebase-system/verification.md), [temporal contract](../../research/rebase/temporal-trees.md), then accounting acceptance cases |
| Wider application boundaries | System [applications](../rebase-system/applications.md) | Current module decisions remain in this blueprint and handoff |
| Core/runtime work | System [core handoff](../rebase-system/core-handoff.md) | [Core audit](../rebase-system/core-audit.md), [configuration](../rebase-system/core-configuration.md), linked evidence |
| Historical engine/database rationale | [Research index](../../research/README.md) | Read the specific dated research note; it is evidence, not policy by itself |

## Authority and evidence rules

1. The latest user instruction controls scope and corrections, including any
   domain planning reopened after an older core handoff.
2. The current blueprint and implementation handoff govern proposed domain
   decisions. The plan retains historical A1/A2 acceptance criteria and
   evidence. Inspect current source and scoped probe evidence for behavior.
3. The system core handoff governs core stabilization and runtime integration;
   it does not override a later instruction to resume domain planning.
4. A probe proves only its named fixture/profile. Algebra, compilation, and
   native schema validation alone do not prove full integration, migration
   safety, production behavior, or performance.
5. Older plans, audit snapshots, and research preserve history and rationale.
   Keep their useful evidence, but do not promote stale status or superseded
   policy over a newer decision.

## Decisions and open boundaries

- Current domain scope is accounting, logistics, commodity exchange, and basic
  assembly. CRM/HRM remain future work. Proposed recipes without matching
  domain-specific compiled/native evidence remain proposals.
- The current identity/effect model is direct user or organization economic
  identity, separate real/receivable/payable effects, and independent
  calculation sources and validation memberships. Authorization ownership is
  separate; personal accounts do not require an artificial organization/book.
- H2 posts assessed purchase tax immediately as a receivable. H4b3 records
  eligible/usable recognition separately without posting another receivable.
  H4b5c residual source/sign/range/precision/destination/effective-date policy
  must be defined before implementation. See handoff for evidence and limits.
- H8's bounded profile has no writable `end_at`; managed roles compute planned
  start plus immutable duration. It is not a production migration and excludes
  workforce and costing. H8 physical cost measurement remains open.
- A full populated migration from a deployed legacy profile, tax-law rules,
  accounting temporal/window policy, remaining claims/documents, paired
  recipes, domain integrations, and measured operation cost remain open unless
  newer scoped evidence closes a named item.
- Older README/core-handoff text deferred domain work and described an
  organization/book requirement. The later user instruction reopened domain
  planning; the current blueprint and H1 schema use direct economic identity.
  H1's fixture is bounded; populated legacy cutover remains unproved.
- Older fixed slot/edge counts describe specific implementations, not a
  universal recipe or cost target. Compare active memberships and reactive
  visits for equivalent business operations.
- Older "core-only" integration routes are prior implementation boundaries,
  not a ban on requested domain planning. Preserve declarative stages,
  required-effect lifecycle, rollback, and direct lifecycle fixtures when
  proposing integrations. Multiple positions and required outputs are engine
  capabilities; same-row root/node slots still need a direct lifecycle fixture
  before reliance.
- TCS uses sales-invoice tax components at invoice time; this does not imply a
  statutory interpretation. Valuation and financial reports remain outside the
  module's stated scope.

## Lossless compression procedure

1. Inventory each scoped file and repeated claim: path, section/line, date or
   checkpoint, and whether it is policy, proposal, implementation fact, or
   evidence.
2. Give retained decisions/evidence stable IDs. Preserve exact claim, scope,
   profile, date, source, verification command/fixture where available, and
   limitations. Keep probes distinct from integration and performance claims.
3. Record contradictions. Resolve only from newer user direction or stronger
   scoped evidence; otherwise retain both dated claims and mark the issue open.
4. Replace repeated prose with short canonical statements and links. Preserve
   operational constraints: complete-timestamp batching, required dependent
   output lifecycle and atomic rollback, published-basis limits, and measured-
   cost scope.
5. Mark superseded material historical and link to its replacement. Preserve
   unique dated evidence with scope, source, and limits; remove only verified
   duplicates after checking coverage and inbound links.
6. Check relative links from each file, search inbound links to moved/removed
   paths or headings, and review the scoped diff. Do not claim broad compression
   complete until inventory, contradiction ledger, and link checks are complete.

This pass covers only the six documentation files listed in
[`context-compression-map.md`](./context-compression-map.md). Broader research
compression remains a separate packet.
