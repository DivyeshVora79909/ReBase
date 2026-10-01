# ReBase system redesign

This index routes design history; the [core handoff](./core-handoff.md) owns
K1–K5 implementation and restart requirements, while the [accounting handoff](../all-in-accounting/implementation-handoff.md)
owns H1–H8 packet status, evidence, and domain limits. H4b5c residual policy
and H8 physical cost measurement remain open there. Start core work with the
[core handoff](./core-handoff.md), then its packet-specific
source list and [configuration reference](./core-configuration.md).
The [fresh audit](./core-audit.md) and linked evidence record current checks,
the original queue admission failure, and remaining reliability limits. The
[credential contract](./credential-ownership-contract.md) records K4a's matrix;
the core handoff links K4b/K5 execution evidence. CRM/HRM remain future scope.

Astra's original marker is `9581208`; the audited checkout is `a6626c0` plus
the recorded dirty tree. The detailed [plan](./plan.md) and
[verification chronology](./verification.md) preserve earlier design and
execution history; their old next-step wording does not override this handoff.

ReBase should compose **native typed records, ordered memberships, associative
summaries, explicit calculation dependencies, and durable external operations**.
Keep the intrusive AVL mechanics. Make ordering/ownership explicit, simplify
the compiler and authorization surface, and give external work a clear
post-commit recovery boundary.

## Document routing

Read the core handoff first. Open the longer design documents only for the
active packet; reading every document on each model switch wastes context.

| Document | Purpose |
|---|---|
| [Core handoff](./core-handoff.md) | Current core scope, K1–K5 requirements, restart instruction. |
| [Accounting handoff](../all-in-accounting/implementation-handoff.md) | Revised economic identities, multi-effect sources, net limits, and H0–H8 domain packets. |
| [Configuration reference](./core-configuration.md) | Existing settings/defaults, internal constants, traps, focused checks. |
| [Credential ownership contract](./credential-ownership-contract.md) | K4a actor/action matrix and source gaps; K4b acceptance. |
| [Core audit](./core-audit.md) | Fresh evidence, reproduced defects, retained decisions, and remaining limits. |
| [Design review](./review.md) | Complete request map, conflicting suggestions resolved, and current-code findings. |
| [Foundation](./foundation.md) | Record/tree composition, key and summary contracts, write settlement, compiler passes, audit, readers, and JS tools. |
| [Operations](./operations.md) | Native Node, BYOC, one-shot tasks, one bounded BullMQ queue, typed handlers, durable webhooks, and failure recovery. |
| [Implementation plan](./plan.md) | Dependency-ordered work packets, exact exit conditions, and removal/cutover sequence. |
| [Verification and research](./verification.md) | Current baseline checks, small function/queue measurements, algorithm comparison, and future verification matrix. |
| [Domain blueprint](./blueprint.md) | Shared invariants and repeatable module/integration recipe. |
| [Application contracts](./applications.md) | Accounting/billing/logistics/manufacturing, independent CRM/HRM, work, reporting, and explicit bridges. |
| [Tree catalog](./tree-catalog.md) | Current root inventory and justified proposed family budgets. |
| [Historical ordinal checkpoint](./ordinal-feasibility.md) | Original integer feasibility experiment, superseded by the compiled C1 proof. |

## Decisions

- A table fixes record shape; a tree fixes an ordered projection. Membership
  identity is `(record, slot)`, independently of mutable ordering values.
- Support multiple families and multiple positions per source/owner through
  explicit typed contracts. C2a-d now verify multi-position maintenance,
  complete-time capacity summaries, private required outputs, multi-root
  diamonds, downstream rekey, and feedback rejection; generalized keys still
  need their own implementation proofs.
- Only calculation dependencies form a DAG. AVL topology, ordinary references,
  and reader sources have different meanings and rules.
- Use a small fixed compiler pipeline over one resolved model. Keep native
  SurrealQL and static handler composition; remove redundant annotation dialects.
- Audit is field-selected. Readers inherit only explicitly marked direct
  parents' owners. Framework principal names are fixed; privacy remains native.
- Use Node HTTP and BYOC provider configuration. Grants, committed inline
  actions, and queued actions have explicit execution boundaries.
- One scheduled task means one execution time. Redis holds replaceable hints;
  accepted tasks and verified webhook receipts are durable in SurrealDB.
- Keep application modules independent over shared identities. Cross-module
  writes use typed compositions with explicit required effects and idempotency.
- Make a coherent breaking cutover after replacement checks pass. Do not keep
  duplicate runtime/configuration/annotation paths for compatibility.

## Earlier implementation evidence

The paragraphs below retain the earlier implementation history. Use the fresh
audit above for current independent results and remaining reliability gates.

Explicit `datetime`/`int` keys and finite owner targets are implemented. The
compiled stage fixture passed 113 mutation checkpoints, 1,308 ordered reads,
101 rejection snapshots and competing writes for one remaining rank slot.
It covers independent time/rank histories, versioned scales, exact table/slot
pairing, native field privacy, rollback and populated schema reapplication.
The C2a fixture passed 221 mutation checkpoints, 1,084 ordered reads and 12
rejection snapshots; it covers multiple datetime/int positions, stable
coincident-slot identity, linked-slot deletion topologies, randomized source
reconstruction, last-unit contention and rollback. Ordinal, quick temporal,
typed-root, CRM/HRM, and accounting regressions passed against the shared tree
changes. C2b added complete-primary-key boundary extrema beside strict record
prefixes. Its compiled interval probe and 61,386 exhaustive binary folds passed;
the typed, ordinal, temporal, accounting, and CRM/HRM regressions passed again
with the expanded summary contract. C2c now reconciles required source-owned
outputs under `PERMISSIONS NONE`, refreshes each child before reconciling the
next, and publishes/validates once at the outer source boundary. Its compiled
probe passed paired-output settlement, final-guard rollback, schema reapplication,
stable role edits, obsolete-role removal, source deletion with multiple AVL
slots, and record-user privacy/CRUD checks. The managed-source marker stores the
canonical source ID as a string to allow cleanup after source deletion. C2d's
compiled fixture updates two input roots in one operation, refreshes one basis,
updates both sides of a diamond, and rekeys a downstream future output. Its
final floor is set so the first input change alone would fail; the complete
change passes. Feedback into an input root is rejected, failure restores the
entire graph including audit, and deletion clears the chain. Typed, temporal,
accounting, and CRM/HRM regressions passed across C2 changes. The 2026-09-28
source review corrects an earlier overstatement: distinct root and node fields
on one record are permitted by the contract; a direct own-root seed lifecycle
still needs its own fixture. C4's reader-cycle rejection is a separate rule.
Small local
experiments measured function-call overhead and verified BullMQ priority, delay,
duplicate-ID, and removal semantics. These are bounded checks, not a new
runtime certification or physical-storage benchmark.

C3 now separates the public compile API into resolve/validate, emit, and
artifact-write calls, with explicit framework/project profiles and source
locations. Local derived DAGs resolve once; private numbered helper fields
initialize native CREATE values, while private topological LET evaluation
handles refreshes. Record-user CREATE, reactive updates, native assertion/type/
reference rollback, reapplication, missing optional values, and a declared
opaque dependency all passed with natural and reordered field declarations.
Nested audit projection logged only `profile.email`, kept absent email values
and sibling secrets out of the projection, and kept generated helper fields
out of logs.
`probe:compiler` and `probe:derived-order` passed; full temporal and typed-tree
regressions, accounting, and CRM/HRM reapplication also passed after the
ACL-preserving initialization change.

C4 fixes principals to `rebase_user`/`rebase_group`, removes principal/internal
marker discovery, and uses native table/field privacy. Reader access comes only
from explicitly marked direct reference fields; a private computed index
contains each direct parent's owner without copying ancestors. The security
probe passed owner, direct-parent, group-member, outsider, unmarked-reference,
reparent/revocation, forged-metadata, and tree/grandparent boundary checks under
both select policies. Direct and multi-row cycles reject before reader
cascades. Field-only value/change audit writes one synchronous `audit_mutation`
event path: value projections exclude unselected/private leaves, technical
framework writes stay outside business audit, rejected source writes leave no
committed event, and create/delete lifecycle events remain recorded when an
optional selected field is absent. Authentication/challenge, runtime, tree,
accounting, and CRM/HRM regressions pass; see the exact
[verification matrix](./verification.md).

The existing all-in-one source declares **22 root families**. Runtime tree
count depends on owner records; maintenance cost depends on active memberships
and reactive visits. Do not equate these counts.

Current H/H domain gates and their limits are maintained in the [accounting
handoff](../all-in-accounting/implementation-handoff.md); core gates and limits
are in the [core handoff](./core-handoff.md) and [audit](./core-audit.md).
The [accounting blueprint](../all-in-accounting/blueprint.md) incorporates the
personal-account clarification and multi-effect source model. Old A1/A2
schemas remain evidence for the earlier book model; they are not current
implementation instructions.
