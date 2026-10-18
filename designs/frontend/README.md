# MetaSol accounting workspace

MetaSol now targets the current subsidiary accounting contract from ReBase
`ebe999d`. The separate frontend repository replaces the October 8 forms and
scan-based readers with generated public inputs, native reference/index reads
and contextual record creation.

The application is a harness for connected calculation facts. Start with a
subsidiary, inspect its native positions, follow a reference, or create the
next fact. Missing prerequisites can be authored while the original draft stays
mounted. The database owns authorization, constraints and calculations.

Read:

1. [Design and acceptance plan](redesign-2026-10-18.md).
2. [Execution decisions](execution-plan.md) and [architecture](architecture.md).
3. [Screen contracts](screen-contracts.md).
4. [Developer guide](developer-guide.md).
5. [Verification and limits](verification.md).
6. [Deferred extensions](deferred-work.md) and [continuation](continuation-prompts.md).
7. [MetaSol README](../../MetaSol/README.md) for startup and configuration.

[Accounting meaning](../all-in-accounting/blueprint.md),
[current backend APIs](../all-in-accounting/developer-guide.md), and
[public tree reads](../rebase-system/ordered-tree-contract.md) remain authoritative.
MetaSol is an ignored, independent repository inside ReBase; inspect and commit
both repositories separately. October 2/8 screenshots and evidence describe
historical implementations.
