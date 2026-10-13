# MetaSol accounting frontend

The current frontend targets ReBase `cada5e2`: direct accounting records, explicit
tenants, scalar readers, adjustment notes, payment charges and typed analytics.
The separate MetaSol repository contains the implementation at `89799ec`. Earlier October 2/3
frontend evidence describes the removed API and does not validate this version.

The October 13 [subsidiary accounting API](../all-in-accounting/developer-guide.md)
replaces that backend contract. This frontend and the guides below still describe
`cada5e2`; their forms, queries and demo require adaptation before use with the new
schema. The backend redesign does not include frontend implementation changes.

The intended result is a small JavaScript/Solid engineering foundation demonstrated
by accounting. Business pages author their own forms and queries. Shared code owns
session lifetime, native values, confirmed writes, reusable UI and scoped notices.

Start with:

1. [Meaning and execution plan](execution-plan.md): user intent, current authority and scope.
2. [Architecture](architecture.md): ownership and extension boundaries.
3. [Screen contracts](screen-contracts.md): current workflows and record types.
4. [Developer guide](developer-guide.md): add a page using ordinary composition.
5. [Verification](verification.md): fresh checks and their limits.
6. [Deferred work](deferred-work.md): future capabilities and necessary contracts.
7. [Continuation](continuation-prompts.md): how to resume from current source.
8. [MetaSol README](../../MetaSol/README.md): run the disposable demo or configure a backend.

The [backend blueprint](../all-in-accounting/blueprint.md),
[extension contract](../all-in-accounting/extension-contract.md), and
[public tree reader](../rebase-system/ordered-tree-contract.md) remain authoritative.
The frontend does not calculate postings, invent compliance policy or create
implicit business children. Read both Git repositories when reviewing a change.
