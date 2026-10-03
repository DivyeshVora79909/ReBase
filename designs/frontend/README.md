# Frontend implementation

Started 2026-10-02 as separate work from the completed developer-tools redesign.
The current request authorizes direct frontend implementation, including breaking
changes and removal of superseded frontend code. This package owns the frontend
plan and evidence; the existing core and accounting handoffs retain their scope.

The user's 2026-10-03 request includes fresh frontend and backend verification.
See [the current review](verification.md#redesign-review--2026-10-03) for the
passed baseline, invoice timestamp correction and acceptance boundary.

## Reading route

1. [Execution plan](execution-plan.md): decisions, implementation sequence and gates.
2. [Architecture](architecture.md): contexts, state, native values and extension boundaries.
3. [Screen contracts](screen-contracts.md): delivered routes, writes and time semantics.
4. [Developer guide](developer-guide.md): page/query/form examples and component APIs.
5. [Deferred work](deferred-work.md): concrete frontend packets and unresolved backend policies.
6. [Continuation prompts](continuation-prompts.md): scoped instructions for future changes.
7. [Verification](verification.md): results, evidence, screenshots and limits.
8. The application lives in the separate [MetaSol checkout](../../MetaSol/README.md).
   ReBase ignores that nested repository. Inspect both Git statuses to review work.

## Starting facts

- ReBase HEAD: `0625f9bf6ac370721d22f855d1e904e99479e1e4`, clean before this work.
- MetaSol HEAD: `cccd1df7c53aba2f43b6c8b1b949452094420fbb`, with the earlier
  uncommitted small Solid starter replacing the old generic console. That working
  starter, rather than the obsolete committed console, is the implementation base.
- Installed: Solid 1.9.14, TanStack Solid Router 1.170.36 / Query 5.101.4,
  SurrealDB SDK 2.0.8, Vite 8.1.5, Tailwind 4.3.3, daisyUI 5.7.0.
- Backend source is split across `designs/all-in-accounting/core`, `movements`,
  and `claims`. The five public JSON Schemas describe create input only.
- Database permissions, exact decimal arithmetic, derived effects and final
  transactional guards remain the authority for accounting behavior.

## Scope

Implement a usable accounting application and a small, composable developer
environment: sessions/workspaces/preferences, explicit routes, typed record
selection, accessible tables/cards/boards, native SDK reads and source writes.
Plan independent CRM/HRM and unresolved accounting/operations work with explicit
prerequisites. A future backend policy is not a reason to invent a browser policy.

The accounting frontend is implemented directly. Final verification is recorded
in the linked verification document. Historical backend tests remain separate
from fresh frontend evidence; the deferred-work map identifies the remaining
tax, returns/refunds, onboarding and policy work explicitly.
