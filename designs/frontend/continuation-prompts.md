# Instructions for future changes

The tenant backend migration below takes precedence. Other prompts apply after
that compatibility packet; historical frontend tests do not establish it.
Start with the [backend execution handoff](../rebase-system/tenant-tree-handoff.md)
and its [2026-10-05 verification](../rebase-system/evidence/2026-10-05-tenant-tree-verification.json).
Backend acceptance and the lead review precede this separate frontend migration.

## Tenant backend migration — next required packet

```text
Continue in ReBase and the separate ignored MetaSol repository. Inspect both
Git trees. The backend tenant/tree redesign is newer than the existing browser
implementation; start with designs/rebase-system/tenant-tree-redesign.md,
ordered-tree-contract.md, tenant-authentication.md, single-design-runtime.md, current auth source and
designs/all-in-accounting/claims/invoices.surql. Read the 2026-10-05 backend
evidence and compare its source hashes to the checkout before reusing results.

Keep fixed namespace/database in public design configuration. Make tenant an
explicit signin/session choice within that design. Scope routes, credentials,
Query keys and late-response epoch guards by canonical tenant plus endpoint,
design and access method. Do not reuse a token/cache across tenant changes.
Pass tenant for password, code, OAuth and passkey signin. Use the new public
challenge/passkey routes, retain exact native IDs/Decimal and one-use exchange
semantics. Identity rows use owned_by. Remove visibility UI and old root-group
or descendant-array assumptions; current native permissions decide authority.

Use explicit tenant filters to narrow normal native table queries. For a sort
path declared and published by the design, use bounded tree seek/page rather
than an unbounded chain or one HTTP request per link. Preserve cursor key types
and reset pages on incompatible root revisions. Never read private managed
slots/tables to construct a financial ledger in the browser.

Record-scoped materialized views can return multiple visible groups for one
business key. Respect their owner/reader policy and generated computed-field
permissions; tenant-published aggregates are an explicit backend contract.
Carry the SurrealDB 3.3.0 ID-order scan limitation from ordered-tree-contract.md:
affected native source queries use WITH NOINDEX ORDER BY id until a verified
replacement is available. Compare complete results; do not hide duplicate rows
with client deduplication. The primary scan has no indexed-performance promise.

Update invoice forms/projections to distinguish delivery tax components from
explicit invoice-wide variants. Show delivery, invoice, tax account, currency
and rule provenance. A physical delivery may have multiple priced portions;
rounding and tax recognition belong to each line at the issue timestamp. Make
empty, line-only, invoice-only and combined input modes explicit: selecting
both posts both. Keep the backend responsible for calculations and final
transaction validation; don't reimplement tax policy in client code.

Finish one simple tenant-aware login/accounting slice first, using ordinary
Solid modules and direct SDK/library APIs. Prove two tenants in the SAME database,
including identical email addresses, failed cross-tenant access, role revocation,
tenant switching while a response is pending, and native write rollback.
Then repair the existing browser suite and update source contracts/evidence.
Do not deploy or call real providers. No generic registry/DSL/form framework.
```

## Start from the actual checkout

```text
Work in /home/divyeshvora/javascript/node/projects/ReBase and its separate
MetaSol repository. Read designs/frontend/README.md, architecture.md,
screen-contracts.md and verification.md. Inspect Git status in both roots.
Do not restore the removed generic console, resource registry, query engine,
compatibility routes or old scripts. Preserve unrelated work.

Implement the requested change yourself. Use ordinary Solid/JavaScript and
the installed TanStack and SurrealDB libraries directly. Read the relevant
route, native data function and backend source contract before editing.
Write down the successful behavior, rejected behavior and smallest check.
Keep native record keys, decimal amounts, epoch fencing and exact-row writes.

Change the smallest complete user-visible workflow. Run the focused native
and browser checks that establish its behavior. Update the corresponding
contract and evidence, distinguishing verified behavior from future work.
Routine fixes and removal of superseded frontend code are authorized.
Do not deploy, call real providers or send messages as part of local testing.
```

## Implement a new screen/action

```text
Implement packet [ID] from designs/frontend/deferred-work.md.
Read its named source contract and the current similar route/data module.
Confirm prerequisites from the checkout; historical evidence alone is not
acceptance. List the public fields, permissions, dimensions and time meaning.

Create an ordinary route component and explicit native SDK functions. Use
the existing Records, RecordPicker, feedback and session helpers where they
fit. Add a shared component only for actual repeated behavior. Do not build
a registry, form generator, query DSL, universal context or generic editor.

Keep a stable create ID across retries, snapshot Solid stores, bind values,
and check every transactional result. Use updated_at on changes/deletes.
Write one native success/rollback case and the actual browser interaction.
Inspect mobile layout when controls/forms change. Explain any genuine
remaining policy decision without inventing a browser-side accounting rule.
```

## Review a change

```text
Review the requested diff against the working baseline, not against the
obsolete committed generic console. Identify concrete defects with paths
for reproducing them. Check permission affordances versus server authorization,
record-key types, exact decimals, timestamp preservation, stable ordering,
pagination bounds and the population represented by every total.

For asynchronous code, hold an actual response and change the term, account
or workspace. Verify the late response cannot replace current data, lose
form focus, reopen a dialog or report a different account's save as success.
For writes, test a useful rejected case and inspect the source/aggregate
after rollback. A build alone is not financial behavior verification.

Keep findings scoped. Do not require unrelated provider/capacity suites or
propose a framework rewrite to fix a normal route/component problem.
```

## Verification and completion record

Record the changed behavior and exact source revision/fingerprint, the commands
actually run, their outcomes, and any material limitations. Keep screenshots
from disposable fixtures. Link current documentation to actual files. A plan,
mock screen or passed build is not a native workflow test. A native fixture is
not a production migration, live-provider test or physical-capacity claim.

The completion response should lead with the result, give the relevant test
counts and link the implementation/docs. Do not claim deferred tax, filing,
valuation, CRM or HRM work is implemented because a scaffold or plan exists.
