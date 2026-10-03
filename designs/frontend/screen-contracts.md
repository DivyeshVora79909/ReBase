# Delivered screen contracts

These are the frontend's explicit workflows. A table existing in the backend
does not imply that every operation on it has a browser form. All lists contain
accessible records; empty results can mean no records or insufficient access.
Amounts in different currencies/resources are never added into one total.

## Screens and source records

| Screen | Reads | Writes available in this application |
| --- | --- | --- |
| Overview | Cash totals and claim positions grouped by currency; recent direct cash and treasury accounts | Links to the source workflows |
| Treasury | Treasury accounts with currency, entity, recorded balance and minimum; account detail and exclusive historical cutoff | Create an account |
| Cash movements | `cash_in`, `cash_out`, `cash_transfer`, filtered by kind/entity/account | Create each family; edit amount/date; delete with concurrency/dependency checks |
| Receivables & payables | Claim-account receivable/payable/net positions; standalone `receivable` or `payable` remaining amount | Create claim accounts, either claim family and existing-cash allocations |
| Invoices | Sales/purchase headers, issue inputs and recorded outstanding | Atomically create header + untaxed issue with up to 50 stock-source lines; allocate existing cash |
| Inventory | Stock accounts by location/resource and their recorded quantity/availability; direct stock movements | Create stock accounts; receive, issue or transfer stock |
| Currency exchange | Entered-amount `cash_exchange` and `cash_exchange_reversal` | Create ordered currency pairs, execute entered amounts, reverse in full |
| Production | Timed production runs or immediate assembly batches | Create immutable recipe versions; create runs/batches; edit count/date/state through the source |
| Directory | Organizations, treasuries, currencies, locations, units, items, services and work types | Explicit create forms for these eight families |
| Users | Readable principal list/detail | Read only |
| Settings | Current preferences/session | Appearance, accent, density, display zone and token-storage choice |

The corresponding native functions are in
[`treasury.js`](../../MetaSol/src/data/treasury.js),
[`claims.js`](../../MetaSol/src/data/claims.js),
[`invoices.js`](../../MetaSol/src/data/invoices.js),
[`inventory.js`](../../MetaSol/src/data/inventory.js),
[`exchange.js`](../../MetaSol/src/data/exchange.js),
[`production.js`](../../MetaSol/src/data/production.js),
[`directory.js`](../../MetaSol/src/data/directory.js), and
[`overview.js`](../../MetaSol/src/data/overview.js).

## Read contracts and time semantics

- Main lists request 26 rows, display 25, and use the extra row only to enable
  Next. Sorts have an ID tie-breaker. Page numbers and search lengths are bounded.
  Permission filtering remains server-side; there is no misleading total count.
- Lookups request 13 rows, display 12 and hydrate at most 50 selections. A finite
  table allowlist bounds polymorphic references. Every option shows its table
  and ID as well as useful labels/dimensions.
- Tree summary totals include future-dated effects. Labels say **recorded**.
  Stock availability is not a promise of availability today. An account cutoff
  calls `fn::tree::read(id, 'z_history', 'before', [cutoff])`; it excludes all
  entries at the exact cutoff.
- Net claims is always `receivable - payable`. It has no input control or
  independently writable balance. Optional floor/ceiling controls belong to a
  claim account; the backend's derived net history enforces them.
- Overview limits each grouped query to ten currency groups plus a sentinel and
  says when truncated. It hydrates the union of those currencies. Recent cash
  and account panels show smaller labeled subsets of the bounded first pages.
- Boards group only the loaded page, with ten groups plus Other. Treasury groups
  by currency, inventory by location/movement and production by status or a
  named device-local start-date range. They have no drag-to-write behavior.
- CSV exports the current page with exact decimal text and spreadsheet-formula
  escaping. They are not a full ledger or a server export job.

List, detail and lookup reads use explicit projections and database timeouts.
The scalar treasury cutoff uses `RETURN fn::tree::read(...)` without an explicit
query timeout. No browser `INFO STRUCTURE`, generic `SELECT *`, private
operation bundle or root login is needed by an application route.

## Write contracts

Every create explicitly chooses `owned_by`. Master/account forms also choose
their economic entity and dimensions; movements derive dimensions from their
references on the server. The form's initial owner is the session principal.
Clearing the picker clears the value; the UI must never display an implicit
fallback that differs from the submitted payload.

Cash and production edits submit the last-read `updated_at`. A zero-row update
or delete is a conflict, absence or loss of access, never success. Refresh and
reopen the current record before editing again. Mutations invalidate the active
session's queries only after confirmed commit. Financial totals are not updated
optimistically.

Invoices bind a stable header ID and issue ID in one transaction. If a line
fails its source-capacity checks, neither header nor issue remains. A selected
stock source creates one line; removing/reselecting sources preserves the
values of retained lines. Unit prices are exact decimals; currency rounding is
server-owned. The current form creates invoices without tax components.

Cash allocation consumes an already recorded movement; it does not make a new
payment. The backend rejects incompatible party/entity/currency and exhausted
capacity. Invoice allocation supports the exact issue timestamp through the
backend's complete-timestamp outstanding floor. The client keeps the entered
date without adding an offset. Allocation before its source or beyond the
outstanding balance is rejected. Standalone claims retain their own
complete-timestamp capacity rules.

An exchange reversal uses the original executed amounts and reverses both
treasury legs. There is no quote refresh. The database permits one full reversal.
Production end time comes from start plus immutable recipe duration. The app
does not infer completion from the clock. Recipe inputs/outputs use the current
two-input/two-output count-unit contract; all managed effects remain private.

The browser never directly edits invoice lines/tax outputs, production roles,
assembly output records, tree nodes or derived balance fields. Their lifecycle
belongs to the source transaction.

## Interaction and failure states

Record selection is lazy and debounced. Arrow keys move the active choice,
Enter selects and Escape closes; multi-select is duplicate-free and bounded to
50. Pending data reads are guarded before accessing Solid Query's suspending
data getter, so a lookup cannot detach the form or lose input focus.

Native dialogs provide focus containment and restoration, dirty drafts block
accidental navigation, and long forms scroll within the viewport. On mobile,
the closed sidebar is hidden from assistive navigation and cannot take focus;
the open navigation traps Tab and closes with Escape. Reduced motion and clear
focus outlines are supported. Tables scroll horizontally when their content
requires it; forms use one column on small screens.

Unknown saves retain their stable reference and provide **Check current record**
with a nonsecret current-value projection. Failed requests are not automatically
retried. A found row does not prove that an edited draft matches it; compare the
values. An absent/inaccessible row does not prove rollback. After an account or
workspace switch, late results cannot reopen a dialog or mark a new account's
form successful.

## Intentional limits

This is an operational accounting frontend, not a statutory filing system or
a complete historical ledger explorer. Tax workflows, returns/refunds,
quote-derived FX, richer account maintenance, credential administration and
authentication challenges have explicit packets in
[deferred-work.md](deferred-work.md). Existing backend evidence for those
features is distinct from frontend acceptance evidence.
