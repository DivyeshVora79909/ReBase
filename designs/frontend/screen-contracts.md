# Accounting screen contracts

Paths follow `/w/:profile/:tenant/`. All 48 public input schemas are available
through Overview's creation menu. Pages offer narrower entry points; any
accessible record opens at `records/:id`. Create, edit and delete affordances
use native permissions. Server guards decide whether a write is accepted.

## Published inputs

Each input type is counted once below; a contextual action can appear on several pages.

| Surface | Published record types |
| --- | --- |
| Directory (9) | `subsidiary`, `organization`, `currency`, `measure_unit`, `operating_unit`, `item`, `service`, `exchange_pair`, `exchange_rate` |
| Accounts and entries (10) | `treasury`, `stock_account`, `organization_currency_account`, `organization_resource_account`, `direct_tax_account`, `indirect_tax_account`, `misc_currency_account`, `misc_stock_account`, `account_entry`, `stock_entry` |
| Invoices (5) | `sales_invoice`, `purchase_invoice`, `sales_issue`, `purchase_issue`, `invoice_settlement` |
| Corrections (9) | `sales_adjustment_note`, `purchase_adjustment_note`, `issue_adjustment`, `tax_adjustment`, `net_tax_adjustment`, `issue_adjustment_tax`, `issue_adjustment_net_tax`, `tax_adjustment_net_tax`, `payment_adjustment` |
| Claims (2) | `account_claim`, `claim_settlement` |
| Taxes (7) | `issue_tax`, `issue_net_tax`, `payment_withholding`, `tax_settlement`, `tax_deposit`, `tax_refund`, `tax_offset` |
| Transfers (1) | `resource_exchange` |
| Production (5) | `production`, `production_input`, `production_output`, `production_cost`, `production_capacity` |

Overview shows the selected subsidiary's reporting summary and indexed activity.
Accounts use that subsidiary's `z_accounts` root and show real, receivable,
payable and available positions in each account's native unit. Invoices show
native total, paid and outstanding balance. Production's collection lists runs;
inputs and outputs are reached from the run because they have no direct
subsidiary field. People/groups are a read-only view of accessible principals.

## Reads, pagination and units

A page visits at most 50 native tree members; pickers visit at most 30. Filtering
examines those candidates and retains continuation through empty result pages.
Previous reuses the earlier native cursor. Direction and selection changes
restart the cursor history. A changed revision on a subsequent database read
offers Start again; cached pages may remain available until refresh.

Composite readers require a leading typed prefix. Prefix walks are forward and
stop at the partition boundary. All current public accounting roots have one
business key component; private composite identity roots are not exposed.
Native key types, duplicate tie breakers and member slots survive pagination.

Without a declared ordered root, collections use bounded inverse-reference
lookups and ask for narrower search when necessary. They do not offer offset
pagination or invented sorts. Copied IDs are parsed natively and checked against
the same relation/index scope as name searches.

Whole-history summaries include scheduled facts. Analytics provides typed
`[start, end)` range reads. Subsidiary currency, organization valuation currency
and an account's native resource are distinct perspectives; the frontend never
adds unlike units or recalculates accounting measures.

## Contextual workflows

- Open an organization's currency account to create an invoice or claim.
  Open an invoice to add a line, payment or adjustment note. Lines expose taxes
  and corrections; payments expose signed corrections and withholding.
- A payment enters cash-account units. Its dated exchange pair converts to the
  invoice currency. A transfer enters outgoing units and converts to incoming
  units. Pair directions are independent; no inverse rate is inferred.
- A conversion field can find an existing pair or open the ordinary pair form
  with its direction and effective date filled in. Saving or cancelling the
  child restores the parent draft and focus. The parent is submitted explicitly.
- Production owns its subsidiary and interval. Material input, finished output,
  cost and capacity records are independently authored from the run.
- Optional charges, limits, availability and ownership use disclosures. Generated
  native types and JSON Schema determine fields and validation; labels and
  dependent selection behavior remain ordinary frontend modules.

## Interaction and write boundaries

Editors retain their original version and stable create ID. Readonly dimensions
remain visible. Optional values clear to native NONE; zero and false remain
explicit. Exact Decimal and DateTime values survive unrelated edits.

Native rejection or an optimistic conflict keeps the draft and actionable
feedback. An unconfirmed save retains the same reference for inspection, with no
automatic retry. A principal refresh does not close drafts; a route or session
change ends their lifetime. Busy dialogs cannot be dismissed.

Kobalte supplies combobox semantics. Native-dialog focus stays on the input during
pointer selection. Keyboard, touch, clear, loading, empty results and retry are
covered by the maintained browser suite. Links show human names with native
identities available in their titles and the record-reference disclosure.

Settings controls color mode, accent, density, radius, typeface, navigation,
display time zone and credential storage. Runtime theme tokens and ordinary JSX
primitive/field overrides provide application customization. Activity is bounded
session memory. CSV exports only displayed columns and rows.

See [verification](verification.md) for tested scenarios and
[deferred work](deferred-work.md) for the remaining product boundaries.
