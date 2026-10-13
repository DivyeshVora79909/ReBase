# Accounting extension plan — October 8

> Historical plan. The active API and acceptance contract are [October 13](redesign-2026-10-13.md).

Baseline: `a8ecfca` commits the completed scalar-reader/custom-index framework
change after checking its 192 source and 56 artifact fingerprints. The earlier
accounting redesign is `88c5ae7`. This packet follows the supplied October 7
discussion, the older attachment's account/document/transaction distinctions,
and the new October 8 request. Current source wins over another agent's guesses.

## Recovered contract

- A record is an authored fact. Deterministic 1:1 effects are fields and additional
  memberships on that fact. Independently authored 1:N facts remain records.
- Real, receivable and payable are independent measures; settlement decreases
  the same claim family. Validators and ledger participants are separate roles.
- Accounts carry explicit units. Stock identity includes currency, item/service
  and operating unit. Same-resource transfers have rate one; FX is explicit.
- Future effective dates, source-local calculations and prior-prefix readers
  already express timed recognition. No new accrual subsystem, automatic
  write-off, statutory workflow or bank-matching subsystem is needed here.
- `resource_exchange` is an actual dated movement. It did not own a
  reusable history of one descriptor pair. A stable pair context is a distinct
  fact; individual movements must not stand in for that context.
- The previous change removed the eight-component ceiling. This request now
  chooses an explicit maximum of 16 key components. Key width and the number of
  tree memberships are different controls.

## Small set of extensions

1. Sales and purchase adjustment-note validators group existing issue, tax and
   payment adjustments. Rule-linked tax adjustments inherit their correction's
   note. Same organization, currency and commercial side are mandatory; positive
   and negative effective lines cannot mix. Neutral capped-tax rows are allowed
   alongside effective lines. Commercial corrections and cash corrections have
   separate totals so a refund does not double the document's commercial value.
   Empty drafts are needed because each source statement settles independently;
   finalization requires at least one nonzero line. Finalized notes remain
   editable only through changes preserving these invariants. This is validation,
   not a statutory document-locking workflow. Existing ungrouped corrections stay
   valid. The draft choice was presented to the user for clarification.
2. Explicit tax cash facts: settlement of a payable, an advance deposit that
   creates credit, and refund of credit. Each moves treasury real and records the
   corresponding tax real movement. A tax offset consumes credit and liability
   without cash, including explicitly selected account/conversion legs. Tax R/P
   capacity must hold across complete timestamps, including after backdating.
3. An independent account claim and its settlement cover non-invoice obligations,
   interest and penalties as explicit amounts/descriptions. Claim capacity is
   dated and source-specific; this does not silently settle invoice balances.
4. One optional bounded charge and one optional tax-on-charge are calculated on
   the payment record. A miscellaneous currency account represents paid charges.
   A creditable tax additionally increases the selected indirect-tax receivable;
   noncreditable tax remains charge cost. No extra 1:1 fee child or statutory
   eligibility inference. Refunds do not automatically refund original fees.
5. A directed exchange-pair context has two currency/item/service descriptors and
   a unique pair index. Existing issues, settlements and resource exchanges can
   explicitly contribute observations. Deltas and observations are distinguished;
   a price correction is not a new executable FX quote. No inferred reverse quote,
   graph arbitrage, manufacturing cost allocation or automatic FX P&L.
6. Selected trade/payment analytics use ordinary source memberships, with
   indexing explicitly separated from reader grants. Monetary roots have one
   currency; quantity roots have one resource. Operating-unit turnover is queried
   as a leading partition within a currency tree. Do not sum mixed currencies or
   unrelated quantities at an operating-unit root.

## Aggregates and queries

Use the existing associative summary: counts, sums, leaf extrema, chronological
endpoints, complete-time balance extrema and uniformity tags. Keep sales and
purchases separate, and keep tax, gross settlement and processing costs separate.
For prices/rates aggregate signed numerator and denominator components; divide
only after querying a coherent range with a positive denominator. Never sum
averages or treat an unweighted average of FX observations as realized P&L.
Returns/corrections alter net components without inventing new gross sales.
Zero denominators return no average. Explicit source enrollment avoids a
Cartesian product of every dimension, time and measure.

## Execution and evidence

Prove each slice on a disposable compiled database before expanding its tests.
Use independent rational arithmetic and source-derived memberships, complete
source/audit rollback snapshots, source/parent edits and deletion, backdating,
two tenants, record-client writes, competing sessions and populated reapplication.
Keep public create schemas, examples and developer instructions with the code.
Run the existing accounting acceptance and the affected compiler/tree/framework
gates. Record exact source fingerprints and distinguish prior results from fresh
acceptance. MetaSol and populated production migration are separate work.

Fee/tax percentages are authored examples, not a built-in legal schedule. The
[PIB charge-tax explanation](https://www.pib.gov.in/PressReleasePage.aspx?PRID=2122747&lang=1&reg=6)
distinguishes tax on processing charges from tax on the payment principal. The
quoted [September MDR announcement](https://www.pib.gov.in/PressReleseDetailm.aspx?PRID=2310586&lang=1&reg=3)
has scope and exemptions; it is not a universal transaction rate.

Status: accepted and complete. Local extension acceptance passed on the recorded
working-tree snapshot; see [extension verification](extension-verification.md)
and its linked evidence. The open draft-policy clarification had no reply, so
draft defaults to true as proposed; finalization rejects empty or zero-only
notes, and every stage rejects mixed signs or dimensions.

The implementation uses nine new record types and five native source files.
Existing `resource_exchange` covers the requested transfers; no separate table
was added for each account-pair permutation. Inline fees share one bounded rule
and effect helper across nine cash record types. Analytics enrollment is explicit.
The source-derived extension proof passed 50 mutation checkpoints and 24 full
rollback snapshots, including populated schema reapplication, operating-unit
reparenting, two currencies and explicit cleanup. The original core suite also
passed 63 checkpoints and 35 rollback snapshots. See [the implementation
contract](extension-contract.md) for exact field names and [verification](extension-verification.md)
for shared-engine gates, oracle details and acceptance limits.
