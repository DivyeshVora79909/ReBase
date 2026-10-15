# Packet A: independent accounting dependencies and exact tree values

Status: root-thread and source-fence oracle defects are fixed in this packet's
commit. The accounting inventory and exact aggregate work below remain OPEN.
Do not label accounting acceptance complete until these checks are implemented.

## Bounded oracle corrections already made

`dev-tools/temporal-tree/read-oracle.js` entered the head root through `visit`,
while neighbour checks lived in `visitOptional`. Descendants were checked; the
root was skipped. The root now enters through the same checking path. Tests
corrupt the root predecessor and successor in both point and interval trees.

The source-fence ID regex rejected nested array IDs. The checker now constructs
expected fence identities from known live source IDs and matches them exactly.
A valid nested source ID and a forged enclosing ID are tested. There is no new
record-ID parser and no restriction to simple string IDs.

Fresh focused tests and the 38-test developer suite pass. These changes improve
the checker used by accounting; they do not supply the missing accounting read
inventory or fix the runtime's whole-group rebuild.

## Why the remaining work is necessary

`dev-tools/accounting/source-oracle.js` calls `verifyReads(..., { rootSpecs })`.
Without `expectedReads`, the checker can validate surviving registrations but
cannot discover that all registrations disappeared. Removing all reads, groups
and frames from an otherwise valid fixture passes in this mode.

The accounting oracle independently replays source arithmetic with the `D`
rational type. Add expected logical reads to that replay. Do not generate the
expected set from `rebase_read`, group membership, generated capture code, or
observed query counts. The set must exist even when those tables are empty.
Do not copy expected branch decisions from stored derived FX values either.

Descriptions contain `reader`, `phase`, `source_root`, `source_slot`, `kind`,
`arguments`, `path`, `fallback`. Identical calls from one reader/phase coalesce;
the same call in refresh and validate is two different dependencies. Do not use
AVL links, selected predecessor IDs, generations, or hashes in the expected
description. Identity remains stable across rotations.

## A1: add a small collector to the existing independent evaluator

1. Add a collector owned by one `verify` invocation. Pass the current reader
   explicitly to `rate` and `trade`; `post` already has it. Avoid mutable global
   current-reader state, which is easy to lose in nested helpers.
2. Add descriptions at independent model operations. Retain rational formulas
   and sorted source arrays. Expose the expected set through a testable helper
   without accidentally changing the public verification contract.
3. Preserve serialization types. HTTP decimal fallbacks are strings such as
   `'0'`, NONE is an absent `value`, and dates require nanosecond precision.
   See `observed-probe.js:expectedReads` for the descriptor convention, not the
   accounting rules. Never use JavaScript Date alone to add one nanosecond.
4. Pass `{ rootSpecs, expectedReads }` to `verifyReads`. An empty expected set is
   legitimate for a fixture with no executed reads; omitting the option is not.

### FX calls, all in refresh

`core/exchange-rates.surql:fn::accounting::rate_at` has these branches:

| Condition | Expected logical reads |
| --- | --- |
| `from === to` | None; the rate is 1 and a pair must be absent. |
| Different resources, any valid lookup | Record read of pair `effective_at` with NONE fallback; latest read of pair `z_rates`, arguments `[[at + 1ns]]`, projection `measures.rate.sum`, NONE fallback. |
| No dated quote at or before `at` | Additionally record-read pair `initial_rate`, NONE fallback. |

Determine quote/fallback selection from source exchange-rate facts and typed
instants. Insertion removes the fallback subscription; deletion restores it.
Pair and reader date moves must replace old calls.

Record the enclosing posting's reader ID, not the account or exchange pair:

- `core/projections.surql:post`: each leg's valuation conversion at its event
  time; organization conversion only when the account has an organization.
- `postings/issues.surql:trade`: reporting and organization trade values. These
  are additional calls to stock/resource valuations. Duplicate descriptions
  coalesce; different pairs, dates and projections remain distinct.
- Original/adjusted taxes, settlement/payment adjustments, withholding, claims,
  tax cash, offsets, and resource exchange derived FX fields.
- `postings/zz-fees.surql`: expense FX when fee account/currency exist; credit FX
  only when creditable and its account/currency exist. Fee member postings have
  their own valuation reads. Production fees include start and end dates.

An entered monetary override does not necessarily skip the separately derived
`exchange_rate` field. That field evaluates if its own expression does. Zero
output also does not imply a skipped call. Follow the expression's branch.

### Prefix calls, all in refresh

Each `fn::accounting::prefix(root, slot, measure, at)` records `kind:'before'`,
`arguments:[at]`, `path:'measures.' + measure + '.sum'`, fallback decimal zero.

| Reader | Root/slot/measure | Boundary |
| --- | --- | --- |
| `issue_adjustment` | `source/z_state/quantity` and `/price` | `effective_at` |
| `issue_tax` | `source/z_state/base` | `effective_at + 1ns` |
| `issue_net_tax` | `source/z_net/amount` | `effective_at` |
| `issue_adjustment_tax` | `source_tax/z_adjustments/basis` | `effective_at` |
| `issue_adjustment_net_tax`, `tax_adjustment_net_tax` | `source_tax/z_adjustments/basis` and `adjustment/z_taxes/amount` | `effective_at` |

The oracle obtains these amounts from `states`, `net`, and `taxAdjustments`
arrays. Annotate those operations; keep the independent source sums.

### Validation calls

After expected posting entries are assembled, derive these calls from their
contents and source inputs, with phase `validate`:

- A nonempty sales/purchase invoice reads its own `z_history` before
  `[invoice_date + 1ns]`, projection `measures.balance.sum`, zero fallback.
  If the last expected contribution is at or after that boundary, it also reads
  range `[[boundary], [last_expected_time + 1ns]]`, projection
  `measures.balance.instant_min`, zero fallback. Empty invoices have no calls.
- `production_input` reads stock `z_history` before `[starts_at]`, projection
  `measures.available.sum`, and stock `z_gross` over
  `[[starts_at], [starts_at + 1ns]]`, projection `measures.quantity.sum`.
  Both have zero fallback.

Correction to an initial delegated inventory suggestion: ordinary
`$row.z_history.summary` access in account/report/invoice validators and
`$row.z_rates.summary` in pair validation do **not** call a capture intrinsic.
Do not invent logical summary registrations for them. The coordinator validates
owners after publishing their roots; test that scheduling separately. Direct
typed-reference dependencies also remain a separate mechanism.

### A1 acceptance and commit

Add valid accounting snapshots and corruption controls removing all read/group/
frame rows, one reader's complete calls and frame, one complete group, one
conditional fallback call, and one validation-only call. Unchanged amounts must
not let these mutations pass. Include legitimate zero-read controls.

Run focused tests, then `npm run probe:accounting-integrity-fx`. For the first
mismatch, compare authored call semantics and independent inputs; do not weaken
the inventory to match surviving runtime rows. Commit the inventory, tests and
compact source-hashed evidence together. Keep domain math unchanged.

## A2: exact tree summaries and extrema

`D` verifies derived amounts exactly, but `add()` converts expected tree measures
using `.number()`, and coalescing converts again. The generic tree oracle uses
numeric tolerance. This can miss small monetary or extrema errors.

Keep exact values through leaf contributions, coincident-slot coalescing,
subtree sums, prefix extrema, complete-timestamp extrema, and range results.
A small exact-arithmetic adapter shared by test oracles is reasonable; do not
introduce a second production aggregation algorithm or a testing DSL. Compare
decimal values as rational numbers, not text formatting or JavaScript Number.
Preserve absent measures, zero contributions, and empty-tree identities.

Expected summaries must come from an independent sorted linear fold. Group all
ties at a business timestamp before checking complete-time extrema; per-key
prefix extrema are a different quantity. Cover equal timestamps, mixed signs,
missing measures, 18-digit fractional precision, cancellation and round-to-even
boundaries. Corrupt one decimal by the smallest tested unit in a leaf, internal
node and root; all must fail. Key order stays typed and nanosecond precise.

Commit A2 separately after small tests pass, then rerun the affected native
fixture. Full consolidated acceptance belongs to final integration after runtime
changes settle, not after every documentation edit.

## Domain invariants

Preserve sparse subsidiary/organization/resource dimensions. Native stock quantity
is independent of pricing/reporting currencies. Reporting values use the event's
dated rate; current-market revaluation is separate. Receivable/payable remain
nonnegative opposing entries. Combined adjustments use `(q+dq)(p+dp)-qp` with the
authored rounding boundaries. Tax adjustments respect prior dated basis and
tax-on-tax order. Invoice records validate participating postings without reposting
their children.

This review found no evidence requiring different equations. Breaking-change
permission permits simpler internals; do not change expected arithmetic to
accommodate an engine defect.

