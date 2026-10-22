# Bounded invoicing model

Select `--model invoicing` for a store using fractional line pricing, chronological
tax assessments, linked monetary credits, payments and refunds. The same compiled schemas drive
validation, catalogs, fixture plans and the inspector. The model uses the existing
transaction, authority, ordered-tree, causal, receipt and storage paths.

```sh
rebase-next --model invoicing model developer
rebase-next --model invoicing fixture list
rebase-next --model invoicing fixture plan invoice-refund \
  --namespace 00000000-0000-4000-8000-000000000100 > draft.json
```

Create/serve an invoicing store using the [ordinary server commands](server.md),
with the same selector for `init`, `serve`, `check`, backup and restore. Submit
the draft through the existing stateless client:

```sh
python3 -B tools/client.py --url http://127.0.0.1:9000/rpc \
  --token-file token.txt prepare draft.json saved-mutation.json
python3 -B tools/client.py --url http://127.0.0.1:9000/rpc \
  --token-file token.txt apply saved-mutation.json
```

Keep the saved request/context for retries. A fixture is a deterministic authored
scenario, not an arbitrary globally valid random-data generator. `invoice` creates
the initial six sources; `invoice-credit` creates nine sources in the corrected
scenario. `invoice-paid` creates eight sources for full settlement; `invoice-refund`
creates twelve for settlement followed by a linked credit/refund and reassessments.
UUIDv5 namespacing makes each plan repeatable. Use a new namespace for
another independent invoice; applying the saved mutation again replays its receipt.

## Authored records

| Code / contract | Fields and purpose |
| --- | --- |
| `101` Invoice | Immutable `currency` code; owns `base` 7, `gross` 13, `paid` 21, `balance` 23, gross `receivable` 29 and gross `payable` 31 histories. Currency scales are a model/user convention; this slice has no currency registry or conversion. |
| `211` Issue | `invoice`, `at`, canonical rational `quantity`, integer-string `unit_price_minor`, `rounding`. Publishes rounded `amount_minor`; owns remaining monetary credit capacity at root 17. |
| `307` Credit | `invoice`, original `issue`, `at`, positive integer-string `amount_minor`. Reduces invoice base/gross/balance and issue capacity; increases gross payable. |
| `401` TaxRule | `invoice`, `kind` (`base` or `net`), canonical nonnegative rational `rate`, `rounding`. Owns cumulative assessed tax at root 19. |
| `509` Assessment | `invoice`, `rule`, `at`. Publishes `basis_minor`, `prior_minor`, `assessed_minor`, `delta_minor`. |
| `601` Treasury | Immutable `currency`, mutable `name` (1–80 characters). Owns cash history 37. |
| `701` Payment | `invoice`, `treasury`, `at`, positive integer-string `amount_minor`. Owns remaining linked refund capacity at root 41. |
| `809` Refund | `invoice`, `treasury`, original `payment`, `at`, positive integer-string `amount_minor`. Returns part or all of that payment. |

All times are canonical `i64` integer strings; amounts use `i128` integer strings.
The [exact-value API](exact-values.md) defines fractions and rounding. For example,
quantity `{"numerator":"3","denominator":"2"}` times price `"6670"` gives
`"10005"` minor units. A Credit is a monetary correction, not a formula for
returning fractional quantities or repricing remaining goods.

All invoice/issue/rule/treasury/payment references are immutable. Credit must name
its Issue's Invoice; Assessment must name its Rule's Invoice. Payment requires
matching invoice/treasury currencies. Refund must name its original payment's
invoice and treasury. Other declared mutable fields use the normal complete-value updates and
CAS versions. No child stores a copied rate. G3b resolves the parent's authored
rate/kind/rounding into an attempt-local parameter bundle for pure evaluation.

## Calculation and history

An assessment reads the invoice basis and its rule's assessed total **strictly
before** its time. For prior assessed amount `A`:

```text
base rule: desired = round(invoice base × rate)
net rule:  desired = round((invoice gross − A) × rate)
new delta = desired − A
```

The net rule subtracts its own previous assessments before applying its rate.
That prevents a repeated unchanged assessment from taxing itself again. It can
still include earlier assessments from other rules: this is tax-on-tax. The same
rule cannot have two assessments at the same time. Different rules can share a
time; their strictly-before reads exclude each other's simultaneous outputs.

The corrected fixture proceeds as follows:

| Time | Authored fact / calculated contribution | Invoice gross |
| --- | --- | --- |
| 0 | Issue: `3/2 × 6670 = 10005` | 10005 |
| 10 | Base rule `1/10`: `1000.5 → 1000`, half-even | 11005 |
| 20 | Net rule `1/20`: `11005/20 → 550` | 11555 |
| 50 | Monetary Credit `−2001` | 9554 |
| 51 | Base reassessment: `800 − 1000 = −200` | 9354 |
| 52 | Net reassessment: `440 − 550 = −110` | 9244 |

The final base is **8004**, assessed base/net taxes are **800/440**, and gross is
**9244**. Later Credit does not rewrite earlier assessments or invent new ones.
The author explicitly adds later assessments when a correction is wanted. Editing
an earlier source or a Rule does recalculate its affected existing consumers.
A Rule's rate edit is retroactive for that entire series; effective-dated rate
replacement is outside this slice.

Every base/gross, credit-capacity and assessed-tax history must remain nonnegative
after each complete timestamp. This prevents early or excessive credit even if a
later line would restore a positive total. The model checks settled roots before
commit; an invalid batch leaves no source, tree, index or success receipt change.

Five private output roles publish each Issue and five publish each Assessment,
using seven private contracts. Each private output has one tree membership.
Zero assessments retain all five output identities, including both directional
claims when their amounts are zero. Private contracts are absent from the public
catalog and reject client writes.

## Settlement, refunds and directional claims

Payments and refunds are authored cash facts. The backend computes their effects;
it does not transfer money or invent a corrective transaction. Each Credit,
Payment and Refund contributes directly to five declared roots. A Payment is a
member of its own refund-capacity root through the explicit `self` declaration.

| Contribution | Gross | Paid | Balance | Receivable | Payable | Cash | Payment capacity |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Issue `a` | +a | 0 | +a | +a | 0 | 0 | 0 |
| Assessment `d` | +d | 0 | +d | max(d,0) | max(-d,0) | 0 | 0 |
| Credit `a` | -a | 0 | -a | 0 | +a | 0 | 0 |
| Payment `a` | 0 | +a | -a | 0 | +a | +a | +a |
| Refund `a` | 0 | -a | +a | +a | 0 | -a | -a |

The claim roots record gross directional activity from this invoice's single
perspective. They are not outstanding receivable/payable balances or mirrored
counterparty books. At each complete timestamp:

```text
balance = gross − paid = receivable − payable
```

Balance, paid, cash and each payment's refund capacity must remain nonnegative
after each complete timestamp. Balance has its own maintained history: subtracting
two independent minimum summaries would not establish this invariant. A refund
cannot precede or cumulatively exceed its linked payment, even when other payments
keep the treasury positive. Simultaneous contributions are checked together at the
final transaction boundary, so command order does not create a temporary deficit.
New referenced parents must still precede their children in a create batch, as
required by the shared API's reference/authority checks. Updates to existing
records and cash contributions settle together. A deleted calculation producer's
UUID remains reserved; use a fresh UUID for a replacement. Sign changes and zero
amounts on a surviving producer retain its existing output identities.

In `invoice-refund`, pay **11555** at time `30`. At `50`, credit **2001** and refund
**2311** together; tax corrections of **−200/−110** follow at `51/52`. Balance is
**310 → 110 → 0** at those three timestamps. Final gross/paid/cash and remaining
payment capacity are **9244**, while receivable and payable are each **13866**.
A credit without the refund, or a refund delayed until `52`, rejects the whole
batch despite the latter's zero final balance. Historical price, rate, payment
or refund edits must still satisfy every complete-time history.

## Acceptance, cost and next step

Run the real HTTP workflow and independent Fraction oracle from `rebase-next/`:

```sh
cargo build --locked --release --bin rebase-next
python3 -B tools/invoicing.py --binary target/release/rebase-next \
  --out target/my-invoicing-run
cargo test --locked --test invoicing
python3 -B tools/test_invoicing.py -v
```

Choose a new output directory per run; the tool retains owned credentials, exact
mutation plans, server logs, a verified backup/restored store and `result.json`.
Use the configured target directory if `CARGO_TARGET_DIR` is set.

This first profile allows **64 public sources, 256 active outputs and 512 retained
roles** with the unchanged 64-command/32-return/200,000-work mutation envelope.
The ceilings interact; they are not independent workload guarantees. The larger
G2 capacity measurements apply to calculation/equipment, not automatically to this
new business model.

A local line/credit touches a fixed number of balanced tree paths. An assessment
does two indexed prefix reads and updates five outputs; affected historical
consumers add work. Parent invalidation and final-graph scheduling are the shared
indexed algorithms, not table scans. Duplicate assessment checks inspect final
neighbours. The independent checker deliberately uses source scans/sorting and can
take quadratic work across a history; it is bounded operator verification, not
the mutation algorithm.

[The G3d/G3e gate](../research/28-settlement-refund-gate.md) owns settlement and
deployment acceptance; [G3c](../research/27-invoicing-gate.md) retains dated pricing
evidence. Package 0.6 uses invoicing behavior `invoice-assessments-2`. Its changed
declarations require a new invoicing store; the previous binary must check and
restore an older invoicing store. Calculation/equipment identities and store/
codec format 4 are unchanged. See [upgrades](storage.md#data-identity-and-upgrades).

This model
implements invoice-level cumulative reassessment, not the old per-issue linked
tax graph or a complete accounting suite. Dated rational FX, distributed storage, arbitrary monoids,
general two-bound reads and frontend remain separate gates.
