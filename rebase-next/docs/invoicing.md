# Bounded invoicing model

Select `--model invoicing` for a store using fractional line pricing, chronological
tax assessments and linked monetary credits. The same compiled schemas drive
validation, catalogs, fixture plans and the inspector. The model uses the existing
transaction, authority, ordered-tree, causal, receipt and storage paths.

```sh
rebase-next --model invoicing model developer
rebase-next --model invoicing fixture list
rebase-next --model invoicing fixture plan invoice-credit \
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
the initial six sources; `invoice-credit` creates all nine sources in the corrected
scenario. UUIDv5 namespacing makes each plan repeatable. Use a new namespace for
another independent invoice; applying the saved mutation again replays its receipt.

## Authored records

| Code / contract | Fields and purpose |
| --- | --- |
| `101` Invoice | Immutable `currency` code; owns `base` root 7 and `gross` root 13. Currency scales are a model/user convention; this slice has no currency registry or conversion. |
| `211` Issue | `invoice`, `at`, canonical rational `quantity`, integer-string `unit_price_minor`, `rounding`. Publishes rounded `amount_minor`; owns remaining monetary credit capacity at root 17. |
| `307` Credit | `invoice`, original `issue`, `at`, positive integer-string `amount_minor`. Contributes its negative amount directly to invoice base/gross and issue capacity. |
| `401` TaxRule | `invoice`, `kind` (`base` or `net`), canonical nonnegative rational `rate`, `rounding`. Owns cumulative assessed tax at root 19. |
| `509` Assessment | `invoice`, `rule`, `at`. Publishes `basis_minor`, `prior_minor`, `assessed_minor`, `delta_minor`. |

All times are canonical `i64` integer strings; amounts use `i128` integer strings.
The [exact-value API](exact-values.md) defines fractions and rounding. For example,
quantity `{"numerator":"3","denominator":"2"}` times price `"6670"` gives
`"10005"` minor units. A Credit is a monetary correction, not a formula for
returning fractional quantities or repricing remaining goods.

Invoice references, Credit's Issue reference and Assessment's Rule reference are
immutable. Credit must name its Issue's Invoice; Assessment must name its Rule's
Invoice. Other declared mutable fields use the normal complete-value updates and
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

Three private output roles publish each Issue; two publish each Assessment. Each
private output has one tree membership, while Credit directly participates in
three trees. Zero assessments retain both output identities/memberships. Private
contracts are absent from the public catalog and reject client writes.

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
does two indexed prefix reads and updates two outputs; affected historical
consumers add work. Parent invalidation and final-graph scheduling are the shared
indexed algorithms, not table scans. Duplicate assessment checks inspect final
neighbours. The independent checker deliberately uses source scans/sorting and can
take quadratic work across a history; it is bounded operator verification, not
the mutation algorithm.

[The G3c gate](../research/27-invoicing-gate.md) owns current evidence. This model
implements invoice-level cumulative reassessment, not the old per-issue linked
tax graph or a complete accounting suite. G3d adds payment/refund histories and
treasury/claim rules. Dated rational FX, distributed storage, arbitrary monoids,
general two-bound reads and frontend remain separate gates.
