# G3d: settlement, linked refunds and directional claims

**G3d/G3e complete, 2026-10-23.** [Deployment acceptance](29-deployment-result.md)
records the verified final bundle and continuation boundary. This extends the accepted
[G3c](27-invoicing-gate.md) binding. The user has chosen this environment and a verified deployment bundle
as the end-to-end destination. Work remains in `rebase-next/`, on `main`, with
no frontend or external host installation.

## Checkpoints and finish line

1. **G3d:** implement the native settlement contracts, independent source checks,
   fixtures and authenticated HTTP acceptance below; committed/published as `54b1249`.
2. **G3e:** package the supported backend and tools, verify the extracted bundle
   through all three models and recovery, record platform/identity/limits and
   exact deployment commands; build checkpoint `305a7b8` and final release
   acceptance complete this gate.

This goal deploys a bounded application on the existing embedded backend. It
does not silently add a distributed adapter, effects, a full accounting port,
quantity-return pricing or arbitrary model loading. Preserve dated G1/G2/G3a–c
evidence; rerun checks where this change can affect behavior.

## Explicit contracts

Keep Invoice/Issue/Credit/TaxRule/Assessment and their pricing/tax semantics.
Add Treasury `601` (`currency`, short `name`), Payment `701` (`invoice`,
`treasury`, `at`, positive `amount_minor`) and Refund `809` (the same fields,
plus its original `payment`). Treasury currency and all settlement references
are immutable. Treasury name, times and positive amounts are mutable. Payments
require matching invoice/treasury currencies; refunds must agree with their
payment's invoice and treasury. There is no hidden traversal during calculation.

Invoice adds paid `21`, balance `23`, receivable `29` and payable `31` roots.
Treasury owns cash `37`; Payment owns remaining refund capacity `41`. All use
the existing complete-time nonnegative financial summary. Enforce historical
balance directly as a maintained history, never by subtracting independent minima.

| Contribution | Gross | Paid | Balance | Receivable | Payable | Cash | Refund capacity |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Issue `a` | +a | 0 | +a | +a | 0 | 0 | 0 |
| Assessment `d` | +d | 0 | +d | max(d,0) | max(-d,0) | 0 | 0 |
| Credit `a` | -a | 0 | -a | 0 | +a | 0 | 0 |
| Payment `a` | 0 | +a | -a | 0 | +a | +a | +a |
| Refund `a` | 0 | -a | +a | +a | 0 | -a | -a |

Receivable/payable are gross directional histories from this invoice's single
perspective. They are not outstanding receivable/payable balances or a mirrored
counterparty ledger. Their difference and `gross - paid` both equal balance at
every complete timestamp. Payments/refunds are authored cash facts; no external
transfer or automatic corrective transaction is performed.

Use direct memberships for authored money. A source may participate in its own
declared root through `self`; resolve that only against its own contract, using
the same existing native tree path. This small declaration extension avoids a
fake copied calculation for Payment's refund capacity. Issue/Assessment use
fixed private output roles for balance and directional claims; sign changes
retain both assessment claim roles, including zero contributions. No generic
framework, new storage encoding or causal algorithm is required.

Bump only invoicing behavior to `invoice-assessments-2`; its new declarations
also change the model identity. Keep calculation/equipment identity and store/
codec 4. Retain the accepted G3c binary and a checked store before replacement;
the new binary must reject the old invoicing store without changing it. A clean
store now receives a read-only identity check before a writable redb handle is
opened. Crashed files can require allocator recovery first; preserve automatic
recovery and document that maintenance bytes can change during that recovery.

## Independent acceptance

Retain the 64 public /256 output /512 retained-role envelope and 200,000 mutation
work budget. Add no capacity claim from constants or the old G2 workloads.

The accepted fixture has base **10005**, gross **11555**. Pay **11555** at `30`.
At `50`, author Credit **2001** and Refund **2311** together; add reassessments
**-200** at `51` and **-110** at `52`. Final base is **8004**, gross/paid/cash
**9244**, balance **0**, and receivable = payable = **13866**. At `50` balance
is **310**, at `51` it is **110**, and at `52` it is **0**. Without the refund,
or with that refund delayed to `52`, historical balance is negative and the
entire mutation must reject even though a later final balance can be zero.

Check partial settlement, same-time grouping and command permutations, historical
price/rate/payment/refund edits, repeated/refunded payment capacity, currency and
parent agreement, private writes, deletion/reference cleanup, exact rollback of
every application table/revision/receipt, replay, reopen and backup/restore.
Check directional outputs across a sign change without identity churn.
Respect the shared API's existing staging contract: new referenced parents must
precede their children. Existing-source updates and same-time cash contributions
settle at the final boundary. Deleted calculation producer UUIDs remain reserved;
use fresh UUIDs for replacements, and verify both constraints explicitly.

The native operator checker must independently reconstruct all source histories,
output memberships, query expectations and invariants before checking actual
trees. Extend the separate Python Fraction oracle first and retain explicit
negative controls. Run the real HTTP workflow with bounded seeded edits and the
64-source boundary, then preserve observed counts, command outcomes, build/source
fingerprints and remaining limits in dated evidence. Do not derive expected money
from maintained outputs or claims.

## Starting observation

The tree was clean at `53ff9e7`; `git pull --ff-only origin main` was already up
to date. The local cached executable was 0.3, so G3c was rebuilt from accepted
source with `CARGO_INCREMENTAL=0`. Its three model/store identities match G3c
evidence. The compatible binary and identity are retained in the ignored
`target/g3c-retained-53ff9e7/` directory; its bytes differ from the cloud build,
as expected for a different build host. This was the starting observation before
the accepted execution below.

## G3d result

[Dated evidence](evidence/2026-10-23-g3d-settlement.json) fingerprints the reviewed
sources and retained execution artifacts. Package **0.6.0**, invoicing behavior
`invoice-assessments-2`, model
`7230c26cc5c85bd56db3ba67da1748e727aebee59d5aaaae1ce188d7da8d33be`.
Calculation/equipment model identities and store/codec 4 are unchanged.

- **76 Rust tests** pass in both debug and optimized builds; formatting and
  warning-denying Clippy pass. Nine invoicing integration tests cover four fixtures,
  same-time grouping, reversed command orders, historical edits, refund capacity,
  private writes, deletion, stable directional roles, complete rollback and reopen.
- **18 Python controls** pass: nine invoice/settlement oracle controls, six client
  controls and three population-oracle controls. The separate native corpora pass
  68 foundation cases /93 operations, 39 causal cases /55 operations and nine local
  cases /14 operations, with independent source checks.
- The real HTTP workflow passes **111 mutations /340 commands**: **75 commits**
  and **36 rejections**. Every rejection compares complete backup payloads and
  confirms receipt absence. It includes 40 pricing/rule stress batches, 24 cash
  stress batches, the 64-source boundary, replay, crash recovery and verified
  restore. The largest observed committed mutation uses **2,984 work units**;
  this is a workload observation, not a general fanout bound.
- Literal paid/refunded totals are gross/paid/cash/capacity **9244**, balance **0**,
  receivable = payable = **13866**. Credit without refund and the late-refund
  final-zero case reject. Sign changes preserve both directional output roles.
- The new binary rejects a checked clean G3c store with **physical bytes unchanged**;
  the retained 0.5 binary still verifies it. Crashed files may need allocator
  recovery before identity can be read, as documented above.

The resumed review reran the optimized suite, formatting, Clippy, all Python
controls and compatibility. Cargo's rebuilt standalone executable has the same
SHA-256 as the retained final native/HTTP runs. Earlier failures are preserved in
the evidence: tests initially assumed arbitrary create ordering and reusable
retired producer UUIDs; the first compatibility probe exposed writable redb
maintenance changes before the read-only identity check was added.

**Continuation at G3d acceptance: G3e.** Package binary/source/tools/templates with checksums and platform
requirements, verify an extracted copy through all three models and recovery,
then publish the release result and exact deployment commands. This checkpoint
does not establish larger invoicing populations, full accounting parity,
external transfers, distributed conformance or a frontend.

## G3e build checkpoint

[Packaging evidence](evidence/2026-10-23-g3e-package.json) records a successful
native build from an exported Git tree outside the checkout. The ordinary
[`tools/package.py`](../tools/package.py) command packages committed sources,
builds with the lockfile and reusable Cargo cache, and emits `BUNDLE.json`,
`SHA256SUMS` and a normalized tar/gzip archive. The manifest reads the model
identities, codec and limits from the compiled executable.

The trial uses G3d commit `54b1249`: all **155 source files** match their Git blob
identities, and all **157 payload checksums** pass after extraction. The executable
is byte-for-byte identical to the G3d build. Changed-file and missing-binary
controls fail checksum verification. The archive contains exactly the source
tree plus the binary, manifest and checksum list; generated runtime state is
excluded. The first trial caught an empty archive caused by invoking Git from
the package subdirectory; exporting from the repository root fixed it, and the
successful trial checks every source blob independently.

The packaging tool and deployment instructions were published as `305a7b8`.
The final bundle builds that snapshot and passes the extracted calculation
workflow, both 64-source model/recovery probes, invoicing settlement, template
identity setup and failed-restore isolation. Two builds produce identical bytes;
all 159 final payload checksums pass. [Final acceptance](29-deployment-result.md)
and its evidence are published separately from the immutable bundle they certify.
The selected goal is complete; no follow-on implementation gate is active.
