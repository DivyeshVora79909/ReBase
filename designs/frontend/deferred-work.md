# Further work and prerequisites

The current frontend is implemented directly. This map separates implemented
backend features awaiting browser workflows from unresolved backend policies.
The canonical references are the [accounting handoff](../all-in-accounting/implementation-handoff.md),
[core handoff](../rebase-system/core-handoff.md), and
[developer-tools handoff](../rebase-system/developer-experience-handoff.md).
Their historical evidence is not a fresh frontend verification claim.

The 2026-10-03 review closes P1 for the delivered invoice workflows; see
[verification](verification.md). Live email/SMS/payment checks are excluded
from this task, and no existing data needs migration. The original packets below remain future features. The newer tenant compatibility
packet is required before using the frontend against the redesigned backend.

## Required compatibility packet: tenant backend (deferred 2026-10-05)

Before P2-P11, migrate the unchanged frontend to the new tenant backend using
[the continuation](continuation-prompts.md#tenant-backend-migration--next-required-packet).
The [backend evidence](../rebase-system/evidence/2026-10-05-tenant-tree-verification.json)
and lead review establish the starting backend scope, separately from browser acceptance.
One design connection contains multiple tenants; login/cache/session identity
must include tenant. Identity owned_by, removal of visibility, root-derived
readers, scoped aggregate views, typed tree cursors and delivery tax provenance
are breaking contracts. Preserve per-priced-portion rounding and the explicit
additive choice of line and invoice-wide tax inputs. Native source scans must
carry the documented SurrealDB 3.3.0 ID-order workaround where affected.
Prove two tenants with the same email in one database and switching with a
pending response. No frontend source work or new browser acceptance is claimed
by this backend continuation.

## Recommended sequence

1. Add source/detail maintenance and a reviewed complete ledger projection.
2. Add returns/refunds and quote-derived FX using their implemented contracts.
3. Add tax/credit/withholding workflows after agreeing their visible public
   projections. Current invoice tax paths need no separate residual posting.
4. Add account onboarding/authentication delivery when gateway configuration and
   delivery-provider expectations are explicitly selected.
5. Measure representative workloads before deciding on virtualization, live
   subscriptions, background exports or more client infrastructure.

## Concrete frontend packets

| Packet | Prerequisite and invariant | Smallest proof | Files and completion |
| --- | --- | --- | --- |
| P1: invoice timestamp boundary — complete 2026-10-03 | `invoice_validate` uses `outstanding.instant_min`; settlement at the issue instant is supported. | Native sales/purchase partial/full settlement and early/excess rollback; browser settlement retains the exact issue timestamp and existing cash sources. | Backend guard and focused regressions, frontend invoice tests and obsolete warning removal. See current verification; no artificial timestamp offsets. |
| P2: maintenance and reconciliation | Account/master dimensions have readonly/reference constraints. Editing source values must retain native IDs and compare last-read versions. | Two independent editors; one stale update fails. Deleting a referenced row fails with no aggregate drift. | Relevant `MetaSol/src/data/` module, route and tests. Add only reviewed writable fields; preserve the current exact-row helper. |
| P3: complete ledger and account ranges | Direct cash/stock lists omit exchange, returns, invoices and managed effects. Define a public effect projection with ordering, dimensions and permission semantics. | One account containing cash, exchange and a reversal has complete paginated activity and a reconciliation to its history summary. | Backend projection if required; treasury/inventory routes. Label source and effective time; no browser reads of private managed tables. |
| P4: returns and refunds | H5b physical returns and H5c standalone receivable refunds have scoped backend implementations. They consume specific source capacities and dates. | Partial return/refund, exact capacity, over-capacity rollback, source edits and inaccessible references. | New explicit data functions and forms beside inventory/claims; new source-ID fixtures and browser flow. Never turn a return into an arbitrary negative movement. |
| P5: quote-derived FX | H6b already has an implemented quote/execution contract. Quote validity, pair direction and original executed amounts must remain explicit. | Expired/mismatched quote rejection and full reversal using the executed quote amount. | Exchange data/route and fixture. No browser-fetched rate pretending to be an authorized quote. |
| P6: tax and credit operations | H3/H4 implement bounded sales tax, purchase receipts, credit recognition, withholding, claim offset and remittance. Public readable projections must identify basis, policy version and source capacities. | One taxed invoice with correct dimensions, explicit recognition and settlement; unavailable/invalid rules and excessive use rejected. | Invoice/claims/directory extensions, schema fixture and browser tests. Do not infer usable input credit from an invoice or equate GST components with income-tax withholding. |
| P7: public validation reuse | Five JSON create schemas exist; native SDK keys support more shapes. Decide the public record-key representation before sharing browser validation. | Native string/number/UUID/unusual keys retain identity; local field errors and server guards agree for supported input; hidden fields are rejected. | Public schemas and the few affected adapters/tests. Prefer authored validation or a normal JSON Schema library; no form generator, metadata fetch or query DSL. |
| P8: onboarding and identities | Password sign-in is implemented. Activation, challenge/recovery, OAuth and contact identities need the selected public gateway endpoint and supported account policy. | Expired challenge, resending, wrong destination, failed delivery, replay and context change; secrets stay server-side. | Explicit auth routes, auth data helpers and gateway fixtures. Preserve session fencing and do not persist challenge secrets as preferences. |
| P9: permission/credential administration | K4 credential ownership has a backend contract. UI requires safe write-only secret fields and readable metadata projections. | Owner/delegate allowed write, unrelated-user denial, secret redaction and authorization before provider access. | New admin routes only after projection review; mock provider checks. Never show private root credential records. |
| P10: client workspace experience | Public profile/namespace/database entry works. A named workspace catalog is optional public configuration, not authorization. | A user selects a known workspace without entering technical context; endpoint changes still isolate tokens. | Runtime parser, entry route and existing session tests. Keep routes and business capabilities compiled explicitly. |
| P11: scale and live work | Current lists are bounded pages; boards group loaded rows. Choose a concrete workload before adding machinery. | Measure first/next page latency, bytes, rows, concurrency and permission churn; stale live events cannot cross sessions. | The affected query/component plus measured fixture. Add server indexes/projections or virtualization only for observed costs. |

Each packet should produce a user-visible vertical slice, a native positive and
negative case, one browser flow and an updated contract. A source/table inventory
alone is not completion. Keep the scope small enough to verify before taking
the next packet.

## Policies and backend work still genuinely open

| Area | Decision or evidence required before implementation |
| --- | --- |
| New residual reconciliation | H4b5c is resolved for current invoice tax paths: no separate residual effect. Reopen only for a concrete feature requiring an explicit source, sign/range, precision, destination and date. |
| Physical cost / capacity | Three bounded H8 samples record transaction-layer keys and bytes. Physical device costs, dependency visits, fan-out and contention remain unmeasured; neither those counters nor serial timings establish capacity or throughput. |
| Populated legacy migration | Not applicable to this task: there is no existing data. A future populated deployment would require its own mapping, identity/collision policy and rollback proof. |
| Live providers | Excluded by the user from this review. A future deployment can verify its chosen delivery configuration and callbacks separately; mock checks do not establish production delivery. |
| Workforce / costing / valuation | A defined quantity/time/cost basis and lifecycle. Timed production does not calculate wages, absorption costs or inventory valuation. |
| Statutory filing | Jurisdiction, period, evidence/eligibility policy, corrections and submission contract. Displaying taxes is not filing or compliance verification. |
| CRM | Independent customer/contact/opportunity identities, ownership and a first lifecycle. Begin with a separate conventional page/domain slice, sharing proven session/UI primitives. |
| HRM | Independent person/employment/organization/time/entitlement identities and access policy. Avoid treating users, employees and financial parties as interchangeable. |

## Working boundaries

Keep ordinary native references between domains. Do not force independent CRM
or HRM data into accounting ownership or adopt a universal entity registry.
Publish the minimum projection needed for a browser task. New rules remain in
their server-owned source contracts; UI code provides explanation and input.

Frontend breaking changes and removal of superseded frontend implementations
are authorized. Routine implementation choices do not require another approval.
An unresolved business policy needs a concrete decision; continue independent
work while that decision is open. Deployment and live-provider activity are
separate from the local implementation and verification described here.
