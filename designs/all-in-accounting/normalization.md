# Native positions and reporting projections

`organization_currency_account` identifies one organization/currency position;
`organization_resource_account` identifies one organization/item-or-service
position. These are sparse rows. Owned stock is identified by operating unit and
resource within a subsidiary; pricing currency is not part of that identity.
Treasury record identity distinguishes multiple cash locations in one currency.

A source leg declares a native history membership and its required reporting
memberships. The account's `valuation_pair` converts into subsidiary currency;
organization accounts also use `organization_pair`. Reporting happens at the
source's effective time. Parent account or invoice totals do not post a duplicate
financial leg. Coincident legs from one source into one root/time coalesce.

The organization uses the counterparty perspective. The subsidiary mirrors its
claims and keeps owned, counterparty, tax and miscellaneous real measures distinct.
No root sums mixed raw currencies or unrelated resource quantities.

Exchange pairs are directed and tenant-scoped. Dated authoritative rates and
observed trade values are independent trees. Initial fallback and bounded rate
impacts are detailed in the [developer guide](developer-guide.md). Reporting is
event-time valuation, not automatic mark-to-market of the remaining position.

The shared compiler, access closure, derived-field ordering and ordered-tree
runtime remain under `dev-tools/compiler/` and `framework/`. Domain formulas
and memberships remain ordinary authored source in this profile.
