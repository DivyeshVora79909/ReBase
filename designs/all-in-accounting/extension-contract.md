# Financial and production extensions — October 13

All extensions use the [current developer contract](developer-guide.md), native
account units and explicit memberships. The old draft/finalization flag, separate
return/refund tables, scalar entered exchange-rate fields and descriptor-wide
analytics roots are superseded.

- Adjustment notes group one native organization currency account and commercial
  side; nonzero `amount - paid` signs must agree. Empty notes are valid.
- Tax cash settlement, deposits, refunds and offsets use directional R/P plus
  independent signed credit/liability capacities. Same-account legs coalesce.
- Independent monetary/resource claims have source-specific settlement capacity.
- Eight cash tables support bounded inline fee/tax rules and explicit dated
  conversion pairs. Fees preserve the gross invoice/claim settlement amount.
- Resource exchange makes explicit real legs, including cross-subsidiary transfers
  within one tenant. Authoritative dated rates and observed amounts stay separate.
- Production retains native reservations, gross input protection, output capacity,
  resource windows and adjacent operating-capacity intervals. Owned R/P stay zero.
- Trade averages divide summed reporting values by summed quantities for one
  native resource position; taxes are excluded from base trade turnover.

See [extension-probe.js](../../dev-tools/accounting/extension-probe.js) for the
executable cases and [verification](verification.md) for current evidence.
