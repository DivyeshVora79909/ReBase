# Accounting execution plan

The [October 7 execution record](redesign-2026-10-07.md) is the current plan.
The [blueprint](blueprint.md) defines the implementation contract and the
[verification record](verification.md) distinguishes fresh results from history.

The source slices are account roots/invoice dates, temporal taxes/corrections,
settlement/exchange, and production/capacity. They share the existing tree engine
and are validated together by `npm run verify:accounting`.

Acceptance requires source-derived arithmetic, structural reconstruction, exact
native decimal cases, complete rollback, record-user writes, competing sessions,
unchanged populated schema reapplication and complete explicit cleanup. Keep
schema inputs, worked examples and handoff evidence in the same change.
