## 📋 LIST 1: SINGLE‑FIELD VALIDATIONS

_(`ASSERT` that only references `$value` – the field’s own value.)_

| Table                | Field                 | Validation Rule                   | Type                      |
| :------------------- | :-------------------- | :-------------------------------- | :------------------------ |
| `item`               | `a_user_default_cogs` | `$value >= 0dec`                  | Non‑negative numeric      |
| `payment`            | `a_user_amount`       | `$value > 0dec`                   | Strictly positive numeric |
| `payment`            | `a_user_fx_rate`      | `$value > 0dec`                   | Strictly positive numeric |
| `invoice`            | `a_user_type`         | `$value IN ['sales', 'purchase']` | Enumerated string         |
| `invoice`            | `a_user_fx_rate`      | `$value > 0dec`                   | Strictly positive numeric |
| `invoice_line`       | `a_user_qty`          | `$value > 0dec`                   | Strictly positive numeric |
| `invoice_line`       | `a_user_price`        | `$value >= 0dec`                  | Non‑negative numeric      |
| `payment_allocation` | `a_user_amount`       | `$value > 0dec`                   | Strictly positive numeric |
| `sl`                 | `a_user_qty`          | `$value > 0dec`                   | Strictly positive numeric |
| `tax_line`           | `a_user_rate`         | `$value > 0dec`                   | Strictly positive numeric |

---

## 📋 LIST 2: CROSS‑FIELD / TABLE‑LEVEL VALIDATIONS (Final)

_(All `ASSERT` and `THROW` logic that involves **two or more fields**.)_

| Table                | Validation Block                                       | Fields Involved                                                  | Logic Summary                                                                                           |
| :------------------- | :----------------------------------------------------- | :--------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------ |
| `treasury`           | `e_guard_state`                                        | `d1_net_balance` (derived from `c_sum_pay_in` & `c_sum_pay_out`) | Throws if net balance drops below zero.                                                                 |
| `payment`            | `d6_raw_allocation_shield`                             | `d5_raw_active_amount` & `c_sum_pa_amount`                       | `ASSERT` that unallocated payment amount ≥ 0.                                                           |
| `payment`            | `e_guard_state`                                        | `d1_derived_p_from` & `d2_derived_p_to`                          | Throws if both From and To are "External" (neither treasury/acc/tax).                                   |
| `invoice`            | `d4_raw_allocation_shield`                             | `d2_raw_grand_total` & `c_sum_pa_amount`                         | `ASSERT` that unallocated invoice balance ≥ 0.                                                          |
| `adjustment_note`    | `e_guard_state`                                        | `c1_sum_price_delta` & `c2_sum_tax_delta`                        | Throws if Price delta and Tax delta have opposing signs.                                                |
| `payment_allocation` | `e_guard_state` (1st check)                            | `b_ctx_inv_org` vs `b_ctx_pay_from` / `b_ctx_pay_to`             | Throws if Invoice's Org is not the sender or receiver of the Payment.                                   |
| `payment_allocation` | `e_guard_state` (2nd check)                            | `b_ctx_inv_vector` & `b_ctx_pay_vector`                          | Throws if allocation direction mismatches (Purchase requires outbound Payment; Sales requires inbound). |
| `invoice_line`       | `d2_net_base_val`                                      | `d1_raw_base_val` & `c_sum_delta_price`                          | `ASSERT` that net base value ≥ 0.                                                                       |
| `invoice_line`       | `e_guard_fulfillment`                                  | `d6_net_delivered_qty` & `a_user_qty`                            | Throws if delivered qty exceeds contracted qty.                                                         |
| `tax_line`           | `d2_net_tax_curr`                                      | `d1_raw_tax_curr` & `c_sum_delta_tax`                            | `ASSERT` that net tax value (raw + adjustment delta) ≥ 0. _(✅ Added – this was the missed one)_        |
| `sl`                 | `d7_net_qty`                                           | `d6_raw_qty` & `c_sum_delta_qty`                                 | `ASSERT` that net stock quantity ≥ 0.                                                                   |
| `sl`                 | `e_guard_state` (Item resolution)                      | `d4_derived_item` (from multiple sources)                        | Throws if no Item can be resolved.                                                                      |
| `sl`                 | `e_guard_state` (Package logic)                        | `has_invl` (presence of invoice_line) & `a_user_pkg`             | Throws if Invoice Line exists but Package missing; throws if no Invoice Line but Package exists.        |
| `sl`                 | `e_guard_state` (Invoice consistency)                  | `b_ctx_pkg_inv`, `b_ctx_from_inv`, `b_ctx_to_inv`                | Throws if Source/Dest Invoice Line belongs to a different Invoice than the Package Note.                |
| `sl`                 | `e_guard_state` (External‑to‑External)                 | `d1_derived_p_from` & `d2_derived_p_to`                          | Throws if both From and To are external (neither warehouse nor stock_acc).                              |
| `sl`                 | `e_guard_state` (System node check)                    | `d10_derived_from_type` & `d11_derived_to_type`                  | Throws if neither side touches a Warehouse or Stock Account.                                            |
| `sl`                 | `e_guard_state` (Max Invoice Lines)                    | `d10_derived_from_type` & `d11_derived_to_type`                  | Throws if both sides are `invoice_line` (max 1 allowed).                                                |
| `sl`                 | `e_guard_state` (Item conflict)                        | `a_user_item` vs `b_ctx_from_item` / `b_ctx_to_item`             | Throws if payload item conflicts with the Invoice Line's item.                                          |
| `sl`                 | `e_guard_state` (Vector direction)                     | `b_ctx_inv_vector` & `d3_derived_vector`                         | Throws if Purchase receives wrong vector (must be +1) or Sales ships wrong vector (must be -1).         |
| `sl`                 | `e_guard_state` (Sufficient stock – Outbound)          | `past_stock`, `impact`, `before` state, `sl_outbound_qty`        | Throws if outbounding stock makes Warehouse balance negative.                                           |
| `sl`                 | `e_guard_state` (Sufficient stock – Receipt reduction) | `past_stock`, `impact`, `before` state, `sl_inbound_qty`         | Throws if reducing an inbound receipt would cause negative stock (goods already consumed).              |
| `adjustment_line`    | `e_guard_state`                                        | `b_ctx_target_org` & `b_ctx_note_org`                            | Throws if the Adjustment Note's Organization does not match the Target's Organization.                  |

---
