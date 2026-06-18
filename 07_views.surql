USE NS main DB main;

-- 1. POLYMORPHIC MONEY ROUTING
DEFINE TABLE OVERWRITE v_pay_from AS SELECT from AS node, math::sum(zzzzz_out.active_amount) AS total FROM payment WHERE suspended = false GROUP BY node;
DEFINE TABLE OVERWRITE v_pay_to AS SELECT to AS node, math::sum(zzzzz_out.active_amount) AS total FROM payment WHERE suspended = false GROUP BY node;

-- 2. INVOICE & ORG
DEFINE TABLE OVERWRITE v_inv_org AS SELECT org, math::sum(zzzzz_out.total_value) AS total_value FROM invoice WHERE suspended = false GROUP BY org;

-- 3. PAYMENT ALLOCATIONS
DEFINE TABLE OVERWRITE v_pa_pay AS SELECT payment, math::sum(zzzzz_out.amount) AS allocated FROM payment_allocation GROUP BY payment;
DEFINE TABLE OVERWRITE v_pa_inv AS SELECT invoice, math::sum(zzzzz_out.amount) AS allocated FROM payment_allocation GROUP BY invoice;

-- 4. INVOICE LINES & ITEMS (THE RELAY)
DEFINE TABLE OVERWRITE v_invl_inv AS SELECT invoice, math::sum(zzzzz_out.base_value) AS base_value, math::sum(zzzzz_out.ordered_qty) AS ordered_qty, math::sum(zzzzz_out.delivered_qty) AS delivered_qty FROM invoice_line GROUP BY invoice;
DEFINE TABLE OVERWRITE v_invl_item AS SELECT item, math::sum(zzzzz_out.ordered_qty) AS ordered_qty, math::sum(zzzzz_out.base_value) AS base_value, math::sum(zzzzz_out.net_cogs) AS net_cogs FROM invoice_line GROUP BY item;

-- 5. PACKAGES
DEFINE TABLE OVERWRITE v_pkg_inv AS SELECT invoice, count() AS total_packages FROM package_note GROUP BY invoice;
DEFINE TABLE OVERWRITE v_sl_pkg AS SELECT pkg, math::sum(zzzzz_out.qty) AS delivered_qty FROM sl WHERE suspended = false AND pkg != NONE GROUP BY pkg;

-- 6. STOCK MOVEMENTS (THE MATRIX EXCEPTION & RELAY)
DEFINE TABLE OVERWRITE v_sl_invl AS SELECT inv_line, math::sum(zzzzz_out.qty) AS delivered_qty FROM sl WHERE suspended = false AND inv_line != NONE GROUP BY inv_line;
DEFINE TABLE OVERWRITE v_sl_from_node_item AS SELECT from AS node, item, math::sum(zzzzz_out.inventory_qty) AS inventory_qty FROM sl WHERE suspended = false GROUP BY node, item;
DEFINE TABLE OVERWRITE v_sl_to_node_item AS SELECT to AS node, item, math::sum(zzzzz_out.inventory_qty) AS inventory_qty FROM sl WHERE suspended = false GROUP BY node, item;

-- 7. TAX LINES
DEFINE TABLE OVERWRITE v_tl_invl AS SELECT invoice_line, math::sum(zzzzz_out.tax_amount) AS tax_amount FROM tax_line GROUP BY invoice_line;
DEFINE TABLE OVERWRITE v_tl_ta AS SELECT tax_account, math::sum(zzzzz_out.tax_amount) AS tax_amount FROM tax_line GROUP BY tax_account;

-- 8. DELTAS (ADJUSTMENTS)
DEFINE TABLE OVERWRITE v_al_invl AS SELECT invoice_line, math::sum(zzzzz_out.delta_qty) AS delta_qty, math::sum(zzzzz_out.delta_cogs) AS delta_cogs FROM adjustment_line GROUP BY invoice_line;
DEFINE TABLE OVERWRITE v_atl_tl AS SELECT tax_line, math::sum(zzzzz_out.delta_amount) AS delta_amount FROM adjustment_tax_line GROUP BY tax_line;
DEFINE TABLE OVERWRITE v_asl_sl AS SELECT stock_movement, math::sum(zzzzz_out.delta_qty) AS delta_qty FROM adjustment_stock_line GROUP BY stock_movement;