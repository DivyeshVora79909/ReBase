-- ==============================================================================
-- FILE 07: STATELESS AGGREGATORS (VIEWS)
-- ==============================================================================
USE NS main DB main;

-- 1. POLYMORPHIC MONEY ROUTING
DEFINE TABLE OVERWRITE v_pay_to AS SELECT to AS node, math::sum(zzzzz_out.active_amount) AS active_amount FROM payment WHERE suspended = false GROUP BY node;
DEFINE TABLE OVERWRITE v_pay_from AS SELECT from AS node, math::sum(zzzzz_out.active_amount) AS active_amount FROM payment WHERE suspended = false GROUP BY node;

-- 2. INVOICE & ORG
DEFINE TABLE OVERWRITE v_inv_org AS SELECT org, math::sum(zzzzz_out.purchase_base_value) AS purchase_base_value, math::sum(zzzzz_out.sales_base_value) AS sales_base_value, math::sum(zzzzz_out.purchase_tax_value) AS purchase_tax_value, math::sum(zzzzz_out.sales_tax_value) AS sales_tax_value FROM invoice WHERE suspended = false GROUP BY org;

-- 3. PAYMENT ALLOCATIONS
DEFINE TABLE OVERWRITE v_pa_pay AS SELECT payment, math::sum(zzzzz_out.allocated_amount) AS allocated_amount FROM payment_allocation GROUP BY payment;
DEFINE TABLE OVERWRITE v_pa_inv AS SELECT invoice, math::sum(zzzzz_out.allocated_amount) AS allocated_amount FROM payment_allocation GROUP BY invoice;

-- 4. INVOICE LINES & ITEMS
DEFINE TABLE OVERWRITE v_invl_inv AS SELECT invoice, math::sum(zzzzz_out.purchase_base_value) AS purchase_base_value, math::sum(zzzzz_out.sales_base_value) AS sales_base_value, math::sum(zzzzz_out.inbound_physical_qty) AS inbound_physical_qty, math::sum(zzzzz_out.outbound_physical_qty) AS outbound_physical_qty FROM invoice_line GROUP BY invoice;
DEFINE TABLE OVERWRITE v_invl_item AS SELECT item, math::sum(zzzzz_out.purchase_financial_qty) AS purchase_financial_qty, math::sum(zzzzz_out.purchase_base_value) AS purchase_base_value, math::sum(zzzzz_out.sales_financial_qty) AS sales_financial_qty, math::sum(zzzzz_out.sales_base_value) AS sales_base_value FROM invoice_line GROUP BY item;

-- 5. PACKAGES
DEFINE TABLE OVERWRITE v_sl_pkg AS SELECT pkg, math::sum(zzzzz_out.outbound_physical_qty) AS outbound_physical_qty FROM sl WHERE suspended = false AND pkg != NONE GROUP BY pkg;

-- 6. STOCK MOVEMENTS (THE SPLIT MATRIX EXCEPTION)
DEFINE TABLE OVERWRITE v_sl_invl_in AS SELECT to AS inv_line, math::sum(zzzzz_out.inbound_physical_qty) AS inbound_physical_qty FROM sl WHERE suspended = false AND record::tb(to) = 'invoice_line' GROUP BY inv_line;
DEFINE TABLE OVERWRITE v_sl_invl_out AS SELECT from AS inv_line, math::sum(zzzzz_out.outbound_physical_qty) AS outbound_physical_qty FROM sl WHERE suspended = false AND record::tb(from) = 'invoice_line' GROUP BY inv_line;

DEFINE TABLE OVERWRITE v_sl_matrix_in AS SELECT to AS node, zzzzz_out.item AS item, math::sum(zzzzz_out.inbound_physical_qty) AS inbound_physical_qty FROM sl WHERE suspended = false GROUP BY node, item;
DEFINE TABLE OVERWRITE v_sl_matrix_out AS SELECT from AS node, zzzzz_out.item AS item, math::sum(zzzzz_out.outbound_physical_qty) AS outbound_physical_qty FROM sl WHERE suspended = false GROUP BY node, item;

DEFINE TABLE OVERWRITE v_sl_cogs_out AS SELECT from AS acc, math::sum(zzzzz_out.actual_cogs_value) AS actual_cogs_value FROM sl WHERE suspended = false AND record::tb(from) = 'acc' GROUP BY acc;

-- 7. TAX LINES
DEFINE TABLE OVERWRITE v_tl_inv AS SELECT invoice_line.invoice AS invoice, math::sum(zzzzz_out.purchase_tax_value) AS purchase_tax_value, math::sum(zzzzz_out.sales_tax_value) AS sales_tax_value FROM tax_line GROUP BY invoice;
DEFINE TABLE OVERWRITE v_tl AS SELECT tax_account, math::sum(zzzzz_out.sales_tax_value) AS sales_tax_value, math::sum(zzzzz_out.purchase_tax_value) AS purchase_tax_value FROM tax_line GROUP BY tax_account;

-- 8. DELTAS
DEFINE TABLE OVERWRITE v_al_invl AS SELECT invoice_line, math::sum(zzzzz_out.delta_qty) AS delta_qty, math::sum(zzzzz_out.delta_price) AS delta_price FROM adjustment_line GROUP BY invoice_line;