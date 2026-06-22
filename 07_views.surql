-- FILE 07: 1D PULL VIEWS & 2D MATRIX VIEWS
USE NS main DB main;

-- 1. POLYMORPHIC MONEY ROUTING (1D)
DEFINE TABLE OVERWRITE v_pay_node_to AS SELECT a_in_to AS node, math::sum(f_out.active_amount) AS active_amount FROM payment WHERE suspended = false GROUP BY node;
DEFINE TABLE OVERWRITE v_pay_node_from AS SELECT a_in_from AS node, math::sum(f_out.active_amount) AS active_amount FROM payment WHERE suspended = false GROUP BY node;

-- 2. INVOICE & ORG (1D)
DEFINE TABLE OVERWRITE v_inv_org AS SELECT a_in_org AS org, math::sum(f_out.purchase_base_value) AS purchase_base_value, math::sum(f_out.sales_base_value) AS sales_base_value, math::sum(f_out.purchase_tax_value) AS purchase_tax_value, math::sum(f_out.sales_tax_value) AS sales_tax_value FROM invoice WHERE suspended = false GROUP BY org;

-- 3. PAYMENT ALLOCATIONS (1D)
DEFINE TABLE OVERWRITE v_pa_pay AS SELECT a_in_payment AS payment, math::sum(f_out.allocated_pay_amount) AS allocated_pay_amount FROM payment_allocation GROUP BY payment;
DEFINE TABLE OVERWRITE v_pa_inv AS SELECT a_in_invoice AS invoice, math::sum(f_out.allocated_inv_amount) AS allocated_inv_amount FROM payment_allocation GROUP BY invoice;

-- 4. INVOICE LINES & ITEMS (1D)
DEFINE TABLE OVERWRITE v_invl_inv AS SELECT a_in_invoice AS invoice, math::sum(f_out.purchase_base_value) AS purchase_base_value, math::sum(f_out.sales_base_value) AS sales_base_value, math::sum(f_out.inbound_physical_qty) AS inbound_physical_qty, math::sum(f_out.outbound_physical_qty) AS outbound_physical_qty FROM invoice_line GROUP BY invoice;
DEFINE TABLE OVERWRITE v_invl_item AS SELECT a_in_item AS item, math::sum(f_out.purchase_financial_qty) AS purchase_financial_qty, math::sum(f_out.purchase_base_value) AS purchase_base_value, math::sum(f_out.sales_financial_qty) AS sales_financial_qty, math::sum(f_out.sales_base_value) AS sales_base_value FROM invoice_line GROUP BY item;

-- 5. PACKAGES (1D)
DEFINE TABLE OVERWRITE v_sl_pkg AS SELECT a_in_pkg AS pkg, math::sum(f_out.outbound_physical_qty) AS outbound_physical_qty FROM sl WHERE suspended = false AND a_in_pkg != NONE GROUP BY pkg;

-- 6. STOCK MOVEMENTS (1D)
DEFINE TABLE OVERWRITE v_sl_invl_in AS SELECT a_in_to AS inv_line, math::sum(f_out.inbound_physical_qty) AS inbound_physical_qty FROM sl WHERE suspended = false AND record::tb(a_in_to) = 'invoice_line' GROUP BY inv_line;
DEFINE TABLE OVERWRITE v_sl_invl_out AS SELECT a_in_from AS inv_line, math::sum(f_out.outbound_physical_qty) AS outbound_physical_qty FROM sl WHERE suspended = false AND record::tb(a_in_from) = 'invoice_line' GROUP BY inv_line;
DEFINE TABLE OVERWRITE v_sl_item_in AS SELECT f_out.item AS item, math::sum(f_out.inbound_physical_qty) AS inbound_physical_qty FROM sl WHERE suspended = false GROUP BY item;
DEFINE TABLE OVERWRITE v_sl_item_out AS SELECT f_out.item AS item, math::sum(f_out.outbound_physical_qty) AS outbound_physical_qty FROM sl WHERE suspended = false GROUP BY item;
DEFINE TABLE OVERWRITE v_sl_node_in AS SELECT a_in_to AS node, math::sum(f_out.inbound_physical_qty) AS inbound_physical_qty FROM sl WHERE suspended = false GROUP BY node;
DEFINE TABLE OVERWRITE v_sl_node_out AS SELECT a_in_from AS node, math::sum(f_out.outbound_physical_qty) AS outbound_physical_qty FROM sl WHERE suspended = false GROUP BY node;
DEFINE TABLE OVERWRITE v_sl_cogs_out AS SELECT f_out.cogs_account AS acc, math::sum(f_out.actual_cogs_value_acc_curr) AS actual_cogs_value FROM sl WHERE suspended = false AND record::tb(a_in_from) = 'warehouse' GROUP BY acc;

-- 6B. STOCK MOVEMENTS (2D MATRIX - FOR VALIDATION PEEKING ONLY)
DEFINE TABLE OVERWRITE v_sl_matrix_in AS SELECT a_in_to AS node, f_out.item AS item, math::sum(f_out.inbound_physical_qty) AS inbound_physical_qty FROM sl WHERE suspended = false GROUP BY node, item;
DEFINE TABLE OVERWRITE v_sl_matrix_out AS SELECT a_in_from AS node, f_out.item AS item, math::sum(f_out.outbound_physical_qty) AS outbound_physical_qty FROM sl WHERE suspended = false GROUP BY node, item;

-- 7. TAX LINES (1D)
DEFINE TABLE OVERWRITE v_tl_inv AS SELECT a_in_invoice_line.a_in_invoice AS invoice, math::sum(f_out.purchase_tax_value) AS purchase_tax_value, math::sum(f_out.sales_tax_value) AS sales_tax_value FROM tax_line GROUP BY invoice;
DEFINE TABLE OVERWRITE v_tl_acc AS SELECT a_in_tax_account AS tax_account, math::sum(f_out.sales_tax_acc_value) AS sales_tax_value, math::sum(f_out.purchase_tax_acc_value) AS purchase_tax_value FROM tax_line GROUP BY tax_account;

-- 8. DELTAS (1D)
DEFINE TABLE OVERWRITE v_al_invl AS SELECT a_in_invl AS invoice_line, math::sum(f_out.delta_qty) AS delta_qty, math::sum(f_out.delta_unit_price) AS delta_unit_price FROM adjustment_line GROUP BY invoice_line;
DEFINE TABLE OVERWRITE v_atl_tl AS SELECT a_in_tax_line AS tax_line, math::sum(f_out.delta_amount) AS delta_amount FROM adjustment_tax_line GROUP BY tax_line;
DEFINE TABLE OVERWRITE v_asl_sl AS SELECT a_in_sl AS sl, math::sum(f_out.delta_qty) AS delta_qty FROM adjustment_stock_line GROUP BY sl;