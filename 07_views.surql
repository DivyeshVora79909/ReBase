-- FILE 07: O(1) AGGREGATIONS
USE NS main DB main;

-- 1. POLYMORPHIC MONEY ROUTING
DEFINE TABLE OVERWRITE v_pay_node_to AS SELECT a_in_to AS node, math::sum(f_out.pay_inbound_val) AS pay_inbound_val FROM payment GROUP BY node;
DEFINE TABLE OVERWRITE v_pay_node_from AS SELECT a_in_from AS node, math::sum(f_out.pay_outbound_val) AS pay_outbound_val FROM payment GROUP BY node;

-- 2. ORG AGGREGATIONS
DEFINE TABLE OVERWRITE v_inv_org AS SELECT a_in_org AS org, math::sum(f_out.inv_purchase_total) AS inv_purchase_total, math::sum(f_out.inv_sales_total) AS inv_sales_total FROM invoice GROUP BY org;
DEFINE TABLE OVERWRITE v_adj_org AS SELECT a_in_org AS org, math::sum(f_out.adj_debit_val) AS adj_debit_val, math::sum(f_out.adj_credit_val) AS adj_credit_val FROM adjustment_note GROUP BY org;

-- 3. PAYMENT ALLOCATIONS
DEFINE TABLE OVERWRITE v_pa_pay AS SELECT a_in_payment AS payment, math::sum(f_out.pa_alloc_pay_amount) AS pa_alloc_pay_amount FROM payment_allocation GROUP BY payment;
DEFINE TABLE OVERWRITE v_pa_inv AS SELECT a_in_invoice AS invoice, math::sum(f_out.pa_alloc_inv_amount) AS pa_alloc_inv_amount FROM payment_allocation GROUP BY invoice;

-- 4. INVOICE LINES & ITEMS
DEFINE TABLE OVERWRITE v_invl_inv AS SELECT a_in_invoice AS invoice, math::sum(f_out.invl_purchase_value) AS invl_purchase_value, math::sum(f_out.invl_sales_value) AS invl_sales_value FROM invoice_line GROUP BY invoice;
DEFINE TABLE OVERWRITE v_invl_item AS SELECT a_in_item AS item, math::sum(f_out.invl_purchase_qty) AS invl_purchase_qty, math::sum(f_out.invl_purchase_value) AS invl_purchase_value, math::sum(f_out.invl_sales_qty) AS invl_sales_qty, math::sum(f_out.invl_sales_value) AS invl_sales_value FROM invoice_line GROUP BY item;

-- 5. PACKAGES & STOCK MOVEMENTS
DEFINE TABLE OVERWRITE v_sl_pkg AS SELECT a_in_pkg AS pkg, math::sum(f_out.sl_delivered_qty) AS sl_delivered_qty FROM sl WHERE a_in_pkg != NONE GROUP BY pkg;

DEFINE TABLE OVERWRITE v_sl_invl_from AS SELECT a_in_from AS inv_line, math::sum(f_out.sl_delivered_qty) AS qty FROM sl WHERE record::tb(a_in_from) = 'invoice_line' GROUP BY inv_line;
DEFINE TABLE OVERWRITE v_sl_invl_to AS SELECT a_in_to AS inv_line, math::sum(f_out.sl_delivered_qty) AS qty FROM sl WHERE record::tb(a_in_to) = 'invoice_line' GROUP BY inv_line;

DEFINE TABLE OVERWRITE v_sl_node_in AS SELECT a_in_to AS node, math::sum(f_out.sl_inbound_qty) AS sl_inbound_qty FROM sl GROUP BY node;
DEFINE TABLE OVERWRITE v_sl_node_out AS SELECT a_in_from AS node, math::sum(f_out.sl_outbound_qty) AS sl_outbound_qty FROM sl GROUP BY node;

DEFINE TABLE OVERWRITE v_sl_cogs_out AS SELECT f_out.cogs_acc AS acc, math::sum(f_out.sl_cogs_value) AS sl_cogs_value FROM sl WHERE record::tb(a_in_from) = 'warehouse' AND record::tb(a_in_to) != 'warehouse' GROUP BY acc;

-- 6. TAX LINES
DEFINE TABLE OVERWRITE v_tl_inv AS SELECT a_in_invoice_line.a_in_invoice AS invoice, math::sum(f_out.tl_purchase_tax) AS tl_purchase_tax, math::sum(f_out.tl_sales_tax) AS tl_sales_tax FROM tax_line GROUP BY invoice;
DEFINE TABLE OVERWRITE v_tl_acc AS SELECT a_in_tax_account AS tax_account, math::sum(f_out.tl_sales_tax) AS tl_sales_tax, math::sum(f_out.tl_purchase_tax) AS tl_purchase_tax FROM tax_line GROUP BY tax_account;

-- 7. DELTAS
DEFINE TABLE OVERWRITE v_al_invl AS SELECT a_in_invl AS invoice_line, math::sum(f_out.al_delta_qty) AS al_delta_qty, math::sum(f_out.al_delta_price) AS al_delta_price FROM adjustment_line GROUP BY invoice_line;
DEFINE TABLE OVERWRITE v_atl_tl AS SELECT a_in_tax_line AS tax_line, math::sum(f_out.al_delta_amount) AS al_delta_amount FROM adjustment_tax_line GROUP BY tax_line;
DEFINE TABLE OVERWRITE v_asl_sl AS SELECT a_in_sl AS sl, math::sum(f_out.al_delta_qty) AS al_delta_qty FROM adjustment_stock_line GROUP BY sl;

-- 8. O(1) STOCK SHIELD VIEWS
DEFINE TABLE OVERWRITE v_sl_wh_in AS SELECT a_in_to AS warehouse, f_out.item AS item, math::sum(f_out.sl_inbound_qty) AS qty FROM sl WHERE record::tb(a_in_to) = 'warehouse' GROUP BY warehouse, item;
DEFINE TABLE OVERWRITE v_sl_wh_out AS SELECT a_in_from AS warehouse, f_out.item AS item, math::sum(f_out.sl_outbound_qty) AS qty FROM sl WHERE record::tb(a_in_from) = 'warehouse' GROUP BY warehouse, item;

DEFINE INDEX idx_sl_matrix ON sl COLUMNS a_in_from, a_in_to, f_out.item;