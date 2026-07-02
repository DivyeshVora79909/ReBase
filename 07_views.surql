-- ==============================================================================
-- FILE 07: O(1) AGGREGATIONS & BI VIEWS
-- ==============================================================================
USE NS main DB main;

-- 1. PAYMENT ROUTING 
DEFINE TABLE OVERWRITE v_pay_to AS SELECT a_to AS node, math::sum(a_amount) AS amount, math::sum(a_amount * a_fx_rate) AS val FROM payment WHERE d2_p_to = 1 GROUP BY node;
DEFINE TABLE OVERWRITE v_pay_from AS SELECT a_from AS node, math::sum(a_amount) AS amount, math::sum(a_amount * a_fx_rate) AS val FROM payment WHERE d1_p_from = 1 GROUP BY node;

-- 2. PAYMENT ALLOCATIONS
DEFINE TABLE OVERWRITE v_pa_pay AS SELECT a_payment AS payment, math::sum(a_amount) AS amount FROM payment_allocation GROUP BY payment;
DEFINE TABLE OVERWRITE v_pa_inv AS SELECT a_invoice AS invoice, math::sum(d1_alloc_inv_amount) AS amount FROM payment_allocation GROUP BY invoice;

-- 3. INVOICES & ORG TOTALS (Grouped by Vector)
DEFINE TABLE OVERWRITE v_invl_inv AS SELECT a_invoice AS invoice, d1_vector AS vector, math::sum(d2_raw_base) AS raw_base, math::sum(d3_net_base) AS net_base, math::sum(d7_raw_gross) AS raw_gross, math::sum(d8_net_gross) AS net_gross FROM invoice_line GROUP BY invoice, vector;
DEFINE TABLE OVERWRITE v_inv_org AS SELECT a_invoice.a_org AS org, d1_vector AS vector, math::sum(d7_raw_gross) AS raw_gross, math::sum(d8_net_gross) AS net_gross, math::sum(a_qty) AS qty, math::mean(d8_net_gross) AS mean_gross, math::variance(d8_net_gross) AS var_gross FROM invoice_line GROUP BY org, vector;
DEFINE TABLE OVERWRITE v_invl_item AS SELECT a_item AS item, d1_vector AS vector, math::sum(a_qty) AS qty, math::sum(d3_net_base) AS val, math::mean(a_price) AS mean_price, math::max(a_price) AS max_price, math::min(a_price) AS min_price, math::variance(a_price) AS var_price FROM invoice_line GROUP BY item, vector;

-- 4. STOCK MOVEMENTS (Polymorphic Node Context & Package Notes)
DEFINE TABLE OVERWRITE v_sl_in_ctx AS SELECT a_to AS node, d8_is_contract_backed AS is_contract_backed, math::sum(d6_net_qty) AS qty, math::sum(d7_impact_qty * d5_cogs * (a_from.a_invoice.a_fx_rate ?? a_to.a_invoice.a_fx_rate ?? 1.0dec)) AS val, math::variance(d6_net_qty) AS var_qty, math::max(d6_net_qty) AS max_qty FROM sl WHERE d2_p_to = 1 GROUP BY node, is_contract_backed;
DEFINE TABLE OVERWRITE v_sl_out_ctx AS SELECT a_from AS node, d8_is_contract_backed AS is_contract_backed, math::sum(d6_net_qty) AS qty, math::sum(d7_impact_qty * d5_cogs * (a_from.a_invoice.a_fx_rate ?? a_to.a_invoice.a_fx_rate ?? 1.0dec)) AS val, math::variance(d6_net_qty) AS var_qty, math::max(d6_net_qty) AS max_qty FROM sl WHERE d1_p_from = 1 GROUP BY node, is_contract_backed;

DEFINE TABLE OVERWRITE v_sl_pkg AS SELECT a_pkg AS pkg, math::sum(d6_net_qty) AS qty, math::sum(d7_impact_qty * d5_cogs * (a_from.a_invoice.a_fx_rate ?? a_to.a_invoice.a_fx_rate ?? 1.0dec)) AS val, math::variance(d6_net_qty) AS var_qty, math::max(d6_net_qty) AS max_qty, math::min(d6_net_qty) AS min_qty, math::max(d5_cogs) AS max_cogs FROM sl WHERE a_pkg != NONE GROUP BY pkg;

DEFINE TABLE OVERWRITE v_sl_from AS SELECT a_from AS inv_line, d8_is_contract_backed AS is_contract_backed, math::sum(d6_net_qty) AS total_qty, math::sum(d7_impact_qty * d5_cogs * (a_from.a_invoice.a_fx_rate ?? 1.0dec)) AS total_val FROM sl WHERE record::tb(a_from) = 'invoice_line' GROUP BY inv_line, is_contract_backed;
DEFINE TABLE OVERWRITE v_sl_to AS SELECT a_to AS inv_line, d8_is_contract_backed AS is_contract_backed, math::sum(d6_net_qty) AS total_qty, math::sum(d7_impact_qty * d5_cogs * (a_to.a_invoice.a_fx_rate ?? 1.0dec)) AS total_val FROM sl WHERE record::tb(a_to) = 'invoice_line' GROUP BY inv_line, is_contract_backed;

DEFINE TABLE OVERWRITE v_bi_sl_item AS SELECT d4_item AS item, d8_is_contract_backed AS is_contract_backed, math::sum(d7_impact_qty * d5_cogs * (a_from.a_invoice.a_fx_rate ?? a_to.a_invoice.a_fx_rate ?? 1.0dec)) AS total_val, math::mean(d5_cogs) AS mean_cogs, math::variance(d5_cogs) AS var_cogs, math::variance(d6_net_qty) AS var_qty FROM sl GROUP BY item, is_contract_backed;

-- 5. WAREHOUSE MATRIX (Absolute Physical Limits)
DEFINE TABLE OVERWRITE v_sl_matrix_in AS SELECT a_to AS node, d4_item AS item, math::sum(d7_impact_qty) AS qty, math::sum(d7_impact_qty * d5_cogs * (a_from.a_invoice.a_fx_rate ?? a_to.a_invoice.a_fx_rate ?? 1.0dec)) AS cogs_val FROM sl WHERE d2_p_to = 1 GROUP BY node, item;
DEFINE TABLE OVERWRITE v_sl_matrix_out AS SELECT a_from AS node, d4_item AS item, math::sum(d7_impact_qty) AS qty, math::sum(d7_impact_qty * d5_cogs * (a_from.a_invoice.a_fx_rate ?? a_to.a_invoice.a_fx_rate ?? 1.0dec)) AS cogs_val FROM sl WHERE d1_p_from = 1 GROUP BY node, item;

-- 6. TAX ACCOUNTS
DEFINE TABLE OVERWRITE v_tl_invl AS SELECT a_invoice_line AS invoice_line, math::sum(d2_raw_tax) AS raw_tax, math::sum(d3_net_tax) AS net_tax FROM tax_line GROUP BY invoice_line;
DEFINE TABLE OVERWRITE v_tl_acc AS SELECT a_tax_account AS tax_account, d1_vector AS vector, math::sum(d3_net_tax * (a_invoice_line.a_invoice.a_fx_rate ?? 1.0dec)) AS tax_base_curr, math::mean(a_rate) AS mean_rate, math::variance(a_rate) AS var_rate FROM tax_line GROUP BY tax_account, vector;

-- 7. ADJUSTMENT TARGETS
DEFINE TABLE OVERWRITE v_adj_target AS SELECT a_target AS target, math::sum(a_delta) AS delta FROM adjustment_line GROUP BY target;
DEFINE TABLE OVERWRITE v_adj_note AS SELECT a_note AS note, d1_target_type AS target_type, math::sum(a_delta) AS delta FROM adjustment_line GROUP BY note, target_type;