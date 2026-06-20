-- ReBase integrity smoke test
-- Run this as a super admin / test admin session.
-- This script is split into:
--   1) cleanup
--   2) positive-path integrity checks
--   3) intentional negative checks at the very end
--
-- Notes:
-- - The negative checks stop execution when they hit the expected THROW.
-- - Keep them at the end.
-- - v_sl_stock currently looks suspicious because it sums z_stock_impact_in + z_stock_impact_out
--   for the same row, which often collapses to zero. This test file will expose that.

USE NS main DB main;

-- =========================================================
-- 0. CLEANUP (safe to rerun)
-- =========================================================

DELETE adjustment_line:test_adj_line;
DELETE adjustment_note:test_adj_note;

DELETE payment_allocation:test_alloc;

DELETE delivery_line:test_delivery;
DELETE tax_line:test_tax_line;
DELETE invoice_line:test_sale_line;
DELETE invoice_line:test_buy_line;

DELETE payment:test_fund_treasury;
DELETE payment:test_treasury_to_acc;
DELETE payment:test_org_to_tax;

DELETE invoice:test_sale;
DELETE invoice:test_buy;
DELETE stock_ledger:test_stock_ledger;

DELETE item:test_sale_item;
DELETE item:test_stock_item;
DELETE service:test_service;

DELETE org:test_org;
DELETE treasury:test_treasury;
DELETE acc:test_acc;
DELETE tax:test_tax;
DELETE warehouse:test_warehouse;
DELETE stock_acc:test_stock_acc;

-- =========================================================
-- 1. BASE NODES
-- =========================================================

CREATE org:test_org SET
    name = "Test Org",
    owned_by = groups:root;

CREATE treasury:test_treasury SET
    name = "Test Treasury",
    currency = "USD",
    owned_by = groups:root;

CREATE acc:test_acc SET
    name = "Test Acc",
    type = "equity",
    owned_by = groups:root;

CREATE tax:test_tax SET
    name = "Test Tax",
    owned_by = groups:root;

CREATE warehouse:test_warehouse SET
    name = "Test Warehouse",
    owned_by = groups:root;

CREATE stock_acc:test_stock_acc SET
    name = "Test Stock Acc",
    owned_by = groups:root;

CREATE item:test_sale_item SET
    name = "Sale Item",
    cog = 0dec,
    owned_by = groups:root;

CREATE item:test_stock_item SET
    name = "Stock Item",
    cog = 0dec,
    owned_by = groups:root;

CREATE service:test_service SET
    name = "Test Service",
    owned_by = groups:root;

SELECT
    id, name, owned_by, created_by, created_at, updated_at
FROM org:test_org;

SELECT
    id, name, currency, total_in, total_out, balance, owned_by, created_by, created_at, updated_at
FROM treasury:test_treasury;

SELECT
    id, name, type, total_in, total_out, balance, owned_by, created_by, created_at, updated_at
FROM acc:test_acc;

SELECT
    id, name, total_accrued, total_in, total_out, balance, owned_by, created_by, created_at, updated_at
FROM tax:test_tax;

-- =========================================================
-- 2. MONEY MOVEMENT / VIEW INTEGRITY
-- =========================================================

CREATE payment:test_fund_treasury SET
    from = org:test_org,
    to = treasury:test_treasury,
    amount = 1000dec,
    currency = "USD",
    fx_rate = 1dec,
    status = "posted",
    owned_by = groups:root;

CREATE payment:test_treasury_to_acc SET
    from = treasury:test_treasury,
    to = acc:test_acc,
    amount = 350dec,
    currency = "USD",
    fx_rate = 1dec,
    status = "posted",
    owned_by = groups:root;

CREATE payment:test_org_to_tax SET
    from = org:test_org,
    to = tax:test_tax,
    amount = 120dec,
    currency = "USD",
    fx_rate = 1dec,
    status = "posted",
    owned_by = groups:root;

SELECT * FROM v_payment_in;
SELECT * FROM v_payment_out;

SELECT
    id, total_in, total_out, balance
FROM treasury:test_treasury;

SELECT
    id, total_in, total_out, balance
FROM acc:test_acc;

SELECT
    id, total_in, total_out, total_accrued, balance
FROM tax:test_tax;

-- =========================================================
-- 3. SALES INVOICE / TAX / ALLOCATION
-- =========================================================

CREATE invoice:test_sale SET
    org = org:test_org,
    type = "sales",
    status = "draft",
    owned_by = groups:root;

CREATE invoice_line:test_sale_line SET
    invoice = invoice:test_sale,
    target = item:test_sale_item,
    qty = 2dec,
    unit_price = 200dec;

CREATE tax_line:test_tax_line SET
    invoice_line = invoice_line:test_sale_line,
    tax = tax:test_tax,
    rate = 18dec;

CREATE payment_allocation:test_alloc SET
    payment = payment:test_fund_treasury,
    invoice = invoice:test_sale,
    amount = 236dec;

SELECT * FROM v_tax_to_line;
SELECT * FROM v_alloc_outbound;
SELECT * FROM v_alloc_to_invoice;
SELECT * FROM v_inv_totals;

SELECT
    id, invoice, target, qty, unit_price,
    z_countable_qty, z_countable_base,
    invoice_status, invoice_type,
    z_active_qty, z_active_base,
    total_delivered_qty, delivery_shield,
    created_at, updated_at
FROM invoice_line:test_sale_line;

SELECT
    id, invoice_line, tax, rate,
    invoice_status, invoice_type,
    line_active_base,
    z_calculated_tax, z_active_tax, z_liability_impact,
    created_at, updated_at
FROM tax_line:test_tax_line;

SELECT
    id, org, total_base, total_tax, z_total_amount, total_paid, status
FROM invoice:test_sale;

SELECT
    id, total_allocated, status
FROM payment:test_fund_treasury;

-- Post invoice to activate the state machine and lock rules.
UPDATE invoice:test_sale SET status = "posted";

SELECT
    id, invoice, invoice_status, z_active_base, updated_at
FROM invoice_line:test_sale_line;

SELECT
    id, invoice_line, invoice_status, z_active_tax, z_liability_impact, updated_at
FROM tax_line:test_tax_line;

SELECT
    id, total_base, total_tax, z_total_amount, total_paid, status, updated_at
FROM invoice:test_sale;

SELECT
    id, total_accrued, balance
FROM tax:test_tax;

-- Adjustment that changes the active quantity/base/tax without touching the locked raw line.
CREATE adjustment_note:test_adj_note SET
    org = org:test_org,
    status = "posted",
    owned_by = groups:root;

CREATE adjustment_line:test_adj_line SET
    adjustment_note = adjustment_note:test_adj_note,
    invoice_line = invoice_line:test_sale_line,
    tax_line = tax_line:test_tax_line,
    delta_qty = -1dec,
    delta_amount = 0dec,
    delta_tax = -36dec,
    owned_by = groups:root;

SELECT * FROM v_adj_to_line;
SELECT * FROM v_adj_to_tax;
SELECT * FROM v_inv_totals;

SELECT
    id, qty, unit_price, delta_qty, delta_amount,
    z_countable_qty, z_countable_base, z_active_qty, z_active_base,
    total_delivered_qty, delivery_shield, updated_at
FROM invoice_line:test_sale_line;

SELECT
    id, rate, delta_tax, z_calculated_tax, z_active_tax, z_liability_impact, updated_at
FROM tax_line:test_tax_line;

SELECT
    id, total_base, total_tax, z_total_amount, total_paid, status, updated_at
FROM invoice:test_sale;

-- =========================================================
-- 4. STOCK / DELIVERY / PURCHASE FLOW
-- =========================================================

CREATE invoice:test_buy SET
    org = org:test_org,
    type = "purchase",
    status = "draft",
    owned_by = groups:root;

CREATE invoice_line:test_buy_line SET
    invoice = invoice:test_buy,
    target = item:test_stock_item,
    qty = 10dec,
    unit_price = 50dec;

CREATE delivery_line:test_delivery SET
    invoice_line = invoice_line:test_buy_line,
    qty = 10dec,
    status = "delivered";

CREATE stock_ledger:test_stock_ledger SET
    from = warehouse:test_warehouse,
    to = stock_acc:test_stock_acc,
    item = item:test_stock_item,
    qty = 8dec,
    status = "posted";

SELECT * FROM v_dl_to_line;
SELECT * FROM v_dl_stock;
SELECT * FROM v_sl_stock;

SELECT
    id, invoice, target, qty, status,
    invoice_type, z_delivered_qty, z_stock_impact, updated_at
FROM delivery_line:test_delivery;

SELECT
    id, total_dl_impact, total_sl_impact, stock_qty, updated_at
FROM item:test_stock_item;

-- =========================================================
-- 5. DYNAMIC STATE CHECKS
-- =========================================================
-- Trigger an invoice header update to verify child touch propagation.
UPDATE invoice:test_buy SET status = "posted";

SELECT
    id, status, updated_at
FROM invoice:test_buy;

SELECT
    id, invoice_status, z_active_base, updated_at
FROM invoice_line:test_buy_line;

SELECT
    id, invoice_line, invoice_status, invoice_type, z_stock_impact, updated_at
FROM delivery_line:test_delivery;

SELECT
    id, total_dl_impact, total_sl_impact, stock_qty, updated_at
FROM item:test_stock_item;

-- =========================================================
-- 6. INTENTIONAL NEGATIVE TESTS (run last)
-- =========================================================
-- These should throw and prove the guards are working.

-- 6.1 locked posted invoice line
UPDATE invoice_line:test_sale_line SET qty = 99dec;

-- 6.2 locked posted tax line
-- UPDATE tax_line:test_tax_line SET rate = 25dec;

-- 6.3 locked delivered delivery line
-- UPDATE delivery_line:test_delivery SET qty = 99dec;

-- 6.4 DAG self-cycle should fail
-- RELATE groups:root -> link -> groups:root;

-- 6.5 orphan prevention should fail on the last edge for the auth user
-- DELETE link WHERE in = groups:root AND out = user:root;
