-- =========================================================
-- ACCOUNTING / INVENTORY TESTS ONLY
-- Logged in as root admin
-- =========================================================

-- =========================================================
-- 1. MASTER DATA
-- =========================================================

CREATE org:test_org SET
    name = 'Test Org',
    owned_by = groups:root;

CREATE treasury:test_treasury SET
    name = 'Main Treasury',
    owned_by = groups:root;

CREATE acc:test_acc SET
    name = 'Expense Account',
    owned_by = groups:root;

CREATE warehouse:test_wh SET
    name = 'Main Warehouse',
    owned_by = groups:root;

CREATE stock_acc:test_stock SET
    name = 'Stock Account',
    owned_by = groups:root;

CREATE item:test_item SET
    name = 'Rice Bag',
    owned_by = groups:root;


-- =========================================================
-- 2. INITIAL STOCK INJECTION
-- Infinite source -> warehouse
-- =========================================================

CREATE sl:stock_in_1 SET
    active = true,
    from = stock_acc:test_stock,
    to = warehouse:test_wh,
    item = item:test_item,
    qty = 100dec,
    owned_by = groups:root;

SELECT
    id,
    stock_balance
FROM warehouse:test_wh;

SELECT
    id,
    turnover,
    average_cogs
FROM item:test_item;


-- =========================================================
-- 3. PURCHASE INVOICE
-- =========================================================

CREATE invoice:purchase_1 SET
    active = true,
    org = org:test_org,
    tax = 0.05,
    type = 'purchase',
    owned_by = groups:root;

CREATE invoice_line:purchase_line_1 SET
    inv = invoice:purchase_1,
    item = item:test_item,
    qty = 50dec,
    cogs = 40dec,
    owned_by = groups:root;

SELECT
    id,
    v_ordered_value,
    v_remaining_value,
    v_tax,
    z_active_amount
FROM invoice:purchase_1;

SELECT
    id,
    z_total_value,
    z_remaining_value,
    z_qty_remaining
FROM invoice_line:purchase_line_1;


-- =========================================================
-- 4. SALES INVOICE
-- =========================================================

CREATE invoice:sales_1 SET
    active = true,
    org = org:test_org,
    tax = 0.18,
    type = 'sales',
    owned_by = groups:root;

CREATE invoice_line:sales_line_1 SET
    inv = invoice:sales_1,
    item = item:test_item,
    qty = 10dec,
    cogs = 100dec,
    owned_by = groups:root;

SELECT
    id,
    v_ordered_value,
    v_remaining_value,
    v_tax,
    z_active_amount
FROM invoice:sales_1;


-- =========================================================
-- 5. STOCK DELIVERY AGAINST SALES
-- Warehouse -> customer
-- =========================================================

CREATE sl:delivery_1 SET
    active = true,
    from = warehouse:test_wh,
    to = stock_acc:test_stock,
    inv_line = invoice_line:sales_line_1,
    qty = 10dec,
    owned_by = groups:root;

SELECT
    id,
    v_delivered_qty,
    z_qty_remaining,
    z_remaining_value
FROM invoice_line:sales_line_1;

SELECT
    id,
    stock_balance
FROM warehouse:test_wh;


-- =========================================================
-- 6. CUSTOMER PAYMENT
-- =========================================================

CREATE payment:payment_1 SET
    active = true,
    amount = 1180dec,
    from = org:test_org,
    to = treasury:test_treasury,
    date = time::now(),
    owned_by = groups:root;

SELECT
    id,
    balance
FROM treasury:test_treasury;

SELECT
    id,
    net_money,
    total_invoices
FROM org:test_org;


-- =========================================================
-- 7. PAYMENT ALLOCATION
-- =========================================================

CREATE payment_allocation:alloc_1 SET
    payment = payment:payment_1,
    invoice = invoice:sales_1,
    amount = 1180dec,
    owned_by = groups:root;

SELECT
    id,
    z_total_allocated,
    z_active_amount
FROM payment:payment_1;

SELECT
    id,
    z_total_allocated,
    z_active_amount
FROM invoice:sales_1;


-- =========================================================
-- 8. NEGATIVE TESTS
-- RUN THESE ONE BY ONE
-- EACH SHOULD FAIL
-- =========================================================

-- ---------------------------------------------------------
-- A. OVER ALLOCATION
-- Invoice total is 1180, adding more should fail
-- ---------------------------------------------------------

-- CREATE payment_allocation:bad_alloc_1 SET
--     payment = payment:payment_1,
--     invoice = invoice:sales_1,
--     amount = 1dec,
--     owned_by = groups:root;


-- ---------------------------------------------------------
-- B. NEGATIVE STOCK
-- Warehouse currently has 90.
-- Attempting 999 should fail.
-- ---------------------------------------------------------

-- CREATE sl:bad_stock_1 SET
--     active = true,
--     from = warehouse:test_wh,
--     to = stock_acc:test_stock,
--     item = item:test_item,
--     qty = 999dec,
--     owned_by = groups:root;


-- ---------------------------------------------------------
-- C. PAYMENT WITHOUT TREASURY
-- Should fail assert_treasury
-- ---------------------------------------------------------

-- CREATE payment:bad_payment_1 SET
--     active = true,
--     amount = 100dec,
--     from = org:test_org,
--     to = acc:test_acc,
--     owned_by = groups:root;


-- ---------------------------------------------------------
-- D. OVER DELIVERY
-- Invoice line only ordered 10
-- ---------------------------------------------------------

-- CREATE sl:bad_delivery_1 SET
--     active = true,
--     from = warehouse:test_wh,
--     to = stock_acc:test_stock,
--     inv_line = invoice_line:sales_line_1,
--     qty = 1dec,
--     owned_by = groups:root;


-- =========================================================
-- 9. FINAL SYSTEM STATE
-- =========================================================

SELECT * FROM warehouse:test_wh;
SELECT * FROM treasury:test_treasury;
SELECT * FROM item:test_item;
SELECT * FROM invoice:sales_1;
SELECT * FROM invoice_line:sales_line_1;
SELECT * FROM payment:payment_1;
SELECT * FROM payment_allocation:alloc_1;