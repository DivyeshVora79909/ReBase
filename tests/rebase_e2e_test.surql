USE NS main DB main;

-- =====================================================================
-- STEP 1: CREATE THE ANCHORS (Level 0)
-- =====================================================================
CREATE org:tech_supplier SET name = "Tech Distro Inc.", currency = "USD";
CREATE org:acme_customer SET name = "Acme Corp", currency = "EUR";

CREATE treasury:main SET name = "Central Bank", currency = "USD";
CREATE acc:cogs SET name = "Cost of Goods Sold", type = "expense";
CREATE tax_account:sales_tax SET name = "Sales Tax Payable";

CREATE warehouse:main SET name = "Central Fulfillment";
CREATE stock_acc:vendor SET name = "Vendor Transit";
CREATE stock_acc:customer SET name = "Customer Transit";

CREATE item:laptop SET name = "Pro Laptop", is_service = false, default_cogs = 0dec;
CREATE item:setup SET name = "Setup Service", is_service = true;

SELECT '1. ANCHORS CREATED' AS step;


-- =====================================================================
-- STEP 2: PURCHASE INVENTORY (Level 1 & 2)
-- Buying 10 Laptops at $1000 each.
-- =====================================================================
CREATE invoice:pur_1 SET org = org:tech_supplier, raw_type = "purchase";
CREATE invoice_line:il_pur_1 SET invoice = invoice:pur_1, item = item:laptop, raw_qty = 10dec, raw_unit_price = 1000dec;

-- PROOF: Invoice aggregates the $10,000. Item sees 10 inbound financial qty.
SELECT '2. PURCHASE INTENT' AS step, zz.grand_total FROM invoice:pur_1;


-- =====================================================================
-- STEP 3: PHYSICAL RECEIVE (Level 3)
-- Moving stock from the contract (inv_line) to the Warehouse.
-- =====================================================================
CREATE sl:in_1 SET from = invoice_line:il_pur_1, to = warehouse:main, raw_qty = 10dec;

-- PROOF: Matrix Shield allows it. Item Avg COGS calculates. Warehouse fills up.
SELECT '3. INVENTORY RECEIVED' AS step, zz.physical_stock, zz.avg_cogs FROM item:laptop;
SELECT '3. WAREHOUSE STOCK' AS step, zz.global_matrix_stock FROM warehouse:main;


-- =====================================================================
-- STEP 4: SALES & TAXES (Level 1, 2, 3)
-- Selling 2 Laptops at $2000 each + 10% Tax.
-- =====================================================================
CREATE invoice:sale_1 SET org = org:acme_customer, raw_type = "sales";
CREATE invoice_line:il_sale_1 SET invoice = invoice:sale_1, item = item:laptop, raw_qty = 2dec, raw_unit_price = 2000dec;
CREATE tax_line:tl_1 SET invoice_line = invoice_line:il_sale_1, tax_account = tax_account:sales_tax, raw_rate = 10dec;

-- PROOF: Tax calculates automatically. Invoice totals $4400.
SELECT '4. SALES TOTALS' AS step, zzzzz_out.sales_base_value, zzzzz_out.sales_tax_value, zz.grand_total FROM invoice:sale_1;


-- =====================================================================
-- STEP 5: PHYSICAL SHIP (Level 3 Matrix Check)
-- Moving stock from Warehouse to the Sales Contract.
-- =====================================================================
CREATE package_note:pkg_1 SET invoice = invoice:sale_1, tracking = "TRACK-123";
CREATE sl:out_1 SET from = warehouse:main, to = invoice_line:il_sale_1, pkg = package_note:pkg_1, raw_qty = 2dec;

-- PROOF: Warehouse drops to 8. COGS ledger hits $2000 (2 * 1000 avg_cost).
SELECT '5. WH REMAINING' AS step, zz.global_matrix_stock FROM warehouse:main;
SELECT '5. COGS EXPENSE' AS step, zz.balance FROM acc:cogs;


-- =====================================================================
-- STEP 6: PAYMENT & DAG CHECK
-- Acme pays the $4400 invoice.
-- =====================================================================
CREATE payment:pay_1 SET from = org:acme_customer, to = treasury:main, raw_amount = 4400dec, fx_rate = 1.0dec;
CREATE payment_allocation:pa_1 SET payment = payment:pay_1, invoice = invoice:sale_1, raw_amount = 4400dec;

-- PROOF: Treasury hits 4400. Acme's Net Financial Position hits 0. Invoice allocation shield hits 0.
SELECT '6. TREASURY' AS step, zz.balance FROM treasury:main;
SELECT '6. ORG BALANCE' AS step, zz.net_financial_position FROM org:acme_customer;
SELECT '6. INV UNPAID' AS step, zzz.allocation_shield FROM invoice:sale_1;


-- =====================================================================
-- STEP 7: THE ZIG-ZAG DELTA RIPPLE
-- The Vendor gives us a retroactive discount on the laptops. Drops price by $100.
-- =====================================================================
CREATE adjustment_note:an_1 SET org = org:tech_supplier;
CREATE adjustment_line:al_1 SET adjustment_note = adjustment_note:an_1, invoice_line = invoice_line:il_pur_1, delta_qty = 0dec, delta_cogs = -100dec;

-- PROOF: Watch the engine ripple!
-- 1. Invoice Line cost drops from 1000 to 900.
-- 2. Item Avg COGS recalculates from 1000 to 900.
-- 3. The Downward Ping wakes up SL! The COGS expense for the sale we already made drops from 2000 to 1800!
SELECT '7. NEW AVG COGS' AS step, zz.avg_cogs FROM item:laptop;
SELECT '7. NEW COGS EXPENSE' AS step, zz.balance FROM acc:cogs;
SELECT '7. VENDOR OWED' AS step, zz.net_financial_position FROM org:tech_supplier;


-- =====================================================================
-- STEP 8: NEGATIVE DESTRUCTIVE TESTS
-- (Uncomment to test the physical shields)
-- =====================================================================

-- TEST A: MATRIX SHIELD (Try to ship 100 laptops when we only have 8)
-- EXPECTED: THROW "ASSERT $value = true failed"
-- CREATE sl:fail_1 SET from = warehouse:main, to = stock_acc:customer, item = item:laptop, raw_qty = 100dec;

-- TEST B: DAG FRACTURE (Try to allocate Acme's money to Tech Distro's invoice)
-- EXPECTED: THROW "UX_ERR: DAG Fracture. Payment and Invoice do not share Org."
-- CREATE payment_allocation:fail_2 SET payment = payment:pay_1, invoice = invoice:pur_1, raw_amount = 1dec;

-- TEST C: VECTOR SHIELD (Try to receive inbound goods on a Sales Invoice)
-- EXPECTED: THROW "PHYSICS_ERR: Sales invoice cannot have inbound deliveries."
-- CREATE sl:fail_3 SET from = stock_acc:vendor, to = invoice_line:il_sale_1, raw_qty = 1dec;