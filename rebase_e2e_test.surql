USE NS main DB main;

-- =========================================================
-- ReBase ERP: End-to-End Execution Test
-- Tests the Universal Ledger, O(1) Views, and Police Events.
-- =========================================================

-- ---------------------------------------------------------
-- 0) LAYER 1: MASTER DATA & CHART OF ACCOUNTS
-- ---------------------------------------------------------
CREATE ledger_account:rev SET name = "Sales Revenue", category = "revenue", owned_by = groups:root;
CREATE ledger_account:cogs SET name = "Cost of Goods Sold", category = "expense", owned_by = groups:root;
CREATE ledger_account:tax_liab SET name = "Tax Liability", category = "liability", owned_by = groups:root;
CREATE equity_account:capital SET name = "Owner Capital", owned_by = groups:root;
CREATE expense_account:fx_loss SET name = "FX Gains/Losses", owned_by = groups:root;

CREATE tax_node:gst_10 SET name = "GST 10%", behavior = "add", ledger_ref = ledger_account:tax_liab, owned_by = groups:root;

CREATE treasury_account:bank SET name = "HSBC Bank", currency = "USD", owned_by = groups:root;
CREATE trade_account:vendor_apple SET name = "Apple Inc", owned_by = groups:root;
CREATE trade_account:customer_acme SET name = "Acme Corp", owned_by = groups:root;

CREATE location_node:wh_a SET name = "Warehouse A", owned_by = groups:root;
CREATE location_node:wh_b SET name = "Warehouse B", owned_by = groups:root;

CREATE inventory_node:macbook SET 
    name = "MacBook Pro", sku = "MAC-16", 
    income_account_ref = ledger_account:rev, expense_account_ref = ledger_account:cogs, 
    owned_by = groups:root;

CREATE catalog_node:shipping SET 
    name = "Express Shipping", 
    income_account_ref = ledger_account:rev, expense_account_ref = ledger_account:cogs, 
    owned_by = groups:root;

-- ---------------------------------------------------------
-- 1) CAPITAL INJECTION (Financial Adjustment)
-- ---------------------------------------------------------
-- Proves: Manual journal entries work.
CREATE financial_adjustment:cap_1 SET 
    kind = "capital", 
    from_node = equity_account:capital, 
    to_node = treasury_account:bank, 
    amount = 100000dec, 
    currency = "USD", fx_rate = 1dec, 
    owned_by = groups:root;

-- ---------------------------------------------------------
-- 2) PROCURE TO PAY (Vendor Bill)
-- ---------------------------------------------------------
-- Proves: Purchasing adds to physical stock and creates Accounts Payable.
CREATE vendor_bill:vb_1 SET 
    party_ref = trade_account:vendor_apple, 
    currency = "USD", fx_rate = 1dec, status = "draft", owned_by = groups:root;

CREATE vendor_bill_line:vbl_1 SET 
    bill_ref = vendor_bill:vb_1, item_ref = inventory_node:macbook, location_ref = location_node:wh_a, 
    qty = 50dec, unit_cost = 1000dec;

UPDATE vendor_bill:vb_1 SET status = "posted";

-- ---------------------------------------------------------
-- 3) ORDER TO CASH (Multi-Currency Sales Invoice)
-- ---------------------------------------------------------
-- Proves: Selling physical items moves stock. Selling catalog items does not.
-- Proves: FX rate scales base_amount in the journal correctly.
CREATE invoice:inv_1 SET 
    party_ref = trade_account:customer_acme, 
    currency = "EUR", fx_rate = 1.10dec, status = "draft", owned_by = groups:root;

-- 5 MacBooks @ 2000 EUR + 10% GST
CREATE invoice_line:invl_1 SET 
    invoice_ref = invoice:inv_1, item_ref = inventory_node:macbook, location_ref = location_node:wh_a, 
    qty = 5dec, unit_price = 2000dec, 
    taxes =[{ tax_ref: tax_node:gst_10, rate: 10dec }];

-- 1 Shipping Fee @ 100 EUR (No Tax, Catalog Node)
CREATE invoice_line:invl_2 SET 
    invoice_ref = invoice:inv_1, item_ref = catalog_node:shipping, location_ref = location_node:wh_a, 
    qty = 1dec, unit_price = 100dec, taxes =[];

UPDATE invoice:inv_1 SET status = "posted";

-- ---------------------------------------------------------
-- 4) SETTLEMENT (Payment with FX Gain/Loss)
-- ---------------------------------------------------------
-- The invoice total was 11,100 EUR. Customer pays the exact 11,100 EUR.
-- BUT the Euro is stronger today (1.15 instead of 1.10). 
-- Proves: The `auto_fx_gain_loss` event automatically creates the $555 USD FX Gain.
CREATE payment:pay_1 SET 
    direction = "inbound", treasury_ref = treasury_account:bank, party_ref = trade_account:customer_acme, 
    amount = 11100dec, currency = "EUR", fx_rate = 1.15dec, status = "draft", owned_by = groups:root;

CREATE payment_allocation:pa_1 SET 
    payment_ref = payment:pay_1, target_ref = invoice:inv_1, 
    pay_currency_amount = 11100dec, doc_currency_amount = 11100dec;

UPDATE payment:pay_1 SET status = "posted";

-- ---------------------------------------------------------
-- 5) RETURNS (Adjustment Note / Credit Note)
-- ---------------------------------------------------------
-- Customer returns 1 MacBook. 
-- Proves: Stock is reversed (restocked) and revenue/AR is shrunk safely.
CREATE adjustment_note:adj_1 SET 
    party_ref = trade_account:customer_acme, status = "draft", owned_by = groups:root;

CREATE adjustment_note_line:adjl_1 SET 
    note_ref = adjustment_note:adj_1, target_line_ref = invoice_line:invl_1, 
    delta_qty = -1dec, delta_base_amount = -2000dec, 
    restock_inventory = true;

UPDATE adjustment_note:adj_1 SET status = "posted";

-- ---------------------------------------------------------
-- 6) WAREHOUSE OPERATIONS (Exchange)
-- ---------------------------------------------------------
-- Proves: Internal transfers do not touch AR/AP but successfully move stock.
CREATE exchange:exc_1 SET status = "draft", owned_by = groups:root;

CREATE exchange_line:excl_1 SET 
    exchange_ref = exchange:exc_1, item_ref = inventory_node:macbook, 
    from_location_ref = location_node:wh_a, to_location_ref = location_node:wh_b, 
    qty = 10dec;

UPDATE exchange:exc_1 SET status = "posted";

-- ---------------------------------------------------------
-- 7) THE MOMENT OF TRUTH: O(1) VIEW QUERIES
-- ---------------------------------------------------------
-- 7A: Check Warehouse A Stock. Expected: 50 (In) - 5 (Sold) + 1 (Returned) - 10 (Transferred) = 36
SELECT * FROM type::record('v_stock_balance',[inventory_node:macbook, location_node:wh_a]);

-- 7B: Check Warehouse B Stock. Expected: 10 (Transferred)
SELECT * FROM type::record('v_stock_balance',[inventory_node:macbook, location_node:wh_b]);

-- 7C: Check Customer AR Balance. 
-- Expected: EUR Total should be exactly -2000 EUR (Because they paid the 11100, but we refunded them 2000 EUR).
SELECT * FROM type::record('v_account_balance',[trade_account:customer_acme]);

-- 7D: Check the Bank Account Balance.
SELECT * FROM type::record('v_account_balance', [treasury_account:bank]);

-- ---------------------------------------------------------
-- 8) INTENTIONAL FAILURES (The CQRS Police Tests)
-- Uncomment these one by one to verify the system's defenses.
-- ---------------------------------------------------------

-- TEST 8A: Try to void an invoice that has been paid. (Should fail).
-- UPDATE invoice:inv_1 SET status = "void";

-- TEST 8B: Try to sell more stock than we have. (Should fail).
-- CREATE invoice:inv_fail SET party_ref = trade_account:customer_acme, currency = "USD", status = "draft", owned_by = groups:root;
-- CREATE invoice_line SET invoice_ref = invoice:inv_fail, item_ref = inventory_node:macbook, location_ref = location_node:wh_a, qty = 999dec, unit_price = 100dec;
-- UPDATE invoice:inv_fail SET status = "posted";

-- TEST 8C: Try to refund 10 MacBooks on a line that only sold 5. (Should fail).
-- CREATE adjustment_note_line SET note_ref = adjustment_note:adj_1, target_line_ref = invoice_line:invl_1, delta_qty = -10dec, delta_base_amount = -20000dec;

-- TEST 8D: Try to allocate $5,000 cash from a Payment that only holds $100. (Should fail).
-- CREATE payment:pay_fail SET direction = "inbound", treasury_ref = treasury_account:bank, amount = 100dec, currency = "USD", status = "draft", owned_by = groups:root;
-- CREATE payment_allocation SET payment_ref = payment:pay_fail, target_ref = invoice:inv_1, pay_currency_amount = 5000dec, doc_currency_amount = 5000dec;