USE NS main DB main;

-- =========================================================
-- ReBase end-to-end commerce/accounting test
-- Assumes schema from 01_auth_rbac.surql .. 07_events.surql is already loaded.
-- Run on a clean test database, or ensure the fixed ids below are unused.
-- =========================================================

-- ---------------------------------------------------------
-- 0) Core master data
-- ---------------------------------------------------------
CREATE company_settings:main SET
    base_currency = "INR",
    invoice_lock_after = 30d;

CREATE expense_account:fx_losses SET
    name = "FX Gains/Losses",
    owned_by = groups:root;

CREATE expense_account:raw_materials SET
    name = "Raw Materials Expense",
    owned_by = groups:root;

CREATE treasury_account:cash SET
    name = "Cash",
    currency = "INR",
    owned_by = groups:root;

CREATE treasury_account:bank SET
    name = "Bank",
    currency = "INR",
    owned_by = groups:root;

CREATE equity_account:share_capital SET
    name = "Share Capital",
    owned_by = groups:root;

CREATE trade_account:vendor_a SET
    name = "Vendor A",
    tax_id = "GSTIN-VENDOR-A",
    owned_by = groups:root;

CREATE trade_account:customer_a SET
    name = "Customer A",
    tax_id = "GSTIN-CUSTOMER-A",
    owned_by = groups:root;

CREATE location_node:main SET
    name = "Main Warehouse",
    owned_by = groups:root;

CREATE location_node:secondary SET
    name = "Secondary Warehouse",
    owned_by = groups:root;

CREATE inventory_node:raw_steel SET
    name = "Raw Steel",
    sku = "RAW-STEEL",
    owned_by = groups:root;

CREATE inventory_node:finished_widget SET
    name = "Finished Widget",
    sku = "WIDGET-001",
    owned_by = groups:root;

CREATE catalog_node:installation_service SET
    name = "Installation Service",
    owned_by = groups:root;

CREATE tax_node:gst18 SET
    name = "GST 18%",
    behavior = "add",
    owned_by = groups:root;

CREATE tax_node:tds2 SET
    name = "TDS 2%",
    behavior = "subtract",
    owned_by = groups:root;

-- ---------------------------------------------------------
-- 1) Capital investment
-- ---------------------------------------------------------
CREATE financial_adjustment:capital_001 SET
    kind = "capital",
    from_node = equity_account:share_capital,
    to_node = treasury_account:cash,
    amount = 100000dec,
    currency = "INR",
    owned_by = groups:root;

-- ---------------------------------------------------------
-- 2) Bring in raw materials and catalog/service items from vendor
-- ---------------------------------------------------------
CREATE vendor_bill:vb_raw SET
    status = "posted",
    party_ref = trade_account:vendor_a,
    currency = "INR",
    fx_rate = 1dec,
    owned_by = groups:root;

CREATE vendor_bill_line SET
    bill_ref = vendor_bill:vb_raw,
    item_ref = inventory_node:raw_steel,
    location_ref = location_node:main,
    qty = 100dec,
    unit_cost = 20dec,
    taxes = [
        { tax_ref: tax_node:gst18, rate: 18dec }
    ];

CREATE vendor_bill_line SET
    bill_ref = vendor_bill:vb_raw,
    item_ref = catalog_node:installation_service,
    location_ref = location_node:main,
    qty = 1dec,
    unit_cost = 500dec,
    taxes = [
        { tax_ref: tax_node:gst18, rate: 18dec }
    ];

-- ---------------------------------------------------------
-- 3) Manufacture finished goods
-- ---------------------------------------------------------
CREATE production_run:pr1 SET
    status = "draft",
    owned_by = groups:root;

CREATE production_line SET
    run_ref = production_run:pr1,
    item_ref = inventory_node:raw_steel,
    location_ref = location_node:main,
    direction = "consume",
    qty = 40dec;

CREATE production_line SET
    run_ref = production_run:pr1,
    item_ref = inventory_node:finished_widget,
    location_ref = location_node:main,
    direction = "yield",
    qty = 10dec;

-- ---------------------------------------------------------
-- 4) Sales order + invoice with taxes
-- ---------------------------------------------------------
CREATE order:ord1 SET
    status = "draft",
    party_ref = trade_account:customer_a,
    currency = "INR",
    owned_by = groups:root;

CREATE order_line SET
    order_ref = order:ord1,
    item_ref = inventory_node:finished_widget,
    qty = 2dec,
    unit_price = 250dec;

CREATE order_line SET
    order_ref = order:ord1,
    item_ref = catalog_node:installation_service,
    qty = 1dec,
    unit_price = 500dec;

CREATE invoice:inv1 SET
    status = "posted",
    party_ref = trade_account:customer_a,
    currency = "INR",
    fx_rate = 1.10dec,
    owned_by = groups:root;

CREATE invoice_line SET
    invoice_ref = invoice:inv1,
    item_ref = inventory_node:finished_widget,
    location_ref = location_node:main,
    qty = 2dec,
    unit_price = 250dec,
    taxes = [
        { tax_ref: tax_node:gst18, rate: 18dec }
    ];

CREATE invoice_line SET
    invoice_ref = invoice:inv1,
    item_ref = catalog_node:installation_service,
    location_ref = location_node:main,
    qty = 1dec,
    unit_price = 500dec,
    taxes = [
        { tax_ref: tax_node:gst18, rate: 18dec },
        { tax_ref: tax_node:tds2, rate: 2dec }
    ];

-- ---------------------------------------------------------
-- 5) Payments and allocations
--    These should also trigger FX gain/loss adjustments.
-- ---------------------------------------------------------
CREATE payment:pay1 SET
    direction = "inbound",
    treasury_ref = treasury_account:cash,
    amount = 5000dec,
    currency = "INR",
    fx_rate = 1.12dec,
    owned_by = groups:root;

CREATE payment_allocation SET
    payment_ref = payment:pay1,
    target_ref = invoice:inv1,
    pay_currency_amount = 1000dec,
    doc_currency_amount = 1190dec;

CREATE payment_allocation SET
    payment_ref = payment:pay1,
    target_ref = vendor_bill:vb_raw,
    pay_currency_amount = 2500dec,
    doc_currency_amount = 2950dec;

-- ---------------------------------------------------------
-- 6) Inventory exchange
-- ---------------------------------------------------------
CREATE exchange:ex1 SET
    status = "draft",
    owned_by = groups:root;

CREATE exchange_line SET
    exchange_ref = exchange:ex1,
    item_ref = inventory_node:finished_widget,
    from_location_ref = location_node:main,
    to_location_ref = location_node:secondary,
    qty = 2dec;

-- ---------------------------------------------------------
-- 7) Read back views and core records
-- ---------------------------------------------------------
SELECT * FROM company_settings:main;
SELECT * FROM financial_adjustment:capital_001;
SELECT * FROM vendor_bill:vb_raw;
SELECT * FROM order:ord1;
SELECT * FROM invoice:inv1;
SELECT * FROM payment:pay1;
SELECT * FROM exchange:ex1;

SELECT * FROM v_vendor_bill_totals WHERE bill_ref = vendor_bill:vb_raw;
SELECT * FROM v_invoice_totals WHERE invoice_ref = invoice:inv1;
SELECT * FROM v_payment_outbound WHERE payment_ref = payment:pay1;
SELECT * FROM v_payment_allocations WHERE target_ref = invoice:inv1 OR target_ref = vendor_bill:vb_raw;
SELECT * FROM v_stock_in WHERE item_ref = inventory_node:raw_steel AND location_ref = location_node:main;
SELECT * FROM v_stock_out WHERE item_ref = inventory_node:finished_widget AND location_ref = location_node:main;
SELECT * FROM v_exchange_out WHERE item_ref = inventory_node:finished_widget AND from_location_ref = location_node:main;
SELECT * FROM v_exchange_in WHERE item_ref = inventory_node:finished_widget AND to_location_ref = location_node:secondary;
SELECT * FROM v_production_totals WHERE item_ref = inventory_node:raw_steel OR item_ref = inventory_node:finished_widget;

-- ---------------------------------------------------------
-- 8) Expected-failure enforcer tests
--    Run these one at a time. Each failure is intentional.
-- ---------------------------------------------------------

-- 8.1 Field assertion: invalid enum
-- CREATE tax_node:bad_tax SET name = "Bad Tax", behavior = "multiply", owned_by = groups:root;

-- 8.2 Stock police: sale with insufficient stock
-- CREATE invoice_line SET
--     invoice_ref = invoice:inv1,
--     item_ref = inventory_node:raw_steel,
--     location_ref = location_node:secondary,
--     qty = 9999dec,
--     unit_price = 1dec,
--     taxes = [];

-- 8.3 Payment overpayment: invoice allocation above invoice total
-- CREATE payment:pay_over_invoice SET
--     direction = "inbound",
--     treasury_ref = treasury_account:bank,
--     amount = 100dec,
--     currency = "INR",
--     fx_rate = 1dec,
--     owned_by = groups:root;
--
-- CREATE payment_allocation SET
--     payment_ref = payment:pay_over_invoice,
--     target_ref = invoice:inv1,
--     pay_currency_amount = 100dec,
--     doc_currency_amount = 999999dec;

-- 8.4 Payment over-allocation: more cash allocated than payment contains
-- CREATE payment:pay_small SET
--     direction = "inbound",
--     treasury_ref = treasury_account:bank,
--     amount = 50dec,
--     currency = "INR",
--     fx_rate = 1dec,
--     owned_by = groups:root;
--
-- CREATE payment_allocation SET
--     payment_ref = payment:pay_small,
--     target_ref = trade_account:customer_a,
--     pay_currency_amount = 60dec,
--     doc_currency_amount = 60dec;

-- 8.5 Dynamic lockout: update posted invoice after lockout is zero
-- UPDATE company_settings:main SET invoice_lock_after = 0s;
-- UPDATE invoice:inv1 SET status = "void";

-- 8.6 Role escalation: group role outside auth permissions
-- CREATE groups:bad_group SET
--     name = "Bad Group",
--     role = ["invoice_select", "nonexistent_permission"];

-- 8.7 Cycle prevention: second RELATE should fail
-- CREATE user:cycle_a SET name = "Cycle A", email = "cycle-a@example.com";
-- CREATE user:cycle_b SET name = "Cycle B", email = "cycle-b@example.com";
-- RELATE user:cycle_a -> link -> user:cycle_b;
-- RELATE user:cycle_b -> link -> user:cycle_a;

-- 8.8 Non-leaf delete: delete a user with children
-- DELETE user:cycle_a;

-- 8.9 Orphan prevention: delete last edge of a record that still needs a link
-- DELETE link WHERE in = user:cycle_a OR out = user:cycle_a;

-- 8.10 Rate limit: run this twice immediately; the second run should fail
-- UPDATE user:root SET last_refreshed_at = time::now();
-- UPDATE user:root SET last_refreshed_at = time::now();
