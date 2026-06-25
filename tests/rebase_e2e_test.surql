-- ------------------------------------------------------------------------------
-- PHASE 0: BOOTSTRAP ANCHORS
-- ------------------------------------------------------------------------------
CREATE org:vendor SET a_in_name = 'Supplier Inc', owned_by = groups:root;
CREATE org:customer SET a_in_name = 'Client LLC', owned_by = groups:root;
CREATE org:rogue SET a_in_name = 'Rogue Corp', owned_by = groups:root;

CREATE treasury:main SET a_in_name = 'HQ Bank', owned_by = groups:root;
CREATE acc:cogs SET a_in_name = 'COGS', owned_by = groups:root;
CREATE tax_account:vat SET a_in_name = 'VAT 10%', owned_by = groups:root;
CREATE warehouse:ny SET a_in_name = 'New York Depot', owned_by = groups:root;

CREATE item:alpha SET a_in_name = 'Product Alpha', a_in_cogs_acc = acc:cogs, owned_by = groups:root;
CREATE item:srv SET a_in_name = 'Consulting', a_in_is_service = true, a_in_cogs_acc = acc:cogs, owned_by = groups:root;


-- ------------------------------------------------------------------------------
-- PHASE 1: PROCUREMENT (INBOUND PHYSICS)
-- ------------------------------------------------------------------------------
CREATE invoice:pur1 SET a_in_org = org:vendor, a_in_type = 'purchase', owned_by = groups:root;
-- Buy 100 Alpha @ $50
CREATE invoice_line:il_pur1 SET a_in_invoice = invoice:pur1, a_in_item = item:alpha, a_in_qty = 100dec, a_in_price = 50dec;
-- Receive 100 Alpha into NY Warehouse
CREATE sl:recv1 SET a_in_from = invoice_line:il_pur1, a_in_to = warehouse:ny, a_in_qty = 100dec;

-- 🔍 DEBUG 1: POST-RECEIPT STATE
SELECT 'DEBUG 1A: TABLE STOCK (REALITY)' AS debug_step, d_c1_global_matrix_stock AS total_stock FROM warehouse:ny;
SELECT 'DEBUG 1B: VIEW STOCK (AGGREGATION)' AS debug_step, * FROM v_sl_node_in WHERE node = warehouse:ny;
SELECT 'DEBUG 1C: ITEM COGS' AS debug_step, f_out.actual_unit_cogs AS avg_cogs FROM item:alpha;


-- ------------------------------------------------------------------------------
-- PHASE 2: SALES (OUTBOUND PHYSICS & TAXES)
-- ------------------------------------------------------------------------------
CREATE invoice:sal1 SET a_in_org = org:customer, a_in_type = 'sales', owned_by = groups:root;
-- Sell 10 Alpha @ $100 ($1000 Base)
CREATE invoice_line:il_sal_alpha SET a_in_invoice = invoice:sal1, a_in_item = item:alpha, a_in_qty = 10dec, a_in_price = 100dec;
-- Sell 1 Service @ $200 ($200 Base)
CREATE invoice_line:il_sal_srv SET a_in_invoice = invoice:sal1, a_in_item = item:srv, a_in_qty = 1dec, a_in_price = 200dec;
-- 10% Tax on Alpha only ($100 Tax)
CREATE tax_line:tl_sal1 SET a_in_invoice_line = invoice_line:il_sal_alpha, a_in_tax_account = tax_account:vat, a_in_rate = 10dec;
CREATE package_note:pkg1 SET a_in_invoice = invoice:sal1, owned_by = groups:root;

-- 🔍 DEBUG 2: PRE-SHIPMENT INVOICE STATE
SELECT 'DEBUG 2A: PRE-SHIP INVOICE' AS debug_step, f_out.inv_grand_total AS total, f_out.tl_sales_tax AS tax FROM invoice:sal1;
SELECT 'DEBUG 2B: PRE-SHIP LINE' AS debug_step, d_c4_delivered_qty AS delivered FROM invoice_line:il_sal_alpha;

-- Ship 10 Alpha out of NY (Should trigger O(1) Matrix Guard and Package View)
CREATE sl:ship1 SET a_in_from = warehouse:ny, a_in_to = invoice_line:il_sal_alpha, a_in_qty = 10dec, a_in_pkg = package_note:pkg1;

-- 🔍 DEBUG 3: POST-SHIPMENT STATE & TIMING DIAGNOSTICS
SELECT 'DEBUG 3A: PACKAGE VIEW' AS debug_step, f_out.pkg_delivered_qty AS packaged FROM package_note:pkg1;
SELECT 'DEBUG 3B: INV LINE VIEW' AS debug_step, d_c4_delivered_qty AS delivered FROM invoice_line:il_sal_alpha;
-- VERY IMPORTANT: This checks the specific failing Materialized View from your last run
SELECT 'DEBUG 3C: THE FAILING MAT-VIEW' AS debug_step, inbound, outbound, (inbound - outbound) AS net FROM v_wh_item_stock WHERE warehouse = warehouse:ny;


-- ------------------------------------------------------------------------------
-- PHASE 4: THE DAG RIPPLE (ADJUSTMENTS)
-- ------------------------------------------------------------------------------
CREATE adjustment_note:adj1 SET a_in_org = org:customer, a_in_type = 'credit', owned_by = groups:root;
-- Drop Alpha price by -$20 (Base drops 1000 -> 800)
CREATE adjustment_line:al_alpha SET a_in_note = adjustment_note:adj1, a_in_invl = invoice_line:il_sal_alpha, a_in_delta_price = -20dec;

-- 🔍 DEBUG 4: THE PHYSICS CASCADE
-- Expected Base: $800. Expected Tax: $80. Expected Total: $800 + $200 (srv) + $80 = $1080.
SELECT 'DEBUG 4A: ADJUSTED INVOICE TOTAL' AS debug_step, f_out.inv_grand_total AS grand_total FROM invoice:sal1;
SELECT 'DEBUG 4B: ADJUSTED TAX LINE' AS debug_step, f_out.tl_sales_tax AS dynamic_tax FROM tax_line:tl_sal1;


-- ------------------------------------------------------------------------------
-- PHASE 5: FINANCIAL SETTLEMENT
-- ------------------------------------------------------------------------------
CREATE payment:pay1 SET a_in_from = org:customer, a_in_to = treasury:main, a_in_amount = 1080dec;
CREATE payment_allocation:pa1 SET a_in_payment = payment:pay1, a_in_invoice = invoice:sal1, a_in_amount = 1080dec;

-- 🔍 DEBUG 5: SETTLEMENT STATE
SELECT 'DEBUG 5A: ORG BALANCES' AS debug_step, d_c1_net_financial_position AS vendor_bal FROM org:vendor;
SELECT 'DEBUG 5B: ORG BALANCES' AS debug_step, d_c1_net_financial_position AS customer_bal FROM org:customer;
SELECT 'DEBUG 5C: INVOICE SHIELD' AS debug_step, d_c2_allocation_shield AS shield_remaining FROM invoice:sal1;


-- ------------------------------------------------------------------------------
-- PHASE 6: THE SABOTAGE GAUNTLET (PERMUTATIONS)
-- ------------------------------------------------------------------------------

-- PERMUTATION 1: Cross-Org DAG Fracture (Adjustment Note)
CREATE adjustment_note:adj_fail SET a_in_org = org:rogue, a_in_type = 'credit', owned_by = groups:root;
CREATE adjustment_line:fail_adj SET a_in_note = adjustment_note:adj_fail, a_in_invl = invoice_line:il_sal_alpha, a_in_delta_price = -1dec;
-- EXPECTED: Throws DAG FRACTURE (Note Org != Inv Line Org)

-- PERMUTATION 2: Cross-Invoice DAG Fracture (Package Note)
CREATE invoice:sal_dummy SET a_in_org = org:customer, a_in_type = 'sales', owned_by = groups:root;
CREATE package_note:pkg_fail SET a_in_invoice = invoice:sal_dummy, owned_by = groups:root;
CREATE sl:fail_pkg SET a_in_from = warehouse:ny, a_in_to = invoice_line:il_sal_alpha, a_in_qty = 1dec, a_in_pkg = package_note:pkg_fail;
-- EXPECTED: Throws DAG FRACTURE (Package Note Inv != SL Inv Target)

-- PERMUTATION 3: Physics Direction Collision (Receiving into a Sales Contract)
CREATE sl:fail_dir SET a_in_from = invoice_line:il_sal_alpha, a_in_to = warehouse:ny, a_in_qty = 1dec;
-- EXPECTED: Throws PHYSICS_ERR (Sales cannot receive inbound stock)

-- PERMUTATION 4: Physics Over-Delivery
CREATE sl:fail_over SET a_in_from = warehouse:ny, a_in_to = invoice_line:il_sal_alpha, a_in_qty = 1dec;
-- EXPECTED: Throws PHYSICS_ERR (Delivered qty exceeds net contract qty)

-- PERMUTATION 5: Physics Negative Stock / O(1) Matrix Guard
CREATE invoice_line:il_fail_stock SET a_in_invoice = invoice:sal1, a_in_item = item:alpha, a_in_qty = 5000dec, a_in_price = 1dec;
CREATE sl:fail_stock SET a_in_from = warehouse:ny, a_in_to = invoice_line:il_fail_stock, a_in_qty = 5000dec;
-- EXPECTED: Throws PHYSICS_ERR (Insufficient Physical Stock)

-- PERMUTATION 6: Financial Over-Allocation
CREATE payment:pay_fail SET a_in_from = org:customer, a_in_to = treasury:main, a_in_amount = 500dec;
CREATE payment_allocation:fail_alloc SET a_in_payment = payment:pay_fail, a_in_invoice = invoice:sal1, a_in_amount = 500dec;
-- EXPECTED: Throws UX_ERR (Exceeds invoice shield)