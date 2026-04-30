USE NS main DB main;

-- ============================================================
-- FILE: 02_core_business_tables_and_fields.surql
-- ============================================================
-- PHILOSOPHY:
-- 1. Normalized Line Tables (not nested arrays) for strict ERP lineage:
--    Order -> Invoice -> Credit Note | Procurement -> Vendor Bill -> Debit Note.
--    This enables partial billing, partial refunds, and audit trails.
-- 2. Implicit Integrity via VALUE + ASSERT + z_ shadow/computed fields.
--    We define WHAT must be true; SurrealDB enforces it alphabetically.
-- 3. Referential Safety: REFERENCE ON DELETE REJECT on all top-level record links.
--    No application-level join checks required.
-- 4. Multi-Currency Ready: fx_rate on every document; base-currency snapshots
--    on organization_account for zero-cost AR/AP reads.
-- 5. No PERMISSIONS, owned_by, or audit fields here — handled in your 04/05 files.
-- ============================================================

-- ============================================================
-- 1. COMPANY SETTINGS
-- ============================================================
DEFINE TABLE OVERWRITE company_settings SCHEMAFULL;

DEFINE FIELD OVERWRITE base_currency ON company_settings TYPE string DEFAULT "INR";
DEFINE FIELD OVERWRITE payment_lock_after ON company_settings TYPE duration DEFAULT 3d;
DEFINE FIELD OVERWRITE exchange_lock_after ON company_settings TYPE duration DEFAULT 3d;
DEFINE FIELD OVERWRITE invoice_lock_after ON company_settings TYPE duration DEFAULT 3d;
DEFINE FIELD OVERWRITE bill_lock_after ON company_settings TYPE duration DEFAULT 3d;

-- ============================================================
-- 2. TAX MASTER
-- ============================================================
-- Tax accounts are global masters. They map to the Chart of Accounts (ledger_account)
-- so every tax line hits the correct GL bucket automatically.
-- kind distinguishes Output Tax (liability), Input Tax (asset), and Withholding.
DEFINE TABLE OVERWRITE tax_account SCHEMAFULL;

DEFINE FIELD OVERWRITE name ON tax_account TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE code ON tax_account TYPE option<string>;
DEFINE FIELD OVERWRITE rate ON tax_account TYPE decimal DEFAULT 0 ASSERT $value >= 0;
DEFINE FIELD OVERWRITE kind ON tax_account TYPE string ASSERT $value IN ['output_liability', 'input_asset', 'withholding'];
DEFINE FIELD OVERWRITE z_ledger_ref ON tax_account TYPE record<ledger_account> REFERENCE ON DELETE REJECT;

-- ============================================================
-- 3. CATALOG ITEM (Non-Stock / Service Masters)
-- ============================================================
-- Every sellable/purchasable thing MUST map to a GL income/expense account.
-- No free-text items allowed — this guarantees the P&L always balances.
DEFINE TABLE OVERWRITE catalog_item SCHEMAFULL;

DEFINE FIELD OVERWRITE name ON catalog_item TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE kind ON catalog_item TYPE string ASSERT $value IN ['service', 'product', 'fee', 'discount', 'shipping', 'misc'];
DEFINE FIELD OVERWRITE units ON catalog_item TYPE option<string>;
DEFINE FIELD OVERWRITE income_account_ref ON catalog_item TYPE record<ledger_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE expense_account_ref ON catalog_item TYPE option<record<ledger_account>> REFERENCE ON DELETE REJECT;

-- Default tax configuration copied to lines at document creation time.
-- This freezes tax rates historically so government rate changes never corrupt old invoices.
DEFINE FIELD OVERWRITE tax_defaults ON catalog_item TYPE option<array<object>>;
DEFINE FIELD OVERWRITE tax_defaults.*.tax_account_ref ON catalog_item TYPE record<tax_account>;
DEFINE FIELD OVERWRITE tax_defaults.*.rate ON catalog_item TYPE decimal ASSERT $value >= 0;

-- ============================================================
-- 4. INVENTORY (Stock-Masters)
-- ============================================================
-- z_stock_qty is a reactive aggregate: Bills (in) - Invoices (out) + Exchange (manual).
-- z_avg_cost is derived from posted vendor bills (Weighted Average).
-- ASSERT $value >= 0 on z_stock_qty implicitly prevents negative stock — no app code needed.
DEFINE TABLE OVERWRITE inventory SCHEMAFULL;

DEFINE FIELD OVERWRITE name ON inventory TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE kind ON inventory TYPE string ASSERT $value IN ['raw_material', 'product', 'asset'];
DEFINE FIELD OVERWRITE units ON inventory TYPE option<string>;
DEFINE FIELD OVERWRITE income_account_ref ON inventory TYPE record<ledger_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE expense_account_ref ON inventory TYPE record<ledger_account> REFERENCE ON DELETE REJECT;

-- Weighted Average Cost from all posted vendor bill lines.
DEFINE FIELD OVERWRITE z_avg_cost ON inventory TYPE decimal
    VALUE {
        LET $total_value = (SELECT VALUE math::sum(qty * unit_cost) FROM vendor_bill_line WHERE item_ref = $this.id AND vendor_bill_ref.status = 'posted')[0] ?? 0dec;
        LET $total_qty = (SELECT VALUE math::sum(qty) FROM vendor_bill_line WHERE item_ref = $this.id AND vendor_bill_ref.status = 'posted')[0] ?? 0dec;
        IF $total_qty > 0dec {
            type::decimal(math::round(($total_value / $total_qty) * 100dec) / 100dec)
        } ELSE {
            0dec
        }
    };

-- Reactive stock level. NOTE: invoice_line and vendor_bill_line filter on parent status != 'void'
-- so voided documents do not affect physical stock.
DEFINE FIELD OVERWRITE z_stock_qty ON inventory TYPE decimal
    VALUE (
        (SELECT VALUE math::sum(qty) FROM vendor_bill_line WHERE item_ref = $this.id AND vendor_bill_ref.status = 'posted')[0] ?? 0dec
        - (SELECT VALUE math::sum(qty) FROM invoice_line WHERE item_ref = $this.id AND invoice_ref.status = 'posted')[0] ?? 0dec
        + (SELECT VALUE math::sum(qty) FROM exchange WHERE to_account = $this.id)[0] ?? 0dec
        - (SELECT VALUE math::sum(qty) FROM exchange WHERE from_account = $this.id)[0] ?? 0dec
    )
    ASSERT $value >= 0;

-- ============================================================
-- 5. CHART OF ACCOUNTS (Unified Ledger)
-- ============================================================
-- Replaces the old icce + operating_finance_account split.
-- One table drives the entire General Ledger: Balance Sheet, P&L, and Tax reports.
DEFINE TABLE OVERWRITE ledger_account SCHEMAFULL;

DEFINE FIELD OVERWRITE name ON ledger_account TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE code ON ledger_account TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE category ON ledger_account TYPE string ASSERT $value IN ['asset', 'liability', 'equity', 'revenue', 'expense'];
DEFINE FIELD OVERWRITE sub_type ON ledger_account TYPE string ASSERT $value IN ['bank', 'cash', 'accounts_receivable', 'accounts_payable', 'inventory', 'general', 'tax', 'fx_gain_loss'];
DEFINE FIELD OVERWRITE currency ON ledger_account TYPE option<string>
    ASSERT IF $this.sub_type IN ['bank', 'cash'] THEN $value != NONE ELSE true END;

-- ============================================================
-- 6. ORGANIZATION ACCOUNT (Customers, Vendors, Government)
-- ============================================================
-- AR/AP balances are zero-cost snapshots computed from invoices, credit notes,
-- vendor bills, debit notes, and payments. No cron jobs, no background workers.
DEFINE TABLE OVERWRITE organization_account SCHEMAFULL;

DEFINE FIELD OVERWRITE name ON organization_account TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE kind ON organization_account TYPE string ASSERT $value IN ['customer', 'vendor', 'government', 'counterparty', 'other'];
DEFINE FIELD OVERWRITE default_currency ON organization_account TYPE option<string>;

-- Accounts Receivable (Base Currency)
DEFINE FIELD OVERWRITE z_ar_balance ON organization_account TYPE decimal
    VALUE (
        (SELECT VALUE math::sum(z_total_base) FROM invoice WHERE party = $this.id AND status = 'posted')[0] ?? 0dec
        - (SELECT VALUE math::sum(z_total_base) FROM credit_note WHERE party = $this.id AND status = 'posted')[0] ?? 0dec
        - (SELECT VALUE math::sum(z_base_amount) FROM payment WHERE from_account = $this.id)[0] ?? 0dec
    );

-- Accounts Payable (Base Currency)
DEFINE FIELD OVERWRITE z_ap_balance ON organization_account TYPE decimal
    VALUE (
        (SELECT VALUE math::sum(z_total_base) FROM vendor_bill WHERE party = $this.id AND status = 'posted')[0] ?? 0dec
        - (SELECT VALUE math::sum(z_total_base) FROM debit_note WHERE party = $this.id AND status = 'posted')[0] ?? 0dec
        - (SELECT VALUE math::sum(z_base_amount) FROM payment WHERE to_account = $this.id)[0] ?? 0dec
    );

DEFINE FIELD OVERWRITE zz_net_balance ON organization_account TYPE decimal VALUE $this.z_ar_balance - $this.z_ap_balance;

-- ============================================================
-- 7. SALES ORDER (Intent / Non-Financial)
-- ============================================================
-- Orders are promises. They do not recognize revenue.
-- The line table enforces that you cannot invoice more than was ordered.
DEFINE TABLE OVERWRITE order SCHEMAFULL;

DEFINE FIELD OVERWRITE status ON order TYPE string DEFAULT 'draft' ASSERT $value IN ['draft', 'confirmed', 'cancelled', 'closed'];
DEFINE FIELD OVERWRITE party ON order TYPE record<organization_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE currency ON order TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE fx_rate ON order TYPE decimal DEFAULT 1 ASSERT $value > 0;
DEFINE FIELD OVERWRITE display_number ON order TYPE string ASSERT $value.len() > 0;

DEFINE FIELD OVERWRITE z_base_total ON order TYPE decimal VALUE (SELECT VALUE math::sum(z_base_amount) FROM order_line WHERE order_ref = $this.id)[0] ?? 0dec;
DEFINE FIELD OVERWRITE z_tax_total ON order TYPE decimal VALUE (SELECT VALUE math::sum(z_tax_amount) FROM order_line WHERE order_ref = $this.id)[0] ?? 0dec;
DEFINE FIELD OVERWRITE z_total_amount ON order TYPE decimal VALUE $this.z_base_total + $this.z_tax_total;
DEFINE FIELD OVERWRITE z_touched_at ON order TYPE datetime VALUE time::now();

-- ============================================================
-- 8. SALES ORDER LINE
-- ============================================================
DEFINE TABLE OVERWRITE order_line SCHEMAFULL;

DEFINE FIELD OVERWRITE order_ref ON order_line TYPE record<order> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE item_ref ON order_line TYPE record<inventory | catalog_item> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE description ON order_line TYPE string VALUE $value OR $this.item_ref.name;
DEFINE FIELD OVERWRITE qty ON order_line TYPE decimal ASSERT $value > 0;
DEFINE FIELD OVERWRITE unit_price ON order_line TYPE decimal ASSERT $value >= 0;
DEFINE FIELD OVERWRITE tax_inclusive ON order_line TYPE bool DEFAULT false;

-- Taxes copied from item defaults at creation time; user can override.
DEFINE FIELD OVERWRITE taxes ON order_line TYPE array<object> DEFAULT [];
DEFINE FIELD OVERWRITE taxes.*.tax_account_ref ON order_line TYPE record<tax_account>;
DEFINE FIELD OVERWRITE taxes.*.rate ON order_line TYPE decimal ASSERT $value >= 0;

-- Line-level tax math (inclusive vs exclusive) rounded to 2 decimals.
DEFINE FIELD OVERWRITE z_tax_amount ON order_line TYPE decimal
    VALUE {
        LET $base = $this.qty * $this.unit_price;
        LET $total_rate = math::sum($this.taxes.rate) ?? 0dec;
        IF $this.tax_inclusive {
            type::decimal(math::round(($base - ($base / (1dec + ($total_rate / 100dec)))) * 100dec) / 100dec)
        } ELSE {
            type::decimal(math::round(($base * ($total_rate / 100dec)) * 100dec) / 100dec)
        }
    };

DEFINE FIELD OVERWRITE z_base_amount ON order_line TYPE decimal VALUE $this.qty * $this.unit_price;
DEFINE FIELD OVERWRITE z_total_amount ON order_line TYPE decimal
    VALUE IF $this.tax_inclusive THEN $this.z_base_amount ELSE $this.z_base_amount + $this.z_tax_amount END;

-- Integrity Lock: invoiced qty can never exceed ordered qty.
DEFINE FIELD OVERWRITE z_qty_invoiced ON order_line TYPE decimal
    VALUE (SELECT VALUE math::sum(qty) FROM invoice_line WHERE order_line_ref = $this.id)[0] ?? 0dec
    ASSERT $value <= $this.qty;

-- ============================================================
-- 9. SALES INVOICE (Financial / Revenue Recognition)
-- ============================================================
-- Invoices are legally binding. Once posted, they create AR.
-- Voiding is allowed only if nothing has been paid (enforced by z_void_valid).
DEFINE TABLE OVERWRITE invoice SCHEMAFULL;

DEFINE FIELD OVERWRITE status ON invoice TYPE string DEFAULT 'draft' ASSERT $value IN ['draft', 'posted', 'void'];
DEFINE FIELD OVERWRITE party ON invoice TYPE record<organization_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE currency ON invoice TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE fx_rate ON invoice TYPE decimal DEFAULT 1 ASSERT $value > 0;
DEFINE FIELD OVERWRITE display_number ON invoice TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE order_ref ON invoice TYPE option<record<order>> REFERENCE ON DELETE REJECT;

DEFINE FIELD OVERWRITE z_base_total ON invoice TYPE decimal VALUE (SELECT VALUE math::sum(z_base_amount) FROM invoice_line WHERE invoice_ref = $this.id)[0] ?? 0dec;
DEFINE FIELD OVERWRITE z_tax_total ON invoice TYPE decimal VALUE (SELECT VALUE math::sum(z_tax_amount) FROM invoice_line WHERE invoice_ref = $this.id)[0] ?? 0dec;
DEFINE FIELD OVERWRITE z_total_amount ON invoice TYPE decimal VALUE $this.z_base_total + $this.z_tax_total;
DEFINE FIELD OVERWRITE z_total_base ON invoice TYPE decimal VALUE $this.z_total_amount * $this.fx_rate;

-- Void nullifier: mathematically zeros the invoice without deleting it (auditor-friendly).
DEFINE FIELD OVERWRITE z_net_due ON invoice TYPE decimal VALUE IF $this.status = 'void' THEN 0dec ELSE $this.z_total_amount END;
DEFINE FIELD OVERWRITE z_net_due_base ON invoice TYPE decimal VALUE IF $this.status = 'void' THEN 0dec ELSE $this.z_total_base END;

-- Tracks payment allocations.
DEFINE FIELD OVERWRITE z_amount_paid ON invoice TYPE decimal
    VALUE (SELECT VALUE math::sum(allocations.amount) FROM payment WHERE $this.id IN allocations.document_ref)[0] ?? 0dec;

-- Cross-field integrity: z_amount_paid evaluates before z_void_valid (alphabetical).
DEFINE FIELD OVERWRITE z_void_valid ON invoice TYPE bool
    VALUE IF $this.status = 'void' THEN $this.z_amount_paid = 0dec ELSE true END
    ASSERT $value = true;

DEFINE FIELD OVERWRITE z_touched_at ON invoice TYPE datetime VALUE time::now();

-- ============================================================
-- 10. INVOICE LINE
-- ============================================================
-- frozen_unit_cost captures inventory.z_avg_cost at the exact moment of sale.
-- This permanently locks COGS so historical margins never drift.
DEFINE TABLE OVERWRITE invoice_line SCHEMAFULL;

DEFINE FIELD OVERWRITE invoice_ref ON invoice_line TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE order_line_ref ON invoice_line TYPE option<record<order_line>> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE item_ref ON invoice_line TYPE record<inventory | catalog_item> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE description ON invoice_line TYPE string VALUE $value OR $this.item_ref.name;
DEFINE FIELD OVERWRITE qty ON invoice_line TYPE decimal ASSERT $value > 0;
DEFINE FIELD OVERWRITE unit_price ON invoice_line TYPE decimal ASSERT $value >= 0;
DEFINE FIELD OVERWRITE tax_inclusive ON invoice_line TYPE bool DEFAULT false;

DEFINE FIELD OVERWRITE taxes ON invoice_line TYPE array<object> DEFAULT [];
DEFINE FIELD OVERWRITE taxes.*.tax_account_ref ON invoice_line TYPE record<tax_account>;
DEFINE FIELD OVERWRITE taxes.*.rate ON invoice_line TYPE decimal ASSERT $value >= 0;

-- COGS frozen at creation time. READONLY prevents accidental historical corruption.
DEFINE FIELD OVERWRITE frozen_unit_cost ON invoice_line TYPE decimal
    VALUE $before OR ($this.item_ref.z_avg_cost ?? 0dec) READONLY;

DEFINE FIELD OVERWRITE z_tax_amount ON invoice_line TYPE decimal
    VALUE {
        LET $base = $this.qty * $this.unit_price;
        LET $total_rate = math::sum($this.taxes.rate) ?? 0dec;
        IF $this.tax_inclusive {
            type::decimal(math::round(($base - ($base / (1dec + ($total_rate / 100dec)))) * 100dec) / 100dec)
        } ELSE {
            type::decimal(math::round(($base * ($total_rate / 100dec)) * 100dec) / 100dec)
        }
    };

DEFINE FIELD OVERWRITE z_base_amount ON invoice_line TYPE decimal VALUE $this.qty * $this.unit_price;
DEFINE FIELD OVERWRITE z_total_amount ON invoice_line TYPE decimal
    VALUE IF $this.tax_inclusive THEN $this.z_base_amount ELSE $this.z_base_amount + $this.z_tax_amount END;
DEFINE FIELD OVERWRITE z_total_cogs ON invoice_line TYPE decimal VALUE $this.qty * $this.frozen_unit_cost;

-- Integrity Lock: credited qty can never exceed billed qty.
DEFINE FIELD OVERWRITE z_qty_credited ON invoice_line TYPE decimal
    VALUE (SELECT VALUE math::sum(qty) FROM credit_note_line WHERE invoice_line_ref = $this.id)[0] ?? 0dec
    ASSERT $value <= $this.qty;

-- ============================================================
-- 11. CREDIT NOTE (AR Reduction / Customer Refund)
-- ============================================================
-- Credit notes reverse invoices. Each line MUST point to an invoice_line.
DEFINE TABLE OVERWRITE credit_note SCHEMAFULL;

DEFINE FIELD OVERWRITE status ON credit_note TYPE string DEFAULT 'draft' ASSERT $value IN ['draft', 'posted', 'void'];
DEFINE FIELD OVERWRITE party ON credit_note TYPE record<organization_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE currency ON credit_note TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE fx_rate ON credit_note TYPE decimal DEFAULT 1 ASSERT $value > 0;
DEFINE FIELD OVERWRITE display_number ON credit_note TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE invoice_ref ON credit_note TYPE option<record<invoice>> REFERENCE ON DELETE REJECT;

DEFINE FIELD OVERWRITE z_base_total ON credit_note TYPE decimal VALUE (SELECT VALUE math::sum(z_base_amount) FROM credit_note_line WHERE credit_note_ref = $this.id)[0] ?? 0dec;
DEFINE FIELD OVERWRITE z_tax_total ON credit_note TYPE decimal VALUE (SELECT VALUE math::sum(z_tax_amount) FROM credit_note_line WHERE credit_note_ref = $this.id)[0] ?? 0dec;
DEFINE FIELD OVERWRITE z_total_amount ON credit_note TYPE decimal VALUE $this.z_base_total + $this.z_tax_total;
DEFINE FIELD OVERWRITE z_total_base ON credit_note TYPE decimal VALUE $this.z_total_amount * $this.fx_rate;

DEFINE FIELD OVERWRITE z_net_due ON credit_note TYPE decimal VALUE IF $this.status = 'void' THEN 0dec ELSE $this.z_total_amount END;
DEFINE FIELD OVERWRITE z_net_due_base ON credit_note TYPE decimal VALUE IF $this.status = 'void' THEN 0dec ELSE $this.z_total_base END;

DEFINE FIELD OVERWRITE z_amount_applied ON credit_note TYPE decimal
    VALUE (SELECT VALUE math::sum(allocations.amount) FROM payment WHERE $this.id IN allocations.document_ref)[0] ?? 0dec;

DEFINE FIELD OVERWRITE z_void_valid ON credit_note TYPE bool
    VALUE IF $this.status = 'void' THEN $this.z_amount_applied = 0dec ELSE true END
    ASSERT $value = true;

DEFINE FIELD OVERWRITE z_touched_at ON credit_note TYPE datetime VALUE time::now();

-- ============================================================
-- 12. CREDIT NOTE LINE
-- ============================================================
DEFINE TABLE OVERWRITE credit_note_line SCHEMAFULL;

DEFINE FIELD OVERWRITE credit_note_ref ON credit_note_line TYPE record<credit_note> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE invoice_line_ref ON credit_note_line TYPE record<invoice_line> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE qty ON credit_note_line TYPE decimal ASSERT $value > 0;
DEFINE FIELD OVERWRITE unit_price ON credit_note_line TYPE decimal VALUE $value OR $this.invoice_line_ref.unit_price ASSERT $value >= 0;

DEFINE FIELD OVERWRITE taxes ON credit_note_line TYPE array<object> DEFAULT [];
DEFINE FIELD OVERWRITE taxes.*.tax_account_ref ON credit_note_line TYPE record<tax_account>;
DEFINE FIELD OVERWRITE taxes.*.rate ON credit_note_line TYPE decimal ASSERT $value >= 0;

DEFINE FIELD OVERWRITE z_tax_amount ON credit_note_line TYPE decimal
    VALUE {
        LET $base = $this.qty * $this.unit_price;
        LET $total_rate = math::sum($this.taxes.rate) ?? 0dec;
        IF $this.tax_inclusive {
            type::decimal(math::round(($base - ($base / (1dec + ($total_rate / 100dec)))) * 100dec) / 100dec)
        } ELSE {
            type::decimal(math::round(($base * ($total_rate / 100dec)) * 100dec) / 100dec)
        }
    };

DEFINE FIELD OVERWRITE z_base_amount ON credit_note_line TYPE decimal VALUE $this.qty * $this.unit_price;
DEFINE FIELD OVERWRITE z_total_amount ON credit_note_line TYPE decimal
    VALUE IF $this.tax_inclusive THEN $this.z_base_amount ELSE $this.z_base_amount + $this.z_tax_amount END;

-- ============================================================
-- 13. PROCUREMENT / PURCHASE ORDER (AP Intent)
-- ============================================================
DEFINE TABLE OVERWRITE procurement SCHEMAFULL;

DEFINE FIELD OVERWRITE status ON procurement TYPE string DEFAULT 'draft' ASSERT $value IN ['draft', 'issued', 'received', 'billed', 'cancelled'];
DEFINE FIELD OVERWRITE party ON procurement TYPE record<organization_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE currency ON procurement TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE fx_rate ON procurement TYPE decimal DEFAULT 1 ASSERT $value > 0;
DEFINE FIELD OVERWRITE display_number ON procurement TYPE string ASSERT $value.len() > 0;

DEFINE FIELD OVERWRITE z_base_total ON procurement TYPE decimal VALUE (SELECT VALUE math::sum(z_base_amount) FROM procurement_line WHERE procurement_ref = $this.id)[0] ?? 0dec;
DEFINE FIELD OVERWRITE z_tax_total ON procurement TYPE decimal VALUE (SELECT VALUE math::sum(z_tax_amount) FROM procurement_line WHERE procurement_ref = $this.id)[0] ?? 0dec;
DEFINE FIELD OVERWRITE z_total_amount ON procurement TYPE decimal VALUE $this.z_base_total + $this.z_tax_total;
DEFINE FIELD OVERWRITE z_touched_at ON procurement TYPE datetime VALUE time::now();

-- ============================================================
-- 14. PROCUREMENT LINE
-- ============================================================
DEFINE TABLE OVERWRITE procurement_line SCHEMAFULL;

DEFINE FIELD OVERWRITE procurement_ref ON procurement_line TYPE record<procurement> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE item_ref ON procurement_line TYPE record<inventory | catalog_item> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE description ON procurement_line TYPE string VALUE $value OR $this.item_ref.name;
DEFINE FIELD OVERWRITE qty ON procurement_line TYPE decimal ASSERT $value > 0;
DEFINE FIELD OVERWRITE unit_cost ON procurement_line TYPE decimal ASSERT $value >= 0;
DEFINE FIELD OVERWRITE tax_inclusive ON procurement_line TYPE bool DEFAULT false;

DEFINE FIELD OVERWRITE taxes ON procurement_line TYPE array<object> DEFAULT [];
DEFINE FIELD OVERWRITE taxes.*.tax_account_ref ON procurement_line TYPE record<tax_account>;
DEFINE FIELD OVERWRITE taxes.*.rate ON procurement_line TYPE decimal ASSERT $value >= 0;

DEFINE FIELD OVERWRITE z_tax_amount ON procurement_line TYPE decimal
    VALUE {
        LET $base = $this.qty * $this.unit_cost;
        LET $total_rate = math::sum($this.taxes.rate) ?? 0dec;
        IF $this.tax_inclusive {
            type::decimal(math::round(($base - ($base / (1dec + ($total_rate / 100dec)))) * 100dec) / 100dec)
        } ELSE {
            type::decimal(math::round(($base * ($total_rate / 100dec)) * 100dec) / 100dec)
        }
    };

DEFINE FIELD OVERWRITE z_base_amount ON procurement_line TYPE decimal VALUE $this.qty * $this.unit_cost;
DEFINE FIELD OVERWRITE z_total_amount ON procurement_line TYPE decimal
    VALUE IF $this.tax_inclusive THEN $this.z_base_amount ELSE $this.z_base_amount + $this.z_tax_amount END;

-- Integrity Lock: billed qty can never exceed ordered qty.
DEFINE FIELD OVERWRITE z_qty_billed ON procurement_line TYPE decimal
    VALUE (SELECT VALUE math::sum(qty) FROM vendor_bill_line WHERE procurement_line_ref = $this.id)[0] ?? 0dec
    ASSERT $value <= $this.qty;

-- ============================================================
-- 15. VENDOR BILL (AP Liability)
-- ============================================================
DEFINE TABLE OVERWRITE vendor_bill SCHEMAFULL;

DEFINE FIELD OVERWRITE status ON vendor_bill TYPE string DEFAULT 'draft' ASSERT $value IN ['draft', 'posted', 'void'];
DEFINE FIELD OVERWRITE party ON vendor_bill TYPE record<organization_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE currency ON vendor_bill TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE fx_rate ON vendor_bill TYPE decimal DEFAULT 1 ASSERT $value > 0;
DEFINE FIELD OVERWRITE display_number ON vendor_bill TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE procurement_ref ON vendor_bill TYPE option<record<procurement>> REFERENCE ON DELETE REJECT;

DEFINE FIELD OVERWRITE z_base_total ON vendor_bill TYPE decimal VALUE (SELECT VALUE math::sum(z_base_amount) FROM vendor_bill_line WHERE vendor_bill_ref = $this.id)[0] ?? 0dec;
DEFINE FIELD OVERWRITE z_tax_total ON vendor_bill TYPE decimal VALUE (SELECT VALUE math::sum(z_tax_amount) FROM vendor_bill_line WHERE vendor_bill_ref = $this.id)[0] ?? 0dec;
DEFINE FIELD OVERWRITE z_total_amount ON vendor_bill TYPE decimal VALUE $this.z_base_total + $this.z_tax_total;
DEFINE FIELD OVERWRITE z_total_base ON vendor_bill TYPE decimal VALUE $this.z_total_amount * $this.fx_rate;

DEFINE FIELD OVERWRITE z_net_due ON vendor_bill TYPE decimal VALUE IF $this.status = 'void' THEN 0dec ELSE $this.z_total_amount END;
DEFINE FIELD OVERWRITE z_net_due_base ON vendor_bill TYPE decimal VALUE IF $this.status = 'void' THEN 0dec ELSE $this.z_total_base END;

DEFINE FIELD OVERWRITE z_amount_paid ON vendor_bill TYPE decimal
    VALUE (SELECT VALUE math::sum(allocations.amount) FROM payment WHERE $this.id IN allocations.document_ref)[0] ?? 0dec;

DEFINE FIELD OVERWRITE z_void_valid ON vendor_bill TYPE bool
    VALUE IF $this.status = 'void' THEN $this.z_amount_paid = 0dec ELSE true END
    ASSERT $value = true;

DEFINE FIELD OVERWRITE z_touched_at ON vendor_bill TYPE datetime VALUE time::now();

-- ============================================================
-- 16. VENDOR BILL LINE
-- ============================================================
DEFINE TABLE OVERWRITE vendor_bill_line SCHEMAFULL;

DEFINE FIELD OVERWRITE vendor_bill_ref ON vendor_bill_line TYPE record<vendor_bill> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE procurement_line_ref ON vendor_bill_line TYPE option<record<procurement_line>> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE item_ref ON vendor_bill_line TYPE record<inventory | catalog_item> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE description ON vendor_bill_line TYPE string VALUE $value OR $this.item_ref.name;
DEFINE FIELD OVERWRITE qty ON vendor_bill_line TYPE decimal ASSERT $value > 0;
DEFINE FIELD OVERWRITE unit_cost ON vendor_bill_line TYPE decimal ASSERT $value >= 0;
DEFINE FIELD OVERWRITE tax_inclusive ON vendor_bill_line TYPE bool DEFAULT false;

DEFINE FIELD OVERWRITE taxes ON vendor_bill_line TYPE array<object> DEFAULT [];
DEFINE FIELD OVERWRITE taxes.*.tax_account_ref ON vendor_bill_line TYPE record<tax_account>;
DEFINE FIELD OVERWRITE taxes.*.rate ON vendor_bill_line TYPE decimal ASSERT $value >= 0;

DEFINE FIELD OVERWRITE z_tax_amount ON vendor_bill_line TYPE decimal
    VALUE {
        LET $base = $this.qty * $this.unit_cost;
        LET $total_rate = math::sum($this.taxes.rate) ?? 0dec;
        IF $this.tax_inclusive {
            type::decimal(math::round(($base - ($base / (1dec + ($total_rate / 100dec)))) * 100dec) / 100dec)
        } ELSE {
            type::decimal(math::round(($base * ($total_rate / 100dec)) * 100dec) / 100dec)
        }
    };

DEFINE FIELD OVERWRITE z_base_amount ON vendor_bill_line TYPE decimal VALUE $this.qty * $this.unit_cost;
DEFINE FIELD OVERWRITE z_total_amount ON vendor_bill_line TYPE decimal
    VALUE IF $this.tax_inclusive THEN $this.z_base_amount ELSE $this.z_base_amount + $this.z_tax_amount END;

-- Integrity Lock: debited qty can never exceed billed qty.
DEFINE FIELD OVERWRITE z_qty_debited ON vendor_bill_line TYPE decimal
    VALUE (SELECT VALUE math::sum(qty) FROM debit_note_line WHERE vendor_bill_line_ref = $this.id)[0] ?? 0dec
    ASSERT $value <= $this.qty;

-- ============================================================
-- 17. DEBIT NOTE (AP Reduction / Vendor Return)
-- ============================================================
DEFINE TABLE OVERWRITE debit_note SCHEMAFULL;

DEFINE FIELD OVERWRITE status ON debit_note TYPE string DEFAULT 'draft' ASSERT $value IN ['draft', 'posted', 'void'];
DEFINE FIELD OVERWRITE party ON debit_note TYPE record<organization_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE currency ON debit_note TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE fx_rate ON debit_note TYPE decimal DEFAULT 1 ASSERT $value > 0;
DEFINE FIELD OVERWRITE display_number ON debit_note TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE vendor_bill_ref ON debit_note TYPE option<record<vendor_bill>> REFERENCE ON DELETE REJECT;

DEFINE FIELD OVERWRITE z_base_total ON debit_note TYPE decimal VALUE (SELECT VALUE math::sum(z_base_amount) FROM debit_note_line WHERE debit_note_ref = $this.id)[0] ?? 0dec;
DEFINE FIELD OVERWRITE z_tax_total ON debit_note TYPE decimal VALUE (SELECT VALUE math::sum(z_tax_amount) FROM debit_note_line WHERE debit_note_ref = $this.id)[0] ?? 0dec;
DEFINE FIELD OVERWRITE z_total_amount ON debit_note TYPE decimal VALUE $this.z_base_total + $this.z_tax_total;
DEFINE FIELD OVERWRITE z_total_base ON debit_note TYPE decimal VALUE $this.z_total_amount * $this.fx_rate;

DEFINE FIELD OVERWRITE z_net_due ON debit_note TYPE decimal VALUE IF $this.status = 'void' THEN 0dec ELSE $this.z_total_amount END;
DEFINE FIELD OVERWRITE z_net_due_base ON debit_note TYPE decimal VALUE IF $this.status = 'void' THEN 0dec ELSE $this.z_total_base END;

DEFINE FIELD OVERWRITE z_amount_applied ON debit_note TYPE decimal
    VALUE (SELECT VALUE math::sum(allocations.amount) FROM payment WHERE $this.id IN allocations.document_ref)[0] ?? 0dec;

DEFINE FIELD OVERWRITE z_void_valid ON debit_note TYPE bool
    VALUE IF $this.status = 'void' THEN $this.z_amount_applied = 0dec ELSE true END
    ASSERT $value = true;

DEFINE FIELD OVERWRITE z_touched_at ON debit_note TYPE datetime VALUE time::now();

-- ============================================================
-- 18. DEBIT NOTE LINE
-- ============================================================
DEFINE TABLE OVERWRITE debit_note_line SCHEMAFULL;

DEFINE FIELD OVERWRITE debit_note_ref ON debit_note_line TYPE record<debit_note> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE vendor_bill_line_ref ON debit_note_line TYPE record<vendor_bill_line> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE qty ON debit_note_line TYPE decimal ASSERT $value > 0;
DEFINE FIELD OVERWRITE unit_cost ON debit_note_line TYPE decimal VALUE $value OR $this.vendor_bill_line_ref.unit_cost ASSERT $value >= 0;

DEFINE FIELD OVERWRITE taxes ON debit_note_line TYPE array<object> DEFAULT [];
DEFINE FIELD OVERWRITE taxes.*.tax_account_ref ON debit_note_line TYPE record<tax_account>;
DEFINE FIELD OVERWRITE taxes.*.rate ON debit_note_line TYPE decimal ASSERT $value >= 0;

DEFINE FIELD OVERWRITE z_tax_amount ON debit_note_line TYPE decimal
    VALUE {
        LET $base = $this.qty * $this.unit_cost;
        LET $total_rate = math::sum($this.taxes.rate) ?? 0dec;
        IF $this.tax_inclusive {
            type::decimal(math::round(($base - ($base / (1dec + ($total_rate / 100dec)))) * 100dec) / 100dec)
        } ELSE {
            type::decimal(math::round(($base * ($total_rate / 100dec)) * 100dec) / 100dec)
        }
    };

DEFINE FIELD OVERWRITE z_base_amount ON debit_note_line TYPE decimal VALUE $this.qty * $this.unit_cost;
DEFINE FIELD OVERWRITE z_total_amount ON debit_note_line TYPE decimal
    VALUE IF $this.tax_inclusive THEN $this.z_base_amount ELSE $this.z_base_amount + $this.z_tax_amount END;

-- ============================================================
-- 19. PAYMENT (Universal Settlement)
-- ============================================================
-- Payments move money between Organization Accounts (AR/AP) and Ledger Accounts (Bank/Cash).
-- The allocations array settles specific invoices, bills, or notes.
-- z_document_refs is a Shadow Set (SurrealDB 3.0 §5.2) that enforces referential
-- integrity on the nested allocations.*.document_ref pointers.
DEFINE TABLE OVERWRITE payment SCHEMAFULL;

DEFINE FIELD OVERWRITE from_account ON payment TYPE record<organization_account | ledger_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE to_account ON payment TYPE record<organization_account | ledger_account> REFERENCE ON DELETE REJECT ASSERT $value != $this.from_account;
DEFINE FIELD OVERWRITE amount ON payment TYPE decimal ASSERT $value > 0;
DEFINE FIELD OVERWRITE fx_rate ON payment TYPE decimal DEFAULT 1 ASSERT $value > 0;
DEFINE FIELD OVERWRITE currency ON payment TYPE string ASSERT $value.len() > 0;

-- Allocation matrix: each element points to a document being settled.
DEFINE FIELD OVERWRITE allocations ON payment TYPE array<object> DEFAULT [];
DEFINE FIELD OVERWRITE allocations.*.document_ref ON payment TYPE record<invoice | vendor_bill | credit_note | debit_note>;
DEFINE FIELD OVERWRITE allocations.*.amount ON payment TYPE decimal ASSERT $value > 0;

-- Shadow reference flattening nested document_refs into a top-level set for REFERENCE integrity.
DEFINE FIELD OVERWRITE z_document_refs ON payment TYPE set<record<invoice | vendor_bill | credit_note | debit_note>>
    VALUE <set> ($this.allocations.document_ref ?? []).filter(|$v| $v != NONE)
    REFERENCE ON DELETE REJECT;

-- Integrity Lock: you cannot allocate more than the payment amount.
DEFINE FIELD OVERWRITE z_total_allocated ON payment TYPE decimal
    VALUE math::sum($this.allocations.amount) ?? 0dec
    ASSERT $value <= $this.amount;

DEFINE FIELD OVERWRITE z_base_amount ON payment TYPE decimal VALUE $this.amount * $this.fx_rate;
DEFINE FIELD OVERWRITE z_touched_at ON payment TYPE datetime VALUE time::now();

-- ============================================================
-- 20. EXCHANGE (Inventory Movements & Manual Corrections)
-- ============================================================
-- Exchange handles physical stock corrections: damage, manufacturing, warehouse moves.
-- It does NOT handle sales/purchases — those are reactive via invoice_line/vendor_bill_line.
DEFINE TABLE OVERWRITE exchange SCHEMAFULL;

DEFINE FIELD OVERWRITE from_account ON exchange TYPE record<inventory | ledger_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE to_account ON exchange TYPE record<inventory | ledger_account> REFERENCE ON DELETE REJECT ASSERT $value != $this.from_account;
DEFINE FIELD OVERWRITE kind ON exchange TYPE string ASSERT $value IN ['manufacturing', 'conversion', 'adjustment', 'stock_move', 'manual_journal'];
DEFINE FIELD OVERWRITE qty ON exchange TYPE decimal ASSERT $value > 0;
DEFINE FIELD OVERWRITE unit_cost ON exchange TYPE decimal DEFAULT 0 ASSERT $value >= 0;
DEFINE FIELD OVERWRITE z_amount ON exchange TYPE decimal VALUE $this.qty * $this.unit_cost;
DEFINE FIELD OVERWRITE z_touched_at ON exchange TYPE datetime VALUE time::now();