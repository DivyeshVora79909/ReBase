USE NS main DB main;

-- 1. CONFIGURATION & MASTER NODES
-- Company Settings
DEFINE FIELD OVERWRITE base_currency ON company_settings TYPE string DEFAULT 'USD';
DEFINE FIELD OVERWRITE lock_period_days ON company_settings TYPE int DEFAULT 30;

-- Account (Hierarchical Chart of Accounts)
DEFINE FIELD OVERWRITE code ON account TYPE string;
DEFINE FIELD OVERWRITE name ON account TYPE string;
DEFINE FIELD OVERWRITE category ON account TYPE string ASSERT $value IN ['asset', 'liability', 'equity', 'revenue', 'expense'];
DEFINE FIELD OVERWRITE parent_account_ref ON account TYPE option<record<account>> REFERENCE ON DELETE REJECT DEFAULT NONE;

-- Tracking Tag (Replaces Cost Centers, Departments, Locations)
DEFINE FIELD OVERWRITE category ON tracking_tag TYPE string; -- e.g., 'Project', 'Department'
DEFINE FIELD OVERWRITE name ON tracking_tag TYPE string;     -- e.g., 'Alpha', 'Marketing'

-- Tax Rate
DEFINE FIELD OVERWRITE name ON tax_rate TYPE string;
DEFINE FIELD OVERWRITE rate ON tax_rate TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD OVERWRITE liability_account_ref ON tax_rate TYPE record<account> REFERENCE ON DELETE REJECT;

-- Contact (Unified Party)
DEFINE FIELD OVERWRITE type ON contact TYPE string ASSERT $value IN ['customer', 'vendor', 'both'];
DEFINE FIELD OVERWRITE name ON contact TYPE string;
DEFINE FIELD OVERWRITE email ON contact TYPE option<string> DEFAULT NONE;
DEFINE FIELD OVERWRITE address ON contact TYPE object DEFAULT {};

-- Item (Unified Catalog)
DEFINE FIELD OVERWRITE type ON item TYPE string ASSERT $value IN ['product', 'service'];
DEFINE FIELD OVERWRITE name ON item TYPE string;
DEFINE FIELD OVERWRITE default_price ON item TYPE decimal DEFAULT 0dec;
DEFINE FIELD OVERWRITE income_account_ref ON item TYPE record<account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE expense_account_ref ON item TYPE record<account> REFERENCE ON DELETE REJECT;

-- Bank Account
DEFINE FIELD OVERWRITE name ON bank_account TYPE string;
DEFINE FIELD OVERWRITE currency ON bank_account TYPE string;
DEFINE FIELD OVERWRITE account_number ON bank_account TYPE string;
DEFINE FIELD OVERWRITE asset_account_ref ON bank_account TYPE record<account> REFERENCE ON DELETE REJECT;


-- 2. DOCUMENTS & OPERATIONS (Intent Layer)
-- Document (Polymorphic Master for Invoices, Bills, Notes)
DEFINE FIELD OVERWRITE type ON document TYPE string ASSERT $value IN ['sales_invoice', 'vendor_bill', 'credit_note', 'journal_voucher'];
DEFINE FIELD OVERWRITE document_number ON document TYPE string;
DEFINE FIELD OVERWRITE status ON document TYPE string DEFAULT 'draft' ASSERT $value IN ['draft', 'posted', 'void'];
DEFINE FIELD OVERWRITE issue_date ON document TYPE datetime DEFAULT time::now();
DEFINE FIELD OVERWRITE due_date ON document TYPE datetime;
DEFINE FIELD OVERWRITE contact_ref ON document TYPE record<contact> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE currency ON document TYPE string;
DEFINE FIELD OVERWRITE fx_rate ON document TYPE decimal DEFAULT 1dec ASSERT $value > 0dec;

-- Document Line (Child of Document)
DEFINE FIELD OVERWRITE document_ref ON document_line TYPE record<document> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE item_ref ON document_line TYPE record<item> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE tracking_tag_ref ON document_line TYPE option<record<tracking_tag>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD OVERWRITE description ON document_line TYPE string DEFAULT "";

-- Line Math & Taxes
DEFINE FIELD OVERWRITE qty ON document_line TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD OVERWRITE unit_price ON document_line TYPE decimal ASSERT $value >= 0dec;

DEFINE FIELD OVERWRITE taxes ON document_line TYPE array<object> DEFAULT [];
DEFINE FIELD OVERWRITE taxes.*.tax_ref ON document_line TYPE record<tax_rate>;

-- [HACK]: Shadow Referential Integrity for nested tax records
DEFINE FIELD OVERWRITE z_tax_refs ON document_line TYPE set<record<tax_rate>> 
    VALUE <set> ($this.taxes.tax_ref ?? []).filter(|$v| $v != NONE) 
    REFERENCE ON DELETE REJECT;

-- [HACK]: Intra-Record Autonomy (Dynamic Execution Alphabetically A-Z)
DEFINE FIELD OVERWRITE z_base_amount ON document_line TYPE decimal 
    VALUE $this.qty * $this.unit_price;

DEFINE FIELD OVERWRITE z_tax_amount ON document_line TYPE decimal VALUE {
    -- Calculates tax based on the actual live rate of the linked tax_rate nodes
    LET $rates = ($this.taxes.tax_ref.rate ?? []);
    LET $total_rate_pct = math::sum($rates) ?? 0dec;
    RETURN type::decimal(math::round(($this.z_base_amount * ($total_rate_pct / 100dec)) * 100dec) / 100dec);
};

DEFINE FIELD OVERWRITE z_total_amount ON document_line TYPE decimal 
    VALUE $this.z_base_amount + $this.z_tax_amount;


-- 3. TREASURY & SETTLEMENT
-- Payment
DEFINE FIELD OVERWRITE type ON payment TYPE string ASSERT $value IN ['receive_money', 'spend_money'];
DEFINE FIELD OVERWRITE status ON payment TYPE string DEFAULT 'draft' ASSERT $value IN ['draft', 'posted', 'void'];
DEFINE FIELD OVERWRITE payment_date ON payment TYPE datetime DEFAULT time::now();
DEFINE FIELD OVERWRITE reference ON payment TYPE string DEFAULT "";
DEFINE FIELD OVERWRITE contact_ref ON payment TYPE record<contact> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE bank_account_ref ON payment TYPE record<bank_account> REFERENCE ON DELETE REJECT;

DEFINE FIELD OVERWRITE amount ON payment TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD OVERWRITE currency ON payment TYPE string;
DEFINE FIELD OVERWRITE fx_rate ON payment TYPE decimal DEFAULT 1dec ASSERT $value > 0dec;

-- Payment Allocation (Edges mapping Cash to Documents)
DEFINE FIELD OVERWRITE payment_ref ON payment_allocation TYPE record<payment> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE document_ref ON payment_allocation TYPE record<document> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE pay_currency_amount ON payment_allocation TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD OVERWRITE doc_currency_amount ON payment_allocation TYPE decimal ASSERT $value > 0dec;


-- 4. THE IMMUTABLE LEDGER (Physics Layer)
-- Journal Entry (Header)
DEFINE FIELD OVERWRITE status ON journal_entry TYPE string DEFAULT 'posted' ASSERT $value IN ['posted', 'void'];
DEFINE FIELD OVERWRITE posting_date ON journal_entry TYPE datetime DEFAULT time::now();
DEFINE FIELD OVERWRITE description ON journal_entry TYPE string DEFAULT "";

-- Polymorphic Link: Can be spawned by a document, a payment, or manually
DEFINE FIELD OVERWRITE source_doc ON journal_entry TYPE option<record<document | payment>> REFERENCE ON DELETE CASCADE DEFAULT NONE;

-- Journal Line (The Core Double-Entry Row)
DEFINE FIELD OVERWRITE journal_entry_ref ON journal_line TYPE record<journal_entry> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE account_ref ON journal_line TYPE record<account> REFERENCE ON DELETE REJECT;

-- Optional Sub-ledger Links
DEFINE FIELD OVERWRITE contact_ref ON journal_line TYPE option<record<contact>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD OVERWRITE tracking_tag_ref ON journal_line TYPE option<record<tracking_tag>> REFERENCE ON DELETE REJECT DEFAULT NONE;

-- [HACK]: Signed Mathematics for pure O(1) View aggregations
-- Positive = Debit (Increases Assets/Expenses)
-- Negative = Credit (Increases Liabilities/Equity/Revenue)
DEFINE FIELD OVERWRITE amount_currency ON journal_line TYPE decimal;
DEFINE FIELD OVERWRITE currency ON journal_line TYPE string;
DEFINE FIELD OVERWRITE fx_rate ON journal_line TYPE decimal DEFAULT 1dec ASSERT $value > 0dec;

-- Automatically computes the base equivalent at write-time
DEFINE FIELD OVERWRITE z_amount_base ON journal_line TYPE decimal 
    VALUE $this.amount_currency * $this.fx_rate;