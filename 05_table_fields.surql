USE NS main DB main;

-- 1. THE NOUNS (Semantic Nodes)
DEFINE FIELD OVERWRITE base_currency ON company_settings TYPE string DEFAULT 'USD';
DEFINE FIELD OVERWRITE invoice_lock_after ON company_settings TYPE duration DEFAULT 30d;

DEFINE FIELD OVERWRITE name ON treasury_account TYPE string;
DEFINE FIELD OVERWRITE currency ON treasury_account TYPE string;

DEFINE FIELD OVERWRITE name ON trade_account TYPE string;
DEFINE FIELD OVERWRITE tax_id ON trade_account TYPE option<string>;

DEFINE FIELD OVERWRITE name ON expense_account TYPE string;
DEFINE FIELD OVERWRITE name ON equity_account TYPE string;

DEFINE FIELD OVERWRITE sku ON inventory_node TYPE string;
DEFINE INDEX OVERWRITE idx_inventory_sku ON inventory_node COLUMNS sku UNIQUE;
DEFINE FIELD OVERWRITE name ON inventory_node TYPE string;

DEFINE FIELD OVERWRITE name ON catalog_node TYPE string;
DEFINE FIELD OVERWRITE name ON location_node TYPE string;

DEFINE FIELD OVERWRITE name ON tax_node TYPE string;
DEFINE FIELD OVERWRITE behavior ON tax_node TYPE string ASSERT $value IN ['add', 'subtract'];

-- 2. THE VERBS (Sales)
DEFINE FIELD OVERWRITE status ON order TYPE string DEFAULT 'draft';
DEFINE FIELD OVERWRITE party_ref ON order TYPE record<trade_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE currency ON order TYPE string;

DEFINE FIELD OVERWRITE order_ref ON order_line TYPE record<order> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE item_ref ON order_line TYPE record<inventory_node | catalog_node> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE qty ON order_line TYPE decimal ASSERT $value > 0;
DEFINE FIELD OVERWRITE unit_price ON order_line TYPE decimal ASSERT $value >= 0;

DEFINE FIELD OVERWRITE status ON invoice TYPE string DEFAULT 'draft' ASSERT $value IN ['draft', 'posted', 'void'];
DEFINE FIELD OVERWRITE party_ref ON invoice TYPE record<trade_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE currency ON invoice TYPE string;
DEFINE FIELD OVERWRITE fx_rate ON invoice TYPE decimal DEFAULT 1dec;

DEFINE FIELD OVERWRITE invoice_ref ON invoice_line TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE item_ref ON invoice_line TYPE record<inventory_node | catalog_node> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE location_ref ON invoice_line TYPE record<location_node> DEFAULT location_node:main REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE qty ON invoice_line TYPE decimal ASSERT $value > 0;
DEFINE FIELD OVERWRITE unit_price ON invoice_line TYPE decimal ASSERT $value >= 0;

DEFINE FIELD OVERWRITE taxes ON invoice_line TYPE array<object> DEFAULT[];
DEFINE FIELD OVERWRITE taxes.*.tax_ref ON invoice_line TYPE record<tax_node>;
DEFINE FIELD OVERWRITE taxes.*.rate ON invoice_line TYPE decimal ASSERT $value >= 0;
DEFINE FIELD OVERWRITE z_tax_refs ON invoice_line TYPE set<record<tax_node>> 
    VALUE <set> ($this.taxes.tax_ref ??[]).filter(|$v| $v != NONE) 
    REFERENCE ON DELETE REJECT;

DEFINE FIELD OVERWRITE z_base_amount ON invoice_line TYPE decimal VALUE $this.qty * $this.unit_price;
DEFINE FIELD OVERWRITE z_tax_amount ON invoice_line TYPE decimal VALUE {
    LET $add_rates = math::sum(($this.taxes[WHERE tax_ref.behavior = 'add']).rate) ?? 0dec;
    LET $sub_rates = math::sum(($this.taxes[WHERE tax_ref.behavior = 'subtract']).rate) ?? 0dec;
    LET $added = $this.z_base_amount * ($add_rates / 100dec);
    LET $sub = $this.z_base_amount * ($sub_rates / 100dec);
    RETURN type::decimal(math::round(($added - $sub) * 100dec) / 100dec);
};

-- 3. THE VERBS (Purchasing)
DEFINE FIELD OVERWRITE status ON vendor_bill TYPE string DEFAULT 'draft' ASSERT $value IN['draft', 'posted', 'void'];
DEFINE FIELD OVERWRITE party_ref ON vendor_bill TYPE record<trade_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE currency ON vendor_bill TYPE string;
DEFINE FIELD OVERWRITE fx_rate ON vendor_bill TYPE decimal DEFAULT 1dec;

DEFINE FIELD OVERWRITE bill_ref ON vendor_bill_line TYPE record<vendor_bill> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE item_ref ON vendor_bill_line TYPE record<inventory_node | catalog_node | expense_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE location_ref ON vendor_bill_line TYPE record<location_node> DEFAULT location_node:main REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE qty ON vendor_bill_line TYPE decimal ASSERT $value > 0;
DEFINE FIELD OVERWRITE unit_cost ON vendor_bill_line TYPE decimal ASSERT $value >= 0;

DEFINE FIELD OVERWRITE taxes ON vendor_bill_line TYPE array<object> DEFAULT[];
DEFINE FIELD OVERWRITE taxes.*.tax_ref ON vendor_bill_line TYPE record<tax_node>;
DEFINE FIELD OVERWRITE taxes.*.rate ON vendor_bill_line TYPE decimal ASSERT $value >= 0;

DEFINE FIELD OVERWRITE z_tax_refs ON vendor_bill_line TYPE set<record<tax_node>> 
    VALUE <set> ($this.taxes.tax_ref ??[]).filter(|$v| $v != NONE) 
    REFERENCE ON DELETE REJECT;

DEFINE FIELD OVERWRITE z_base_amount ON vendor_bill_line TYPE decimal VALUE $this.qty * $this.unit_cost;
DEFINE FIELD OVERWRITE z_tax_amount ON vendor_bill_line TYPE decimal VALUE {
    LET $add_rates = math::sum(($this.taxes[WHERE tax_ref.behavior = 'add']).rate) ?? 0dec;
    LET $sub_rates = math::sum(($this.taxes[WHERE tax_ref.behavior = 'subtract']).rate) ?? 0dec;
    LET $added = $this.z_base_amount * ($add_rates / 100dec);
    LET $sub = $this.z_base_amount * ($sub_rates / 100dec);
    RETURN type::decimal(math::round(($added - $sub) * 100dec) / 100dec);
};

-- 4. DELTAS
DEFINE FIELD OVERWRITE status ON adjustment_note TYPE string DEFAULT 'draft' ASSERT $value IN['draft', 'posted', 'void'];
DEFINE FIELD OVERWRITE party_ref ON adjustment_note TYPE record<trade_account> REFERENCE ON DELETE REJECT;

DEFINE FIELD OVERWRITE note_ref ON adjustment_note_line TYPE record<adjustment_note> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE target_line_ref ON adjustment_note_line TYPE record<invoice_line | vendor_bill_line> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE delta_qty ON adjustment_note_line TYPE decimal;
DEFINE FIELD OVERWRITE delta_base_amount ON adjustment_note_line TYPE decimal;
DEFINE FIELD OVERWRITE delta_tax_amount ON adjustment_note_line TYPE decimal;
DEFINE FIELD OVERWRITE restock_inventory ON adjustment_note_line TYPE bool DEFAULT false;

-- 5. SETTLEMENT
DEFINE FIELD OVERWRITE direction ON payment TYPE string ASSERT $value IN ['inbound', 'outbound'];
DEFINE FIELD OVERWRITE treasury_ref ON payment TYPE record<treasury_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE amount ON payment TYPE decimal ASSERT $value > 0;
DEFINE FIELD OVERWRITE currency ON payment TYPE string;
DEFINE FIELD OVERWRITE fx_rate ON payment TYPE decimal DEFAULT 1dec;

DEFINE FIELD OVERWRITE payment_ref ON payment_allocation TYPE record<payment> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE target_ref ON payment_allocation TYPE record<invoice | vendor_bill | trade_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE pay_currency_amount ON payment_allocation TYPE decimal ASSERT $value > 0;
DEFINE FIELD OVERWRITE doc_currency_amount ON payment_allocation TYPE decimal ASSERT $value > 0;

DEFINE FIELD OVERWRITE kind ON financial_adjustment TYPE string ASSERT $value IN['fx_gain', 'fx_loss', 'depreciation', 'writeoff', 'capital'];
DEFINE FIELD OVERWRITE from_node ON financial_adjustment TYPE record REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE to_node ON financial_adjustment TYPE record REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE amount ON financial_adjustment TYPE decimal ASSERT $value > 0;
DEFINE FIELD OVERWRITE currency ON financial_adjustment TYPE string;

-- 6. PHYSICAL OPERATIONS
DEFINE FIELD OVERWRITE status ON exchange TYPE string;
DEFINE FIELD OVERWRITE exchange_ref ON exchange_line TYPE record<exchange> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE item_ref ON exchange_line TYPE record<inventory_node> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE from_location_ref ON exchange_line TYPE option<record<location_node | expense_account>> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE to_location_ref ON exchange_line TYPE option<record<location_node | expense_account>> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE qty ON exchange_line TYPE decimal ASSERT $value > 0;

DEFINE FIELD OVERWRITE status ON production_run TYPE string ASSERT $value IN ['draft', 'in_progress', 'completed'];
DEFINE FIELD OVERWRITE run_ref ON production_line TYPE record<production_run> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE item_ref ON production_line TYPE record<inventory_node | expense_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE location_ref ON production_line TYPE record<location_node> DEFAULT location_node:main REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE direction ON production_line TYPE string ASSERT $value IN['consume', 'yield'];
DEFINE FIELD OVERWRITE qty ON production_line TYPE decimal ASSERT $value > 0;