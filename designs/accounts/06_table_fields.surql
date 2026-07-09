-- ==============================================================================
-- LEVEL 0: INDEPENDENT ANCHORS
-- ==============================================================================
USE NS main DB main;

DEFINE TABLE org SCHEMAFULL;
DEFINE FIELD a_name ON org TYPE string;
DEFINE FIELD a_currency ON org TYPE string DEFAULT 'USD';


DEFINE TABLE treasury SCHEMAFULL;
DEFINE FIELD a_name ON treasury TYPE string;
DEFINE FIELD e_guard ON treasury TYPE bool VALUE {
    LET $in = (type::record('v_pay_to', [$this.id])).val ?? 0dec;
    LET $out = (type::record('v_pay_from', [$this.id])).val ?? 0dec;
    IF ($in - $out) < 0dec { THROW "FINANCE_ERR: Treasury balance cannot drop below absolute zero."; };
    RETURN true;
} ASSERT $value = true;


DEFINE TABLE acc SCHEMAFULL;
DEFINE FIELD a_name ON acc TYPE string;


DEFINE TABLE stock_acc SCHEMAFULL;
DEFINE FIELD a_name ON stock_acc TYPE string;


DEFINE TABLE tax_account SCHEMAFULL;
DEFINE FIELD a_name ON tax_account TYPE string;
DEFINE FIELD a_currency ON tax_account TYPE string DEFAULT 'USD';


DEFINE TABLE warehouse SCHEMAFULL;
DEFINE FIELD a_name ON warehouse TYPE string;


DEFINE TABLE item SCHEMAFULL;
DEFINE FIELD a_name ON item TYPE string;
DEFINE FIELD a_is_service ON item TYPE bool DEFAULT false;
DEFINE FIELD a_default_cogs ON item TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec;

DEFINE FIELD d1_avg_cogs ON item TYPE decimal VALUE {
    LET $purch_mean = (type::record('v_invl_item', [$this.id, 1])).mean_price ?? 0dec;
    RETURN IF $purch_mean > 0dec THEN $purch_mean ELSE $this.a_default_cogs END;
};


-- ==============================================================================
-- LEVEL 1: INTENTS
-- ==============================================================================
DEFINE TABLE payment SCHEMAFULL;
DEFINE FIELD a_from ON payment TYPE record<org | treasury | acc | tax_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_to ON payment TYPE record<org | treasury | acc | tax_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_amount ON payment TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_fx_rate ON payment TYPE decimal DEFAULT 1.0dec ASSERT $value > 0dec;

DEFINE FIELD d1_p_from ON payment TYPE int VALUE IF record::tb($this.a_from) IN ['treasury', 'acc', 'tax_account'] THEN 1 ELSE 0 END;
DEFINE FIELD d2_p_to ON payment TYPE int VALUE IF record::tb($this.a_to) IN ['treasury', 'acc', 'tax_account'] THEN 1 ELSE 0 END;
DEFINE FIELD d3_vector ON payment TYPE int VALUE $this.d2_p_to - $this.d1_p_from;
DEFINE FIELD d4_currency ON payment TYPE string VALUE $this.a_from.a_currency ?? $this.a_to.a_currency ?? company:settings.default_currency ?? 'USD';

DEFINE FIELD e_guard ON payment TYPE bool VALUE {
    IF record::tb($this.a_from) != 'treasury' AND record::tb($this.a_to) != 'treasury' { 
        THROW "PHYSICS_ERR: Payment must involve at least one Treasury account."; 
    };

    IF $this.d1_p_from = 0 AND $this.d2_p_to = 0 { THROW "PHYSICS_ERR: External-to-External payment invalid."; };
    
    LET $alloc = (type::record('v_pa_pay', [$this.id])).amount ?? 0dec;
    IF ($this.a_amount - $alloc) < 0dec { THROW "MATH_ERR: Payment allocation shield dropped below zero."; };
    RETURN true;
} ASSERT $value = true;


DEFINE TABLE invoice SCHEMAFULL;
DEFINE FIELD a_org ON invoice TYPE record<org> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_type ON invoice TYPE string ASSERT $value IN ['sales', 'purchase'];
DEFINE FIELD a_fx_rate ON invoice TYPE decimal DEFAULT 1.0dec ASSERT $value > 0dec;

DEFINE FIELD d1_vector ON invoice TYPE int VALUE IF $this.a_type = 'purchase' THEN 1 ELSE -1 END;

DEFINE FIELD e_guard ON invoice TYPE bool VALUE {
    LET $raw_gross = (type::record('v_invl_inv', [$this.id, $this.d1_vector])).raw_gross ?? 0dec;
    LET $allocated = (type::record('v_pa_inv', [$this.id])).amount ?? 0dec;
    IF ($raw_gross - $allocated) < 0dec { THROW "MATH_ERR: Invoice allocation shield dropped below zero. Un-allocate payments before adjusting this invoice downwards."; };
    RETURN true;
} ASSERT $value = true;


DEFINE TABLE adjustment_note SCHEMAFULL;
DEFINE FIELD a_org ON adjustment_note TYPE record<org> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_name ON adjustment_note TYPE string;

DEFINE FIELD e_guard ON adjustment_note TYPE bool VALUE {
    LET $price_delta = (type::record('v_adj_note', [$this.id, 'invoice_line'])).delta ?? 0dec;
    LET $tax_delta = (type::record('v_adj_note', [$this.id, 'tax_line'])).delta ?? 0dec;
    IF ($price_delta > 0dec AND $tax_delta < 0dec) OR ($price_delta < 0dec AND $tax_delta > 0dec) { 
        THROW "ACCOUNTING_ERR: Tax delta and Amount delta cannot have opposing signs in a single note."; 
    };
    RETURN true;
} ASSERT $value = true;


-- ==============================================================================
-- LEVEL 2: BRANCHES
-- ==============================================================================
DEFINE TABLE payment_allocation SCHEMAFULL;
DEFINE FIELD a_payment ON payment_allocation TYPE record<payment> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_invoice ON payment_allocation TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_amount ON payment_allocation TYPE decimal ASSERT $value > 0dec;

DEFINE FIELD d1_alloc_inv_amount ON payment_allocation TYPE decimal VALUE ($this.a_amount * $this.a_payment.a_fx_rate) / ($this.a_invoice.a_fx_rate ?? 1.0dec);

DEFINE FIELD e_guard ON payment_allocation TYPE bool VALUE {
    IF ($this.a_invoice.a_org != $this.a_payment.a_from AND $this.a_invoice.a_org != $this.a_payment.a_to) { 
        THROW "DAG FRACTURE: Payment Org does not match Invoice Org."; 
    };

    LET $inv_vec = $this.a_invoice.d1_vector;
    LET $pay_vec = $this.a_payment.d3_vector;
    LET $inv_raw_total = (type::record('v_invl_inv', [$this.a_invoice.id, $inv_vec])).raw_gross ?? 0dec;
    
    LET $c_eff = IF $inv_raw_total < 0dec THEN ($inv_vec * -1) ELSE $inv_vec END;
    IF ($c_eff + $pay_vec) != 0 {
        IF $c_eff = 1 { THROW "DIRECTION_ERR: Purchase requires Outbound Payment."; }
        ELSE { THROW "DIRECTION_ERR: Sales requires Inbound Payment."; };
    };
    RETURN true;
} ASSERT $value = true;


DEFINE TABLE package_note SCHEMAFULL;
DEFINE FIELD a_invoice ON package_note TYPE record<invoice> REFERENCE ON DELETE CASCADE;


DEFINE TABLE invoice_line SCHEMAFULL;
DEFINE FIELD a_invoice ON invoice_line TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_item ON invoice_line TYPE record<item> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_qty ON invoice_line TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_price ON invoice_line TYPE decimal ASSERT $value >= 0dec;

DEFINE FIELD d1_vector ON invoice_line TYPE int VALUE $this.a_invoice.d1_vector ?? 1;
DEFINE FIELD d2_raw_base ON invoice_line TYPE decimal VALUE ($this.a_qty * $this.a_price);
DEFINE FIELD d3_net_base ON invoice_line TYPE decimal VALUE ($this.d2_raw_base + ((type::record('v_adj_target', [$this.id])).delta ?? 0dec)) ASSERT $value >= 0dec;
DEFINE FIELD d4_actual_cogs ON invoice_line TYPE decimal VALUE IF $this.d1_vector = 1 THEN ($this.d2_raw_base / $this.a_qty) ELSE ($this.a_item.d1_avg_cogs ?? 0dec) END;
DEFINE FIELD d5_raw_tax ON invoice_line TYPE decimal VALUE (type::record('v_tl_invl', [$this.id])).raw_tax ?? 0dec;
DEFINE FIELD d6_net_tax ON invoice_line TYPE decimal VALUE (type::record('v_tl_invl', [$this.id])).net_tax ?? 0dec;
DEFINE FIELD d7_raw_gross ON invoice_line TYPE decimal VALUE ($this.d2_raw_base + $this.d5_raw_tax);
DEFINE FIELD d8_net_gross ON invoice_line TYPE decimal VALUE ($this.d3_net_base + $this.d6_net_tax);

DEFINE FIELD e_guard ON invoice_line TYPE bool VALUE {
    IF $this.d3_net_base < 0dec { THROW "MATH_ERR: Net base value negative."; };

    LET $delivered = IF $this.d1_vector = 1 THEN ((type::record('v_sl_from', [$this.id, true])).total_qty ?? 0dec) ELSE ((type::record('v_sl_to', [$this.id, true])).total_qty ?? 0dec) END;
    IF $delivered > $this.a_qty { THROW "PHYSICS_ERR: Delivered qty exceeds contract limit."; };
    
    RETURN true;
} ASSERT $value = true;


-- ==============================================================================
-- LEVEL 3: LEAVES
-- ==============================================================================
DEFINE TABLE sl SCHEMAFULL;
DEFINE FIELD a_from ON sl TYPE record<warehouse | stock_acc | invoice_line> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_to ON sl TYPE record<warehouse | stock_acc | invoice_line> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_pkg ON sl TYPE option<record<package_note>> REFERENCE ON DELETE CASCADE DEFAULT NONE;
DEFINE FIELD a_qty ON sl TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_item ON sl TYPE option<record<item>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_cogs ON sl TYPE option<decimal> DEFAULT NONE;

DEFINE FIELD d1_p_from ON sl TYPE int VALUE IF record::tb($this.a_from) IN ['warehouse', 'stock_acc'] THEN 1 ELSE 0 END;
DEFINE FIELD d2_p_to ON sl TYPE int VALUE IF record::tb($this.a_to) IN ['warehouse', 'stock_acc'] THEN 1 ELSE 0 END;
DEFINE FIELD d3_vector ON sl TYPE int VALUE $this.d2_p_to - $this.d1_p_from;
DEFINE FIELD d4_item ON sl TYPE record<item> VALUE $this.a_from.a_item ?? $this.a_to.a_item ?? $this.a_item;
DEFINE FIELD d5_cogs ON sl TYPE decimal VALUE $this.a_from.d4_actual_cogs ?? $this.a_to.d4_actual_cogs ?? $this.a_cogs ?? $this.d4_item.d1_avg_cogs ?? 0dec;
DEFINE FIELD d6_net_qty ON sl TYPE decimal VALUE ($this.a_qty + ((type::record('v_adj_target', [$this.id])).delta ?? 0dec)) ASSERT $value >= 0dec;
DEFINE FIELD d7_impact_qty ON sl TYPE decimal VALUE IF ($this.d4_item.a_is_service ?? false) THEN 0dec ELSE $this.d6_net_qty END;
DEFINE FIELD d8_is_contract_backed ON sl TYPE bool VALUE (record::tb($this.a_from) = 'invoice_line' OR record::tb($this.a_to) = 'invoice_line');

DEFINE FIELD e_guard ON sl TYPE bool VALUE {
    IF $this.d6_net_qty < 0dec { THROW "MATH_ERR: Net qty negative."; };
    IF $this.d4_item = NONE { THROW "PHYSICS_ERR: Missing Item Resolution."; };
    IF $this.d1_p_from = 0 AND $this.d2_p_to = 0 { THROW "PHYSICS_ERR: External-to-External invalid."; };

    IF $this.d8_is_contract_backed = true AND $this.a_pkg = NONE { THROW "PHYSICS_ERR: Package Note mandatory for Invoice contracts."; };
    IF $this.d8_is_contract_backed = false AND $this.a_pkg != NONE { THROW "PHYSICS_ERR: Internal transfers cannot link to Package Notes."; };

    IF $this.a_pkg != NONE {
        LET $tb_from = record::tb($this.a_from);
        LET $tb_to = record::tb($this.a_to);
        IF $tb_from = 'invoice_line' AND $tb_to = 'invoice_line' { THROW "PHYSICS_ERR: Max 1 Inv Line per SL."; };
        IF $tb_from = 'invoice_line' AND $this.a_from.a_invoice != $this.a_pkg.a_invoice { THROW "DAG FRACTURE: Source Inv mismatch."; };
        IF $tb_to = 'invoice_line' AND $this.a_to.a_invoice != $this.a_pkg.a_invoice { THROW "DAG FRACTURE: Dest Inv mismatch."; };
        IF $tb_from = 'invoice_line' AND $this.a_item != NONE AND $this.a_item != $this.a_from.a_item { THROW "API_ERR: Item conflict."; };
        IF $tb_to = 'invoice_line' AND $this.a_item != NONE AND $this.a_item != $this.a_to.a_item { THROW "API_ERR: Item conflict."; };
    };

    LET $inv_vec = $this.a_from.d1_vector ?? $this.a_to.d1_vector;
    IF $inv_vec != NONE AND $inv_vec != $this.d3_vector { THROW "DIRECTION_ERR: SL Vector contradicts Invoice Vector."; };

    RETURN true;
} ASSERT $value = true;


DEFINE TABLE tax_line SCHEMAFULL;
DEFINE FIELD a_invoice_line ON tax_line TYPE record<invoice_line> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_tax_account ON tax_line TYPE record<tax_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_rate ON tax_line TYPE decimal ASSERT $value > 0dec;

DEFINE FIELD d1_vector ON tax_line TYPE int VALUE $this.a_invoice_line.d1_vector ?? 1;
DEFINE FIELD d2_raw_tax ON tax_line TYPE decimal VALUE ($this.a_invoice_line.d2_raw_base * ($this.a_rate / 100dec));
DEFINE FIELD d3_net_tax ON tax_line TYPE decimal VALUE ($this.d2_raw_tax + ((type::record('v_adj_target', [$this.id])).delta ?? 0dec)) ASSERT $value >= 0dec;

DEFINE FIELD e_guard ON tax_line TYPE bool VALUE {
    IF $this.d3_net_tax < 0dec { THROW "MATH_ERR: Net tax negative."; };
    RETURN true;
} ASSERT $value = true;


-- ==============================================================================
-- LEVEL 4: THE DELTAS
-- ==============================================================================
DEFINE TABLE adjustment_line SCHEMAFULL;
DEFINE FIELD a_note ON adjustment_line TYPE record<adjustment_note> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_target ON adjustment_line TYPE record<invoice_line | tax_line | sl> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_delta ON adjustment_line TYPE decimal ASSERT $value != 0dec;

DEFINE INDEX idx_adj_line_unique ON adjustment_line COLUMNS a_note, a_target UNIQUE;

DEFINE FIELD d1_target_type ON adjustment_line TYPE string VALUE record::tb($this.a_target);

DEFINE FIELD e_guard ON adjustment_line TYPE bool VALUE {
    LET $tb = $this.d1_target_type;
    LET $target_org = 
        IF $tb = 'invoice_line' THEN $this.a_target.a_invoice.a_org 
        ELSE IF $tb = 'tax_line' THEN $this.a_target.a_invoice_line.a_invoice.a_org 
        ELSE IF $tb = 'sl' THEN ($this.a_target.a_from.a_invoice.a_org ?? $this.a_target.a_to.a_invoice.a_org) 
        ELSE NONE END;
    
    IF $target_org != NONE AND $this.a_note.a_org != $target_org { THROW "DAG FRACTURE: Org mismatch."; };
    RETURN true;
} ASSERT $value = true;