USE NS main DB main;

-- ==========================================
-- 1. PARENT / STATELESS NODES
-- ==========================================

DEFINE FIELD OVERWRITE name ON acc TYPE string;

DEFINE FIELD OVERWRITE name ON treasury TYPE string;
DEFINE FIELD OVERWRITE balance ON treasury TYPE decimal 
    VALUE (type::record('v_payment_to', [id])).total ?? 0dec - (type::record('v_payment_from', [id])).total ?? 0dec
    ASSERT $value >= 0dec;

DEFINE FIELD OVERWRITE name ON org TYPE string;
DEFINE FIELD OVERWRITE net_money ON org TYPE decimal 
    VALUE (type::record('v_payment_to', [id])).total ?? 0dec - (type::record('v_payment_from', [id])).total ?? 0dec;
DEFINE FIELD OVERWRITE total_invoices ON org TYPE decimal
    VALUE (type::record('v_invoice_org', [id])).total ?? 0dec;

DEFINE FIELD OVERWRITE name ON item TYPE string;
DEFINE FIELD OVERWRITE turnover ON item TYPE decimal 
    VALUE (type::record('v_inv_line_item', [id])).total_qty ?? 0dec;
DEFINE FIELD OVERWRITE average_cogs ON item TYPE decimal 
    VALUE (type::record('v_inv_line_item', [id])).avg_cogs ?? 0dec;

DEFINE FIELD OVERWRITE name ON stock_acc TYPE string;

DEFINE FIELD OVERWRITE name ON warehouse TYPE string;
-- A generic visual balance for the pitch (Summing all items combined)
DEFINE FIELD OVERWRITE stock_balance ON warehouse TYPE decimal 
    VALUE (type::record('v_sl_to_generic', [id])).total ?? 0dec - (type::record('v_sl_from_generic', [id])).total ?? 0dec
    ASSERT $value >= 0dec;


-- ==========================================
-- 2. DEPENDENT NODES
-- ==========================================

-- ------------------------------------------
-- PAYMENT
-- Alphabetical flow: active -> amount -> a_treasury -> v_from -> v_to -> z_active -> z_total
-- ------------------------------------------
DEFINE FIELD OVERWRITE active ON payment TYPE bool DEFAULT true;
DEFINE FIELD OVERWRITE amount ON payment TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD OVERWRITE date ON payment TYPE datetime DEFAULT time::now();
DEFINE FIELD OVERWRITE from ON payment TYPE record<org | treasury | acc> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE to ON payment TYPE record<org | treasury | acc> REFERENCE ON DELETE REJECT;

DEFINE FIELD OVERWRITE assert_treasury ON payment TYPE bool 
    VALUE (record::tb(from) = 'treasury' OR record::tb(to) = 'treasury') 
    ASSERT $value = true;

DEFINE FIELD OVERWRITE z_active_amount ON payment TYPE decimal 
    VALUE IF active THEN amount ELSE 0dec END;

DEFINE FIELD OVERWRITE z_total_allocated ON payment TYPE decimal 
    VALUE (type::record('v_pa_pay', [id])).total ?? 0dec 
    ASSERT $value <= z_active_amount;


-- ------------------------------------------
-- PAYMENT_ALLOCATION
-- ------------------------------------------
DEFINE FIELD OVERWRITE amount ON payment_allocation TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD OVERWRITE invoice ON payment_allocation TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE payment ON payment_allocation TYPE record<payment> REFERENCE ON DELETE CASCADE;

DEFINE FIELD OVERWRITE org ON payment_allocation TYPE option<record<org>> VALUE {
    IF $this.invoice.org != $this.payment.to AND $this.invoice.org != $this.payment.from {
        THROW "DAG_VIOLATION: Payment and Invoice do not share the same Organization.";
    };
    RETURN $this.invoice.org;
};


-- ------------------------------------------
-- INVOICE
-- Alphabetical flow: active -> org -> tax -> type -> v_ordered -> v_remain -> v_tax -> z_active -> z_total
-- ------------------------------------------
DEFINE FIELD OVERWRITE active ON invoice TYPE bool DEFAULT true;
DEFINE FIELD OVERWRITE org ON invoice TYPE record<org> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE tax ON invoice TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec AND $value <= 1dec;
DEFINE FIELD OVERWRITE type ON invoice TYPE string ASSERT $value IN ['sales', 'purchase'];

DEFINE FIELD OVERWRITE v_ordered_value ON invoice TYPE decimal 
    VALUE (type::record('v_inv_line_inv', [id])).total_value ?? 0dec;
    
DEFINE FIELD OVERWRITE v_remaining_value ON invoice TYPE decimal 
    VALUE (type::record('v_inv_line_inv', [id])).remaining_value ?? 0dec 
    ASSERT $value >= 0dec;
    
DEFINE FIELD OVERWRITE v_tax ON invoice TYPE decimal VALUE v_ordered_value * tax;

DEFINE FIELD OVERWRITE z_active_amount ON invoice TYPE decimal 
    VALUE IF active THEN (v_ordered_value + v_tax) ELSE 0dec END;
    
DEFINE FIELD OVERWRITE z_total_allocated ON invoice TYPE decimal 
    VALUE (type::record('v_pa_inv', [id])).total ?? 0dec 
    ASSERT $value <= z_active_amount;


-- ------------------------------------------
-- INVOICE_LINE
-- Alphabetical flow: cogs -> inv -> item -> qty -> v_delivered -> z_qty_remain -> z_remain_val -> z_total_val
-- ------------------------------------------
DEFINE FIELD OVERWRITE cogs ON invoice_line TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD OVERWRITE inv ON invoice_line TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD OVERWRITE item ON invoice_line TYPE record<item> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE qty ON invoice_line TYPE decimal ASSERT $value > 0dec;

DEFINE FIELD OVERWRITE v_delivered_qty ON invoice_line TYPE decimal 
    VALUE (type::record('v_sl_inv_line', [id])).total_qty ?? 0dec;
    
DEFINE FIELD OVERWRITE z_qty_remaining ON invoice_line TYPE decimal 
    VALUE qty - v_delivered_qty 
    ASSERT $value >= 0dec;

DEFINE FIELD OVERWRITE z_remaining_value ON invoice_line TYPE decimal VALUE z_qty_remaining * cogs;
DEFINE FIELD OVERWRITE z_total_value ON invoice_line TYPE decimal VALUE qty * cogs;


-- ------------------------------------------
-- SL (Stock Ledger)
-- Alphabetical flow: active -> from -> inv_line -> item -> qty -> to -> z_active -> z_shield
-- ------------------------------------------
DEFINE FIELD OVERWRITE active ON sl TYPE bool DEFAULT true;
DEFINE FIELD OVERWRITE from ON sl TYPE record<warehouse | stock_acc> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE inv_line ON sl TYPE option<record<invoice_line>> REFERENCE ON DELETE CASCADE DEFAULT NONE;
DEFINE FIELD OVERWRITE item ON sl TYPE record<item> VALUE $this.inv_line.item OR $value ASSERT $value != NONE;
DEFINE FIELD OVERWRITE qty ON sl TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD OVERWRITE to ON sl TYPE record<warehouse | stock_acc> REFERENCE ON DELETE REJECT;

DEFINE FIELD OVERWRITE z_active_qty ON sl TYPE decimal VALUE IF active THEN qty ELSE 0dec END;

-- Self-enforcing item-level stock validation
DEFINE FIELD OVERWRITE z_stock_shield ON sl TYPE decimal VALUE {
    LET $in = (type::record('v_sl_to', [$this.from, $this.item])).total ?? 0dec;
    LET $out = (type::record('v_sl_from', [$this.from, $this.item])).total ?? 0dec;
    
    RETURN IF record::tb($this.from) = 'warehouse' THEN 
        ($in - $out) + ($before.z_active_qty ?? 0dec)
    ELSE 
        999999999dec 
    END;
} ASSERT $value >= $this.z_active_qty;
