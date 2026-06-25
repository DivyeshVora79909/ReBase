-- ==============================================================================
-- LEVEL 0: INDEPENDENT ANCHORS
-- ==============================================================================
USE NS main DB main;

DEFINE TABLE org SCHEMAFULL;
DEFINE FIELD a_in_name ON org TYPE string;
DEFINE FIELD a_in_currency ON org TYPE string DEFAULT 'USD';

DEFINE FIELD c_vw_inv ON org VALUE type::record('v_inv_org', [$this.id]);
DEFINE FIELD c_vw_pay_to ON org VALUE type::record('v_pay_node_to', [$this.id]);
DEFINE FIELD c_vw_pay_from ON org VALUE type::record('v_pay_node_from', [$this.id]);
DEFINE FIELD c_vw_adj ON org VALUE type::record('v_adj_org', [$this.id]);

DEFINE FIELD d_c1_net_financial_position ON org TYPE decimal VALUE 
    (($this.c_vw_inv.inv_sales_total ?? 0dec) - ($this.c_vw_inv.inv_purchase_total ?? 0dec)) 
    + (($this.c_vw_pay_to.pay_inbound_val ?? 0dec) - ($this.c_vw_pay_from.pay_outbound_val ?? 0dec));

DEFINE FIELD f_out ON org TYPE object DEFAULT {};
DEFINE FIELD f_out.currency ON org TYPE string VALUE $this.a_in_currency;


DEFINE TABLE treasury SCHEMAFULL;
DEFINE FIELD a_in_name ON treasury TYPE string;
DEFINE FIELD c_vw_pay_to ON treasury VALUE type::record('v_pay_node_to', [$this.id]);
DEFINE FIELD c_vw_pay_from ON treasury VALUE type::record('v_pay_node_from', [$this.id]);
DEFINE FIELD d_c1_balance ON treasury TYPE decimal VALUE ($this.c_vw_pay_to.pay_inbound_val ?? 0dec) - ($this.c_vw_pay_from.pay_outbound_val ?? 0dec);
DEFINE FIELD e_guard_state ON treasury TYPE bool VALUE $this.d_c1_balance >= 0dec ASSERT $value = true;
DEFINE FIELD f_out ON treasury TYPE object DEFAULT {};


DEFINE TABLE acc SCHEMAFULL;
DEFINE FIELD a_in_name ON acc TYPE string;
DEFINE FIELD c_vw_pay_to ON acc VALUE type::record('v_pay_node_to', [$this.id]);
DEFINE FIELD c_vw_pay_from ON acc VALUE type::record('v_pay_node_from', [$this.id]);
DEFINE FIELD c_vw_cogs_out ON acc VALUE type::record('v_sl_cogs_out', [$this.id]);
DEFINE FIELD d_c1_balance ON acc TYPE decimal VALUE ($this.c_vw_pay_to.pay_inbound_val ?? 0dec) - ($this.c_vw_pay_from.pay_outbound_val ?? 0dec) + ($this.c_vw_cogs_out.sl_cogs_value ?? 0dec);
DEFINE FIELD f_out ON acc TYPE object DEFAULT {};


DEFINE TABLE tax_account SCHEMAFULL;
DEFINE FIELD a_in_name ON tax_account TYPE string;
DEFINE FIELD c_vw_pay_to ON tax_account VALUE type::record('v_pay_node_to', [$this.id]);
DEFINE FIELD c_vw_pay_from ON tax_account VALUE type::record('v_pay_node_from', [$this.id]);
DEFINE FIELD c_vw_tl ON tax_account VALUE type::record('v_tl_acc', [$this.id]);
DEFINE FIELD d_c1_liability ON tax_account TYPE decimal VALUE ($this.c_vw_tl.tl_sales_tax ?? 0dec) - ($this.c_vw_tl.tl_purchase_tax ?? 0dec) - ($this.c_vw_pay_to.pay_inbound_val ?? 0dec) + ($this.c_vw_pay_from.pay_outbound_val ?? 0dec);
DEFINE FIELD f_out ON tax_account TYPE object DEFAULT {};


DEFINE TABLE item SCHEMAFULL;
DEFINE FIELD a_in_name ON item TYPE string;
DEFINE FIELD a_in_is_service ON item TYPE bool DEFAULT false;
DEFINE FIELD a_in_default_cogs ON item TYPE decimal DEFAULT 0dec;
DEFINE FIELD a_in_cogs_acc ON item TYPE record<acc> REFERENCE ON DELETE REJECT;
DEFINE FIELD c_vw_invl ON item VALUE type::record('v_invl_item', [$this.id]);
DEFINE FIELD d_c1_turnover ON item TYPE decimal VALUE ($this.c_vw_invl.invl_sales_qty ?? 0dec);
DEFINE FIELD d_c2_avg_cogs ON item TYPE decimal VALUE IF ($this.c_vw_invl.invl_purchase_qty ?? 0dec) > 0dec THEN ($this.c_vw_invl.invl_purchase_value ?? 0dec) / ($this.c_vw_invl.invl_purchase_qty ?? 0dec) ELSE $this.a_in_default_cogs END;
DEFINE FIELD f_out ON item TYPE object DEFAULT {};
DEFINE FIELD f_out.actual_unit_cogs ON item TYPE decimal VALUE $this.d_c2_avg_cogs ?? 0dec;
DEFINE FIELD f_out.is_service ON item TYPE bool VALUE $this.a_in_is_service;
DEFINE FIELD f_out.cogs_acc ON item TYPE record<acc> VALUE $this.a_in_cogs_acc;


DEFINE TABLE warehouse SCHEMAFULL;
DEFINE FIELD a_in_name ON warehouse TYPE string;
DEFINE FIELD c_vw_sl_in ON warehouse VALUE type::record('v_sl_node_in', [$this.id]);
DEFINE FIELD c_vw_sl_out ON warehouse VALUE type::record('v_sl_node_out', [$this.id]);
DEFINE FIELD d_c1_global_matrix_stock ON warehouse TYPE decimal VALUE ($this.c_vw_sl_in.sl_inbound_qty ?? 0dec) - ($this.c_vw_sl_out.sl_outbound_qty ?? 0dec);
DEFINE FIELD f_out ON warehouse TYPE object DEFAULT {};


DEFINE TABLE stock_acc SCHEMAFULL;
DEFINE FIELD a_in_name ON stock_acc TYPE string;
DEFINE FIELD f_out ON stock_acc TYPE object DEFAULT {};


-- ==============================================================================
-- LEVEL 1: INTENTS
-- ==============================================================================
DEFINE TABLE payment SCHEMAFULL;
DEFINE FIELD a_in_from ON payment TYPE record<org | treasury | acc | tax_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_in_to ON payment TYPE record<org | treasury | acc | tax_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_in_amount ON payment TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_in_fx_rate ON payment TYPE decimal DEFAULT 1.0dec ASSERT $value > 0dec;

DEFINE FIELD b_ctx_from_curr ON payment VALUE $this.a_in_from.f_out.currency;
DEFINE FIELD b_ctx_to_curr ON payment VALUE $this.a_in_to.f_out.currency;
DEFINE FIELD b_ctx_sys_curr ON payment VALUE (SELECT VALUE default_currency FROM company:settings LIMIT 1)[0];
DEFINE FIELD c_vw_pa ON payment VALUE type::record('v_pa_pay', [$this.id]);

DEFINE FIELD d_c1_currency ON payment TYPE string VALUE $this.b_ctx_from_curr ?? $this.b_ctx_to_curr ?? $this.b_ctx_sys_curr;
DEFINE FIELD d_c2_active_amount ON payment TYPE decimal VALUE ($this.a_in_amount ?? 0dec);
DEFINE FIELD d_c3_allocation_shield ON payment TYPE decimal VALUE ($this.d_c2_active_amount ?? 0dec) - ($this.c_vw_pa.pa_alloc_pay_amount ?? 0dec) ASSERT $value >= 0dec;

DEFINE FIELD e_guard_state ON payment TYPE bool VALUE {
    LET $is_from_tr = record::tb($this.a_in_from) = 'treasury';
    LET $is_to_tr = record::tb($this.a_in_to) = 'treasury';
    IF NOT ($is_from_tr OR $is_to_tr) { THROW "PHYSICS_ERR: At least one leg of a Payment must touch a Treasury."; };
    RETURN true;
} ASSERT $value = true;

DEFINE FIELD f_out ON payment TYPE object DEFAULT {};
DEFINE FIELD f_out.pay_inbound_val ON payment TYPE decimal VALUE $this.d_c2_active_amount;
DEFINE FIELD f_out.pay_outbound_val ON payment TYPE decimal VALUE $this.d_c2_active_amount;
DEFINE FIELD f_out.fx_rate ON payment TYPE decimal VALUE $this.a_in_fx_rate;
DEFINE FIELD f_out.from_node ON payment TYPE record VALUE $this.a_in_from;
DEFINE FIELD f_out.to_node ON payment TYPE record VALUE $this.a_in_to;


DEFINE TABLE invoice SCHEMAFULL;
DEFINE FIELD a_in_org ON invoice TYPE record<org> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_in_type ON invoice TYPE string ASSERT $value IN ['sales', 'purchase'];
DEFINE FIELD a_in_fx_rate ON invoice TYPE decimal DEFAULT 1.0dec ASSERT $value > 0dec;

DEFINE FIELD c_vw_invl ON invoice VALUE type::record('v_invl_inv', [$this.id]);
DEFINE FIELD c_vw_tl ON invoice VALUE type::record('v_tl_inv', [$this.id]);
DEFINE FIELD c_vw_pa ON invoice VALUE type::record('v_pa_inv', [$this.id]);

DEFINE FIELD d_c1_grand_total ON invoice TYPE decimal VALUE ($this.c_vw_invl.invl_purchase_value ?? 0dec) + ($this.c_vw_invl.invl_sales_value ?? 0dec) + ($this.c_vw_tl.tl_purchase_tax ?? 0dec) + ($this.c_vw_tl.tl_sales_tax ?? 0dec);
DEFINE FIELD d_c2_allocation_shield ON invoice TYPE decimal VALUE ($this.d_c1_grand_total ?? 0dec) - ($this.c_vw_pa.pa_alloc_inv_amount ?? 0dec) ASSERT $value >= 0dec;

DEFINE FIELD f_out ON invoice TYPE object DEFAULT {};
DEFINE FIELD f_out.inv_sales_total ON invoice TYPE decimal VALUE IF $this.a_in_type = 'sales' THEN $this.d_c1_grand_total ELSE 0dec END;
DEFINE FIELD f_out.inv_purchase_total ON invoice TYPE decimal VALUE IF $this.a_in_type = 'purchase' THEN $this.d_c1_grand_total ELSE 0dec END;
DEFINE FIELD f_out.fx_rate ON invoice TYPE decimal VALUE $this.a_in_fx_rate;
DEFINE FIELD f_out.type ON invoice TYPE string VALUE $this.a_in_type;
DEFINE FIELD f_out.org ON invoice TYPE record<org> VALUE $this.a_in_org;


DEFINE TABLE adjustment_note SCHEMAFULL;
DEFINE FIELD a_in_org ON adjustment_note TYPE record<org> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_in_type ON adjustment_note TYPE string ASSERT $value IN ['debit', 'credit'];

DEFINE FIELD d_c1_computed_json ON adjustment_note TYPE string VALUE {
    LET $my_id = $this.id; 
    LET $details = (SELECT a_in_invl, f_out.al_delta_qty, f_out.al_delta_price FROM adjustment_line WHERE a_in_note = $my_id);
    RETURN type::string($details);
};
DEFINE FIELD d_c2_total_adj_val ON adjustment_note TYPE decimal VALUE {
    LET $my_id = $this.id; 
    LET $res = (SELECT VALUE math::sum(f_out.al_delta_price) FROM adjustment_line WHERE a_in_note = $my_id GROUP ALL);
    RETURN $res[0] ?? 0dec;
};

DEFINE FIELD f_out ON adjustment_note TYPE object DEFAULT {};
DEFINE FIELD f_out.adj_debit_val ON adjustment_note TYPE decimal VALUE IF $this.a_in_type = 'debit' THEN $this.d_c2_total_adj_val ELSE 0dec END;
DEFINE FIELD f_out.adj_credit_val ON adjustment_note TYPE decimal VALUE IF $this.a_in_type = 'credit' THEN $this.d_c2_total_adj_val ELSE 0dec END;
DEFINE FIELD f_out.org ON adjustment_note TYPE record<org> VALUE $this.a_in_org;


-- ==============================================================================
-- LEVEL 2: BRANCHES
-- ==============================================================================
DEFINE TABLE payment_allocation SCHEMAFULL;
DEFINE FIELD a_in_payment ON payment_allocation TYPE record<payment> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_in_invoice ON payment_allocation TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_in_amount ON payment_allocation TYPE decimal ASSERT $value > 0dec;

DEFINE FIELD b_ctx_pay_fx ON payment_allocation VALUE $this.a_in_payment.f_out.fx_rate ?? 1.0dec;
DEFINE FIELD b_ctx_pay_from ON payment_allocation VALUE $this.a_in_payment.f_out.from_node;
DEFINE FIELD b_ctx_pay_to ON payment_allocation VALUE $this.a_in_payment.f_out.to_node;
DEFINE FIELD b_ctx_inv_org ON payment_allocation VALUE $this.a_in_invoice.f_out.org;

DEFINE FIELD e_guard_dag ON payment_allocation TYPE bool VALUE {
    IF $this.b_ctx_inv_org NOT IN [$this.b_ctx_pay_from, $this.b_ctx_pay_to] { 
        THROW "DAG FRACTURE: The Payment does not belong to the Invoice's Organization."; 
    };
    RETURN true;
} ASSERT $value = true;

DEFINE FIELD f_out ON payment_allocation TYPE object DEFAULT {};
DEFINE FIELD f_out.pa_alloc_pay_amount ON payment_allocation TYPE decimal VALUE $this.a_in_amount;
DEFINE FIELD f_out.pa_alloc_inv_amount ON payment_allocation TYPE decimal VALUE ($this.a_in_amount * $this.b_ctx_pay_fx);


DEFINE TABLE package_note SCHEMAFULL;
DEFINE FIELD a_in_invoice ON package_note TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD c_vw_sl ON package_note VALUE type::record('v_sl_pkg', [$this.id]);
DEFINE FIELD f_out ON package_note TYPE object DEFAULT {};
DEFINE FIELD f_out.pkg_delivered_qty ON package_note TYPE decimal VALUE $this.c_vw_sl.sl_delivered_qty ?? 0dec;
DEFINE FIELD f_out.invoice ON package_note TYPE record<invoice> VALUE $this.a_in_invoice;


DEFINE TABLE invoice_line SCHEMAFULL;
DEFINE FIELD a_in_invoice ON invoice_line TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_in_item ON invoice_line TYPE record<item> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_in_qty ON invoice_line TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_in_price ON invoice_line TYPE decimal ASSERT $value >= 0dec;

DEFINE FIELD b_ctx_inv_type ON invoice_line VALUE $this.a_in_invoice.f_out.type ?? '';
DEFINE FIELD b_ctx_inv_fx ON invoice_line VALUE $this.a_in_invoice.f_out.fx_rate ?? 1.0dec;
DEFINE FIELD b_ctx_inv_org ON invoice_line VALUE $this.a_in_invoice.f_out.org;
DEFINE FIELD b_ctx_item_cogs ON invoice_line VALUE $this.a_in_item.f_out.actual_unit_cogs ?? 0dec;
DEFINE FIELD b_ctx_item_service ON invoice_line VALUE $this.a_in_item.f_out.is_service ?? false;

DEFINE FIELD c_vw_sl_from ON invoice_line VALUE type::record('v_sl_invl_from', [$this.id]);
DEFINE FIELD c_vw_sl_to ON invoice_line VALUE type::record('v_sl_invl_to', [$this.id]);
DEFINE FIELD c_vw_al ON invoice_line VALUE type::record('v_al_invl', [$this.id]);

DEFINE FIELD d_c1_net_qty ON invoice_line TYPE decimal VALUE ($this.a_in_qty ?? 0dec) + ($this.c_vw_al.al_delta_qty ?? 0dec) ASSERT $value >= 0dec;
DEFINE FIELD d_c2_base_val ON invoice_line TYPE decimal VALUE ($this.d_c1_net_qty * (($this.a_in_price ?? 0dec) + ($this.c_vw_al.al_delta_price ?? 0dec))) ASSERT $value >= 0dec;
DEFINE FIELD d_c3_actual_cogs ON invoice_line TYPE decimal VALUE IF $this.b_ctx_inv_type = 'purchase' THEN ($this.d_c2_base_val / $this.d_c1_net_qty) ELSE $this.b_ctx_item_cogs END;
DEFINE FIELD d_c4_delivered_qty ON invoice_line TYPE decimal VALUE IF $this.b_ctx_inv_type = 'purchase' THEN ($this.c_vw_sl_from.qty ?? 0dec) ELSE ($this.c_vw_sl_to.qty ?? 0dec) END;

DEFINE FIELD e_guard_state ON invoice_line TYPE bool VALUE {
    IF $this.b_ctx_inv_type = 'sales' AND ($this.c_vw_sl_from.qty ?? 0dec) > 0dec { THROW "PHYSICS_ERR: Sales contracts cannot act as the source of stock (must be destination)."; };
    IF $this.b_ctx_inv_type = 'purchase' AND ($this.c_vw_sl_to.qty ?? 0dec) > 0dec { THROW "PHYSICS_ERR: Purchase contracts cannot act as the destination of stock (must be source)."; };
    IF ($this.d_c4_delivered_qty ?? 0dec) > ($this.d_c1_net_qty ?? 0dec) { THROW "PHYSICS_ERR: Delivered qty exceeds net contract qty."; };
    RETURN true;
} ASSERT $value = true;

DEFINE FIELD f_out ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD f_out.invl_purchase_value ON invoice_line TYPE decimal VALUE IF $this.b_ctx_inv_type = 'purchase' THEN $this.d_c2_base_val ELSE 0dec END;
DEFINE FIELD f_out.invl_sales_value ON invoice_line TYPE decimal VALUE IF $this.b_ctx_inv_type = 'sales' THEN $this.d_c2_base_val ELSE 0dec END;
DEFINE FIELD f_out.invl_purchase_qty ON invoice_line TYPE decimal VALUE IF $this.b_ctx_inv_type = 'purchase' THEN $this.d_c1_net_qty ELSE 0dec END;
DEFINE FIELD f_out.invl_sales_qty ON invoice_line TYPE decimal VALUE IF $this.b_ctx_inv_type = 'sales' THEN $this.d_c1_net_qty ELSE 0dec END;
DEFINE FIELD f_out.actual_unit_cogs ON invoice_line TYPE decimal VALUE $this.d_c3_actual_cogs;
DEFINE FIELD f_out.inv_fx_rate ON invoice_line TYPE decimal VALUE $this.b_ctx_inv_fx;
DEFINE FIELD f_out.type ON invoice_line TYPE string VALUE $this.b_ctx_inv_type;
DEFINE FIELD f_out.item ON invoice_line TYPE record<item> VALUE $this.a_in_item;
DEFINE FIELD f_out.org ON invoice_line TYPE record<org> VALUE $this.b_ctx_inv_org;
DEFINE FIELD f_out.invoice ON invoice_line TYPE record<invoice> VALUE $this.a_in_invoice;


-- ==============================================================================
-- LEVEL 3: LEAVES
-- ==============================================================================
DEFINE TABLE sl SCHEMAFULL;
DEFINE FIELD a_in_from ON sl TYPE record<warehouse | stock_acc | invoice_line> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_in_to ON sl TYPE record<warehouse | stock_acc | invoice_line> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_in_pkg ON sl TYPE option<record<package_note>> REFERENCE ON DELETE CASCADE DEFAULT NONE;
DEFINE FIELD a_in_qty ON sl TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD a_in_item ON sl TYPE option<record<item>> REFERENCE ON DELETE REJECT DEFAULT NONE;

DEFINE FIELD b_ctx_from_item ON sl VALUE $this.a_in_from.f_out.item;
DEFINE FIELD b_ctx_to_item ON sl VALUE $this.a_in_to.f_out.item;
DEFINE FIELD b_ctx_pkg_inv ON sl VALUE $this.a_in_pkg.f_out.invoice;
DEFINE FIELD b_ctx_from_inv ON sl VALUE $this.a_in_from.f_out.invoice;
DEFINE FIELD b_ctx_to_inv ON sl VALUE $this.a_in_to.f_out.invoice;
DEFINE FIELD b_ctx_from_org ON sl VALUE $this.a_in_from.f_out.org;
DEFINE FIELD b_ctx_to_org ON sl VALUE $this.a_in_to.f_out.org;
DEFINE FIELD b_ctx_from_cogs ON sl VALUE $this.a_in_from.f_out.actual_unit_cogs;
DEFINE FIELD b_ctx_to_cogs ON sl VALUE $this.a_in_to.f_out.actual_unit_cogs;
DEFINE FIELD b_ctx_from_fx ON sl VALUE $this.a_in_from.f_out.inv_fx_rate ?? 1.0dec;
DEFINE FIELD b_ctx_to_fx ON sl VALUE $this.a_in_to.f_out.inv_fx_rate ?? 1.0dec;

DEFINE FIELD c_vw_adj ON sl VALUE type::record('v_asl_sl', [$this.id]);

DEFINE FIELD d_c1_item ON sl VALUE $this.b_ctx_from_item ?? $this.b_ctx_to_item ?? $this.a_in_item;
DEFINE FIELD d_c2_unit_cogs ON sl TYPE decimal VALUE $this.b_ctx_from_cogs ?? $this.b_ctx_to_cogs ?? 0dec;
DEFINE FIELD d_c3_net_qty ON sl TYPE decimal VALUE ($this.a_in_qty + ($this.c_vw_adj.al_delta_qty ?? 0dec)) ASSERT $value >= 0dec;
DEFINE FIELD d_c4_wh_impact_qty ON sl TYPE decimal VALUE IF ($this.d_c1_item.f_out.is_service ?? false) THEN 0dec ELSE $this.d_c3_net_qty END;
DEFINE FIELD d_c5_fx ON sl TYPE decimal VALUE $this.b_ctx_from_fx ?? $this.b_ctx_to_fx ?? 1.0dec;
-- Extract types safely for the guards to reuse
DEFINE FIELD d_c6_from_type ON sl TYPE string VALUE IF $this.a_in_from != NONE THEN record::tb($this.a_in_from) ELSE '' END;
DEFINE FIELD d_c7_to_type ON sl TYPE string VALUE IF $this.a_in_to != NONE THEN record::tb($this.a_in_to) ELSE '' END;

DEFINE FIELD e_guard_dag ON sl TYPE bool VALUE {
    LET $p_inv = $this.b_ctx_pkg_inv;
    IF $p_inv != NONE {
        IF ($this.b_ctx_from_inv != NONE AND $this.b_ctx_from_inv != $p_inv) OR ($this.b_ctx_to_inv != NONE AND $this.b_ctx_to_inv != $p_inv) { RETURN false; };
    };
    RETURN true;
} ASSERT $value = true;

DEFINE FIELD e_guard_has_item ON sl TYPE bool 
    VALUE $this.d_c1_item != NONE 
    ASSERT $value = true;

DEFINE FIELD e_guard_wh_presence ON sl TYPE bool 
    VALUE ($this.d_c6_from_type = 'warehouse' OR $this.d_c7_to_type = 'warehouse') 
    ASSERT $value = true;

DEFINE FIELD e_guard_invl_limit ON sl TYPE bool 
    VALUE $this.d_c6_from_type != 'invoice_line' OR $this.d_c7_to_type != 'invoice_line'
    ASSERT $value = true;

DEFINE FIELD e_guard_item_match ON sl TYPE bool VALUE {
    IF $this.d_c6_from_type = 'invoice_line' AND $this.a_in_item != NONE { IF $this.a_in_item != $this.b_ctx_from_item { RETURN false; }; };
    IF $this.d_c7_to_type = 'invoice_line' AND $this.a_in_item != NONE { IF $this.a_in_item != $this.b_ctx_to_item { RETURN false; }; };
    RETURN true;
} ASSERT $value = true;

-- The O(1) Negative Stock Guard (Outbound)
DEFINE FIELD e_guard_stock_outbound ON sl TYPE bool VALUE {
    IF $this.d_c6_from_type = 'warehouse' {
        LET $impact = $this.d_c4_wh_impact_qty ?? 0dec;
        LET $in = (type::record('v_sl_wh_in', [$this.a_in_from, $this.d_c1_item])).qty ?? 0dec;
        LET $out = (type::record('v_sl_wh_out', [$this.a_in_from, $this.d_c1_item])).qty ?? 0dec;
        
        IF ($in - $out + ($before.f_out.sl_outbound_qty ?? 0dec) - $impact) < 0dec { RETURN false; };
    };
    RETURN true;
} ASSERT $value = true;

-- The O(1) Negative Stock Guard (Inbound Consumption)
DEFINE FIELD e_guard_stock_inbound ON sl TYPE bool VALUE {
    IF $this.d_c7_to_type = 'warehouse' {
        LET $impact = $this.d_c4_wh_impact_qty ?? 0dec;
        LET $in = (type::record('v_sl_wh_in', [$this.a_in_to, $this.d_c1_item])).qty ?? 0dec;
        LET $out = (type::record('v_sl_wh_out', [$this.a_in_to, $this.d_c1_item])).qty ?? 0dec;
        
        IF ($in - $out - ($before.f_out.sl_inbound_qty ?? 0dec) + $impact) < 0dec { RETURN false; };
    };
    RETURN true;
} ASSERT $value = true;

DEFINE FIELD f_out ON sl TYPE object DEFAULT {};
DEFINE FIELD f_out.sl_inbound_qty ON sl TYPE decimal VALUE IF $this.d_c7_to_type = 'warehouse' THEN $this.d_c4_wh_impact_qty ELSE 0dec END;
DEFINE FIELD f_out.sl_outbound_qty ON sl TYPE decimal VALUE IF $this.d_c6_from_type = 'warehouse' THEN $this.d_c4_wh_impact_qty ELSE 0dec END;
DEFINE FIELD f_out.sl_delivered_qty ON sl TYPE decimal VALUE $this.d_c3_net_qty; 
DEFINE FIELD f_out.item ON sl TYPE record<item> VALUE $this.d_c1_item;
DEFINE FIELD f_out.invl_org ON sl TYPE option<record<org>> VALUE $this.b_ctx_from_org ?? $this.b_ctx_to_org ?? NONE;
DEFINE FIELD f_out.cogs_acc ON sl TYPE option<record<acc>> VALUE $this.d_c1_item.f_out.cogs_acc;
DEFINE FIELD f_out.sl_cogs_value ON sl TYPE decimal VALUE (($this.d_c3_net_qty * $this.d_c2_unit_cogs) * $this.d_c5_fx);


DEFINE TABLE tax_line SCHEMAFULL;
DEFINE FIELD a_in_invoice_line ON tax_line TYPE record<invoice_line> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_in_tax_account ON tax_line TYPE record<tax_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_in_rate ON tax_line TYPE decimal ASSERT $value >= 0dec;

DEFINE FIELD b_ctx_invl_type ON tax_line VALUE $this.a_in_invoice_line.f_out.type ?? '';
DEFINE FIELD b_ctx_invl_fx ON tax_line VALUE $this.a_in_invoice_line.f_out.inv_fx_rate ?? 1.0dec;
DEFINE FIELD b_ctx_invl_sales_val ON tax_line VALUE $this.a_in_invoice_line.f_out.invl_sales_value ?? 0dec;
DEFINE FIELD b_ctx_invl_pur_val ON tax_line VALUE $this.a_in_invoice_line.f_out.invl_purchase_value ?? 0dec;
DEFINE FIELD b_ctx_invl_org ON tax_line VALUE $this.a_in_invoice_line.f_out.org;

DEFINE FIELD c_vw_adj ON tax_line VALUE type::record('v_atl_tl', [$this.id]);

DEFINE FIELD d_c1_base_val ON tax_line TYPE decimal VALUE IF $this.b_ctx_invl_type = 'sales' THEN $this.b_ctx_invl_sales_val ELSE $this.b_ctx_invl_pur_val END;
DEFINE FIELD d_c2_net_tax_curr ON tax_line TYPE decimal VALUE (($this.d_c1_base_val * ($this.a_in_rate / 100dec)) + ($this.c_vw_adj.al_delta_amount ?? 0dec)) ASSERT $value >= 0dec;
DEFINE FIELD d_c3_net_tax_acc ON tax_line TYPE decimal VALUE ($this.d_c2_net_tax_curr * $this.b_ctx_invl_fx);

DEFINE FIELD f_out ON tax_line TYPE object DEFAULT {};
DEFINE FIELD f_out.tl_sales_tax ON tax_line TYPE decimal VALUE IF $this.b_ctx_invl_type = 'sales' THEN $this.d_c3_net_tax_acc ELSE 0dec END;
DEFINE FIELD f_out.tl_purchase_tax ON tax_line TYPE decimal VALUE IF $this.b_ctx_invl_type = 'purchase' THEN $this.d_c3_net_tax_acc ELSE 0dec END;
DEFINE FIELD f_out.tl_rate ON tax_line TYPE decimal VALUE $this.a_in_rate;
DEFINE FIELD f_out.invl_org ON tax_line TYPE record<org> VALUE $this.b_ctx_invl_org;


-- ==============================================================================
-- LEVEL 4: DELTAS
-- ==============================================================================
DEFINE TABLE adjustment_line SCHEMAFULL;
DEFINE FIELD a_in_note ON adjustment_line TYPE record<adjustment_note> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_in_invl ON adjustment_line TYPE record<invoice_line> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_in_delta_qty ON adjustment_line TYPE decimal DEFAULT 0dec;
DEFINE FIELD a_in_delta_price ON adjustment_line TYPE decimal DEFAULT 0dec;

DEFINE FIELD b_ctx_note_org ON adjustment_line VALUE $this.a_in_note.f_out.org;
DEFINE FIELD b_ctx_invl_org ON adjustment_line VALUE $this.a_in_invl.f_out.org;

DEFINE FIELD e_guard_dag ON adjustment_line TYPE bool VALUE {
    IF $this.b_ctx_note_org != $this.b_ctx_invl_org { THROW "DAG FRACTURE: Org mismatch between Note and Invoice Line."; };
    RETURN true;
} ASSERT $value = true;

DEFINE FIELD f_out ON adjustment_line TYPE object DEFAULT {};
DEFINE FIELD f_out.al_delta_qty ON adjustment_line TYPE decimal VALUE $this.a_in_delta_qty;
DEFINE FIELD f_out.al_delta_price ON adjustment_line TYPE decimal VALUE $this.a_in_delta_price;


DEFINE TABLE adjustment_tax_line SCHEMAFULL;
DEFINE FIELD a_in_note ON adjustment_tax_line TYPE record<adjustment_note> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_in_tax_line ON adjustment_tax_line TYPE record<tax_line> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_in_delta_amount ON adjustment_tax_line TYPE decimal DEFAULT 0dec;

DEFINE FIELD b_ctx_note_org ON adjustment_tax_line VALUE $this.a_in_note.f_out.org;
DEFINE FIELD b_ctx_tl_org ON adjustment_tax_line VALUE $this.a_in_tax_line.f_out.invl_org;

DEFINE FIELD e_guard_dag ON adjustment_tax_line TYPE bool VALUE {
    IF $this.b_ctx_note_org != $this.b_ctx_tl_org { THROW "DAG FRACTURE: Org mismatch between Note and Tax Line."; };
    RETURN true;
} ASSERT $value = true;

DEFINE FIELD f_out ON adjustment_tax_line TYPE object DEFAULT {};
DEFINE FIELD f_out.al_delta_amount ON adjustment_tax_line TYPE decimal VALUE $this.a_in_delta_amount;


DEFINE TABLE adjustment_stock_line SCHEMAFULL;
DEFINE FIELD a_in_note ON adjustment_stock_line TYPE record<adjustment_note> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_in_sl ON adjustment_stock_line TYPE record<sl> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_in_delta_qty ON adjustment_stock_line TYPE decimal DEFAULT 0dec;

DEFINE FIELD b_ctx_note_org ON adjustment_stock_line VALUE $this.a_in_note.f_out.org;
DEFINE FIELD b_ctx_sl_org ON adjustment_stock_line VALUE $this.a_in_sl.f_out.invl_org;

DEFINE FIELD e_guard_dag ON adjustment_stock_line TYPE bool VALUE {
    IF $this.b_ctx_sl_org != NONE {
        IF $this.b_ctx_note_org != $this.b_ctx_sl_org { THROW "DAG FRACTURE: Org mismatch between Note and Stock Ledger."; };
    };
    RETURN true;
} ASSERT $value = true;

DEFINE FIELD f_out ON adjustment_stock_line TYPE object DEFAULT {};
DEFINE FIELD f_out.al_delta_qty ON adjustment_stock_line TYPE decimal VALUE $this.a_in_delta_qty;