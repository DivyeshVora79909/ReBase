-- FILE 06: THE FLAT ALPHABETICAL LEXICON
USE NS main DB main;

-- ==========================================
-- LEVEL 0: INDEPENDENT ANCHORS
-- ==========================================
DEFINE TABLE org SCHEMAFULL;
    DEFINE FIELD a_in_name ON org TYPE string;
    DEFINE FIELD a_in_currency ON org TYPE string DEFAULT 'USD';

    DEFINE FIELD c_vw_inv ON org VALUE type::record('v_inv_org', [$this.id]);
    DEFINE FIELD c_vw_pay_to ON org VALUE type::record('v_pay_node_to', [$this.id]);
    DEFINE FIELD c_vw_pay_from ON org VALUE type::record('v_pay_node_from', [$this.id]);

    DEFINE FIELD d_c1_net_financial_position ON org TYPE decimal VALUE 
        (($this.c_vw_inv.sales_base_value ?? 0dec) + ($this.c_vw_inv.sales_tax_value ?? 0dec) - ($this.c_vw_inv.purchase_base_value ?? 0dec) - ($this.c_vw_inv.purchase_tax_value ?? 0dec)) 
        + (($this.c_vw_pay_to.active_amount ?? 0dec) - ($this.c_vw_pay_from.active_amount ?? 0dec));

    DEFINE FIELD f_out ON org TYPE object DEFAULT {};
    DEFINE FIELD f_out.is_locked ON org TYPE bool VALUE false;
    DEFINE FIELD f_out.currency ON org TYPE string VALUE $this.a_in_currency;


DEFINE TABLE treasury SCHEMAFULL;
    DEFINE FIELD a_in_name ON treasury TYPE string;
    DEFINE FIELD a_in_currency ON treasury TYPE string DEFAULT 'USD';

    DEFINE FIELD c_vw_pay_to ON treasury VALUE type::record('v_pay_node_to', [$this.id]);
    DEFINE FIELD c_vw_pay_from ON treasury VALUE type::record('v_pay_node_from', [$this.id]);

    DEFINE FIELD d_c1_balance ON treasury TYPE decimal VALUE ($this.c_vw_pay_to.active_amount ?? 0dec) - ($this.c_vw_pay_from.active_amount ?? 0dec);
    DEFINE FIELD e_guard_shield ON treasury TYPE bool VALUE $this.d_c1_balance >= 0dec ASSERT $value = true;

    DEFINE FIELD f_out ON treasury TYPE object DEFAULT {};
    DEFINE FIELD f_out.is_locked ON treasury TYPE bool VALUE false;


DEFINE TABLE acc SCHEMAFULL;
    DEFINE FIELD a_in_name ON acc TYPE string;
    DEFINE FIELD a_in_type ON acc TYPE string;

    DEFINE FIELD c_vw_pay_to ON acc VALUE type::record('v_pay_node_to', [$this.id]);
    DEFINE FIELD c_vw_pay_from ON acc VALUE type::record('v_pay_node_from', [$this.id]);
    DEFINE FIELD c_vw_cogs_out ON acc VALUE type::record('v_sl_cogs_out', [$this.id]);

    DEFINE FIELD d_c1_balance ON acc TYPE decimal VALUE ($this.c_vw_pay_to.active_amount ?? 0dec) - ($this.c_vw_pay_from.active_amount ?? 0dec) + ($this.c_vw_cogs_out.actual_cogs_value ?? 0dec);

    DEFINE FIELD f_out ON acc TYPE object DEFAULT {};
    DEFINE FIELD f_out.is_locked ON acc TYPE bool VALUE false;


DEFINE TABLE tax_account SCHEMAFULL;
    DEFINE FIELD a_in_name ON tax_account TYPE string;

    DEFINE FIELD c_vw_pay_to ON tax_account VALUE type::record('v_pay_node_to', [$this.id]);
    DEFINE FIELD c_vw_pay_from ON tax_account VALUE type::record('v_pay_node_from', [$this.id]);
    DEFINE FIELD c_vw_tl ON tax_account VALUE type::record('v_tl_acc', [$this.id]);

    DEFINE FIELD d_c1_liability ON tax_account TYPE decimal VALUE ($this.c_vw_tl.sales_tax_value ?? 0dec) - ($this.c_vw_tl.purchase_tax_value ?? 0dec) - ($this.c_vw_pay_to.active_amount ?? 0dec) + ($this.c_vw_pay_from.active_amount ?? 0dec);

    DEFINE FIELD f_out ON tax_account TYPE object DEFAULT {};
    DEFINE FIELD f_out.is_locked ON tax_account TYPE bool VALUE false;


DEFINE TABLE item SCHEMAFULL;
    DEFINE FIELD a_in_name ON item TYPE string;
    DEFINE FIELD a_in_is_service ON item TYPE bool DEFAULT false;
    DEFINE FIELD a_in_default_cogs ON item TYPE decimal DEFAULT 0dec;
    DEFINE FIELD a_in_cogs_acc ON item TYPE record<acc> REFERENCE ON DELETE REJECT; 

    DEFINE FIELD c_vw_invl ON item VALUE type::record('v_invl_item', [$this.id]);
    DEFINE FIELD c_vw_sl_in ON item VALUE type::record('v_sl_item_in', [$this.id]);
    DEFINE FIELD c_vw_sl_out ON item VALUE type::record('v_sl_item_out', [$this.id]);

    DEFINE FIELD d_c1_turnover ON item TYPE decimal VALUE ($this.c_vw_invl.sales_financial_qty ?? 0dec);
    DEFINE FIELD d_c2_avg_cogs ON item TYPE decimal VALUE IF ($this.c_vw_invl.purchase_financial_qty ?? 0dec) > 0dec THEN ($this.c_vw_invl.purchase_base_value ?? 0dec) / ($this.c_vw_invl.purchase_financial_qty ?? 0dec) ELSE $this.a_in_default_cogs END;
    DEFINE FIELD d_c3_physical_stock ON item TYPE decimal VALUE ($this.c_vw_sl_in.inbound_physical_qty ?? 0dec) - ($this.c_vw_sl_out.outbound_physical_qty ?? 0dec);

    DEFINE FIELD f_out ON item TYPE object DEFAULT {};
    DEFINE FIELD f_out.actual_unit_cogs ON item TYPE decimal VALUE $this.d_c2_avg_cogs ?? 0dec;
    DEFINE FIELD f_out.cogs_account ON item TYPE record<acc> VALUE $this.a_in_cogs_acc;
    DEFINE FIELD f_out.is_service ON item TYPE bool VALUE $this.a_in_is_service;
    DEFINE FIELD f_out.is_locked ON item TYPE bool VALUE false;


DEFINE TABLE warehouse SCHEMAFULL;
    DEFINE FIELD a_in_name ON warehouse TYPE string;

    DEFINE FIELD c_vw_sl_in ON warehouse VALUE type::record('v_sl_node_in', [$this.id]);
    DEFINE FIELD c_vw_sl_out ON warehouse VALUE type::record('v_sl_node_out', [$this.id]);

    DEFINE FIELD d_c1_global_matrix_stock ON warehouse TYPE decimal VALUE ($this.c_vw_sl_in.inbound_physical_qty ?? 0dec) - ($this.c_vw_sl_out.outbound_physical_qty ?? 0dec);

    DEFINE FIELD f_out ON warehouse TYPE object DEFAULT {};
    DEFINE FIELD f_out.is_locked ON warehouse TYPE bool VALUE false;


DEFINE TABLE stock_acc SCHEMAFULL;
    DEFINE FIELD a_in_name ON stock_acc TYPE string;
    DEFINE FIELD f_out ON stock_acc TYPE object DEFAULT {};
    DEFINE FIELD f_out.is_locked ON stock_acc TYPE bool VALUE false;


-- ==========================================
-- LEVEL 1: INTENTS
-- ==========================================
DEFINE TABLE invoice SCHEMAFULL;
    DEFINE FIELD a_in_org ON invoice TYPE record<org> REFERENCE ON DELETE REJECT;
    DEFINE FIELD a_in_type ON invoice TYPE string ASSERT $value IN ['sales', 'purchase'];
    DEFINE FIELD a_in_fx_rate ON invoice TYPE decimal DEFAULT 1.0dec ASSERT $value > 0dec;
    DEFINE FIELD suspended ON invoice TYPE bool DEFAULT false;
    DEFINE FIELD locked ON invoice TYPE bool DEFAULT false;

    DEFINE FIELD b_ctx_currency ON invoice VALUE $this.a_in_org.f_out.currency ?? 'USD';

    DEFINE FIELD c_vw_invl ON invoice VALUE type::record('v_invl_inv', [$this.id]);
    DEFINE FIELD c_vw_tl ON invoice VALUE type::record('v_tl_inv', [$this.id]);
    DEFINE FIELD c_vw_pa ON invoice VALUE type::record('v_pa_inv', [$this.id]);

    DEFINE FIELD d_c1_grand_total ON invoice TYPE decimal VALUE ($this.c_vw_invl.purchase_base_value ?? 0dec) + ($this.c_vw_invl.sales_base_value ?? 0dec) + ($this.c_vw_tl.purchase_tax_value ?? 0dec) + ($this.c_vw_tl.sales_tax_value ?? 0dec);
    DEFINE FIELD d_c2_allocation_shield ON invoice TYPE decimal VALUE ($this.d_c1_grand_total ?? 0dec) - ($this.c_vw_pa.allocated_inv_amount ?? 0dec) ASSERT $value >= 0dec;

    DEFINE FIELD e_guard_state ON invoice TYPE bool VALUE {
        IF $before.suspended = false AND suspended = true {
            IF ($this.c_vw_invl.inbound_physical_qty ?? 0dec) > 0dec OR ($this.c_vw_invl.outbound_physical_qty ?? 0dec) > 0dec { THROW "UX_ERR: Cannot suspend invoice, stock deliveries exist."; };
            IF ($this.c_vw_pa.allocated_inv_amount ?? 0dec) > 0dec { THROW "UX_ERR: Cannot suspend invoice, allocations exist."; };
        };
        IF $this.a_in_type = 'purchase' AND ($this.c_vw_invl.outbound_physical_qty ?? 0dec) > 0dec { THROW "PHYSICS_ERR: Purchases cannot have outbound deliveries."; };
        IF $this.a_in_type = 'sales' AND ($this.c_vw_invl.inbound_physical_qty ?? 0dec) > 0dec { THROW "PHYSICS_ERR: Sales cannot have inbound deliveries."; };
        RETURN true;
    } ASSERT $value = true;

    DEFINE FIELD f_out ON invoice TYPE object DEFAULT {};
    DEFINE FIELD f_out.purchase_base_value ON invoice TYPE decimal VALUE IF suspended THEN 0dec ELSE ($this.c_vw_invl.purchase_base_value ?? 0dec) END;
    DEFINE FIELD f_out.sales_base_value ON invoice TYPE decimal VALUE IF suspended THEN 0dec ELSE ($this.c_vw_invl.sales_base_value ?? 0dec) END;
    DEFINE FIELD f_out.purchase_tax_value ON invoice TYPE decimal VALUE IF suspended THEN 0dec ELSE ($this.c_vw_tl.purchase_tax_value ?? 0dec) END;
    DEFINE FIELD f_out.sales_tax_value ON invoice TYPE decimal VALUE IF suspended THEN 0dec ELSE ($this.c_vw_tl.sales_tax_value ?? 0dec) END;
    DEFINE FIELD f_out.grand_total ON invoice TYPE decimal VALUE IF suspended THEN 0dec ELSE ($this.d_c1_grand_total ?? 0dec) END;
    DEFINE FIELD f_out.is_locked ON invoice TYPE bool VALUE $this.locked ?? false;
    DEFINE FIELD f_out.fx_rate ON invoice TYPE decimal VALUE $this.a_in_fx_rate ?? 1.0dec;
    DEFINE FIELD f_out.type ON invoice TYPE string VALUE $this.a_in_type ?? '';


DEFINE TABLE payment SCHEMAFULL;
    DEFINE FIELD a_in_from ON payment TYPE record<org | treasury | acc | tax_account> REFERENCE ON DELETE REJECT;
    DEFINE FIELD a_in_to ON payment TYPE record<org | treasury | acc | tax_account> REFERENCE ON DELETE REJECT;
    DEFINE FIELD a_in_amount ON payment TYPE decimal ASSERT $value > 0dec;
    DEFINE FIELD a_in_fx_rate ON payment TYPE decimal DEFAULT 1dec ASSERT $value > 0dec;
    DEFINE FIELD suspended ON payment TYPE bool DEFAULT false;
    DEFINE FIELD locked ON payment TYPE bool DEFAULT false;

    DEFINE FIELD c_vw_pa ON payment VALUE type::record('v_pa_pay', [$this.id]);

    DEFINE FIELD d_c1_active_amount ON payment TYPE decimal VALUE ($this.a_in_amount ?? 0dec) * ($this.a_in_fx_rate ?? 1dec);
    DEFINE FIELD d_c2_allocation_shield ON payment TYPE decimal VALUE ($this.d_c1_active_amount ?? 0dec) - ($this.c_vw_pa.allocated_pay_amount ?? 0dec) ASSERT $value >= 0dec;

    DEFINE FIELD e_guard_state ON payment TYPE bool VALUE {
        IF $before.suspended = false AND suspended = true {
            IF ($this.c_vw_pa.allocated_pay_amount ?? 0dec) > 0dec { THROW "UX_ERR: Cannot suspend, allocations exist."; };
        };
        RETURN true;
    } ASSERT $value = true;

    DEFINE FIELD f_out ON payment TYPE object DEFAULT {};
    DEFINE FIELD f_out.active_amount ON payment TYPE decimal VALUE IF suspended THEN 0dec ELSE ($this.d_c1_active_amount ?? 0dec) END;
    DEFINE FIELD f_out.is_locked ON payment TYPE bool VALUE $this.locked ?? false;
    DEFINE FIELD f_out.fx_rate ON payment TYPE decimal VALUE $this.a_in_fx_rate ?? 1.0dec;

DEFINE TABLE adjustment_note SCHEMAFULL;
    DEFINE FIELD a_in_org ON adjustment_note TYPE record<org> REFERENCE ON DELETE REJECT;

    DEFINE FIELD d_c1_total_delta_qty ON adjustment_note TYPE decimal VALUE {
        LET $my_id = $this.id; 
        LET $res = (SELECT VALUE math::sum(f_out.delta_qty) FROM adjustment_line WHERE a_in_note = $my_id GROUP ALL);
        RETURN IF $before = NONE OR $before.system_ping != $this.system_ping THEN ($res[0] ?? 0dec) ELSE ($before.d_c1_total_delta_qty ?? 0dec) END;
    };
    DEFINE FIELD d_c2_total_delta_price ON adjustment_note TYPE decimal VALUE {
        LET $my_id = $this.id; 
        LET $res = (SELECT VALUE math::sum(f_out.delta_unit_price) FROM adjustment_line WHERE a_in_note = $my_id GROUP ALL);
        RETURN IF $before = NONE OR $before.system_ping != $this.system_ping THEN ($res[0] ?? 0dec) ELSE ($before.d_c2_total_delta_price ?? 0dec) END;
    };

    DEFINE FIELD f_out ON adjustment_note TYPE object DEFAULT {};
    DEFINE FIELD f_out.is_locked ON adjustment_note TYPE bool VALUE false;


-- ==========================================
-- LEVEL 2: BRANCHES
-- ==========================================
DEFINE TABLE invoice_line SCHEMAFULL;
    DEFINE FIELD a_in_invoice ON invoice_line TYPE record<invoice> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD a_in_item ON invoice_line TYPE record<item> REFERENCE ON DELETE REJECT;
    DEFINE FIELD a_in_qty ON invoice_line TYPE decimal ASSERT $value > 0dec;
    DEFINE FIELD a_in_price ON invoice_line TYPE decimal ASSERT $value >= 0dec;

    DEFINE FIELD b_ctx_inv_suspended ON invoice_line VALUE $this.a_in_invoice.suspended ?? false;
    DEFINE FIELD b_ctx_inv_locked ON invoice_line VALUE $this.a_in_invoice.f_out.is_locked ?? false;
    DEFINE FIELD b_ctx_inv_type ON invoice_line VALUE $this.a_in_invoice.f_out.type ?? '';
    DEFINE FIELD b_ctx_inv_fx ON invoice_line VALUE $this.a_in_invoice.f_out.fx_rate ?? 1.0dec;
    DEFINE FIELD b_ctx_item_cogs ON invoice_line VALUE $this.a_in_item.f_out.actual_unit_cogs ?? 0dec;
    DEFINE FIELD b_ctx_item_service ON invoice_line VALUE $this.a_in_item.f_out.is_service ?? false;

    DEFINE FIELD c_vw_sl_in ON invoice_line VALUE type::record('v_sl_invl_in', [$this.id]);
    DEFINE FIELD c_vw_sl_out ON invoice_line VALUE type::record('v_sl_invl_out', [$this.id]);
    DEFINE FIELD c_vw_al ON invoice_line VALUE type::record('v_al_invl', [$this.id]);

    DEFINE FIELD d_c1_net_qty ON invoice_line TYPE decimal VALUE ($this.a_in_qty ?? 0dec) + ($this.c_vw_al.delta_qty ?? 0dec);
    DEFINE FIELD d_c2_actual_cogs ON invoice_line TYPE decimal VALUE IF $this.b_ctx_inv_type = 'purchase' THEN (($this.a_in_price ?? 0dec) + ($this.c_vw_al.delta_unit_price ?? 0dec)) ELSE ($this.b_ctx_item_cogs ?? 0dec) END;
    DEFINE FIELD d_c3_base_val ON invoice_line TYPE decimal VALUE ($this.d_c1_net_qty ?? 0dec) * (($this.a_in_price ?? 0dec) + ($this.c_vw_al.delta_unit_price ?? 0dec));
    DEFINE FIELD d_c4_inventory_qty ON invoice_line TYPE decimal VALUE IF $this.b_ctx_item_service THEN 0dec ELSE ($this.d_c1_net_qty ?? 0dec) END;
    DEFINE FIELD d_c5_qty_shield ON invoice_line TYPE decimal VALUE IF $this.b_ctx_inv_type = 'purchase' THEN (($this.d_c4_inventory_qty ?? 0dec) - ($this.c_vw_sl_in.inbound_physical_qty ?? 0dec)) ELSE (($this.d_c4_inventory_qty ?? 0dec) - ($this.c_vw_sl_out.outbound_physical_qty ?? 0dec)) END ASSERT $value >= 0dec;

    DEFINE FIELD e_guard_state ON invoice_line TYPE bool VALUE {
        IF ($this.b_ctx_inv_locked ?? false) = true {
            IF $before.a_in_qty != $this.a_in_qty OR $before.a_in_price != $this.a_in_price { THROW "UX_ERR: Invoice is locked."; };
        };
        RETURN true;
    } ASSERT $value = true;

    DEFINE FIELD f_out ON invoice_line TYPE object DEFAULT {};
    DEFINE FIELD f_out.purchase_base_value ON invoice_line TYPE decimal VALUE IF $this.b_ctx_inv_suspended THEN 0dec ELSE (IF $this.b_ctx_inv_type = 'purchase' THEN ($this.d_c3_base_val ?? 0dec) ELSE 0dec END) END;
    DEFINE FIELD f_out.sales_base_value ON invoice_line TYPE decimal VALUE IF $this.b_ctx_inv_suspended THEN 0dec ELSE (IF $this.b_ctx_inv_type = 'sales' THEN ($this.d_c3_base_val ?? 0dec) ELSE 0dec END) END;
    DEFINE FIELD f_out.purchase_financial_qty ON invoice_line TYPE decimal VALUE IF $this.b_ctx_inv_suspended THEN 0dec ELSE (IF $this.b_ctx_inv_type = 'purchase' THEN ($this.d_c1_net_qty ?? 0dec) ELSE 0dec END) END;
    DEFINE FIELD f_out.sales_financial_qty ON invoice_line TYPE decimal VALUE IF $this.b_ctx_inv_suspended THEN 0dec ELSE (IF $this.b_ctx_inv_type = 'sales' THEN ($this.d_c1_net_qty ?? 0dec) ELSE 0dec END) END;
    DEFINE FIELD f_out.inbound_physical_qty ON invoice_line TYPE decimal VALUE $this.c_vw_sl_in.inbound_physical_qty ?? 0dec;
    DEFINE FIELD f_out.outbound_physical_qty ON invoice_line TYPE decimal VALUE $this.c_vw_sl_out.outbound_physical_qty ?? 0dec;
    DEFINE FIELD f_out.actual_unit_cogs ON invoice_line TYPE decimal VALUE $this.d_c2_actual_cogs ?? 0dec;
    DEFINE FIELD f_out.item ON invoice_line TYPE record<item> VALUE $this.a_in_item;
    DEFINE FIELD f_out.is_locked ON invoice_line TYPE bool VALUE $this.b_ctx_inv_locked ?? false;
    DEFINE FIELD f_out.inv_fx_rate ON invoice_line TYPE decimal VALUE $this.b_ctx_inv_fx ?? 1.0dec;
    DEFINE FIELD f_out.type ON invoice_line TYPE string VALUE $this.b_ctx_inv_type ?? '';


DEFINE TABLE payment_allocation SCHEMAFULL;
    DEFINE FIELD a_in_payment ON payment_allocation TYPE record<payment> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD a_in_invoice ON payment_allocation TYPE record<invoice> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD a_in_amount ON payment_allocation TYPE decimal ASSERT $value > 0dec;

    DEFINE FIELD b_ctx_pay_fx ON payment_allocation VALUE $this.a_in_payment.f_out.fx_rate ?? 1.0dec;
    DEFINE FIELD b_ctx_pay_susp ON payment_allocation VALUE $this.a_in_payment.suspended ?? false;
    DEFINE FIELD b_ctx_inv_susp ON payment_allocation VALUE $this.a_in_invoice.suspended ?? false;
    DEFINE FIELD b_ctx_pay_lock ON payment_allocation VALUE $this.a_in_payment.f_out.is_locked ?? false;
    DEFINE FIELD b_ctx_inv_lock ON payment_allocation VALUE $this.a_in_invoice.f_out.is_locked ?? false;
    DEFINE FIELD b_ctx_pay_avail ON payment_allocation VALUE $this.a_in_payment.f_out.active_amount ?? 0dec;
    DEFINE FIELD b_ctx_inv_total ON payment_allocation VALUE $this.a_in_invoice.f_out.grand_total ?? 0dec;

    DEFINE FIELD e_guard_state ON payment_allocation TYPE bool VALUE {
        IF $this.b_ctx_pay_susp OR $this.b_ctx_inv_susp { THROW "UX_ERR: Cannot allocate against suspended records."; };
        IF $this.b_ctx_pay_lock OR $this.b_ctx_inv_lock {
            IF $before.a_in_amount != $this.a_in_amount { THROW "UX_ERR: Locked."; };
        };
        LET $pay_impact = ($this.a_in_amount ?? 0dec) * ($this.b_ctx_pay_fx ?? 1dec);
        IF $pay_impact > ($this.b_ctx_pay_avail ?? 0dec) { THROW "UX_ERR: Exceeds payment."; };
        IF ($this.a_in_amount ?? 0dec) > ($this.b_ctx_inv_total ?? 0dec) { THROW "UX_ERR: Exceeds invoice."; };
        RETURN true;
    } ASSERT $value = true;

    DEFINE FIELD f_out ON payment_allocation TYPE object DEFAULT {};
    DEFINE FIELD f_out.allocated_inv_amount ON payment_allocation TYPE decimal VALUE IF $this.b_ctx_pay_susp OR $this.b_ctx_inv_susp THEN 0dec ELSE ($this.a_in_amount ?? 0dec) END;
    DEFINE FIELD f_out.allocated_pay_amount ON payment_allocation TYPE decimal VALUE IF $this.b_ctx_pay_susp OR $this.b_ctx_inv_susp THEN 0dec ELSE (($this.a_in_amount ?? 0dec) * ($this.b_ctx_pay_fx ?? 1dec)) END;


DEFINE TABLE package_note SCHEMAFULL;
    DEFINE FIELD a_in_invoice ON package_note TYPE record<invoice> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD a_in_tracking ON package_note TYPE string;

    DEFINE FIELD b_ctx_inv_locked ON package_note VALUE $this.a_in_invoice.f_out.is_locked ?? false;

    DEFINE FIELD c_vw_sl ON package_note VALUE type::record('v_sl_pkg', [$this.id]);

    DEFINE FIELD f_out ON package_note TYPE object DEFAULT {};
    DEFINE FIELD f_out.outbound_physical_qty ON package_note TYPE decimal VALUE $this.c_vw_sl.outbound_physical_qty ?? 0dec;
    DEFINE FIELD f_out.is_locked ON package_note TYPE bool VALUE $this.b_ctx_inv_locked ?? false;


-- ==========================================
-- LEVEL 3: LEAVES
-- ==========================================
DEFINE TABLE sl SCHEMAFULL;
    DEFINE FIELD a_in_from ON sl TYPE record<warehouse | stock_acc | invoice_line | acc> REFERENCE ON DELETE REJECT;
    DEFINE FIELD a_in_to ON sl TYPE record<warehouse | stock_acc | invoice_line | acc> REFERENCE ON DELETE REJECT;
    DEFINE FIELD a_in_pkg ON sl TYPE option<record<package_note>> REFERENCE ON DELETE CASCADE DEFAULT NONE;
    DEFINE FIELD a_in_qty ON sl TYPE decimal ASSERT $value > 0dec;
    DEFINE FIELD a_in_item ON sl TYPE option<record<item>> REFERENCE ON DELETE REJECT DEFAULT NONE;
    DEFINE FIELD a_in_cogs ON sl TYPE option<decimal> DEFAULT NONE;
    DEFINE FIELD suspended ON sl TYPE bool DEFAULT false;
    DEFINE FIELD locked ON sl TYPE bool DEFAULT false;

    DEFINE FIELD b_ctx_from_locked ON sl VALUE $this.a_in_from.f_out.is_locked ?? false;
    DEFINE FIELD b_ctx_to_locked ON sl VALUE $this.a_in_to.f_out.is_locked ?? false;
    DEFINE FIELD b_ctx_pkg_locked ON sl VALUE $this.a_in_pkg.f_out.is_locked ?? false;
    DEFINE FIELD b_ctx_from_susp ON sl VALUE $this.a_in_from.suspended ?? false;
    DEFINE FIELD b_ctx_to_susp ON sl VALUE $this.a_in_to.suspended ?? false;
    DEFINE FIELD b_ctx_from_fx ON sl VALUE $this.a_in_from.f_out.inv_fx_rate ?? 1.0dec;
    DEFINE FIELD b_ctx_to_fx ON sl VALUE $this.a_in_to.f_out.inv_fx_rate ?? 1.0dec;
    DEFINE FIELD b_ctx_from_item ON sl VALUE $this.a_in_from.f_out.item;
    DEFINE FIELD b_ctx_to_item ON sl VALUE $this.a_in_to.f_out.item;
    DEFINE FIELD b_ctx_from_cogs ON sl VALUE $this.a_in_from.f_out.actual_unit_cogs;
    DEFINE FIELD b_ctx_to_cogs ON sl VALUE $this.a_in_to.f_out.actual_unit_cogs;

    DEFINE FIELD c_vw_adj ON sl VALUE type::record('v_asl_sl', [$this.id]);

    DEFINE FIELD d_c1_item ON sl VALUE $this.b_ctx_from_item ?? $this.b_ctx_to_item ?? $this.a_in_item;
    DEFINE FIELD d_c2_unit_cogs ON sl TYPE decimal VALUE $this.b_ctx_from_cogs ?? $this.b_ctx_to_cogs ?? $this.a_in_cogs ?? 0dec;
    DEFINE FIELD d_c3_active_qty ON sl TYPE decimal VALUE IF suspended THEN 0dec ELSE (($this.a_in_qty ?? 0dec) + ($this.c_vw_adj.delta_qty ?? 0dec)) END;
    DEFINE FIELD d_c4_cogs_val ON sl TYPE decimal VALUE ($this.d_c3_active_qty ?? 0dec) * ($this.d_c2_unit_cogs ?? 0dec);
    DEFINE FIELD d_c5_fx ON sl TYPE decimal VALUE $this.b_ctx_from_fx ?? $this.b_ctx_to_fx ?? 1.0dec;
    DEFINE FIELD d_c6_susp ON sl TYPE bool VALUE $this.b_ctx_from_susp ?? $this.b_ctx_to_susp ?? false;

    DEFINE FIELD e_guard_state ON sl TYPE bool VALUE {
        IF $this.d_c1_item = NONE { THROW "UX_ERR: Missing Item Resolution."; };
        LET $p_locked = $this.b_ctx_from_locked ?? $this.b_ctx_to_locked ?? $this.b_ctx_pkg_locked ?? false;
        IF $p_locked { IF $before.a_in_qty != $this.a_in_qty { THROW "UX_ERR: Parent contract is sealed."; }; };
        RETURN true;
    } ASSERT $value = true;

    DEFINE FIELD f_out ON sl TYPE object DEFAULT {};
    DEFINE FIELD f_out.inbound_physical_qty ON sl TYPE decimal VALUE IF suspended OR $this.d_c6_susp THEN 0dec ELSE (IF record::tb($this.a_in_to) = 'warehouse' THEN $this.d_c3_active_qty ELSE 0dec END) END;
    DEFINE FIELD f_out.outbound_physical_qty ON sl TYPE decimal VALUE IF suspended OR $this.d_c6_susp THEN 0dec ELSE (IF record::tb($this.a_in_from) = 'warehouse' THEN $this.d_c3_active_qty ELSE 0dec END) END;
    DEFINE FIELD f_out.actual_cogs_value_inv_curr ON sl TYPE decimal VALUE IF suspended OR $this.d_c6_susp THEN 0dec ELSE $this.d_c4_cogs_val END;
    DEFINE FIELD f_out.actual_cogs_value_acc_curr ON sl TYPE decimal VALUE IF suspended OR $this.d_c6_susp THEN 0dec ELSE ($this.d_c4_cogs_val * $this.d_c5_fx) END;
    DEFINE FIELD f_out.item ON sl TYPE record<item> VALUE $this.d_c1_item;
    DEFINE FIELD f_out.cogs_account ON sl TYPE record<acc> VALUE $this.d_c1_item.f_out.cogs_account;
    DEFINE FIELD f_out.is_locked ON sl TYPE bool VALUE $this.b_ctx_from_locked ?? $this.b_ctx_to_locked ?? false;


DEFINE TABLE tax_line SCHEMAFULL;
    DEFINE FIELD a_in_invoice_line ON tax_line TYPE record<invoice_line> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD a_in_tax_account ON tax_line TYPE record<tax_account> REFERENCE ON DELETE REJECT;
    DEFINE FIELD a_in_rate ON tax_line TYPE decimal ASSERT $value >= 0dec;

    DEFINE FIELD b_ctx_invl_locked ON tax_line VALUE $this.a_in_invoice_line.f_out.is_locked ?? false;
    DEFINE FIELD b_ctx_invl_type ON tax_line VALUE $this.a_in_invoice_line.f_out.type ?? '';
    DEFINE FIELD b_ctx_invl_fx ON tax_line VALUE $this.a_in_invoice_line.f_out.inv_fx_rate ?? 1.0dec;
    DEFINE FIELD b_ctx_invl_sales_val ON tax_line VALUE $this.a_in_invoice_line.f_out.sales_base_value ?? 0dec;
    DEFINE FIELD b_ctx_invl_pur_val ON tax_line VALUE $this.a_in_invoice_line.f_out.purchase_base_value ?? 0dec;

    DEFINE FIELD c_vw_adj ON tax_line VALUE type::record('v_atl_tl', [$this.id]);

    DEFINE FIELD d_c1_base_val ON tax_line TYPE decimal VALUE IF $this.b_ctx_invl_type = 'sales' THEN $this.b_ctx_invl_sales_val ELSE $this.b_ctx_invl_pur_val END;
    DEFINE FIELD d_c2_tax_inv_curr ON tax_line TYPE decimal VALUE (($this.d_c1_base_val ?? 0dec) * (($this.a_in_rate ?? 0dec) / 100dec)) + ($this.c_vw_adj.delta_amount ?? 0dec);
    DEFINE FIELD d_c3_tax_acc_curr ON tax_line TYPE decimal VALUE ($this.d_c2_tax_inv_curr * $this.b_ctx_invl_fx);

    DEFINE FIELD e_guard_state ON tax_line TYPE bool VALUE {
        IF $this.b_ctx_invl_locked { IF $before.a_in_rate != $this.a_in_rate { THROW "UX_ERR: Locked."; }; };
        RETURN true;
    } ASSERT $value = true;

    DEFINE FIELD f_out ON tax_line TYPE object DEFAULT {};
    DEFINE FIELD f_out.sales_tax_value ON tax_line TYPE decimal VALUE IF $this.b_ctx_invl_type = 'sales' THEN $this.d_c2_tax_inv_curr ELSE 0dec END;
    DEFINE FIELD f_out.purchase_tax_value ON tax_line TYPE decimal VALUE IF $this.b_ctx_invl_type = 'purchase' THEN $this.d_c2_tax_inv_curr ELSE 0dec END;
    DEFINE FIELD f_out.sales_tax_acc_value ON tax_line TYPE decimal VALUE IF $this.b_ctx_invl_type = 'sales' THEN $this.d_c3_tax_acc_curr ELSE 0dec END;
    DEFINE FIELD f_out.purchase_tax_acc_value ON tax_line TYPE decimal VALUE IF $this.b_ctx_invl_type = 'purchase' THEN $this.d_c3_tax_acc_curr ELSE 0dec END;


-- ==========================================
-- LEVEL 4: DELTAS
-- ==========================================
DEFINE TABLE adjustment_line SCHEMAFULL;
    DEFINE FIELD a_in_note ON adjustment_line TYPE record<adjustment_note> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD a_in_invl ON adjustment_line TYPE record<invoice_line> REFERENCE ON DELETE REJECT;
    DEFINE FIELD a_in_delta_qty ON adjustment_line TYPE decimal DEFAULT 0dec;
    DEFINE FIELD a_in_delta_price ON adjustment_line TYPE decimal DEFAULT 0dec;

    DEFINE FIELD b_ctx_note_lock ON adjustment_line VALUE $this.a_in_note.f_out.is_locked ?? false;

    DEFINE FIELD e_guard_state ON adjustment_line TYPE bool VALUE {
        IF $this.b_ctx_note_lock { IF $before.a_in_delta_qty != $this.a_in_delta_qty { THROW "UX_ERR: Locked."; }; };
        RETURN true;
    } ASSERT $value = true;

    DEFINE FIELD f_out ON adjustment_line TYPE object DEFAULT {};
    DEFINE FIELD f_out.delta_qty ON adjustment_line TYPE decimal VALUE $this.a_in_delta_qty ?? 0dec;
    DEFINE FIELD f_out.delta_unit_price ON adjustment_line TYPE decimal VALUE $this.a_in_delta_price ?? 0dec;

DEFINE TABLE adjustment_tax_line SCHEMAFULL;
    DEFINE FIELD a_in_note ON adjustment_tax_line TYPE record<adjustment_note> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD a_in_tax_line ON adjustment_tax_line TYPE record<tax_line> REFERENCE ON DELETE REJECT;
    DEFINE FIELD a_in_delta_amount ON adjustment_tax_line TYPE decimal DEFAULT 0dec;
    DEFINE FIELD f_out ON adjustment_tax_line TYPE object DEFAULT {};
    DEFINE FIELD f_out.delta_amount ON adjustment_tax_line TYPE decimal VALUE $this.a_in_delta_amount ?? 0dec;

DEFINE TABLE adjustment_stock_line SCHEMAFULL;
    DEFINE FIELD a_in_note ON adjustment_stock_line TYPE record<adjustment_note> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD a_in_sl ON adjustment_stock_line TYPE record<sl> REFERENCE ON DELETE REJECT;
    DEFINE FIELD a_in_delta_qty ON adjustment_stock_line TYPE decimal DEFAULT 0dec;
    DEFINE FIELD f_out ON adjustment_stock_line TYPE object DEFAULT {};
    DEFINE FIELD f_out.delta_qty ON adjustment_stock_line TYPE decimal VALUE $this.a_in_delta_qty ?? 0dec;