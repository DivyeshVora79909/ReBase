-- ==============================================================================
-- FILE 06: THE 7-TIER LEXICOGRAPHICAL PHYSICS PIPELINE
-- ==============================================================================
USE NS main DB main;

-- ==========================================
-- LEVEL 0: INDEPENDENT ANCHORS
-- ==========================================
DEFINE FIELD name ON org TYPE string;
DEFINE FIELD currency ON org TYPE string DEFAULT 'USD';
DEFINE FIELD zb_child ON org TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_inv_org ON org TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_inv_org.purchase_base_value ON org TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_inv_org.sales_base_value ON org TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_inv_org.purchase_tax_value ON org TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_inv_org.sales_tax_value ON org TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_pay_to ON org TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_to.active_amount ON org TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_pay_from ON org TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_from.active_amount ON org TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz_net_financial_position ON org TYPE decimal VALUE 
    (($this.zb_child.v_inv_org.sales_base_value ?? 0dec) + ($this.zb_child.v_inv_org.sales_tax_value ?? 0dec) - ($this.zb_child.v_inv_org.purchase_base_value ?? 0dec) - ($this.zb_child.v_inv_org.purchase_tax_value ?? 0dec)) 
    + 
    (($this.zb_child.v_pay_in.active_amount ?? 0dec) - ($this.zb_child.v_pay_out.active_amount ?? 0dec));

DEFINE FIELD name ON treasury TYPE string;
DEFINE FIELD currency ON treasury TYPE string DEFAULT 'USD';
DEFINE FIELD zb_child ON treasury TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_to ON treasury TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_to.active_amount ON treasury TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_pay_from ON treasury TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_from.active_amount ON treasury TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz_balance ON treasury TYPE decimal VALUE ($this.zb_child.v_pay_to.active_amount ?? 0dec) - ($this.zb_child.v_pay_from.active_amount ?? 0dec);
DEFINE FIELD zzz_shield ON treasury TYPE bool VALUE $this.zz_balance >= 0dec ASSERT $value = true;

DEFINE FIELD name ON acc TYPE string;
DEFINE FIELD type ON acc TYPE string;
DEFINE FIELD currency ON acc TYPE string DEFAULT 'USD';
DEFINE FIELD zb_child ON acc TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_to ON acc TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_to.active_amount ON acc TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_pay_from ON acc TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_from.active_amount ON acc TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_sl_cogs_out ON acc TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_sl_cogs_out.actual_cogs_value ON acc TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz_balance ON acc TYPE decimal VALUE ($this.zb_child.v_pay_to.active_amount ?? 0dec) - ($this.zb_child.v_pay_from.active_amount ?? 0dec) + ($this.zb_child.v_sl_cogs_out.actual_cogs_value ?? 0dec);

DEFINE FIELD name ON tax_account TYPE string;
DEFINE FIELD currency ON tax_account TYPE string DEFAULT 'USD';
DEFINE FIELD zb_child ON tax_account TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_to ON tax_account TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_to.active_amount ON tax_account TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_pay_from ON tax_account TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_from.active_amount ON tax_account TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_tl ON tax_account TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_tl.sales_tax_value ON tax_account TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_tl.purchase_tax_value ON tax_account TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz_liability ON tax_account TYPE decimal VALUE ($this.zb_child.v_tl.sales_tax_value ?? 0dec) - ($this.zb_child.v_tl.purchase_tax_value ?? 0dec) - ($this.zb_child.v_pay_to.active_amount ?? 0dec) + ($this.zb_child.v_pay_from.active_amount ?? 0dec);

DEFINE FIELD name ON item TYPE string;
DEFINE FIELD is_service ON item TYPE bool DEFAULT false;
DEFINE FIELD default_cogs ON item TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child ON item TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_invl_item ON item TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_invl_item.purchase_financial_qty ON item TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_invl_item.purchase_base_value ON item TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_invl_item.sales_financial_qty ON item TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_invl_item.sales_base_value ON item TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_sl_matrix_in ON item TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_sl_matrix_in.inbound_physical_qty ON item TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_sl_matrix_out ON item TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_sl_matrix_out.outbound_physical_qty ON item TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz_turnover ON item TYPE decimal VALUE ($this.zb_child.v_invl_item.sales_financial_qty ?? 0dec);
DEFINE FIELD zz_avg_cogs ON item TYPE decimal VALUE 
    IF ($this.zb_child.v_invl_item.purchase_financial_qty ?? 0dec) > 0dec 
    THEN ($this.zb_child.v_invl_item.purchase_base_value ?? 0dec) / ($this.zb_child.v_invl_item.purchase_financial_qty ?? 0dec) 
    ELSE $this.default_cogs END;
DEFINE FIELD zz_physical_stock ON item TYPE decimal VALUE ($this.zb_child.v_sl_matrix_in.inbound_physical_qty ?? 0dec) - ($this.zb_child.v_sl_matrix_out.outbound_physical_qty ?? 0dec);

DEFINE FIELD name ON warehouse TYPE string;
DEFINE FIELD zb_child ON warehouse TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_sl_matrix_in ON warehouse TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_sl_matrix_in.inbound_physical_qty ON warehouse TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_sl_matrix_out ON warehouse TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_sl_matrix_out.outbound_physical_qty ON warehouse TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz_global_matrix_stock ON warehouse TYPE decimal VALUE ($this.zb_child.v_sl_matrix_in.inbound_physical_qty ?? 0dec) - ($this.zb_child.v_sl_matrix_out.outbound_physical_qty ?? 0dec);

DEFINE FIELD name ON stock_acc TYPE string;

-- ==========================================
-- LEVEL 1: INTENTS
-- ==========================================
DEFINE FIELD org ON invoice TYPE record<org> REFERENCE ON DELETE REJECT;
DEFINE FIELD raw_type ON invoice TYPE string ASSERT $value IN ['sales', 'purchase'];
DEFINE FIELD A_guard ON invoice TYPE object DEFAULT {};
DEFINE FIELD A_guard.state_check ON invoice TYPE bool VALUE {
    IF $before.suspended = false AND suspended = true {
        IF ($this.zb_child.v_invl_inv.inbound_physical_qty ?? 0dec) > 0dec OR ($this.zb_child.v_invl_inv.outbound_physical_qty ?? 0dec) > 0dec { 
            THROW "UX_ERR: Cannot suspend invoice, stock deliveries exist."; 
        };
        IF ($this.zb_child.v_pa_inv.allocated_amount ?? 0dec) > 0dec { 
            THROW "UX_ERR: Cannot suspend invoice, payment allocations exist."; 
        };
    };
    RETURN true;
};
DEFINE FIELD za_parent ON invoice TYPE object DEFAULT {};
DEFINE FIELD za_parent.currency ON invoice TYPE string VALUE $this.org.currency;
DEFINE FIELD zb_child ON invoice TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_invl_inv ON invoice TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_invl_inv.purchase_base_value ON invoice TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_invl_inv.sales_base_value ON invoice TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_invl_inv.inbound_physical_qty ON invoice TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_invl_inv.outbound_physical_qty ON invoice TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_tl_inv ON invoice TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_tl_inv.purchase_tax_value ON invoice TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_tl_inv.sales_tax_value ON invoice TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_pa_inv ON invoice TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pa_inv.allocated_amount ON invoice TYPE decimal DEFAULT 0dec;

DEFINE FIELD z_grand_total ON invoice TYPE decimal VALUE 
    ($this.zb_child.v_invl_inv.purchase_base_value ?? 0dec) + ($this.zb_child.v_invl_inv.sales_base_value ?? 0dec) + 
    ($this.zb_child.v_tl_inv.purchase_tax_value ?? 0dec) + ($this.zb_child.v_tl_inv.sales_tax_value ?? 0dec);

DEFINE FIELD zz_allocation_shield ON invoice TYPE decimal VALUE ($this.z_grand_total ?? 0dec) - ($this.zb_child.v_pa_inv.allocated_amount ?? 0dec) ASSERT $value >= 0dec;
DEFINE FIELD zz_vector_shield ON invoice TYPE bool VALUE {
    IF $this.raw_type = 'purchase' AND ($this.zb_child.v_invl_inv.outbound_physical_qty ?? 0dec) > 0dec { THROW "PHYSICS_ERR: Purchase invoice cannot have outbound deliveries."; };
    IF $this.raw_type = 'sales' AND ($this.zb_child.v_invl_inv.inbound_physical_qty ?? 0dec) > 0dec { THROW "PHYSICS_ERR: Sales invoice cannot have inbound deliveries."; };
    RETURN true;
} ASSERT $value = true;

DEFINE FIELD zzzzz_out ON invoice TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.purchase_base_value ON invoice TYPE decimal VALUE IF suspended THEN 0dec ELSE $this.zb_child.v_invl_inv.purchase_base_value END;
DEFINE FIELD zzzzz_out.sales_base_value ON invoice TYPE decimal VALUE IF suspended THEN 0dec ELSE $this.zb_child.v_invl_inv.sales_base_value END;
DEFINE FIELD zzzzz_out.purchase_tax_value ON invoice TYPE decimal VALUE IF suspended THEN 0dec ELSE $this.zb_child.v_tl_inv.purchase_tax_value END;
DEFINE FIELD zzzzz_out.sales_tax_value ON invoice TYPE decimal VALUE IF suspended THEN 0dec ELSE $this.zb_child.v_tl_inv.sales_tax_value END;
DEFINE FIELD zzzzz_out.is_locked ON invoice TYPE bool VALUE $this.locked;

DEFINE FIELD from ON payment TYPE record<org | treasury | acc | tax_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD to ON payment TYPE record<org | treasury | acc | tax_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD raw_amount ON payment TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD fx_rate ON payment TYPE decimal DEFAULT 1dec ASSERT $value > 0dec;
DEFINE FIELD A_guard ON payment TYPE object DEFAULT {};
DEFINE FIELD A_guard.state_check ON payment TYPE bool VALUE {
    IF $before.suspended = false AND suspended = true {
        IF ($this.zb_child.v_pa_pay.allocated_amount ?? 0dec) > 0dec { THROW "UX_ERR: Cannot suspend, allocations exist."; };
    };
    RETURN true;
};
DEFINE FIELD za_parent ON payment TYPE object DEFAULT {};
DEFINE FIELD za_parent.base_currency ON payment TYPE string VALUE $this.from.currency ?? $this.to.currency ?? 'USD';
DEFINE FIELD zb_child ON payment TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pa_pay ON payment TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pa_pay.allocated_amount ON payment TYPE decimal DEFAULT 0dec;

DEFINE FIELD z_active_amount ON payment TYPE decimal VALUE ($this.raw_amount ?? 0dec) * ($this.fx_rate ?? 1dec);
DEFINE FIELD zz_allocation_shield ON payment TYPE decimal VALUE ($this.z_active_amount ?? 0dec) - ($this.zb_child.v_pa_pay.allocated_amount ?? 0dec) ASSERT $value >= 0dec;

DEFINE FIELD zzzzz_out ON payment TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.active_amount ON payment TYPE decimal VALUE IF suspended THEN 0dec ELSE ($this.z_active_amount ?? 0dec) END;

DEFINE FIELD org ON adjustment_note TYPE record<org> REFERENCE ON DELETE REJECT;
DEFINE FIELD A_guard ON adjustment_note TYPE object DEFAULT {};
DEFINE FIELD A_guard.state_check ON adjustment_note TYPE bool VALUE { RETURN true; };

DEFINE FIELD zz_total_delta_qty ON adjustment_note TYPE decimal VALUE {
    LET $res = (SELECT adjustment_note, math::sum(zzzzz_out.delta_qty) AS t FROM adjustment_line WHERE adjustment_note = $this.id GROUP BY adjustment_note);
    RETURN IF $before = NONE OR $before.system_ping != $this.system_ping THEN ($res[0].t ?? 0dec) ELSE ($before.zz_total_delta_qty ?? 0dec) END;
};
DEFINE FIELD zz_total_delta_cogs ON adjustment_note TYPE decimal VALUE {
    LET $res = (SELECT adjustment_note, math::sum(zzzzz_out.delta_price) AS t FROM adjustment_line WHERE adjustment_note = $this.id GROUP BY adjustment_note);
    RETURN IF $before = NONE OR $before.system_ping != $this.system_ping THEN ($res[0].t ?? 0dec) ELSE ($before.zz_total_delta_cogs ?? 0dec) END;
};

DEFINE FIELD zzzzz_out ON adjustment_note TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.is_active ON adjustment_note TYPE bool VALUE true;

-- ==========================================
-- LEVEL 2: BRANCHES
-- ==========================================
DEFINE FIELD invoice ON invoice_line TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD item ON invoice_line TYPE record<item> REFERENCE ON DELETE REJECT;
DEFINE FIELD raw_qty ON invoice_line TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD raw_unit_price ON invoice_line TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD A_guard ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD A_guard.state_check ON invoice_line TYPE bool VALUE {
    IF ($this.za_parent.inv_locked ?? false) = true {
        IF $before.raw_qty != $this.raw_qty OR $before.raw_unit_price != $this.raw_unit_price { THROW "UX_ERR: Invoice is locked. Core fields immutable."; };
    };
    RETURN true;
};
DEFINE FIELD za_parent ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD za_parent.inv_locked ON invoice_line TYPE bool VALUE $this.invoice.zzzzz_out.is_locked ?? false;
DEFINE FIELD za_parent.inv_type ON invoice_line TYPE string VALUE $this.invoice.raw_type;
DEFINE FIELD za_parent.item_avg_cogs ON invoice_line TYPE decimal VALUE $this.item.zz_avg_cogs ?? 0dec;

DEFINE FIELD zb_child ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_sl_invl_in ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_sl_invl_in.inbound_physical_qty ON invoice_line TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_sl_invl_out ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_sl_invl_out.outbound_physical_qty ON invoice_line TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_al_invl ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_al_invl.delta_qty ON invoice_line TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_al_invl.delta_cogs ON invoice_line TYPE decimal DEFAULT 0dec;

DEFINE FIELD z_net_qty ON invoice_line TYPE decimal VALUE ($this.raw_qty ?? 0dec) + ($this.zb_child.v_al_invl.delta_qty ?? 0dec);
DEFINE FIELD z_actual_unit_cogs ON invoice_line TYPE decimal VALUE IF $this.za_parent.inv_type = 'purchase' THEN ($this.raw_unit_price ?? 0dec) ELSE ($this.za_parent.item_avg_cogs ?? 0dec) END;

DEFINE FIELD zz_base_value ON invoice_line TYPE decimal VALUE ($this.z_net_qty ?? 0dec) * ($this.raw_unit_price ?? 0dec);
DEFINE FIELD zz_inventory_qty ON invoice_line TYPE decimal VALUE IF $this.item.is_service THEN 0dec ELSE ($this.z_net_qty ?? 0dec) END;

DEFINE FIELD zzz_qty_shield ON invoice_line TYPE decimal VALUE 
    IF $this.za_parent.inv_type = 'purchase' THEN (($this.zz_inventory_qty ?? 0dec) - ($this.zb_child.v_sl_invl_in.inbound_physical_qty ?? 0dec))
    ELSE (($this.zz_inventory_qty ?? 0dec) - ($this.zb_child.v_sl_invl_out.outbound_physical_qty ?? 0dec)) END
    ASSERT $value >= 0dec;

DEFINE FIELD zzzzz_out ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.purchase_base_value ON invoice_line TYPE decimal VALUE IF $this.za_parent.inv_type = 'purchase' THEN ($this.zz_base_value ?? 0dec) ELSE 0dec END;
DEFINE FIELD zzzzz_out.sales_base_value ON invoice_line TYPE decimal VALUE IF $this.za_parent.inv_type = 'sales' THEN ($this.zz_base_value ?? 0dec) ELSE 0dec END;
DEFINE FIELD zzzzz_out.purchase_financial_qty ON invoice_line TYPE decimal VALUE IF $this.za_parent.inv_type = 'purchase' THEN ($this.z_net_qty ?? 0dec) ELSE 0dec END;
DEFINE FIELD zzzzz_out.sales_financial_qty ON invoice_line TYPE decimal VALUE IF $this.za_parent.inv_type = 'sales' THEN ($this.z_net_qty ?? 0dec) ELSE 0dec END;
DEFINE FIELD zzzzz_out.inbound_physical_qty ON invoice_line TYPE decimal VALUE $this.zb_child.v_sl_invl_in.inbound_physical_qty ?? 0dec;
DEFINE FIELD zzzzz_out.outbound_physical_qty ON invoice_line TYPE decimal VALUE $this.zb_child.v_sl_invl_out.outbound_physical_qty ?? 0dec;
DEFINE FIELD zzzzz_out.unit_price ON invoice_line TYPE decimal VALUE ($this.raw_unit_price ?? 0dec);
DEFINE FIELD zzzzz_out.actual_unit_cogs ON invoice_line TYPE decimal VALUE ($this.z_actual_unit_cogs ?? 0dec);
DEFINE FIELD zzzzz_out.is_locked ON invoice_line TYPE bool VALUE $this.za_parent.inv_locked ?? false;


DEFINE FIELD payment ON payment_allocation TYPE record<payment> REFERENCE ON DELETE CASCADE;
DEFINE FIELD invoice ON payment_allocation TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD raw_amount ON payment_allocation TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD A_guard ON payment_allocation TYPE object DEFAULT {};
DEFINE FIELD A_guard.dag_check ON payment_allocation TYPE bool VALUE {
    LET $p_org = IF record::tb($this.payment.from) = 'org' THEN $this.payment.from ELSE $this.payment.to END;
    LET $i_org = $this.invoice.org;
    IF $p_org != $i_org { THROW "UX_ERR: DAG Fracture. Payment and Invoice do not share Org."; };
    RETURN true;
};
DEFINE FIELD za_parent ON payment_allocation TYPE object DEFAULT {};
DEFINE FIELD za_parent.pay_fx_rate ON payment_allocation TYPE decimal VALUE $this.payment.fx_rate ?? 1dec;

DEFINE FIELD zzzzz_out ON payment_allocation TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.allocated_amount ON payment_allocation TYPE decimal VALUE ($this.raw_amount ?? 0dec) * ($this.za_parent.pay_fx_rate ?? 1dec);


DEFINE FIELD invoice ON package_note TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD tracking ON package_note TYPE string;
DEFINE FIELD A_guard ON package_note TYPE object DEFAULT {};
DEFINE FIELD za_parent ON package_note TYPE object DEFAULT {};
DEFINE FIELD za_parent.inv_locked ON package_note TYPE bool VALUE $this.invoice.zzzzz_out.is_locked ?? false;
DEFINE FIELD zb_child ON package_note TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_sl_pkg ON package_note TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_sl_pkg.outbound_physical_qty ON package_note TYPE decimal DEFAULT 0dec;

DEFINE FIELD zzzzz_out ON package_note TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.outbound_physical_qty ON package_note TYPE decimal VALUE $this.zb_child.v_sl_pkg.outbound_physical_qty ?? 0dec;
DEFINE FIELD zzzzz_out.is_locked ON package_note TYPE bool VALUE $this.za_parent.inv_locked ?? false;

-- ==========================================
-- LEVEL 3: LEAVES
-- ==========================================
DEFINE FIELD from ON sl TYPE record<warehouse | stock_acc | invoice_line> REFERENCE ON DELETE REJECT;
DEFINE FIELD to ON sl TYPE record<warehouse | stock_acc | invoice_line> REFERENCE ON DELETE REJECT;
DEFINE FIELD pkg ON sl TYPE option<record<package_note>> REFERENCE ON DELETE CASCADE DEFAULT NONE;
DEFINE FIELD raw_qty ON sl TYPE decimal ASSERT $value > 0dec;

DEFINE FIELD A_guard ON sl TYPE object DEFAULT {};
DEFINE FIELD A_guard.state_check ON sl TYPE bool VALUE {
    IF $before.suspended = false AND suspended = true {
        IF ($this.zb_child.v_asl_sl.delta_qty ?? 0dec) != 0dec { THROW "UX_ERR: Cannot suspend, adjustments exist."; };
    };
    IF ($this.za_parent.parent_locked ?? false) = true {
        IF $before.raw_qty != $this.raw_qty { THROW "UX_ERR: Parent contract is sealed."; };
    };
    RETURN true;
};

DEFINE FIELD za_parent ON sl TYPE object DEFAULT {};
DEFINE FIELD za_parent.item ON sl TYPE record<item> VALUE $this.from.item ?? $this.to.item ASSERT $value != NONE;
DEFINE FIELD za_parent.unit_cogs ON sl TYPE decimal VALUE $this.from.zzzzz_out.actual_unit_cogs ?? $this.to.zzzzz_out.actual_unit_cogs ?? 0dec;
DEFINE FIELD za_parent.parent_locked ON sl TYPE bool VALUE $this.from.zzzzz_out.is_locked ?? $this.to.zzzzz_out.is_locked ?? $this.pkg.zzzzz_out.is_locked ?? false;

DEFINE FIELD zb_child ON sl TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_asl_sl ON sl TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_asl_sl.delta_qty ON sl TYPE decimal DEFAULT 0dec;

DEFINE FIELD z_active_qty ON sl TYPE decimal VALUE IF suspended THEN 0dec ELSE (($this.raw_qty ?? 0dec) + ($this.zb_child.v_asl_sl.delta_qty ?? 0dec)) END;
DEFINE FIELD zz_actual_cogs_value ON sl TYPE decimal VALUE (($this.z_active_qty ?? 0dec) * ($this.za_parent.unit_cogs ?? 0dec));

DEFINE FIELD zzz_matrix_shield ON sl TYPE bool VALUE {
    IF record::tb($this.from) = 'warehouse' {
        LET $in = (type::record('v_sl_matrix_in', [$this.from, $this.za_parent.item])).inbound_physical_qty ?? 0dec;
        LET $out = (type::record('v_sl_matrix_out', [$this.from, $this.za_parent.item])).outbound_physical_qty ?? 0dec;
        LET $available = ($in - $out) + ($before.zzzzz_out.outbound_physical_qty ?? 0dec);
        RETURN $available >= ($this.z_active_qty ?? 0dec);
    } ELSE { RETURN true; };
} ASSERT $value = true;

DEFINE FIELD zzzzz_out ON sl TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.inbound_physical_qty ON sl TYPE decimal VALUE IF suspended THEN 0dec ELSE ($this.z_active_qty ?? 0dec) END;
DEFINE FIELD zzzzz_out.outbound_physical_qty ON sl TYPE decimal VALUE IF suspended THEN 0dec ELSE ($this.z_active_qty ?? 0dec) END;
DEFINE FIELD zzzzz_out.actual_cogs_value ON sl TYPE decimal VALUE ($this.zz_actual_cogs_value ?? 0dec);
DEFINE FIELD zzzzz_out.item ON sl TYPE record<item> VALUE $this.za_parent.item;


DEFINE FIELD invoice_line ON tax_line TYPE record<invoice_line> REFERENCE ON DELETE CASCADE;
DEFINE FIELD tax_account ON tax_line TYPE record<tax_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD raw_rate ON tax_line TYPE decimal ASSERT $value >= 0dec;

DEFINE FIELD A_guard ON tax_line TYPE object DEFAULT {};
DEFINE FIELD za_parent ON tax_line TYPE object DEFAULT {};
DEFINE FIELD za_parent.invl_base_value ON tax_line TYPE decimal VALUE $this.invoice_line.zz_base_value ?? 0dec;
DEFINE FIELD za_parent.inv_type ON tax_line TYPE string VALUE $this.invoice_line.za_parent.inv_type;

DEFINE FIELD zb_child ON tax_line TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_atl_tl ON tax_line TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_atl_tl.delta_amount ON tax_line TYPE decimal DEFAULT 0dec;

DEFINE FIELD z_tax_amount ON tax_line TYPE decimal VALUE (($this.za_parent.invl_base_value ?? 0dec) * (($this.raw_rate ?? 0dec) / 100dec)) + ($this.zb_child.v_atl_tl.delta_amount ?? 0dec);

DEFINE FIELD zzzzz_out ON tax_line TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.sales_tax_value ON tax_line TYPE decimal VALUE IF $this.za_parent.inv_type = 'sales' THEN ($this.z_tax_amount ?? 0dec) ELSE 0dec END;
DEFINE FIELD zzzzz_out.purchase_tax_value ON tax_line TYPE decimal VALUE IF $this.za_parent.inv_type = 'purchase' THEN ($this.z_tax_amount ?? 0dec) ELSE 0dec END;


-- ==========================================
-- LEVEL 4: DELTAS
-- ==========================================
DEFINE FIELD adjustment_note ON adjustment_line TYPE record<adjustment_note> REFERENCE ON DELETE CASCADE;
DEFINE FIELD invoice_line ON adjustment_line TYPE record<invoice_line> REFERENCE ON DELETE REJECT;
DEFINE FIELD delta_qty ON adjustment_line TYPE decimal DEFAULT 0dec;
DEFINE FIELD delta_cogs ON adjustment_line TYPE decimal DEFAULT 0dec;

DEFINE FIELD A_guard ON adjustment_line TYPE object DEFAULT {};
DEFINE FIELD A_guard.dag_check ON adjustment_line TYPE bool VALUE {
    LET $a_org = $this.adjustment_note.org;
    LET $i_org = $this.invoice_line.za_parent.invoice_org;
    IF $a_org != $i_org { THROW "UX_ERR: DAG Fracture. Note and Line do not share Org."; };
    RETURN true;
};

DEFINE FIELD zzzzz_out ON adjustment_line TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.delta_qty ON adjustment_line TYPE decimal VALUE $this.delta_qty ?? 0dec;
DEFINE FIELD zzzzz_out.delta_price ON adjustment_line TYPE decimal VALUE $this.delta_cogs ?? 0dec;