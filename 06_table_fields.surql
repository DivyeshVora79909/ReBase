USE NS main DB main;

-- =====================================================================
-- LEVEL 0: INDEPENDENT ANCHORS (Stateless / Parents)
-- =====================================================================

DEFINE FIELD name ON org TYPE string;
DEFINE FIELD zb_child ON org TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_inv ON org TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_inv.total_value ON org TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_pay_in ON org TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_in.total ON org TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_pay_out ON org TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_out.total ON org TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz ON org TYPE object DEFAULT {};
DEFINE FIELD zz.net_money ON org TYPE decimal VALUE ($this.zb_child.v_pay_in.total ?? 0dec) - ($this.zb_child.v_pay_out.total ?? 0dec);

DEFINE FIELD name ON treasury TYPE string;
DEFINE FIELD currency ON treasury TYPE string DEFAULT 'USD';
DEFINE FIELD zb_child ON treasury TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_in ON treasury TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_in.total ON treasury TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_pay_out ON treasury TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_out.total ON treasury TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz ON treasury TYPE object DEFAULT {};
DEFINE FIELD zz.balance ON treasury TYPE decimal VALUE ($this.zb_child.v_pay_in.total ?? 0dec) - ($this.zb_child.v_pay_out.total ?? 0dec) ASSERT $value >= 0dec;

DEFINE FIELD name ON acc TYPE string;
DEFINE FIELD type ON acc TYPE string;
DEFINE FIELD zb_child ON acc TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_in ON acc TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_in.total ON acc TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_pay_out ON acc TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pay_out.total ON acc TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz ON acc TYPE object DEFAULT {};
DEFINE FIELD zz.balance ON acc TYPE decimal VALUE ($this.zb_child.v_pay_in.total ?? 0dec) - ($this.zb_child.v_pay_out.total ?? 0dec);

DEFINE FIELD name ON tax_account TYPE string;
DEFINE FIELD zb_child ON tax_account TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_tl ON tax_account TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_tl.tax_amount ON tax_account TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz ON tax_account TYPE object DEFAULT {};
DEFINE FIELD zz.liability ON tax_account TYPE decimal VALUE ($this.zb_child.v_tl.tax_amount ?? 0dec) + ($this.zb_child.v_atl.delta_amount ?? 0dec);

DEFINE FIELD name ON item TYPE string;
DEFINE FIELD is_service ON item TYPE bool DEFAULT false;
DEFINE FIELD default_cogs ON item TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child ON item TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_invl ON item TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_invl.ordered_qty ON item TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_invl.base_value ON item TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz ON item TYPE object DEFAULT {};
DEFINE FIELD zz.turnover ON item TYPE decimal VALUE $this.zb_child.v_invl.ordered_qty ?? 0dec;
DEFINE FIELD zz.avg_cogs ON item TYPE decimal VALUE IF ($this.zb_child.v_invl.ordered_qty ?? 0dec) > 0dec THEN ($this.zb_child.v_invl.base_value ?? 0dec) / ($this.zb_child.v_invl.ordered_qty ?? 0dec) ELSE 0dec END;

DEFINE FIELD name ON stock_acc TYPE string;

DEFINE FIELD name ON warehouse TYPE string;

-- =====================================================================
-- LEVEL 1: INTENTS (Autonomous Roots)
-- =====================================================================

DEFINE FIELD from ON payment TYPE record<org | treasury | acc | tax_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD to ON payment TYPE record<org | treasury | acc | tax_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD amount ON payment TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD fx_rate ON payment TYPE decimal DEFAULT 1dec ASSERT $value > 0dec;
DEFINE FIELD date ON payment TYPE datetime DEFAULT time::now();
DEFINE FIELD A_guard ON payment TYPE object DEFAULT {};
DEFINE FIELD A_guard.suspend_check ON payment TYPE bool VALUE {
    IF $before.suspended = false AND suspended = true {
        IF ($this.zb_child.v_pa.allocated ?? 0dec) > 0dec { THROW "UX_ERR: Cannot suspend payment, allocations exist."; };
    };
    RETURN true;
};
DEFINE FIELD zb_child ON payment TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pa ON payment TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pa.allocated ON payment TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz ON payment TYPE object DEFAULT {};
DEFINE FIELD zz.active_amount ON payment TYPE decimal VALUE IF suspended THEN 0dec ELSE ($this.amount * $this.fx_rate) END;
DEFINE FIELD zzz ON payment TYPE object DEFAULT {};
DEFINE FIELD zzz.allocation_shield ON payment TYPE decimal VALUE ($this.zz.active_amount) - ($this.zb_child.v_pa.allocated ?? 0dec) ASSERT $value >= 0dec;
DEFINE FIELD zzzzz_out ON payment TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.active_amount ON payment TYPE decimal VALUE $this.zz.active_amount;

DEFINE FIELD org ON invoice TYPE record<org> REFERENCE ON DELETE REJECT;
DEFINE FIELD type ON invoice TYPE string ASSERT $value IN ['sales', 'purchase'];
DEFINE FIELD A_guard ON invoice TYPE object DEFAULT {};
DEFINE FIELD A_guard.suspend_check ON invoice TYPE bool VALUE {
    IF $before.suspended = false AND suspended = true {
        IF ($this.zb_child.v_invl.delivered_qty ?? 0dec) > 0dec { THROW "UX_ERR: Cannot suspend invoice, stock deliveries exist."; };
        IF ($this.zb_child.v_pa.allocated ?? 0dec) > 0dec { THROW "UX_ERR: Cannot suspend invoice, payment allocations exist."; };
    };
    RETURN true;
};
DEFINE FIELD zb_child ON invoice TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_invl ON invoice TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_invl.base_value ON invoice TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_invl.delivered_qty ON invoice TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_tl ON invoice TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_tl.tax_amount ON invoice TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_pa ON invoice TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_pa.allocated ON invoice TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz ON invoice TYPE object DEFAULT {};
DEFINE FIELD zz.total_value ON invoice TYPE decimal VALUE IF suspended THEN 0dec ELSE ($this.zb_child.v_invl.base_value + $this.zb_child.v_tl.tax_amount) END;
DEFINE FIELD zzz ON invoice TYPE object DEFAULT {};
DEFINE FIELD zzz.allocation_shield ON invoice TYPE decimal VALUE ($this.zz.total_value) - ($this.zb_child.v_pa.allocated ?? 0dec) ASSERT $value >= 0dec;
DEFINE FIELD zzzzz_out ON invoice TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.total_value ON invoice TYPE decimal VALUE $this.zz.total_value;

DEFINE FIELD org ON adjustment_note TYPE record<org> REFERENCE ON DELETE REJECT;
DEFINE FIELD type ON adjustment_note TYPE string;
DEFINE FIELD A_guard ON adjustment_note TYPE object DEFAULT {};
DEFINE FIELD A_guard.suspend_check ON adjustment_note TYPE bool VALUE { RETURN true; };
DEFINE FIELD zzzzz_out ON adjustment_note TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.is_active ON adjustment_note TYPE bool VALUE IF suspended THEN false ELSE true END;

-- =====================================================================
-- LEVEL 2: BRANCHES
-- =====================================================================

DEFINE FIELD payment ON payment_allocation TYPE record<payment> REFERENCE ON DELETE CASCADE;
DEFINE FIELD invoice ON payment_allocation TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD amount ON payment_allocation TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD za_parent ON payment_allocation TYPE object DEFAULT {};
DEFINE FIELD za_parent.payment_org ON payment_allocation TYPE option<record<org>> VALUE {
    IF record::tb($this.payment.from) = 'org' THEN RETURN $this.payment.from;
    IF record::tb($this.payment.to) = 'org' THEN RETURN $this.payment.to;
    RETURN NONE;
};
DEFINE FIELD za_parent.invoice_org ON payment_allocation TYPE record<org> VALUE $this.invoice.org;
DEFINE FIELD za_parent.payment_suspended ON payment_allocation TYPE bool VALUE $this.payment.suspended ?? false;
DEFINE FIELD za_parent.invoice_suspended ON payment_allocation TYPE bool VALUE $this.invoice.suspended ?? false;
DEFINE FIELD zz ON payment_allocation TYPE object DEFAULT {};
DEFINE FIELD zz.dag_check ON payment_allocation TYPE bool VALUE {
    IF $this.za_parent.payment_org != NONE AND $this.za_parent.payment_org != $this.za_parent.invoice_org { THROW "DAG_VIOLATION: Payment and Invoice trace to different Orgs."; };
    RETURN true;
};
DEFINE FIELD zzzzz_out ON payment_allocation TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.amount ON payment_allocation TYPE decimal VALUE IF ($this.za_parent.payment_suspended OR $this.za_parent.invoice_suspended) THEN 0dec ELSE $this.amount END;

DEFINE FIELD invoice ON invoice_line TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD item ON invoice_line TYPE record<item> REFERENCE ON DELETE REJECT;
DEFINE FIELD qty ON invoice_line TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD cogs ON invoice_line TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD za_parent ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD za_parent.invoice_locked ON invoice_line TYPE bool VALUE $this.invoice.locked ?? false;
DEFINE FIELD za_parent.invoice_org ON invoice_line TYPE record<org> VALUE $this.invoice.org;
DEFINE FIELD za_parent.invoice_suspended ON invoice_line TYPE bool VALUE $this.invoice.suspended ?? false;
DEFINE FIELD zb_child ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_sl ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_sl.delivered_qty ON invoice_line TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_al ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_al.delta_qty ON invoice_line TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_al.delta_cogs ON invoice_line TYPE decimal DEFAULT 0dec;
DEFINE FIELD zb_child.v_tl ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_tl.tax_amount ON invoice_line TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD zz.net_qty ON invoice_line TYPE decimal VALUE ($this.qty + ($this.zb_child.v_al.delta_qty ?? 0dec));
DEFINE FIELD zz.net_cogs ON invoice_line TYPE decimal VALUE ($this.cogs + ($this.zb_child.v_al.delta_cogs ?? 0dec));
DEFINE FIELD zz.base_value ON invoice_line TYPE decimal VALUE ($this.zz.net_qty * $this.zz.net_cogs);
DEFINE FIELD zz.inventory_qty ON invoice_line TYPE decimal VALUE IF $this.item.is_service = true THEN 0dec ELSE $this.zz.net_qty END;
DEFINE FIELD zzz ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD zzz.qty_remaining ON invoice_line TYPE decimal VALUE ($this.zz.inventory_qty - ($this.zb_child.v_sl.delivered_qty ?? 0dec)) ASSERT $value >= 0dec;
DEFINE FIELD zzzzz_out ON invoice_line TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.ordered_qty ON invoice_line TYPE decimal VALUE IF $this.za_parent.invoice_suspended THEN 0dec ELSE $this.zz.inventory_qty END;
DEFINE FIELD zzzzz_out.base_value ON invoice_line TYPE decimal VALUE IF $this.za_parent.invoice_suspended THEN 0dec ELSE $this.zz.base_value END;
DEFINE FIELD zzzzz_out.delivered_qty ON invoice_line TYPE decimal VALUE IF $this.za_parent.invoice_suspended THEN 0dec ELSE $this.zb_child.v_sl.delivered_qty END;
DEFINE FIELD zzzzz_out.net_cogs ON invoice_line TYPE decimal VALUE $this.zz.net_cogs;

DEFINE FIELD invoice ON package_note TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD tracking ON package_note TYPE string;
DEFINE FIELD za_parent ON package_note TYPE object DEFAULT {};
DEFINE FIELD za_parent.invoice_locked ON package_note TYPE bool VALUE $this.invoice.locked ?? false;
DEFINE FIELD za_parent.invoice_suspended ON package_note TYPE bool VALUE $this.invoice.suspended ?? false;
DEFINE FIELD zb_child ON package_note TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_sl ON package_note TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_sl.delivered_qty ON package_note TYPE decimal DEFAULT 0dec;
DEFINE FIELD zzzzz_out ON package_note TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.delivered_qty ON package_note TYPE decimal VALUE IF $this.za_parent.invoice_suspended THEN 0dec ELSE $this.zb_child.v_sl.delivered_qty END;

-- =====================================================================
-- LEVEL 3: LEAVES
-- =====================================================================

DEFINE FIELD from ON sl TYPE record<warehouse | stock_acc> REFERENCE ON DELETE REJECT;
DEFINE FIELD to ON sl TYPE record<warehouse | stock_acc> REFERENCE ON DELETE REJECT;
DEFINE FIELD item ON sl TYPE record<item> REFERENCE ON DELETE REJECT;
DEFINE FIELD qty ON sl TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD cogs ON sl TYPE decimal DEFAULT 0dec; -- Fallback if no inv_line
DEFINE FIELD pkg ON sl TYPE option<record<package_note>> REFERENCE ON DELETE CASCADE DEFAULT NONE;
DEFINE FIELD inv_line ON sl TYPE option<record<invoice_line>> REFERENCE ON DELETE CASCADE DEFAULT NONE;
DEFINE FIELD A_guard ON sl TYPE object DEFAULT {};
DEFINE FIELD A_guard.suspend_check ON sl TYPE bool VALUE {
    IF $before.suspended = false AND suspended = true {
        IF ($this.zb_child.v_asl.delta_qty ?? 0dec) != 0dec { THROW "UX_ERR: Cannot suspend stock movement, adjustments exist."; };
    };
    RETURN true;
};
DEFINE FIELD za_parent ON sl TYPE object DEFAULT {};
DEFINE FIELD za_parent.final_cogs ON sl TYPE decimal VALUE $this.inv_line.cogs OR $this.cogs ASSERT $value >= 0dec;
DEFINE FIELD za_parent.pkg_locked ON sl TYPE bool VALUE IF $this.pkg != NONE THEN $this.pkg.za_parent.invoice_locked ?? false ELSE false END;
DEFINE FIELD za_parent.inv_line_locked ON sl TYPE bool VALUE IF $this.inv_line != NONE THEN $this.inv_line.za_parent.invoice_locked ?? false ELSE false END;
DEFINE FIELD zb_child ON sl TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_asl ON sl TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_asl.delta_qty ON sl TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz ON sl TYPE object DEFAULT {};
DEFINE FIELD zz.net_qty ON sl TYPE decimal VALUE ($this.qty + ($this.zb_child.v_asl.delta_qty ?? 0dec)) ASSERT $value >= 0dec;
DEFINE FIELD zz.inventory_qty ON sl TYPE decimal VALUE IF $this.item.is_service = true THEN 0dec ELSE $this.zz.net_qty END;
DEFINE FIELD zzz ON sl TYPE object DEFAULT {};
DEFINE FIELD zzz.stock_shield ON sl TYPE bool VALUE {
    IF record::tb($this.from) = 'warehouse' THEN {
        LET $out_view = (type::record('v_sl_from_node_item', [$this.from, $this.item])).inventory_qty ?? 0dec;
        LET $in_view = (type::record('v_sl_to_node_item', [$this.from, $this.item])).inventory_qty ?? 0dec;
        LET $available = ($in_view - $out_view) + ($before.zzzzz_out.inventory_qty ?? 0dec);
        RETURN $available >= $this.zz.inventory_qty;
    } ELSE { 
        RETURN true; 
    };
} ASSERT $value = true;
DEFINE FIELD zzzzz_out ON sl TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.qty ON sl TYPE decimal VALUE IF suspended THEN 0dec ELSE $this.zz.net_qty END;
DEFINE FIELD zzzzz_out.inventory_qty ON sl TYPE decimal VALUE IF suspended THEN 0dec ELSE $this.zz.inventory_qty END;
DEFINE FIELD zzzzz_out.base_value ON sl TYPE decimal VALUE IF suspended THEN 0dec ELSE ($this.zz.net_qty * $this.za_parent.final_cogs) END;

DEFINE FIELD invoice_line ON tax_line TYPE record<invoice_line> REFERENCE ON DELETE CASCADE;
DEFINE FIELD tax_account ON tax_line TYPE record<tax_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD rate ON tax_line TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD za_parent ON tax_line TYPE object DEFAULT {};
DEFINE FIELD za_parent.invl_locked ON tax_line TYPE bool VALUE $this.invoice_line.za_parent.invoice_locked ?? false;
DEFINE FIELD za_parent.invl_suspended ON tax_line TYPE bool VALUE $this.invoice_line.za_parent.invoice_suspended ?? false;
DEFINE FIELD za_parent.invl_base_value ON tax_line TYPE decimal VALUE $this.invoice_line.zz.base_value ?? 0dec;
DEFINE FIELD zb_child ON tax_line TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_atl ON tax_line TYPE object DEFAULT {};
DEFINE FIELD zb_child.v_atl.delta_amount ON tax_line TYPE decimal DEFAULT 0dec;
DEFINE FIELD zz ON tax_line TYPE object DEFAULT {};
DEFINE FIELD zz.tax_amount ON tax_line TYPE decimal VALUE ($this.za_parent.invl_base_value * ($this.rate / 100dec)) + ($this.zb_child.v_atl.delta_amount ?? 0dec);
DEFINE FIELD zzzzz_out ON tax_line TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.tax_amount ON tax_line TYPE decimal VALUE IF $this.za_parent.invl_suspended THEN 0dec ELSE $this.zz.tax_amount END;

-- =====================================================================
-- LEVEL 4: DELTAS
-- =====================================================================

DEFINE FIELD adjustment_note ON adjustment_line TYPE record<adjustment_note> REFERENCE ON DELETE CASCADE;
DEFINE FIELD invoice_line ON adjustment_line TYPE record<invoice_line> REFERENCE ON DELETE REJECT;
DEFINE FIELD delta_qty ON adjustment_line TYPE decimal DEFAULT 0dec;
DEFINE FIELD delta_cogs ON adjustment_line TYPE decimal DEFAULT 0dec;
DEFINE FIELD za_parent ON adjustment_line TYPE object DEFAULT {};
DEFINE FIELD za_parent.note_org ON adjustment_line TYPE record<org> VALUE $this.adjustment_note.org;
DEFINE FIELD za_parent.line_org ON adjustment_line TYPE record<org> VALUE $this.invoice_line.za_parent.invoice_org;
DEFINE FIELD za_parent.note_suspended ON adjustment_line TYPE bool VALUE $this.adjustment_note.suspended ?? false;
DEFINE FIELD zz ON adjustment_line TYPE object DEFAULT {};
DEFINE FIELD zz.dag_check ON adjustment_line TYPE bool VALUE {
    IF $this.za_parent.note_org != $this.za_parent.line_org { THROW "DAG_VIOLATION: Adjustment Note and Invoice Line trace to different Orgs."; };
    RETURN true;
};
DEFINE FIELD zzzzz_out ON adjustment_line TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.delta_qty ON adjustment_line TYPE decimal VALUE IF $this.za_parent.note_suspended THEN 0dec ELSE $this.delta_qty END;
DEFINE FIELD zzzzz_out.delta_cogs ON adjustment_line TYPE decimal VALUE IF $this.za_parent.note_suspended THEN 0dec ELSE $this.delta_cogs END;

DEFINE FIELD adjustment_note ON adjustment_tax_line TYPE record<adjustment_note> REFERENCE ON DELETE CASCADE;
DEFINE FIELD tax_line ON adjustment_tax_line TYPE record<tax_line> REFERENCE ON DELETE REJECT;
DEFINE FIELD delta_rate ON adjustment_tax_line TYPE decimal DEFAULT 0dec;
DEFINE FIELD delta_amount ON adjustment_tax_line TYPE decimal DEFAULT 0dec;
DEFINE FIELD za_parent ON adjustment_tax_line TYPE object DEFAULT {};
DEFINE FIELD za_parent.note_suspended ON adjustment_tax_line TYPE bool VALUE $this.adjustment_note.suspended ?? false;
DEFINE FIELD zzzzz_out ON adjustment_tax_line TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.delta_amount ON adjustment_tax_line TYPE decimal VALUE IF $this.za_parent.note_suspended THEN 0dec ELSE $this.delta_amount END;

DEFINE FIELD adjustment_note ON adjustment_stock_line TYPE record<adjustment_note> REFERENCE ON DELETE CASCADE;
DEFINE FIELD stock_movement ON adjustment_stock_line TYPE record<sl> REFERENCE ON DELETE REJECT;
DEFINE FIELD delta_qty ON adjustment_stock_line TYPE decimal DEFAULT 0dec;
DEFINE FIELD za_parent ON adjustment_stock_line TYPE object DEFAULT {};
DEFINE FIELD za_parent.note_suspended ON adjustment_stock_line TYPE bool VALUE $this.adjustment_note.suspended ?? false;
DEFINE FIELD zzzzz_out ON adjustment_stock_line TYPE object DEFAULT {};
DEFINE FIELD zzzzz_out.delta_qty ON adjustment_stock_line TYPE decimal VALUE IF $this.za_parent.note_suspended THEN 0dec ELSE $this.delta_qty END;