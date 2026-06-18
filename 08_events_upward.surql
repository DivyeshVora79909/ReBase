USE NS main DB main;

-- Polymorphic Routing Pings
DEFINE EVENT ping_pay_from ON TABLE v_pay_from WHEN $event != 'NONE' THEN {
    LET $t = $after.node ?? $before.node;
    IF ($t.locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_pay_out.total = $after.total, updated_at = time::now();
};
DEFINE EVENT ping_pay_to ON TABLE v_pay_to WHEN $event != 'NONE' THEN {
    LET $t = $after.node ?? $before.node;
    IF ($t.locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_pay_in.total = $after.total, updated_at = time::now();
};

-- Invoice & Org Pings
DEFINE EVENT ping_inv_org ON TABLE v_inv_org WHEN $event != 'NONE' THEN {
    LET $t = $after.org ?? $before.org;
    IF ($t.locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_inv.total_value = $after.total_value, updated_at = time::now();
};

-- Allocations
DEFINE EVENT ping_pa_pay ON TABLE v_pa_pay WHEN $event != 'NONE' THEN {
    LET $t = $after.payment ?? $before.payment;
    IF ($t.locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_pa.allocated = $after.allocated, updated_at = time::now();
};
DEFINE EVENT ping_pa_inv ON TABLE v_pa_inv WHEN $event != 'NONE' THEN {
    LET $t = $after.invoice ?? $before.invoice;
    IF ($t.locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_pa.allocated = $after.allocated, updated_at = time::now();
};

-- Invoice Lines & Items (The Relay)
DEFINE EVENT ping_invl_inv ON TABLE v_invl_inv WHEN $event != 'NONE' THEN {
    LET $t = $after.invoice ?? $before.invoice;
    IF ($t.locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET 
        zb_child.v_invl.base_value = $after.base_value, 
        zb_child.v_invl.delivered_qty = $after.delivered_qty, 
        updated_at = time::now();
};
DEFINE EVENT ping_invl_item ON TABLE v_invl_item WHEN $event != 'NONE' THEN {
    LET $t = $after.item ?? $before.item;
    UPDATE $t SET 
        zb_child.v_invl.ordered_qty = $after.ordered_qty, 
        zb_child.v_invl.base_value = $after.base_value, 
        updated_at = time::now();
};

-- Packages
DEFINE EVENT ping_sl_pkg ON TABLE v_sl_pkg WHEN $event != 'NONE' THEN {
    LET $t = $after.pkg ?? $before.pkg;
    IF ($t.za_parent.invoice_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_sl.delivered_qty = $after.delivered_qty, updated_at = time::now();
};

-- Stock to Invoice Line (The Matrix Exception Pings)
DEFINE EVENT ping_sl_invl ON TABLE v_sl_invl WHEN $event != 'NONE' THEN {
    LET $t = $after.inv_line ?? $before.inv_line;
    IF ($t.za_parent.invoice_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_sl.delivered_qty = $after.delivered_qty, updated_at = time::now();
};
DEFINE EVENT ping_sl_from ON TABLE v_sl_from_node_item WHEN $event != 'NONE' THEN {
    LET $node = $after.node ?? $before.node;
    LET $item = $after.item ?? $before.item;
    UPDATE $node SET updated_at = time::now();
    UPDATE $item SET updated_at = time::now();
};
DEFINE EVENT ping_sl_to ON TABLE v_sl_to_node_item WHEN $event != 'NONE' THEN {
    LET $node = $after.node ?? $before.node;
    LET $item = $after.item ?? $before.item;
    UPDATE $node SET updated_at = time::now();
    UPDATE $item SET updated_at = time::now();
};

-- Tax Lines
DEFINE EVENT ping_tl_invl ON TABLE v_tl_invl WHEN $event != 'NONE' THEN {
    LET $t = $after.invoice_line ?? $before.invoice_line;
    IF ($t.za_parent.invoice_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_tl.tax_amount = $after.tax_amount, updated_at = time::now();
};
DEFINE EVENT ping_tl_ta ON TABLE v_tl_ta WHEN $event != 'NONE' THEN {
    LET $t = $after.tax_account ?? $before.tax_account;
    UPDATE $t SET zb_child.v_tl.tax_amount = $after.tax_amount, updated_at = time::now();
};

-- Deltas
DEFINE EVENT ping_al_invl ON TABLE v_al_invl WHEN $event != 'NONE' THEN {
    LET $t = $after.invoice_line ?? $before.invoice_line;
    IF ($t.za_parent.invoice_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_al.delta_qty = $after.delta_qty, zb_child.v_al.delta_cogs = $after.delta_cogs, updated_at = time::now();
};
DEFINE EVENT ping_atl_tl ON TABLE v_atl_tl WHEN $event != 'NONE' THEN {
    LET $t = $after.tax_line ?? $before.tax_line;
    IF ($t.za_parent.invl_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_atl.delta_amount = $after.delta_amount, updated_at = time::now();
};
DEFINE EVENT ping_asl_sl ON TABLE v_asl_sl WHEN $event != 'NONE' THEN {
    LET $t = $after.stock_movement ?? $before.stock_movement;
    IF ($t.locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_asl.delta_qty = $after.delta_qty, updated_at = time::now();
};