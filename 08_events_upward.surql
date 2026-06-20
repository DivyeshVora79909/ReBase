-- ==============================================================================
-- FILE 08: UPWARD PROPAGATION (VIEW TO PARENT PINGS)
-- ==============================================================================
USE NS main DB main;

-- 1. MONEY ROUTING
DEFINE EVENT ping_pay_to ON TABLE v_pay_to WHEN $event != 'NONE' THEN {
    LET $t = $after.node ?? $before.node;
    IF ($t.zzzzz_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_pay_to.active_amount = $after.active_amount, updated_at = time::now();
};

DEFINE EVENT ping_pay_from ON TABLE v_pay_from WHEN $event != 'NONE' THEN {
    LET $t = $after.node ?? $before.node;
    IF ($t.zzzzz_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_pay_from.active_amount = $after.active_amount, updated_at = time::now();
};

-- 2. ORG LEDGER
DEFINE EVENT ping_inv_org ON TABLE v_inv_org WHEN $event != 'NONE' THEN {
    LET $t = $after.org ?? $before.org;
    UPDATE $t SET 
        zb_child.v_inv_org.purchase_base_value = $after.purchase_base_value,
        zb_child.v_inv_org.sales_base_value = $after.sales_base_value,
        zb_child.v_inv_org.purchase_tax_value = $after.purchase_tax_value,
        zb_child.v_inv_org.sales_tax_value = $after.sales_tax_value,
        updated_at = time::now();
};

-- 3. PAYMENT ALLOCATIONS
DEFINE EVENT ping_pa_pay ON TABLE v_pa_pay WHEN $event != 'NONE' THEN {
    LET $t = $after.payment ?? $before.payment;
    IF ($t.zzzzz_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_pa_pay.allocated_amount = $after.allocated_amount, updated_at = time::now();
};

DEFINE EVENT ping_pa_inv ON TABLE v_pa_inv WHEN $event != 'NONE' THEN {
    LET $t = $after.invoice ?? $before.invoice;
    IF ($t.zzzzz_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_pa_inv.allocated_amount = $after.allocated_amount, updated_at = time::now();
};

-- 4. INVOICE LINES TO INVOICE & ITEM
DEFINE EVENT ping_invl_inv ON TABLE v_invl_inv WHEN $event != 'NONE' THEN {
    LET $t = $after.invoice ?? $before.invoice;
    IF ($t.zzzzz_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET 
        zb_child.v_invl_inv.purchase_base_value = $after.purchase_base_value,
        zb_child.v_invl_inv.sales_base_value = $after.sales_base_value,
        zb_child.v_invl_inv.inbound_physical_qty = $after.inbound_physical_qty,
        zb_child.v_invl_inv.outbound_physical_qty = $after.outbound_physical_qty,
        updated_at = time::now();
};

DEFINE EVENT ping_invl_item ON TABLE v_invl_item WHEN $event != 'NONE' THEN {
    LET $t = $after.item ?? $before.item;
    UPDATE $t SET 
        zb_child.v_invl_item.purchase_financial_qty = $after.purchase_financial_qty,
        zb_child.v_invl_item.purchase_base_value = $after.purchase_base_value,
        zb_child.v_invl_item.sales_financial_qty = $after.sales_financial_qty,
        zb_child.v_invl_item.sales_base_value = $after.sales_base_value,
        updated_at = time::now();
};

-- 5. STOCK MOVEMENTS (The Split Matrix Relays)
DEFINE EVENT ping_sl_matrix_in ON TABLE v_sl_matrix_in WHEN $event != 'NONE' THEN {
    LET $node = $after.node ?? $before.node;
    LET $item = $after.item ?? $before.item;
    UPDATE $node SET zb_child.v_sl_matrix_in.inbound_physical_qty = $after.inbound_physical_qty, updated_at = time::now();
    UPDATE $item SET zb_child.v_sl_matrix_in.inbound_physical_qty = $after.inbound_physical_qty, updated_at = time::now();
};

DEFINE EVENT ping_sl_matrix_out ON TABLE v_sl_matrix_out WHEN $event != 'NONE' THEN {
    LET $node = $after.node ?? $before.node;
    LET $item = $after.item ?? $before.item;
    UPDATE $node SET zb_child.v_sl_matrix_out.outbound_physical_qty = $after.outbound_physical_qty, updated_at = time::now();
    UPDATE $item SET zb_child.v_sl_matrix_out.outbound_physical_qty = $after.outbound_physical_qty, updated_at = time::now();
};

DEFINE EVENT ping_sl_invl_in ON TABLE v_sl_invl_in WHEN $event != 'NONE' THEN {
    LET $t = $after.inv_line ?? $before.inv_line;
    IF ($t.zzzzz_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_sl_invl_in.inbound_physical_qty = $after.inbound_physical_qty, updated_at = time::now();
};

DEFINE EVENT ping_sl_invl_out ON TABLE v_sl_invl_out WHEN $event != 'NONE' THEN {
    LET $t = $after.inv_line ?? $before.inv_line;
    IF ($t.zzzzz_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_sl_invl_out.outbound_physical_qty = $after.outbound_physical_qty, updated_at = time::now();
};

DEFINE EVENT ping_sl_pkg ON TABLE v_sl_pkg WHEN $event != 'NONE' THEN {
    LET $t = $after.pkg ?? $before.pkg;
    IF ($t.zzzzz_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET zb_child.v_sl_pkg.outbound_physical_qty = $after.outbound_physical_qty, updated_at = time::now();
};

DEFINE EVENT ping_sl_cogs_out ON TABLE v_sl_cogs_out WHEN $event != 'NONE' THEN {
    LET $t = $after.acc ?? $before.acc;
    UPDATE $t SET zb_child.v_sl_cogs_out.actual_cogs_value = $after.actual_cogs_value, updated_at = time::now();
};

-- 6. TAX LINES
DEFINE EVENT ping_tl_inv ON TABLE v_tl_inv WHEN $event != 'NONE' THEN {
    LET $t = $after.invoice ?? $before.invoice;
    IF ($t.zzzzz_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET 
        zb_child.v_tl_inv.purchase_tax_value = $after.purchase_tax_value,
        zb_child.v_tl_inv.sales_tax_value = $after.sales_tax_value,
        updated_at = time::now();
};

DEFINE EVENT ping_tl_ta ON TABLE v_tl WHEN $event != 'NONE' THEN {
    LET $t = $after.tax_account ?? $before.tax_account;
    UPDATE $t SET 
        zb_child.v_tl.purchase_tax_value = $after.purchase_tax_value,
        zb_child.v_tl.sales_tax_value = $after.sales_tax_value,
        updated_at = time::now();
};

-- 7. DELTAS (Adjustments)
DEFINE EVENT ping_al_invl ON TABLE v_al_invl WHEN $event != 'NONE' THEN {
    LET $t = $after.invoice_line ?? $before.invoice_line;
    IF ($t.zzzzz_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET 
        zb_child.v_al_invl.delta_qty = $after.delta_qty,
        zb_child.v_al_invl.delta_price = $after.delta_price,
        updated_at = time::now();
};