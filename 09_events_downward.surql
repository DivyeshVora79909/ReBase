-- ==============================================================================
-- FILE 09: DOWNWARD PROPAGATION (TOPOLOGY & ZIG-ZAG DATA PINGS)
-- ==============================================================================
USE NS main DB main;

-- 1. INVOICE -> DOWNSTREAM
DEFINE EVENT push_invoice_context ON TABLE invoice
WHEN $event = 'UPDATE' AND (
    $before.org != $after.org OR
    $before.locked != $after.locked OR
    $before.suspended != $after.suspended OR
    $before.raw_type != $after.raw_type
) THEN {
    UPDATE invoice_line SET system_ping = time::now() WHERE invoice = $after.id;
    UPDATE package_note SET system_ping = time::now() WHERE invoice = $after.id;
    UPDATE payment_allocation SET system_ping = time::now() WHERE invoice = $after.id;
};

-- 2. PAYMENT -> ALLOCATION
DEFINE EVENT push_payment_context ON TABLE payment
WHEN $event = 'UPDATE' AND (
    $before.from != $after.from OR
    $before.to != $after.to OR
    $before.fx_rate != $after.fx_rate OR
    $before.locked != $after.locked OR
    $before.suspended != $after.suspended
) THEN {
    UPDATE payment_allocation SET system_ping = time::now() WHERE payment = $after.id;
};

-- 3. ADJUSTMENT NOTE -> DELTAS
DEFINE EVENT push_an_context ON TABLE adjustment_note
WHEN $event = 'UPDATE' AND (
    $before.org != $after.org
) THEN {
    UPDATE adjustment_line SET system_ping = time::now() WHERE adjustment_note = $after.id;
};

-- 4. INVOICE LINE -> TAX, SL, ADJ LINE (The Zig-Zag Data Push)
DEFINE EVENT push_invl_context ON TABLE invoice_line
WHEN $event = 'UPDATE' AND (
    $before.raw_qty != $after.raw_qty OR
    $before.raw_unit_price != $after.raw_unit_price OR
    $before.item != $after.item OR
    $before.zz_base_value != $after.zz_base_value OR
    $before.za_parent.inv_locked != $after.za_parent.inv_locked OR
    $before.za_parent.invoice_suspended != $after.za_parent.invoice_suspended
) THEN {
    UPDATE tax_line SET system_ping = time::now() WHERE invoice_line = $after.id;
    UPDATE sl SET system_ping = time::now() WHERE from = $after.id OR to = $after.id;
    UPDATE adjustment_line SET system_ping = time::now() WHERE invoice_line = $after.id;
};

-- 5. PACKAGE NOTE -> SL
DEFINE EVENT push_pkg_context ON TABLE package_note
WHEN $event = 'UPDATE' AND (
    $before.zzzzz_out.is_locked != $after.zzzzz_out.is_locked
) THEN {
    UPDATE sl SET system_ping = time::now() WHERE pkg = $after.id;
};

-- 6. ADJUSTMENT LINE -> ADJUSTMENT NOTE (Declarative Ping)
DEFINE EVENT ping_adj_note ON TABLE adjustment_line 
WHEN $event IN ['CREATE', 'DELETE'] OR (
    $event = 'UPDATE' AND (
        $before.delta_qty != $after.delta_qty OR 
        $before.delta_price != $after.delta_price
    )
) THEN {
    UPDATE ($after.adjustment_note ?? $before.adjustment_note) SET system_ping = time::now();
};