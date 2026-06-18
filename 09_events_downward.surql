USE NS main DB main;

-- INVOICE -> INVOICE_LINE, PACKAGE_NOTE, PAYMENT_ALLOCATION
DEFINE EVENT push_invoice_context ON TABLE invoice
WHEN $event = 'UPDATE' AND (
    $before.org != $after.org OR
    $before.locked != $after.locked OR
    $before.suspended != $after.suspended OR
    $before.type != $after.type
) THEN {
    UPDATE invoice_line SET updated_at = time::now() WHERE invoice = $after.id;
    UPDATE package_note SET updated_at = time::now() WHERE invoice = $after.id;
    UPDATE payment_allocation SET updated_at = time::now() WHERE invoice = $after.id;
};

-- PAYMENT -> PAYMENT_ALLOCATION
DEFINE EVENT push_payment_context ON TABLE payment
WHEN $event = 'UPDATE' AND (
    $before.from != $after.from OR
    $before.to != $after.to OR
    $before.locked != $after.locked OR
    $before.suspended != $after.suspended
) THEN {
    UPDATE payment_allocation SET updated_at = time::now() WHERE payment = $after.id;
};

-- ADJUSTMENT_NOTE -> ADJUSTMENT_LINE, ADJUSTMENT_TAX_LINE, ADJUSTMENT_STOCK_LINE
DEFINE EVENT push_an_context ON TABLE adjustment_note
WHEN $event = 'UPDATE' AND (
    $before.org != $after.org OR
    $before.locked != $after.locked OR
    $before.suspended != $after.suspended
) THEN {
    UPDATE adjustment_line SET updated_at = time::now() WHERE adjustment_note = $after.id;
    UPDATE adjustment_tax_line SET updated_at = time::now() WHERE adjustment_note = $after.id;
    UPDATE adjustment_stock_line SET updated_at = time::now() WHERE adjustment_note = $after.id;
};

-- INVOICE_LINE -> TAX_LINE, SL, ADJUSTMENT_LINE (The Zig-Zag Data Push)
DEFINE EVENT push_invl_context ON TABLE invoice_line
WHEN $event = 'UPDATE' AND (
    $before.qty != $after.qty OR
    $before.cogs != $after.cogs OR
    $before.item != $after.item OR
    $before.zz.base_value != $after.zz.base_value
) THEN {
    UPDATE tax_line SET updated_at = time::now() WHERE invoice_line = $after.id;
    UPDATE sl SET updated_at = time::now() WHERE inv_line = $after.id;
    UPDATE adjustment_line SET updated_at = time::now() WHERE invoice_line = $after.id;
};

-- PACKAGE_NOTE -> SL
DEFINE EVENT push_pkg_context ON TABLE package_note
WHEN $event = 'UPDATE' AND (
    $before.locked != $after.locked OR
    $before.suspended != $after.suspended
) THEN {
    UPDATE sl SET updated_at = time::now() WHERE pkg = $after.id;
};

-- TAX_LINE -> ADJUSTMENT_TAX_LINE
DEFINE EVENT push_tl_context ON TABLE tax_line
WHEN $event = 'UPDATE' AND (
    $before.rate != $after.rate OR
    $before.tax_account != $after.tax_account
) THEN {
    UPDATE adjustment_tax_line SET updated_at = time::now() WHERE tax_line = $after.id;
};

-- SL -> ADJUSTMENT_STOCK_LINE
DEFINE EVENT push_sl_context ON TABLE sl
WHEN $event = 'UPDATE' AND (
    $before.qty != $after.qty OR
    $before.from != $after.from OR
    $before.to != $after.to
) THEN {
    UPDATE adjustment_stock_line SET updated_at = time::now() WHERE stock_movement = $after.id;
};