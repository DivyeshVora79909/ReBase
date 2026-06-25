-- FILE 09: DOWNWARD PROPAGATION (DAG ALERTS)
USE NS main DB main;

DEFINE EVENT push_org_to_payment_via_a_in_from ON TABLE org
WHEN $event = 'UPDATE' AND ($before.f_out.currency != $after.f_out.currency) THEN {
    UPDATE payment SET system_ping = time::now() WHERE a_in_from = $after.id;
};

DEFINE EVENT push_org_to_payment_via_a_in_to ON TABLE org
WHEN $event = 'UPDATE' AND ($before.f_out.currency != $after.f_out.currency) THEN {
    UPDATE payment SET system_ping = time::now() WHERE a_in_to = $after.id;
};

DEFINE EVENT push_treasury_to_payment_via_a_in_from ON TABLE treasury
WHEN $event = 'UPDATE' AND ($before.f_out.currency != $after.f_out.currency) THEN {
    UPDATE payment SET system_ping = time::now() WHERE a_in_from = $after.id;
};

DEFINE EVENT push_treasury_to_payment_via_a_in_to ON TABLE treasury
WHEN $event = 'UPDATE' AND ($before.f_out.currency != $after.f_out.currency) THEN {
    UPDATE payment SET system_ping = time::now() WHERE a_in_to = $after.id;
};

DEFINE EVENT push_acc_to_payment_via_a_in_from ON TABLE acc
WHEN $event = 'UPDATE' AND ($before.f_out.currency != $after.f_out.currency) THEN {
    UPDATE payment SET system_ping = time::now() WHERE a_in_from = $after.id;
};

DEFINE EVENT push_acc_to_payment_via_a_in_to ON TABLE acc
WHEN $event = 'UPDATE' AND ($before.f_out.currency != $after.f_out.currency) THEN {
    UPDATE payment SET system_ping = time::now() WHERE a_in_to = $after.id;
};

DEFINE EVENT push_tax_account_to_payment_via_a_in_from ON TABLE tax_account
WHEN $event = 'UPDATE' AND ($before.f_out.currency != $after.f_out.currency) THEN {
    UPDATE payment SET system_ping = time::now() WHERE a_in_from = $after.id;
};

DEFINE EVENT push_tax_account_to_payment_via_a_in_to ON TABLE tax_account
WHEN $event = 'UPDATE' AND ($before.f_out.currency != $after.f_out.currency) THEN {
    UPDATE payment SET system_ping = time::now() WHERE a_in_to = $after.id;
};

DEFINE EVENT push_payment_to_payment_allocation_via_a_in_payment ON TABLE payment
WHEN $event = 'UPDATE' AND ($before.f_out.fx_rate != $after.f_out.fx_rate OR $before.f_out.from_node != $after.f_out.from_node OR $before.f_out.to_node != $after.f_out.to_node) THEN {
    UPDATE payment_allocation SET system_ping = time::now() WHERE a_in_payment = $after.id;
};

DEFINE EVENT push_invoice_to_payment_allocation_via_a_in_invoice ON TABLE invoice
WHEN $event = 'UPDATE' AND ($before.f_out.org != $after.f_out.org) THEN {
    UPDATE payment_allocation SET system_ping = time::now() WHERE a_in_invoice = $after.id;
};

DEFINE EVENT push_invoice_to_invoice_line_via_a_in_invoice ON TABLE invoice
WHEN $event = 'UPDATE' AND ($before.f_out.type != $after.f_out.type OR $before.f_out.fx_rate != $after.f_out.fx_rate OR $before.f_out.org != $after.f_out.org) THEN {
    UPDATE invoice_line SET system_ping = time::now() WHERE a_in_invoice = $after.id;
};

DEFINE EVENT push_item_to_invoice_line_via_a_in_item ON TABLE item
WHEN $event = 'UPDATE' AND ($before.f_out.actual_unit_cogs != $after.f_out.actual_unit_cogs OR $before.f_out.is_service != $after.f_out.is_service) THEN {
    UPDATE invoice_line SET system_ping = time::now() WHERE a_in_item = $after.id;
};

DEFINE EVENT push_warehouse_to_sl_via_a_in_from ON TABLE warehouse
WHEN $event = 'UPDATE' AND ($before.f_out.item != $after.f_out.item OR $before.f_out.invoice != $after.f_out.invoice OR $before.f_out.org != $after.f_out.org OR $before.f_out.actual_unit_cogs != $after.f_out.actual_unit_cogs OR $before.f_out.inv_fx_rate != $after.f_out.inv_fx_rate) THEN {
    UPDATE sl SET system_ping = time::now() WHERE a_in_from = $after.id;
};

DEFINE EVENT push_warehouse_to_sl_via_a_in_to ON TABLE warehouse
WHEN $event = 'UPDATE' AND ($before.f_out.item != $after.f_out.item OR $before.f_out.invoice != $after.f_out.invoice OR $before.f_out.org != $after.f_out.org OR $before.f_out.actual_unit_cogs != $after.f_out.actual_unit_cogs OR $before.f_out.inv_fx_rate != $after.f_out.inv_fx_rate) THEN {
    UPDATE sl SET system_ping = time::now() WHERE a_in_to = $after.id;
};

DEFINE EVENT push_stock_acc_to_sl_via_a_in_from ON TABLE stock_acc
WHEN $event = 'UPDATE' AND ($before.f_out.item != $after.f_out.item OR $before.f_out.invoice != $after.f_out.invoice OR $before.f_out.org != $after.f_out.org OR $before.f_out.actual_unit_cogs != $after.f_out.actual_unit_cogs OR $before.f_out.inv_fx_rate != $after.f_out.inv_fx_rate) THEN {
    UPDATE sl SET system_ping = time::now() WHERE a_in_from = $after.id;
};

DEFINE EVENT push_stock_acc_to_sl_via_a_in_to ON TABLE stock_acc
WHEN $event = 'UPDATE' AND ($before.f_out.item != $after.f_out.item OR $before.f_out.invoice != $after.f_out.invoice OR $before.f_out.org != $after.f_out.org OR $before.f_out.actual_unit_cogs != $after.f_out.actual_unit_cogs OR $before.f_out.inv_fx_rate != $after.f_out.inv_fx_rate) THEN {
    UPDATE sl SET system_ping = time::now() WHERE a_in_to = $after.id;
};

DEFINE EVENT push_invoice_line_to_sl_via_a_in_from ON TABLE invoice_line
WHEN $event = 'UPDATE' AND ($before.f_out.item != $after.f_out.item OR $before.f_out.invoice != $after.f_out.invoice OR $before.f_out.org != $after.f_out.org OR $before.f_out.actual_unit_cogs != $after.f_out.actual_unit_cogs OR $before.f_out.inv_fx_rate != $after.f_out.inv_fx_rate) THEN {
    UPDATE sl SET system_ping = time::now() WHERE a_in_from = $after.id;
};

DEFINE EVENT push_invoice_line_to_sl_via_a_in_to ON TABLE invoice_line
WHEN $event = 'UPDATE' AND ($before.f_out.item != $after.f_out.item OR $before.f_out.invoice != $after.f_out.invoice OR $before.f_out.org != $after.f_out.org OR $before.f_out.actual_unit_cogs != $after.f_out.actual_unit_cogs OR $before.f_out.inv_fx_rate != $after.f_out.inv_fx_rate) THEN {
    UPDATE sl SET system_ping = time::now() WHERE a_in_to = $after.id;
};

DEFINE EVENT push_invoice_line_to_tax_line_via_a_in_invoice_line ON TABLE invoice_line
WHEN $event = 'UPDATE' AND ($before.f_out.type != $after.f_out.type OR $before.f_out.inv_fx_rate != $after.f_out.inv_fx_rate OR $before.f_out.invl_sales_value != $after.f_out.invl_sales_value OR $before.f_out.invl_purchase_value != $after.f_out.invl_purchase_value OR $before.f_out.org != $after.f_out.org) THEN {
    UPDATE tax_line SET system_ping = time::now() WHERE a_in_invoice_line = $after.id;
};

DEFINE EVENT push_invoice_line_to_adjustment_line_via_a_in_invl ON TABLE invoice_line
WHEN $event = 'UPDATE' AND ($before.f_out.org != $after.f_out.org) THEN {
    UPDATE adjustment_line SET system_ping = time::now() WHERE a_in_invl = $after.id;
};

DEFINE EVENT push_package_note_to_sl_via_a_in_pkg ON TABLE package_note
WHEN $event = 'UPDATE' AND ($before.f_out.invoice != $after.f_out.invoice) THEN {
    UPDATE sl SET system_ping = time::now() WHERE a_in_pkg = $after.id;
};

DEFINE EVENT push_adjustment_note_to_adjustment_line_via_a_in_note ON TABLE adjustment_note
WHEN $event = 'UPDATE' AND ($before.f_out.org != $after.f_out.org) THEN {
    UPDATE adjustment_line SET system_ping = time::now() WHERE a_in_note = $after.id;
};

DEFINE EVENT push_adjustment_note_to_adjustment_tax_line_via_a_in_note ON TABLE adjustment_note
WHEN $event = 'UPDATE' AND ($before.f_out.org != $after.f_out.org) THEN {
    UPDATE adjustment_tax_line SET system_ping = time::now() WHERE a_in_note = $after.id;
};

DEFINE EVENT push_adjustment_note_to_adjustment_stock_line_via_a_in_note ON TABLE adjustment_note
WHEN $event = 'UPDATE' AND ($before.f_out.org != $after.f_out.org) THEN {
    UPDATE adjustment_stock_line SET system_ping = time::now() WHERE a_in_note = $after.id;
};

DEFINE EVENT push_tax_line_to_adjustment_tax_line_via_a_in_tax_line ON TABLE tax_line
WHEN $event = 'UPDATE' AND ($before.f_out.invl_org != $after.f_out.invl_org) THEN {
    UPDATE adjustment_tax_line SET system_ping = time::now() WHERE a_in_tax_line = $after.id;
};

DEFINE EVENT push_sl_to_adjustment_stock_line_via_a_in_sl ON TABLE sl
WHEN $event = 'UPDATE' AND ($before.f_out.invl_org != $after.f_out.invl_org) THEN {
    UPDATE adjustment_stock_line SET system_ping = time::now() WHERE a_in_sl = $after.id;
};

