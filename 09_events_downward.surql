-- FILE 09: DOWNWARD PROPAGATION (NATIVE GRAPH ROUTING)
USE NS main DB main;

DEFINE EVENT aot_cascade_downward ON TABLE org WHEN $event = 'UPDATE' THEN {
    IF $__rebase_halt_cascade != true {
        IF $before.a_currency != $after.a_currency {
            LET $tgt = array::flatten([$after<~payment]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
    };
};

DEFINE EVENT aot_cascade_downward ON TABLE treasury WHEN $event = 'UPDATE' THEN {
    IF $__rebase_halt_cascade != true {
        IF $before.a_currency != $after.a_currency {
            LET $tgt = array::flatten([$after<~payment]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
    };
};

DEFINE EVENT aot_cascade_downward ON TABLE acc WHEN $event = 'UPDATE' THEN {
    IF $__rebase_halt_cascade != true {
        IF $before.a_currency != $after.a_currency {
            LET $tgt = array::flatten([$after<~payment]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
    };
};

DEFINE EVENT aot_cascade_downward ON TABLE tax_account WHEN $event = 'UPDATE' THEN {
    IF $__rebase_halt_cascade != true {
        IF $before.a_currency != $after.a_currency {
            LET $tgt = array::flatten([$after<~payment]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
    };
};

DEFINE EVENT aot_cascade_downward ON TABLE payment WHEN $event = 'UPDATE' THEN {
    IF $__rebase_halt_cascade != true {
        IF $before.a_fx_rate != $after.a_fx_rate {
            LET $tgt = array::flatten([$after<~payment_allocation]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.a_from != $after.a_from {
            LET $tgt = array::flatten([$after<~payment_allocation]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.a_to != $after.a_to {
            LET $tgt = array::flatten([$after<~payment_allocation]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.d3_vector != $after.d3_vector {
            LET $tgt = array::flatten([$after<~payment_allocation]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
    };
};

DEFINE EVENT aot_cascade_downward ON TABLE invoice WHEN $event = 'UPDATE' THEN {
    IF $__rebase_halt_cascade != true {
        IF $before.a_fx_rate != $after.a_fx_rate {
            LET $tgt = array::flatten([$after<~payment_allocation]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.a_org != $after.a_org {
            LET $tgt = array::flatten([$after<~payment_allocation]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
            LET $tgt = array::flatten([$after<~invoice_line<~adjustment_line]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
            LET $tgt = array::flatten([$after<~invoice_line<~tax_line<~adjustment_line]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
            LET $tgt = array::flatten([$after<~invoice_line<~sl<~adjustment_line]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.d1_vector != $after.d1_vector {
            LET $tgt = array::flatten([$after<~payment_allocation]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
            LET $tgt = array::flatten([$after<~invoice_line]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.id != $after.id {
            LET $tgt = array::flatten([$after<~payment_allocation]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
    };
};

DEFINE EVENT aot_cascade_downward ON TABLE item WHEN $event = 'UPDATE' THEN {
    IF $__rebase_halt_cascade != true {
        IF $before.d1_avg_cogs != $after.d1_avg_cogs {
            LET $tgt = array::flatten([$after<~invoice_line]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
    };
};

DEFINE EVENT aot_cascade_downward ON TABLE warehouse WHEN $event = 'UPDATE' THEN {
    IF $__rebase_halt_cascade != true {
        IF $before.a_item != $after.a_item {
            LET $tgt = array::flatten([$after<~sl]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.d4_actual_cogs != $after.d4_actual_cogs {
            LET $tgt = array::flatten([$after<~sl]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.a_invoice != $after.a_invoice {
            LET $tgt = array::flatten([$after<~sl]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.d1_vector != $after.d1_vector {
            LET $tgt = array::flatten([$after<~sl]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
    };
};

DEFINE EVENT aot_cascade_downward ON TABLE stock_acc WHEN $event = 'UPDATE' THEN {
    IF $__rebase_halt_cascade != true {
        IF $before.a_item != $after.a_item {
            LET $tgt = array::flatten([$after<~sl]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.d4_actual_cogs != $after.d4_actual_cogs {
            LET $tgt = array::flatten([$after<~sl]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.a_invoice != $after.a_invoice {
            LET $tgt = array::flatten([$after<~sl]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.d1_vector != $after.d1_vector {
            LET $tgt = array::flatten([$after<~sl]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
    };
};

DEFINE EVENT aot_cascade_downward ON TABLE invoice_line WHEN $event = 'UPDATE' THEN {
    IF $__rebase_halt_cascade != true {
        IF $before.a_item != $after.a_item {
            LET $tgt = array::flatten([$after<~sl]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.d4_actual_cogs != $after.d4_actual_cogs {
            LET $tgt = array::flatten([$after<~sl]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.a_invoice != $after.a_invoice {
            LET $tgt = array::flatten([$after<~sl]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.d1_vector != $after.d1_vector {
            LET $tgt = array::flatten([$after<~sl]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
            LET $tgt = array::flatten([$after<~tax_line]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
        IF $before.d2_raw_base != $after.d2_raw_base {
            LET $tgt = array::flatten([$after<~tax_line]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
    };
};

DEFINE EVENT aot_cascade_downward ON TABLE package_note WHEN $event = 'UPDATE' THEN {
    IF $__rebase_halt_cascade != true {
        IF $before.a_invoice != $after.a_invoice {
            LET $tgt = array::flatten([$after<~sl]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
    };
};

DEFINE EVENT aot_cascade_downward ON TABLE adjustment_note WHEN $event = 'UPDATE' THEN {
    IF $__rebase_halt_cascade != true {
        IF $before.a_org != $after.a_org {
            LET $tgt = array::flatten([$after<~adjustment_line]).filter(|$v| $v != NONE);
            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
        };
    };
};

