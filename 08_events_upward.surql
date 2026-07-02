-- FILE 08: UPWARD PROPAGATION (O(1) VIEWS TO PARENT SIGNAL)
USE NS main DB main;

DEFINE EVENT ping_v_pay_to ON TABLE v_pay_to WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.node ?? $before.node]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_pay_from ON TABLE v_pay_from WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.node ?? $before.node]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_pa_pay ON TABLE v_pa_pay WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.payment ?? $before.payment]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_pa_inv ON TABLE v_pa_inv WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.invoice ?? $before.invoice]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_invl_inv ON TABLE v_invl_inv WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.invoice ?? $before.invoice]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_inv_org ON TABLE v_inv_org WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.org ?? $before.org]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_invl_item ON TABLE v_invl_item WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.item ?? $before.item]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_sl_in_ctx ON TABLE v_sl_in_ctx WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.node ?? $before.node]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_sl_out_ctx ON TABLE v_sl_out_ctx WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.node ?? $before.node]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_sl_pkg ON TABLE v_sl_pkg WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.pkg ?? $before.pkg]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_sl_from ON TABLE v_sl_from WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.inv_line ?? $before.inv_line]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_sl_to ON TABLE v_sl_to WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.inv_line ?? $before.inv_line]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_bi_sl_item ON TABLE v_bi_sl_item WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.item ?? $before.item]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_sl_matrix_in ON TABLE v_sl_matrix_in WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.node ?? $before.node]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_sl_matrix_out ON TABLE v_sl_matrix_out WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.node ?? $before.node]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_tl_invl ON TABLE v_tl_invl WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.invoice_line ?? $before.invoice_line]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_tl_acc ON TABLE v_tl_acc WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.tax_account ?? $before.tax_account]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_adj_target ON TABLE v_adj_target WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.target ?? $before.target]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_adj_note ON TABLE v_adj_note WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = array::flatten([$after.note ?? $before.note]).filter(|$v| $v != NONE);
        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };
    };
};

