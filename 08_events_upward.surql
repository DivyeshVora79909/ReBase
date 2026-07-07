USE NS main DB main;

DEFINE EVENT ping_v_pay_to_node ON TABLE v_pay_to WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = $after.node ?? $before.node;
        IF $tgt { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_pay_from_node ON TABLE v_pay_from WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = $after.node ?? $before.node;
        IF $tgt { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_pa_pay_payment ON TABLE v_pa_pay WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = $after.payment ?? $before.payment;
        IF $tgt { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_pa_inv_invoice ON TABLE v_pa_inv WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = $after.invoice ?? $before.invoice;
        IF $tgt { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_invl_inv_invoice ON TABLE v_invl_inv WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = $after.invoice ?? $before.invoice;
        IF $tgt { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_invl_item_item ON TABLE v_invl_item WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = $after.item ?? $before.item;
        IF $tgt { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_sl_from_inv_line ON TABLE v_sl_from WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = $after.inv_line ?? $before.inv_line;
        IF $tgt { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_sl_to_inv_line ON TABLE v_sl_to WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = $after.inv_line ?? $before.inv_line;
        IF $tgt { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_tl_invl_invoice_line ON TABLE v_tl_invl WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = $after.invoice_line ?? $before.invoice_line;
        IF $tgt { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_adj_target_target ON TABLE v_adj_target WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = $after.target ?? $before.target;
        IF $tgt { UPDATE $tgt SET system_ping = time::now(); };
    };
};

DEFINE EVENT ping_v_adj_note_note ON TABLE v_adj_note WHEN $event != 'NONE' THEN {
    IF $__rebase_halt_cascade != true {
        LET $tgt = $after.note ?? $before.note;
        IF $tgt { UPDATE $tgt SET system_ping = time::now(); };
    };
};

