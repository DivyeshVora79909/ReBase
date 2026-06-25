-- FILE 08: UPWARD PROPAGATION (O(1) VIEWS TO PARENT SIGNAL)
USE NS main DB main;

DEFINE EVENT ping_v_pay_node_to ON TABLE v_pay_node_to WHEN $event != 'NONE' THEN {
    LET $t = $after.node ?? $before.node;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_pay_node_from ON TABLE v_pay_node_from WHEN $event != 'NONE' THEN {
    LET $t = $after.node ?? $before.node;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_inv_org ON TABLE v_inv_org WHEN $event != 'NONE' THEN {
    LET $t = $after.org ?? $before.org;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_adj_org ON TABLE v_adj_org WHEN $event != 'NONE' THEN {
    LET $t = $after.org ?? $before.org;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_pa_pay ON TABLE v_pa_pay WHEN $event != 'NONE' THEN {
    LET $t = $after.payment ?? $before.payment;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_pa_inv ON TABLE v_pa_inv WHEN $event != 'NONE' THEN {
    LET $t = $after.invoice ?? $before.invoice;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_invl_inv ON TABLE v_invl_inv WHEN $event != 'NONE' THEN {
    LET $t = $after.invoice ?? $before.invoice;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_invl_item ON TABLE v_invl_item WHEN $event != 'NONE' THEN {
    LET $t = $after.item ?? $before.item;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_sl_pkg ON TABLE v_sl_pkg WHEN $event != 'NONE' THEN {
    LET $t = $after.pkg ?? $before.pkg;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_sl_invl_from ON TABLE v_sl_invl_from WHEN $event != 'NONE' THEN {
    LET $t = $after.inv_line ?? $before.inv_line;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_sl_invl_to ON TABLE v_sl_invl_to WHEN $event != 'NONE' THEN {
    LET $t = $after.inv_line ?? $before.inv_line;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_sl_node_in ON TABLE v_sl_node_in WHEN $event != 'NONE' THEN {
    LET $t = $after.node ?? $before.node;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_sl_node_out ON TABLE v_sl_node_out WHEN $event != 'NONE' THEN {
    LET $t = $after.node ?? $before.node;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_sl_cogs_out ON TABLE v_sl_cogs_out WHEN $event != 'NONE' THEN {
    LET $t = $after.acc ?? $before.acc;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_tl_inv ON TABLE v_tl_inv WHEN $event != 'NONE' THEN {
    LET $t = $after.invoice ?? $before.invoice;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_tl_acc ON TABLE v_tl_acc WHEN $event != 'NONE' THEN {
    LET $t = $after.tax_account ?? $before.tax_account;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_al_invl ON TABLE v_al_invl WHEN $event != 'NONE' THEN {
    LET $t = $after.invoice_line ?? $before.invoice_line;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_atl_tl ON TABLE v_atl_tl WHEN $event != 'NONE' THEN {
    LET $t = $after.tax_line ?? $before.tax_line;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

DEFINE EVENT ping_v_asl_sl ON TABLE v_asl_sl WHEN $event != 'NONE' THEN {
    LET $t = $after.sl ?? $before.sl;
    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
};

