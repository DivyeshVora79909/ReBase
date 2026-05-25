USE NS main DB main;

-- ==========================================
-- 1. VIEWS
-- ==========================================

-- Payment Routing
DEFINE TABLE OVERWRITE v_payment_from AS 
    SELECT from AS node, math::sum(z_active_amount) AS total 
    FROM payment GROUP BY node;

DEFINE TABLE OVERWRITE v_payment_to AS 
    SELECT to AS node, math::sum(z_active_amount) AS total 
    FROM payment GROUP BY node;

-- Payment Allocations
DEFINE TABLE OVERWRITE v_pa_pay AS 
    SELECT payment, math::sum(amount) AS total 
    FROM payment_allocation GROUP BY payment;

DEFINE TABLE OVERWRITE v_pa_inv AS 
    SELECT invoice, math::sum(amount) AS total 
    FROM payment_allocation GROUP BY invoice;

-- Invoice Lines Matrix
DEFINE TABLE OVERWRITE v_inv_line_item AS 
    SELECT item, math::mean(cogs) AS avg_cogs, math::sum(qty) AS total_qty 
    FROM invoice_line GROUP BY item;

DEFINE TABLE OVERWRITE v_inv_line_inv AS 
    SELECT inv AS invoice, 
           math::sum(z_total_value) AS total_value, 
           math::sum(z_remaining_value) AS remaining_value, 
           math::sum(qty) AS total_qty, 
           math::sum(z_qty_remaining) AS total_qty_remaining, 
           math::sum(cogs) AS sum_cogs 
    FROM invoice_line GROUP BY invoice;

-- Invoice to Org Total
DEFINE TABLE OVERWRITE v_invoice_org AS 
    SELECT org, math::sum(z_active_amount) AS total 
    FROM invoice GROUP BY org;

-- Stock Movements (Specific item validation)
DEFINE TABLE OVERWRITE v_sl_from AS 
    SELECT from AS node, item, math::sum(z_active_qty) AS total 
    FROM sl GROUP BY node, item;

DEFINE TABLE OVERWRITE v_sl_to AS 
    SELECT to AS node, item, math::sum(z_active_qty) AS total 
    FROM sl GROUP BY node, item;

-- Stock Movements (Generic warehouse total for pitch display)
DEFINE TABLE OVERWRITE v_sl_from_generic AS 
    SELECT from AS node, math::sum(z_active_qty) AS total 
    FROM sl GROUP BY node;

DEFINE TABLE OVERWRITE v_sl_to_generic AS 
    SELECT to AS node, math::sum(z_active_qty) AS total 
    FROM sl GROUP BY node;

-- Stock to Invoice Line fulfillment
DEFINE TABLE OVERWRITE v_sl_inv_line AS 
    SELECT inv_line, math::sum(z_active_qty) AS total_qty 
    FROM sl WHERE inv_line != NONE GROUP BY inv_line;


-- ==========================================
-- 2. EVENTS (THE UPWARD PINGS)
-- ==========================================

DEFINE EVENT OVERWRITE ping_node_from ON TABLE v_payment_from WHEN $event != 'NONE' THEN {
    UPDATE ($after.node ?? $before.node) SET updated_at = time::now();
};

DEFINE EVENT OVERWRITE ping_node_to ON TABLE v_payment_to WHEN $event != 'NONE' THEN {
    UPDATE ($after.node ?? $before.node) SET updated_at = time::now();
};

DEFINE EVENT OVERWRITE ping_payment ON TABLE v_pa_pay WHEN $event != 'NONE' THEN {
    UPDATE ($after.payment ?? $before.payment) SET updated_at = time::now();
};

DEFINE EVENT OVERWRITE ping_invoice_alloc ON TABLE v_pa_inv WHEN $event != 'NONE' THEN {
    UPDATE ($after.invoice ?? $before.invoice) SET updated_at = time::now();
};

DEFINE EVENT OVERWRITE ping_item ON TABLE v_inv_line_item WHEN $event != 'NONE' THEN {
    UPDATE ($after.item ?? $before.item) SET updated_at = time::now();
};

DEFINE EVENT OVERWRITE ping_invoice_lines ON TABLE v_inv_line_inv WHEN $event != 'NONE' THEN {
    UPDATE ($after.invoice ?? $before.invoice) SET updated_at = time::now();
};

-- Pings the Warehouse/Stock Acc when specific items move
DEFINE EVENT OVERWRITE ping_sl_from_generic ON TABLE v_sl_from_generic WHEN $event != 'NONE' THEN {
    UPDATE ($after.node ?? $before.node) SET updated_at = time::now();
};

DEFINE EVENT OVERWRITE ping_sl_to_generic ON TABLE v_sl_to_generic WHEN $event != 'NONE' THEN {
    UPDATE ($after.node ?? $before.node) SET updated_at = time::now();
};

DEFINE EVENT OVERWRITE ping_inv_line_sl ON TABLE v_sl_inv_line WHEN $event != 'NONE' THEN {
    UPDATE ($after.inv_line ?? $before.inv_line) SET updated_at = time::now();
};

DEFINE EVENT OVERWRITE ping_org_inv ON TABLE v_invoice_org WHEN $event != 'NONE' THEN {
    UPDATE ($after.org ?? $before.org) SET updated_at = time::now();
};