REMOVE TABLE IF EXISTS invoice;
REMOVE TABLE IF EXISTS invoice_line;
REMOVE TABLE IF EXISTS sl;
REMOVE TABLE IF EXISTS v_sl_to_line;
REMOVE TABLE IF EXISTS v_inv_lines;

DEFINE TABLE invoice SCHEMAFULL;
    DEFINE FIELD suspended ON invoice TYPE bool DEFAULT false;
    DEFINE FIELD locked ON invoice TYPE bool DEFAULT false;
    DEFINE FIELD updated_at ON invoice TYPE datetime VALUE time::now();
    DEFINE FIELD total_qty ON invoice TYPE decimal 
        VALUE (type::record('v_inv_lines', [id])).total_qty ?? 0dec;
    DEFINE FIELD total_delivered_qty ON invoice TYPE decimal 
        VALUE (type::record('v_inv_lines', [id])).total_delivered_qty ?? 0dec;
    DEFINE FIELD total_ordered_value ON invoice TYPE decimal 
        VALUE (type::record('v_inv_lines', [id])).total_ordered_value ?? 0dec;
    DEFINE FIELD total_delivered_value ON invoice TYPE decimal 
        VALUE (type::record('v_inv_lines', [id])).total_delivered_value ?? 0dec;
    DEFINE FIELD sum_cogs ON invoice TYPE decimal 
        VALUE (type::record('v_inv_lines', [id])).sum_cogs ?? 0dec;
    DEFINE FIELD z_avg_cost ON invoice TYPE decimal 
        VALUE IF total_qty > 0dec THEN total_ordered_value / total_qty ELSE 0dec END;
    DEFINE FIELD z_countable_qty ON invoice TYPE decimal 
        VALUE IF suspended THEN 0dec ELSE total_qty END
        ASSERT $value >= total_delivered_qty;

DEFINE TABLE invoice_line SCHEMAFULL;
    DEFINE FIELD invoice ON invoice_line TYPE record<invoice> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD qty ON invoice_line TYPE decimal ASSERT $value > 0dec;
    DEFINE FIELD cogs ON invoice_line TYPE decimal ASSERT $value >= 0dec;
    DEFINE FIELD updated_at ON invoice_line TYPE datetime VALUE time::now();
    DEFINE FIELD delivered_qty ON invoice_line TYPE decimal 
        VALUE (type::record('v_sl_to_line', [id])).delivered_qty ?? 0dec;
    DEFINE FIELD z_qty_remaining ON invoice_line TYPE decimal 
        VALUE qty - delivered_qty
        ASSERT $value >= 0dec;
    DEFINE FIELD z_total_value ON invoice_line TYPE decimal VALUE qty * cogs;
    DEFINE FIELD z_delivered_value ON invoice_line TYPE decimal VALUE delivered_qty * cogs;

DEFINE TABLE sl SCHEMAFULL;
    DEFINE FIELD inv_line ON sl TYPE record<invoice_line> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD qty ON sl TYPE decimal ASSERT $value > 0dec;
    DEFINE FIELD suspended ON sl TYPE bool DEFAULT false;
    DEFINE FIELD locked ON sl TYPE bool DEFAULT false;
    DEFINE FIELD z_qty ON sl TYPE decimal VALUE IF suspended THEN 0dec ELSE qty END;

DEFINE TABLE v_sl_to_line AS 
    SELECT inv_line, math::sum(z_qty) AS delivered_qty 
    FROM sl 
    GROUP BY inv_line;

DEFINE EVENT ping_inv_line ON TABLE v_sl_to_line WHEN $event != 'NONE' THEN {
    UPDATE ($after.inv_line ?? $before.inv_line) SET updated_at = time::now();
};

DEFINE TABLE v_inv_lines AS 
    SELECT 
        invoice, 
        math::sum(qty) AS total_qty,
        math::sum(delivered_qty) AS total_delivered_qty,
        math::sum(z_total_value) AS total_ordered_value,
        math::sum(z_delivered_value) AS total_delivered_value,
        math::sum(cogs) AS sum_cogs
    FROM invoice_line 
    GROUP BY invoice;

DEFINE EVENT ping_invoice ON TABLE v_inv_lines WHEN $event != 'NONE' THEN {
    LET $inv_id = $after.invoice ?? $before.invoice;
    IF $inv_id.locked = true {
        THROW "LOCKED";
    };
    UPDATE $inv_id SET updated_at = time::now();
};

CREATE invoice:inv_1;

CREATE invoice_line:line_1 SET invoice = invoice:inv_1, qty = 2dec, cogs = 20dec;
CREATE invoice_line:line_2 SET invoice = invoice:inv_1, qty = 3dec, cogs = 10dec;

SELECT '1. INVOICE CREATED' AS step, total_qty, total_ordered_value, z_avg_cost FROM invoice:inv_1;

CREATE sl:del_1 SET inv_line = invoice_line:line_1, qty = 2dec;
CREATE sl:del_2 SET inv_line = invoice_line:line_2, qty = 2dec;

SELECT '2. LINE STATUS' AS step, id, z_qty_remaining, z_total_value, z_delivered_value FROM invoice_line WHERE invoice = invoice:inv_1;
SELECT '2. INVOICE STATUS' AS step, total_delivered_qty, total_delivered_value FROM invoice:inv_1;

-- TESTS
CREATE sl:del_fail SET inv_line = invoice_line:line_2, qty = 5dec; -- ERROR `z_qty_remaining >= 0`
UPDATE invoice:inv_1 SET suspended = true; -- ERROR `z_countable_qty >= total_delivered_qty`
UPDATE invoice:inv_1 SET locked = true;
CREATE invoice_line:line_3 SET invoice = invoice:inv_1, qty = 1dec, cogs = 50dec; -- ERROR "LOCKED"
DELETE invoice_line WHERE invoice = invoice:inv_1; -- ERROR "LOCKED"

SELECT * FROM invoice_line WHERE invoice = invoice:inv_1;