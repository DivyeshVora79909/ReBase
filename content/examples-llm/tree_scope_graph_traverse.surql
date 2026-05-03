REMOVE TABLE IF EXISTS invoice;
REMOVE TABLE IF EXISTS invoice_line;
REMOVE TABLE IF EXISTS tax_line;
REMOVE TABLE IF EXISTS v_line_totals;
REMOVE TABLE IF EXISTS v_invoice_totals;

DEFINE TABLE invoice SCHEMAFULL;
DEFINE FIELD customer ON invoice TYPE string;
DEFINE FIELD date ON invoice TYPE datetime;
DEFINE FIELD status ON invoice TYPE string;

DEFINE TABLE invoice_line SCHEMAFULL;
DEFINE FIELD invoice ON invoice_line TYPE record<invoice> REFERENCE ON DELETE CASCADE;
DEFINE FIELD description ON invoice_line TYPE string;
DEFINE FIELD quantity ON invoice_line TYPE decimal;
DEFINE FIELD unit_price ON invoice_line TYPE decimal;
DEFINE FIELD line_total ON invoice_line TYPE decimal;

DEFINE TABLE tax_line SCHEMAFULL;
DEFINE FIELD invoice_line ON tax_line TYPE record<invoice_line> REFERENCE ON DELETE CASCADE;
DEFINE FIELD tax_name ON tax_line TYPE string;
DEFINE FIELD tax_rate ON tax_line TYPE decimal;
DEFINE FIELD tax_amount ON tax_line TYPE decimal;

DEFINE INDEX idx_line_invoice ON invoice_line COLUMNS invoice;
DEFINE INDEX idx_tax_line ON tax_line COLUMNS invoice_line;

DEFINE TABLE v_line_totals AS SELECT invoice_line, math::sum(tax_amount) AS total_tax, count() AS tax_count FROM tax_line GROUP BY invoice_line;
DEFINE TABLE v_invoice_totals AS SELECT invoice, math::sum(line_total) AS subtotal, math::sum(quantity) AS total_qty, count() AS line_count FROM invoice_line GROUP BY invoice;


CREATE |invoice:1..=5| SET customer = 'Scale Corp', date = time::now(), status = 'sent';

LET $invs = (SELECT VALUE id FROM invoice);
LET $lines_payload = $invs.map(|$inv_id| 
    (<array> 1..=5).map(|$num| {
        invoice: $inv_id,
        description: 'Bulk Widget',
        quantity: 5dec,
        unit_price: 20.00dec,
        line_total: 100.00dec
    })
).flatten();
INSERT INTO invoice_line $lines_payload;

LET $lines = (SELECT VALUE id FROM invoice_line);
LET $taxes_payload = $lines.map(|$line_id|[
    { invoice_line: $line_id, tax_name: 'VAT', tax_rate: 0.20dec, tax_amount: 20.00dec },
    { invoice_line: $line_id, tax_name: 'City Tax', tax_rate: 0.05dec, tax_amount: 5.00dec }
]).flatten();
INSERT INTO tax_line $taxes_payload;


-- RESULT
-- QUERY 1: Graph Traversal + O(1) Direct View Lookup
SELECT
    customer,
    date,
    status,
    (type::record('v_invoice_totals', [id])).{ subtotal, line_count } OR { subtotal: 0dec, line_count: 0 } AS invoice_totals,
    <~invoice_line.{
        description: description,
        line_total: line_total,
        line_totals: (type::record('v_line_totals', [id])).{ total_tax, tax_count } OR { total_tax: 0dec, tax_count: 0 },
        taxes: <~tax_line.{
            tax_name: tax_name,
            tax_amount: tax_amount
        }
    } AS lines
FROM invoice:1;


-- QUERY 2: Indexed Subqueries
SELECT
    customer,
    date,
    status,
    (SELECT subtotal, line_count FROM v_invoice_totals WHERE invoice = $parent.id)[0] ?? { subtotal: 0dec, line_count: 0 } AS invoice_totals,
    (SELECT 
         description,
         line_total,
         (SELECT total_tax, tax_count FROM v_line_totals WHERE invoice_line = $parent.id)[0] AS line_totals,
         (SELECT tax_name, tax_amount FROM tax_line WHERE invoice_line = $parent.id) AS taxes
     FROM invoice_line 
     WHERE invoice = $parent.id
    ) AS lines
FROM invoice:1;


-- QUERY 3: Simple Graph + View
SELECT
    id, customer,
    (type::record('v_invoice_totals', [id])).{ subtotal } OR { subtotal: 0dec } AS totals,
    <~invoice_line.{ description, line_total } AS lines
FROM invoice:1;


-- QUERY 4: Subquery with Sort & Limit (Essential for Pagination)
SELECT id, customer, 
       (type::record('v_invoice_totals', [id])).subtotal ?? 0dec AS subtotal, 
       ( SELECT description, line_total 
         FROM invoice_line 
         WHERE invoice = $parent.id 
         ORDER BY line_total DESC 
         LIMIT 10 
       ) AS top_lines 
FROM invoice:1;


-- QUERY 5: Pure RAM Graph Math (No Views)
SELECT
    id, customer,
    math::sum(<~invoice_line.line_total) ?? 0dec AS dynamic_subtotal,
    count(<~invoice_line[WHERE line_total > 50dec]) AS high_value_lines
FROM invoice:1;


-- QUERY 6: Global Dashboard (Querying the view directly for top 50 across all 1000 invoices)
SELECT 
    invoice AS invoice_id,
    invoice.customer AS customer_name,
    subtotal,
    line_count
FROM v_invoice_totals
WHERE subtotal > 10dec
ORDER BY subtotal DESC
LIMIT 50;