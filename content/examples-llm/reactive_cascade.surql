REMOVE TABLE IF EXISTS org;
REMOVE TABLE IF EXISTS invoice;
REMOVE TABLE IF EXISTS payment;
REMOVE TABLE IF EXISTS allocation;

REMOVE TABLE IF EXISTS v_alloc_to_invoice;
REMOVE TABLE IF EXISTS v_alloc_to_payment;
REMOVE TABLE IF EXISTS v_invoice_to_org;
REMOVE TABLE IF EXISTS v_payment_to_org;

DEFINE TABLE org SCHEMAFULL;
    DEFINE FIELD name ON org TYPE string;
    DEFINE FIELD invoice_revenue ON org TYPE decimal DEFAULT 0dec;
    DEFINE FIELD invoice_collected ON org TYPE decimal DEFAULT 0dec;
    DEFINE FIELD payment_received ON org TYPE decimal DEFAULT 0dec;
    DEFINE FIELD payment_allocated ON org TYPE decimal DEFAULT 0dec;

DEFINE TABLE invoice SCHEMAFULL;
    DEFINE FIELD org ON invoice TYPE record<org>;
    DEFINE FIELD status ON invoice TYPE string ASSERT $value IN ['draft', 'posted', 'void'];
    DEFINE FIELD total_amount ON invoice TYPE decimal DEFAULT 0dec;
    DEFINE FIELD total_paid ON invoice TYPE decimal DEFAULT 0dec; 
    DEFINE FIELD z_posted_revenue ON invoice TYPE decimal 
        VALUE IF status = 'posted' THEN (total_amount ?? 0dec) ELSE 0dec END;
    DEFINE FIELD z_posted_collected ON invoice TYPE decimal 
        VALUE IF status = 'posted' THEN (total_paid ?? 0dec) ELSE 0dec END;

DEFINE TABLE payment SCHEMAFULL;
    DEFINE FIELD org ON payment TYPE record<org>;
    DEFINE FIELD status ON payment TYPE string ASSERT $value IN ['draft', 'posted', 'void'];
    DEFINE FIELD total_amount ON payment TYPE decimal DEFAULT 0dec;
    DEFINE FIELD total_allocated ON payment TYPE decimal DEFAULT 0dec; 
    DEFINE FIELD z_posted_received ON payment TYPE decimal 
        VALUE IF status = 'posted' THEN (total_amount ?? 0dec) ELSE 0dec END;
    DEFINE FIELD z_posted_allocated ON payment TYPE decimal 
        VALUE IF status = 'posted' THEN (total_allocated ?? 0dec) ELSE 0dec END;

DEFINE TABLE allocation SCHEMAFULL;
    DEFINE FIELD invoice ON allocation TYPE record<invoice>;
    DEFINE FIELD payment ON allocation TYPE record<payment>;
    DEFINE FIELD status ON allocation TYPE string ASSERT $value IN ['draft', 'posted', 'void'];
    DEFINE FIELD amount ON allocation TYPE decimal;
    DEFINE FIELD z_posted_amount ON allocation TYPE decimal 
        VALUE IF status = 'posted' THEN (amount ?? 0dec) ELSE 0dec END;


DEFINE TABLE v_alloc_to_invoice AS SELECT invoice, math::sum(z_posted_amount) AS total FROM allocation GROUP BY invoice;
DEFINE TABLE v_alloc_to_payment AS SELECT payment, math::sum(z_posted_amount) AS total FROM allocation GROUP BY payment;

DEFINE TABLE v_invoice_to_org AS 
    SELECT org, math::sum(z_posted_revenue) AS revenue, math::sum(z_posted_collected) AS collected 
    FROM invoice GROUP BY org;
DEFINE TABLE v_payment_to_org AS 
    SELECT org, math::sum(z_posted_received) AS received, math::sum(z_posted_allocated) AS allocated 
    FROM payment GROUP BY org;

DEFINE EVENT sync_inv ON v_alloc_to_invoice WHEN $event != 'NONE' THEN {
    LET $tgt = $after.invoice ?? $before.invoice;
    UPDATE $tgt SET total_paid = ($after.total ?? 0dec);
};

DEFINE EVENT sync_pay ON v_alloc_to_payment WHEN $event != 'NONE' THEN {
    LET $tgt = $after.payment ?? $before.payment;
    UPDATE $tgt SET total_allocated = ($after.total ?? 0dec);
};

DEFINE EVENT sync_inv_org ON v_invoice_to_org WHEN $event != 'NONE' THEN {
    LET $tgt = $after.org ?? $before.org;
    UPDATE $tgt SET 
        invoice_revenue = ($after.revenue ?? 0dec), 
        invoice_collected = ($after.collected ?? 0dec);
};

DEFINE EVENT sync_pay_org ON v_payment_to_org WHEN $event != 'NONE' THEN {
    LET $tgt = $after.org ?? $before.org;
    UPDATE $tgt SET 
        payment_received = ($after.received ?? 0dec), 
        payment_allocated = ($after.allocated ?? 0dec);
};

-- RESULT
CREATE org:R SET name = "Acme Corp";
CREATE invoice:R SET org = org:R, status = 'posted', total_amount = 1000dec;
CREATE payment:R SET org = org:R, status = 'posted', total_amount = 1000dec;
SELECT invoice_revenue, payment_received FROM org:R; -- 1000, 1000

CREATE allocation:R SET invoice = invoice:R, payment = payment:R, status = 'posted', amount = 500dec;
SELECT id, total_amount, total_paid FROM invoice:R; -- 1000, 500
SELECT id, total_amount, total_allocated FROM payment:R; -- 1000, 500
SELECT invoice_collected, invoice_revenue, payment_allocated, payment_received FROM org:R; -- 500, 1000, 500, 1000

UPDATE allocation:R SET status = 'void';
SELECT invoice_collected, invoice_revenue, payment_allocated, payment_received FROM org:R; -- 0, 1000, 0, 1000


-- AGGRESIVE TESTING
CREATE org:A SET name = "Acme Corp";

-- 1,000 Invoices (500 Posted, 500 Draft). All 100dec.
INSERT INTO invoice (<array> 1..=1000).map(|$i| {
    id: type::record('invoice', $i),
    org: org:A,
    status: IF $i <= 500 THEN 'posted' ELSE 'draft' END,
    total_amount: 100dec
});

-- 1,000 Payments (500 Posted, 500 Draft). All 100dec.
INSERT INTO payment (<array> 1..=1000).map(|$i| {
    id: type::record('payment', $i),
    org: org:A,
    status: IF $i <= 500 THEN 'posted' ELSE 'draft' END,
    total_amount: 100dec
});

-- 1,000 Allocations (ALL POSTED). Mapping 1-to-1. Amount 50dec.
INSERT INTO allocation (<array> 1..=1000).map(|$i| {
    id: type::record('allocation', $i),
    invoice: type::record('invoice', $i),
    payment: type::record('payment', $i),
    status: 'posted',
    amount: 50dec
});

-- Check a Draft Invoice. Note that total_paid = 50, but z_posted_collected = 0!
SELECT id, status, total_amount, total_paid, z_posted_revenue, z_posted_collected FROM invoice:1000;

-- Check Org A Dashboard
-- Expected Revenue: 50,000 (500 posted invoices * 100)
-- Expected Collected: 25,000 (500 posted invoices * 50)
-- Draft invoices are safely ignored!
SELECT invoice_revenue, invoice_collected, payment_received, payment_allocated FROM org:A;

UPDATE invoice SET status = 'posted' WHERE status = 'draft';
UPDATE payment SET status = 'posted' WHERE status = 'draft';

-- Check Org A Dashboard
-- Expected Revenue: 100,000 (1000 posted invoices * 100)
-- Expected Collected: 50,000 (1000 posted invoices * 50)
-- The DAG magically caught up and recognized the hidden revenue!
SELECT invoice_revenue, invoice_collected, payment_received, payment_allocated FROM org:A;

UPDATE payment SET status = 'void';

-- Check Org A Dashboard
-- Expected Received/Allocated: 0, 0
-- Expected Revenue/Collected: 100,000, 50,000 (Invoices weren't touched)
SELECT invoice_revenue, invoice_collected, payment_received, payment_allocated FROM org:A;

-- Hard delete 5 allocations
DELETE allocation:1, allocation:2, allocation:3, allocation:4, allocation:5;

-- Check Invoice 1 (Should be missing its 50dec allocation)
-- Expected total_paid: 0
SELECT id, total_amount, total_paid FROM invoice:1;

-- Check Org A Dashboard
-- Expected Collected: 49,750 (50,000 - the 5 deleted 50dec allocations)
SELECT invoice_revenue, invoice_collected FROM org:A;

-- Hard delete Invoice 10
DELETE invoice:10;

-- Expected Revenue: 99,900 (100,000 - the 100dec invoice)
-- Expected Collected: 49,700 (49,750 - the 50dec allocation on that invoice)
SELECT invoice_revenue, invoice_collected FROM org:A;