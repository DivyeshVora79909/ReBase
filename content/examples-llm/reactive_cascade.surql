REMOVE TABLE IF EXISTS org;
REMOVE TABLE IF EXISTS invoice;
REMOVE TABLE IF EXISTS payment;
REMOVE TABLE IF EXISTS allocation;

REMOVE TABLE IF EXISTS v_alloc_to_invoice;
REMOVE TABLE IF EXISTS v_alloc_to_payment;
REMOVE TABLE IF EXISTS v_invoice_to_org;
REMOVE TABLE IF EXISTS v_payment_to_org;
REMOVE TABLE IF EXISTS v_daily_invoice;
REMOVE TABLE IF EXISTS v_daily_payment;

DEFINE TABLE org SCHEMAFULL;
    DEFINE FIELD name ON org TYPE string;
    DEFINE FIELD invoice_revenue ON org TYPE decimal DEFAULT 0dec;
    DEFINE FIELD invoice_collected ON org TYPE decimal DEFAULT 0dec;
    DEFINE FIELD payment_received ON org TYPE decimal DEFAULT 0dec;
    DEFINE FIELD payment_allocated ON org TYPE decimal DEFAULT 0dec;

DEFINE TABLE invoice SCHEMAFULL;
    DEFINE FIELD org ON invoice TYPE record<org> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD status ON invoice TYPE string ASSERT $value IN ['draft', 'posted', 'void'];
    DEFINE FIELD total_amount ON invoice TYPE decimal DEFAULT 0dec;
    DEFINE FIELD total_paid ON invoice TYPE decimal DEFAULT 0dec;
    DEFINE FIELD created_at ON invoice TYPE datetime DEFAULT time::now();
    DEFINE FIELD z_posted_revenue ON invoice TYPE decimal
        VALUE IF status = 'posted' THEN (total_amount ?? 0dec) ELSE 0dec END;
    DEFINE FIELD z_posted_collected ON invoice TYPE decimal
        VALUE IF status = 'posted' THEN (total_paid ?? 0dec) ELSE 0dec END;

DEFINE TABLE payment SCHEMAFULL;
    DEFINE FIELD org ON payment TYPE record<org> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD status ON payment TYPE string ASSERT $value IN ['draft', 'posted', 'void'];
    DEFINE FIELD total_amount ON payment TYPE decimal DEFAULT 0dec;
    DEFINE FIELD total_allocated ON payment TYPE decimal DEFAULT 0dec;
    DEFINE FIELD created_at ON payment TYPE datetime DEFAULT time::now();
    DEFINE FIELD z_posted_received ON payment TYPE decimal
        VALUE IF status = 'posted' THEN (total_amount ?? 0dec) ELSE 0dec END;
    DEFINE FIELD z_posted_allocated ON payment TYPE decimal
        VALUE IF status = 'posted' THEN (total_allocated ?? 0dec) ELSE 0dec END;

DEFINE TABLE allocation SCHEMAFULL;
    DEFINE FIELD invoice ON allocation TYPE record<invoice> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD payment ON allocation TYPE record<payment> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD status ON allocation TYPE string ASSERT $value IN ['draft', 'posted', 'void'];
    DEFINE FIELD amount ON allocation TYPE decimal;
    DEFINE FIELD created_at ON allocation TYPE datetime DEFAULT time::now();
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
DEFINE TABLE v_daily_invoice AS
    SELECT
        time::group(created_at, 'day') AS day,
        org,
        math::sum(z_posted_revenue) AS revenue,
        math::sum(z_posted_collected) AS collected,
        count() AS invoice_count
    FROM invoice
    GROUP BY day, org;

DEFINE TABLE v_daily_payment AS
    SELECT
        time::group(created_at, 'day') AS day,
        org,
        math::sum(z_posted_received) AS received,
        math::sum(z_posted_allocated) AS allocated,
        count() AS payment_count
    FROM payment
    GROUP BY day, org;

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


-- AGGRESSIVE TESTING
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

-- CORE
SELECT id, status, total_amount, total_paid, z_posted_revenue, z_posted_collected FROM invoice:1000; -- 100, 50, 0, 0
SELECT invoice_revenue, invoice_collected, payment_received, payment_allocated FROM org:A; -- 50000, 25000, 50000, 25000

UPDATE invoice SET status = 'posted' WHERE status = 'draft';
UPDATE payment SET status = 'posted' WHERE status = 'draft';

SELECT invoice_revenue, invoice_collected, payment_received, payment_allocated FROM org:A; -- 100000, 50000, 100000, 50000

UPDATE payment SET status = 'void';

SELECT invoice_revenue, invoice_collected, payment_received, payment_allocated FROM org:A; -- 100000, 50000, 0, 0

DELETE allocation:1, allocation:2, allocation:3, allocation:4, allocation:5;

SELECT id, total_amount, total_paid FROM invoice:1; -- 100, 0
SELECT invoice_revenue, invoice_collected FROM org:A; -- 100000, 49750

DELETE invoice:10;

SELECT invoice_revenue, invoice_collected FROM org:A; -- 99900, 49700

-- TIME
CREATE org:T SET name = "Acme Corp";

-- daily
SELECT day, revenue, collected, invoice_count FROM v_daily_invoice WHERE org = org:T;
SELECT day, received, allocated, payment_count FROM v_daily_payment WHERE org = org:T;
SELECT day, revenue, collected FROM v_daily_invoice
    WHERE org = org:T AND day >= d"2026-05-17" AND day <= d"2026-05-17";

-- monthly, yearly, custom range
SELECT time::group(day, 'month') AS month, math::sum(revenue) AS total_revenue, math::sum(collected) AS total_collected
    FROM v_daily_invoice WHERE org = org:T GROUP BY month;
SELECT time::group(day, 'year') AS year, math::sum(revenue) AS total_revenue
    FROM v_daily_invoice WHERE org = org:T GROUP BY year;
SELECT time::group(day, 'month') AS month, math::sum(received) AS total_received, math::sum(allocated) AS total_allocated
    FROM v_daily_payment WHERE org = org:T GROUP BY month;
SELECT math::sum(revenue) AS july_revenue FROM v_daily_invoice 
    WHERE org = org:T AND day >= d"2025-07-01" AND day <= d"2025-07-31" GROUP ALL;

-- RESULT
CREATE invoice:jul01 SET org = org:T, status = 'posted', total_amount = 100dec, created_at = d"2025-07-01T10:00:00Z";
CREATE invoice:jul02 SET org = org:T, status = 'posted', total_amount = 200dec, created_at = d"2025-07-02T10:00:00Z";
CREATE invoice:jul15 SET org = org:T, status = 'posted', total_amount = 300dec, created_at = d"2025-07-15T10:00:00Z";
CREATE invoice:aug01 SET org = org:T, status = 'posted', total_amount = 400dec, created_at = d"2025-08-01T10:00:00Z";

CREATE payment:jul01 SET org = org:T, status = 'posted', total_amount = 50dec, created_at = d"2025-07-01T10:00:00Z";
CREATE payment:jul15 SET org = org:T, status = 'posted', total_amount = 80dec, created_at = d"2025-07-15T10:00:00Z";
CREATE payment:aug01 SET org = org:T, status = 'posted', total_amount = 120dec, created_at = d"2025-08-01T10:00:00Z";

SELECT revenue FROM v_daily_invoice WHERE org = org:T AND day = d"2025-07-01";
UPDATE invoice:jul01 SET created_at = d"2025-07-20T10:00:00Z";
SELECT revenue FROM v_daily_invoice WHERE org = org:T AND day = d"2025-07-01";
SELECT revenue FROM v_daily_invoice WHERE org = org:T AND day = d"2025-07-20";

CREATE allocation:al1 SET invoice = invoice:jul01, payment = payment:jul01, status = 'posted', amount = 20dec;
CREATE allocation:al2 SET invoice = invoice:jul02, payment = payment:jul01, status = 'posted', amount = 30dec;

SELECT id, total_paid FROM invoice WHERE org = org:T;
SELECT id, total_allocated FROM payment WHERE org = org:T;
SELECT day, revenue, collected FROM v_daily_invoice WHERE org = org:T ORDER BY day;

SELECT time::group(day, 'month') AS month, math::sum(collected) AS total_collected
    FROM v_daily_invoice WHERE org = org:T GROUP BY month;

SELECT day, received, allocated FROM v_daily_payment WHERE org = org:T ORDER BY day;
