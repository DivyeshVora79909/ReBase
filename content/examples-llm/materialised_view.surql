REMOVE TABLE IF EXISTS ledger;
REMOVE TABLE IF EXISTS view_metrics;
REMOVE TABLE IF EXISTS view_daily;
REMOVE TABLE IF EXISTS view_min_max;

DEFINE TABLE ledger SCHEMAFULL;
    DEFINE FIELD amount ON ledger TYPE decimal;
    DEFINE FIELD category ON ledger TYPE string;
    DEFINE FIELD created_at ON ledger TYPE datetime DEFAULT time::now();

DEFINE TABLE view_metrics AS 
    SELECT 
        category, 
        count() AS total_tx, 
        math::sum(amount) AS total_amount, 
        math::mean(amount) AS average_amount 
    FROM ledger 
    GROUP BY category;

DEFINE TABLE view_daily AS 
    SELECT 
        time::group(created_at, 'day') AS day, 
        math::sum(amount) AS daily_total 
    FROM ledger 
    GROUP BY day;

DEFINE TABLE view_min_max AS 
    SELECT 
        category, 
        math::min(amount) AS lowest, 
        math::max(amount) AS highest 
    FROM ledger 
    GROUP BY category;

DEFINE EVENT enforce_daily_limit ON ledger WHEN $event IN ["CREATE", "UPDATE"] THEN {
    LET $current_day = time::group($after.created_at, 'day');
    LET $daily_total = (SELECT VALUE daily_total FROM view_daily WHERE day = $current_day LIMIT 1)[0] ?? 0dec;
    
    IF $daily_total > 5000000dec {
        THROW "DAILY_LIMIT_EXCEEDED: Cannot process beyond 5 million per day.";
    };
};

LET $categories =['food', 'software', 'hardware', 'services'];

FOR $i IN 1..100000 {
    CREATE type::record('ledger', $i) CONTENT {
        amount: <decimal>($i % 100),
        category: $categories[$i % 4],
        created_at: time::now()
    };
};

-- RESULT
CREATE ledger:100008 SET amount = 999dec, category = 'food'; -- Fast insert (O(1))
CREATE ledger:100009 SET amount = -999dec, category = 'food'; -- Fast insert (O(1))
UPDATE ledger:1 SET amount = 50dec; -- Safe middle value update but grouped by scan (O(k))
UPDATE ledger:2 SET amount = 2000dec, category = 'food'; -- Pushing new max but grouped by category scan (O(K))
DELETE ledger:100009; -- TRAP: Deleting the MIN record. Forces O(N) scan.
UPDATE ledger:2 SET category = 'travel'; -- TRAP: Group migrating the MAX record. Forces O(N) scan.

-- CREATE ledger:100010 SET amount = 9999999dec, category = 'food'; -- Will trigger the Event THROW rollback

SELECT category, count(), math::sum(amount), math::mean(amount) FROM ledger GROUP BY category;
SELECT time::group(created_at, 'day') AS day, math::sum(amount) FROM ledger GROUP BY day;
SELECT category, math::min(amount), math::max(amount) FROM ledger GROUP BY category;

-- SELECT * FROM view_metrics;
-- SELECT * FROM view_daily;
-- SELECT * FROM view_min_max;

-- CRITICAL NOTE: Avoid min/max if possible in pre-computed view tables. While aggregates like count(), math::sum(), and math::mean() are true O(1) pure math deltas that scale infinitely, using min/max makes updates and deletes average case O(log N), and worst case O(N). If you delete or migrate the record holding the current min/max value, the engine natively pauses the transaction and drops into an O(N) fallback table scan to find the new boundary. Unsupported array aggregates (like array::distinct) will similarly trigger full O(N) recomputes.