REMOVE TABLE IF EXISTS sales;
REMOVE TABLE IF EXISTS v_sales_2025;
REMOVE TABLE IF EXISTS v_sales_2026;

DEFINE TABLE sales SCHEMAFULL;
    DEFINE FIELD category ON sales TYPE string ASSERT $value IN ['electronics', 'clothing'];
    DEFINE FIELD amount ON sales TYPE decimal;
    DEFINE FIELD sold_at ON sales TYPE datetime;

-- PARTITION 2025
DEFINE TABLE v_sales_2025 AS 
    SELECT 
        category, 
        time::group(sold_at, 'month') AS sales_month, 
        math::sum(amount) AS total_amount,
        count() AS total_items
    FROM sales 
    WHERE sold_at >= d"2025-01-01T00:00:00Z" 
      AND sold_at <  d"2026-01-01T00:00:00Z"
    GROUP BY category, sales_month;

-- PARTITION 2026
DEFINE TABLE v_sales_2026 AS 
    SELECT 
        category, 
        time::group(sold_at, 'month') AS sales_month, 
        math::sum(amount) AS total_amount,
        count() AS total_items
    FROM sales 
    WHERE sold_at >= d"2026-01-01T00:00:00Z" 
      AND sold_at <  d"2027-01-01T00:00:00Z"
    GROUP BY category, sales_month;


-- TEST 1: INSERTIONS
CREATE sales:1 SET category = 'electronics', amount = 100dec, sold_at = d"2025-05-10T10:00:00Z";
CREATE sales:2 SET category = 'electronics', amount = 200dec, sold_at = d"2025-05-15T10:00:00Z";
CREATE sales:3 SET category = 'clothing',    amount = 50dec,  sold_at = d"2025-11-20T10:00:00Z";

CREATE sales:4 SET category = 'electronics', amount = 500dec, sold_at = d"2026-01-05T10:00:00Z";
CREATE sales:5 SET category = 'clothing',    amount = 300dec, sold_at = d"2026-05-23T10:00:00Z";

SELECT '2025 INITIAL' AS step, * FROM v_sales_2025 ORDER BY sales_month, category;
SELECT '2026 INITIAL' AS step, * FROM v_sales_2026 ORDER BY sales_month, category;

-- TEST 2: BOUNDARY CROSSING
UPDATE sales:1 SET sold_at = d"2026-05-10T10:00:00Z";

SELECT '2025 AFTER TIME TRAVEL' AS step, * FROM v_sales_2025 ORDER BY sales_month, category;
SELECT '2026 AFTER TIME TRAVEL' AS step, * FROM v_sales_2026 ORDER BY sales_month, category;

-- TEST 3: DELETION AND CATEGORY SHIFT
DELETE sales:4;
UPDATE sales:5 SET category = 'electronics';

SELECT '2026 AFTER DELETE & CATEGORY SHIFT' AS step, * FROM v_sales_2026 ORDER BY sales_month, category;