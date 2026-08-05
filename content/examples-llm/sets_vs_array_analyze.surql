REMOVE TABLE perf_test;
DEFINE TABLE perf_test SCHEMALESS;
    DEFINE FIELD tags ON perf_test TYPE array<int>;
    DEFINE FIELD tags_set ON perf_test TYPE set<int>;

    DEFINE INDEX idx_tags ON perf_test COLUMNS tags.*;

INSERT INTO perf_test (
    SELECT 
        tags, 
        type::set(tags) AS tags_set 
    FROM (
        SELECT (<array> 1..rand::int(20, 50)).map(|$x| rand::int(1, 1000)) AS tags 
        FROM (<array> 1..10000)
    )
) RETURN NONE;

CREATE perf_test:target_doc CONTENT { 
    tags: [500, 501, 502],
    tags_set: type::set([500, 501, 502])
} RETURN NONE;

SELECT count() AS total_records FROM perf_test GROUP ALL;
SELECT math::sum(array::len(tags)) AS total_index_keys FROM perf_test GROUP ALL;


-- PHASE 1: SINGLE ELEMENT SEARCH (Hit vs Miss) × (Left vs Right Syntax)
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE tags CONTAINS 500;
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE tags_set CONTAINS 500;

EXPLAIN ANALYZE SELECT id FROM perf_test WHERE 500 IN tags;
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE 500 IN tags_set;

EXPLAIN ANALYZE SELECT id FROM perf_test WHERE tags CONTAINS 9999;
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE tags_set CONTAINS 9999;

EXPLAIN ANALYZE SELECT id FROM perf_test WHERE 9999 IN tags;
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE 9999 IN tags_set;

-- [ Negative Matches ] (Both will fallback to TableScans)
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE tags CONTAINSNOT 500;
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE tags_set CONTAINSNOT 500;

EXPLAIN ANALYZE SELECT id FROM perf_test WHERE 9999 NOT IN tags;
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE 9999 NOT IN tags_set;


-- PHASE 2: MULTI-ELEMENT SUBSET EXACT (ALL / INSIDE)
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE tags CONTAINSALL [500, 501];
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE tags_set CONTAINSALL type::set([500, 501]);

EXPLAIN ANALYZE SELECT id FROM perf_test WHERE [500, 501] ALLINSIDE tags;
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE type::set([500, 501]) ALLINSIDE tags_set;

-- [ Target: Miss ]
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE tags CONTAINSALL [9998, 9999];
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE tags_set CONTAINSALL type::set([9998, 9999]);

-- [ Target: Mixed ]
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE [500, 9999] ALLINSIDE tags;
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE type::set([500, 9999]) ALLINSIDE tags_set;


-- PHASE 3: MULTI-ELEMENT INTERSECTION (ANY / ANYINSIDE)
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE tags CONTAINSANY [500, 501];
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE tags_set CONTAINSANY type::set([500, 501]);

-- [ Target: Miss ]
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE [9998, 9999] ANYINSIDE tags;
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE type::set([9998, 9999]) ANYINSIDE tags_set;


-- PHASE 4: NEGATIVE MULTI-ELEMENT (NONE / NONEINSIDE)
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE tags CONTAINSNONE [500, 501];
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE tags_set CONTAINSNONE type::set([500, 501]);

EXPLAIN ANALYZE SELECT id FROM perf_test WHERE [9998, 9999] NONEINSIDE tags;
EXPLAIN ANALYZE SELECT id FROM perf_test WHERE type::set([9998, 9999]) NONEINSIDE tags_set;


-- PHASE 5: SET ALGEBRA FUNCTIONS IN AST (TableScan Proofing)
-- Intersection (Equivalent to CONTAINSANY)
EXPLAIN ANALYZE SELECT id FROM perf_test 
WHERE array::len(array::intersect(tags, [500, 501])) > 0;

EXPLAIN ANALYZE SELECT id FROM perf_test 
WHERE set::intersect(tags_set, <set>[500, 501]).len() > 0;

-- Difference (Equivalent to CONTAINSALL)
EXPLAIN ANALYZE SELECT id FROM perf_test 
WHERE array::len(array::difference([500, 501], tags)) == 0;

EXPLAIN ANALYZE SELECT id FROM perf_test 
WHERE set::difference(<set>[500, 501], tags_set).len() == 0;

-- Complement / Union
EXPLAIN ANALYZE SELECT id FROM perf_test 
WHERE array::len(array::complement(tags, [500, 501])) > 0;

EXPLAIN ANALYZE SELECT id FROM perf_test 
WHERE set::union(tags_set, <set>[500, 501]).len() > 500;


-- PHASE 6: MUTATION B-TREE PENALTY (Append / Remove / Delete)
-- Append: Array creates a B-Tree Key; Set just mutates the record.
EXPLAIN ANALYZE UPDATE perf_test:target_doc SET tags += [7777];
EXPLAIN ANALYZE UPDATE perf_test:target_doc SET tags_set += [7777];

-- Remove: Array must search and delete a B-Tree Key; Set just mutates the record.
EXPLAIN ANALYZE UPDATE perf_test:target_doc SET tags -= [7777];
EXPLAIN ANALYZE UPDATE perf_test:target_doc SET tags_set -= [7777];

-- Delete: The DB must find and delete EVERY array item from the B-Tree index.
EXPLAIN ANALYZE DELETE perf_test:target_doc;



-- 1. Get the IDs once and cast to a Set (Instant O(1) lookup)
LET $exclude = type::set((SELECT VALUE id FROM perf_test WHERE tags CONTAINSANY [500, 501]));

-- 2. Do the negative check
EXPLAIN ANALYZE SELECT count() FROM perf_test WHERE id NOT IN $exclude group all;