REMOVE TABLE IF EXISTS test_set;
REMOVE TABLE IF EXISTS test_array;

DEFINE TABLE test_set SCHEMAFULL;
    DEFINE FIELD tags ON test_set TYPE set<string>;
    DEFINE INDEX idx_tags ON test_set COLUMNS tags.*; 

DEFINE TABLE test_array SCHEMAFULL;
    DEFINE FIELD tags ON test_array TYPE array<string>;
    DEFINE INDEX idx_tags_arr ON test_array COLUMNS tags.*;

LET $start_set = time::now();
INSERT INTO test_set (
    (<array> 1..=1000).map(|$i| {
        tags: <set> [ 
            "tag_A", 
            "tag_" + <string>($i % 100), 
            "tag_" + <string>($i % 100), -- Duplicate!
            "tag_" + <string>($i % 500) 
        ]
    })
);
LET $time_set_insert = time::now() - $start_set;
$time_set_insert;
-- 1000 records took 73ms
-- 10000 records took 500ms
-- 50000 records took 3s

LET $start_arr = time::now();
INSERT INTO test_array (
    (<array> 1..=1000).map(|$i| {
        tags: [ 
            "tag_A", 
            "tag_" + <string>($i % 100), 
            "tag_" + <string>($i % 100), -- Duplicate!
            "tag_" + <string>($i % 500) 
        ]
    })
);
LET $time_arr_insert = time::now() - $start_arr;
$time_arr_insert;
-- 1000 records took 55ms
-- 10000 records took 450ms
-- 50000 records took 2s800ms

-- ==============================================================================
-- 3. SEARCH EFFICIENCY BENCHMARK (O(log N) Indexed Lookup)
-- ==============================================================================
LET $start_search_set = time::now();
LET $res_set = (SELECT id FROM test_set WHERE tags CONTAINS 'tag_499');
LET $time_search_set = time::now() - $start_search_set;
$time_search_set;
-- 1000 records took 12ms
-- 10000 records took 90ms
-- 50000 records took 345ms

LET $start_search_arr = time::now();
LET $res_arr = (SELECT id FROM test_array WHERE tags CONTAINS 'tag_499');
LET $time_search_arr = time::now() - $start_search_arr;
$time_search_arr;
-- 1000 records took 25ms
-- 10000 records took 100ms
-- 50000 records took 360ms

-- ==============================================================================
-- 4. SET OPERATIONS (Union, Intersection, Difference)
-- ==============================================================================
LET $s1 = { "apple", "banana", "cherry" };
LET $s2 = { "banana", "dragonfruit", "apple" };

LET $intersect = array::intersect(<array>$s1, <array>$s2);
LET $diff = array::complement(<array>$s1, <array>$s2);
LET $union = <set> array::concat(<array>$s1, <array>$s2); 

-- ==============================================================================
-- 5. RESULTS EXPORT
-- ==============================================================================
RETURN {
    a_visual_proof: {
        set_example: (SELECT tags FROM test_set LIMIT 1)[0].tags,
        array_example: (SELECT tags FROM test_array LIMIT 1)[0].tags
    },
    b_benchmarks: {
        write_10k_sets: $time_set_insert,
        write_10k_arrays: $time_arr_insert,
        search_indexed_set: $time_search_set,
        search_indexed_array: $time_search_arr,
        records_found: array::len($res_set)
    },
    c_operations: {
        set_1: $s1,
        set_2: $s2,
        intersection: $intersect,
        difference: $diff,
        union: $union
    }
};

EXPLAIN SELECT id FROM test_set WHERE tags CONTAINS 'tag_499';
EXPLAIN SELECT id FROM test_arr WHERE tags CONTAINS 'tag_499';

-- when unindexed set and array:
"SelectProject [ctx: Db] [projections: id]\n    TableScan [ctx: Db] [table: test_set, direction: Forward, predicate: tags CONTAINS 'tag_499']\n";
"SelectProject [ctx: Db] [projections: id]\n    TableScan [ctx: Db] [table: test_arr, direction: Forward, predicate: tags CONTAINS 'tag_499']\n";
"
search_indexed_array: 37ms,
search_indexed_set: 40ms,
write_10k_arrays: 340ms,
write_10k_sets: 290ms
";
-- when indexed set and array:
"SelectProject [ctx: Db] [projections: id]\n    Filter [ctx: Db] [predicate: tags CONTAINS 'tag_499']\n        IndexScan [ctx: Db] [index: idx_tags, access: = 'tag_499', direction: Forward]\n";
"SelectProject [ctx: Db] [projections: id]\n    TableScan [ctx: Db] [table: test_arr, direction: Forward, predicate: tags CONTAINS 'tag_499']\n";
"
search_indexed_array: 30ms,
search_indexed_set: 32ms,
write_10k_arrays: 750ms,
write_10k_sets: 450ms
";

-- RESULT
-- DEDUCTION: IF REQUIREMENT IS UNIQUENESS AND UNORDERED, DON'T THINK JUST GO WITH THE INDEXED SET