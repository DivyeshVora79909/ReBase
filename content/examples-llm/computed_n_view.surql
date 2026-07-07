REMOVE TABLE IF EXISTS grandparent;
REMOVE TABLE IF EXISTS parent;
REMOVE TABLE IF EXISTS child;
REMOVE TABLE IF EXISTS v_parent_wealth;
REMOVE TABLE IF EXISTS v_parent_categories;

DEFINE TABLE grandparent SCHEMAFULL;
    DEFINE FIELD name ON grandparent TYPE string;
    DEFINE FIELD recursive_wealth ON grandparent TYPE decimal COMPUTED math::sum((<~parent).total_wealth) OR 0dec;
    DEFINE FIELD view_backed_wealth ON grandparent TYPE decimal COMPUTED math::sum((<~parent).view_total) OR 0dec;

DEFINE TABLE parent SCHEMAFULL;
    DEFINE FIELD grandparent ON parent TYPE record<grandparent> REFERENCE;
    DEFINE FIELD name ON parent TYPE string;
    DEFINE FIELD total_wealth ON parent TYPE decimal COMPUTED math::sum((<~child).amount) OR 0dec; -- RUN TIME
    DEFINE FIELD unique_categories ON parent TYPE array COMPUTED array::distinct((<~child).category) OR []; -- RUN TIME
    DEFINE FIELD view_total ON parent TYPE decimal COMPUTED (type::record('v_parent_wealth', [id])).total_wealth OR 0dec; -- VIEW
    DEFINE FIELD z_base_val ON parent TYPE decimal VALUE 100dec;
    DEFINE FIELD a_relies_on_z ON parent TYPE decimal COMPUTED z_base_val * 2dec;

DEFINE TABLE child SCHEMAFULL;
    DEFINE FIELD parent ON child TYPE record<parent> REFERENCE ON DELETE CASCADE;
    DEFINE FIELD amount ON child TYPE decimal;
    DEFINE FIELD category ON child TYPE string;

DEFINE TABLE v_parent_wealth AS 
    SELECT parent, math::sum(amount) AS total_wealth 
    FROM child GROUP BY parent;

DEFINE TABLE v_parent_categories AS 
    SELECT parent, category, count() AS total_items 
    FROM child GROUP BY parent, category;


CREATE grandparent:1 SET name = "The Patriarch";
CREATE parent:1k   SET grandparent = grandparent:1, name = "1,000 Children";
CREATE parent:10k  SET grandparent = grandparent:1, name = "10,000 Children";
CREATE parent:50k  SET grandparent = grandparent:1, name = "50,000 Children";

INSERT INTO child ( (<array> 1..=1000).map(|$i| { parent: parent:1k, amount: 10dec, category: "CAT_" + <string>($i % 10) }) );

INSERT INTO child ( (<array> 1..=1000).map(|$i| { parent: parent:10k, amount: 10dec, category: "CAT_" + <string>($i % 100) }) );
INSERT INTO child ( (<array> 1001..=2000).map(|$i| { parent: parent:10k, amount: 10dec, category: "CAT_" + <string>($i % 100) }) );
INSERT INTO child ( (<array> 2001..=3000).map(|$i| { parent: parent:10k, amount: 10dec, category: "CAT_" + <string>($i % 100) }) );
INSERT INTO child ( (<array> 3001..=4000).map(|$i| { parent: parent:10k, amount: 10dec, category: "CAT_" + <string>($i % 100) }) );
INSERT INTO child ( (<array> 4001..=5000).map(|$i| { parent: parent:10k, amount: 10dec, category: "CAT_" + <string>($i % 100) }) );
INSERT INTO child ( (<array> 5001..=6000).map(|$i| { parent: parent:10k, amount: 10dec, category: "CAT_" + <string>($i % 100) }) );
INSERT INTO child ( (<array> 6001..=7000).map(|$i| { parent: parent:10k, amount: 10dec, category: "CAT_" + <string>($i % 100) }) );
INSERT INTO child ( (<array> 7001..=8000).map(|$i| { parent: parent:10k, amount: 10dec, category: "CAT_" + <string>($i % 100) }) );
INSERT INTO child ( (<array> 8001..=9000).map(|$i| { parent: parent:10k, amount: 10dec, category: "CAT_" + <string>($i % 100) }) );
INSERT INTO child ( (<array> 9001..=10000).map(|$i| { parent: parent:10k, amount: 10dec, category: "CAT_" + <string>($i % 100) }) );

INSERT INTO child ( (<array> 1..=1000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 1001..=2000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 2001..=3000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 3001..=4000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 4001..=5000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 5001..=6000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 6001..=7000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 7001..=8000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 8001..=9000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 9001..=10000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 10001..=11000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 11001..=12000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 12001..=13000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 13001..=14000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 14001..=15000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 15001..=16000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 16001..=17000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 17001..=18000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 18001..=19000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 19001..=20000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 20001..=21000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 21001..=22000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 22001..=23000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 23001..=24000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 24001..=25000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 25001..=26000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 26001..=27000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 27001..=28000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 28001..=29000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 29001..=30000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 30001..=31000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 31001..=32000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 32001..=33000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 33001..=34000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 34001..=35000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 35001..=36000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 36001..=37000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 37001..=38000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 38001..=39000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 39001..=40000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 40001..=41000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 41001..=42000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 42001..=43000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 43001..=44000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 44001..=45000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 45001..=46000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 46001..=47000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 47001..=48000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 48001..=49000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );
INSERT INTO child ( (<array> 49001..=50000).map(|$i| { parent: parent:50k, amount: 10dec, category: "CAT_" + <string>($i % 500) }) );


SELECT parent, count() FROM child GROUP BY parent; --600ms
SELECT a_relies_on_z FROM parent:1k; --100ms
SELECT math::sum((<~child).amount) AS raw_total FROM parent:50k; --10k: 450ms 50k: 2.9s
SELECT total_wealth FROM parent:50k; --10k: 380ms 50k 2.1s
SELECT unique_categories FROM parent:50k; --50k: 2.1s
SELECT unique_categories FROM parent:50k;  --50k: 2.1s
SELECT recursive_wealth, view_backed_wealth FROM grandparent:1; --4.5s
SELECT view_total FROM parent:1k; -- 70ms
SELECT view_total FROM parent; -- 2.3s
SELECT * FROM v_parent_categories;
SELECT * FROM v_parent_wealth;

"
{ recursive_wealth: 610000dec, view_backed_wealth: 610000dec }
COMPUTED fields are optimised and execute only when they are explicitly selected
For reads COMPUTED fields surpass regular queries even during recursions but for scale more than 20000 pre computed view tables are better.
"
