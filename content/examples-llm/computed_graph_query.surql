REMOVE TABLE IF EXISTS grandparent;
REMOVE TABLE IF EXISTS parent;
REMOVE TABLE IF EXISTS child;
REMOVE TABLE IF EXISTS v_child_totals;
REMOVE TABLE IF EXISTS v_gp_status_totals;

DEFINE TABLE grandparent SCHEMAFULL;
DEFINE FIELD name ON grandparent TYPE string;
DEFINE FIELD c_status_totals ON grandparent COMPUTED (SELECT * FROM v_gp_status_totals WHERE gp = $parent.id) OR [];
-- DEFINE FIELD c_status_totals ON grandparent COMPUTED (SELECT * FROM v_gp_status_totals WHERE record::id(id) CONTAINS grandparent:one) OR [];

DEFINE TABLE parent SCHEMAFULL;
DEFINE FIELD gp ON parent TYPE record<grandparent> REFERENCE ON DELETE CASCADE;
DEFINE FIELD name ON parent TYPE string;
DEFINE FIELD status ON parent TYPE string ASSERT $value IN ['active', 'inactive'];
DEFINE FIELD c_totals ON parent COMPUTED type::record('v_child_totals', [id]) OR { amount: 0dec, qty: 0dec };

DEFINE TABLE child SCHEMAFULL;
DEFINE FIELD parent ON child TYPE record<parent> REFERENCE ON DELETE CASCADE;
DEFINE FIELD amount ON child TYPE decimal;
DEFINE FIELD qty ON child TYPE decimal;

DEFINE TABLE v_child_totals AS 
    SELECT 
        parent, 
        math::sum(amount) AS amount, 
        math::sum(qty) AS qty 
    FROM child 
    GROUP BY parent;

DEFINE TABLE v_gp_status_totals AS 
    SELECT 
        parent.gp AS gp, 
        parent.status AS status, 
        math::sum(amount) AS total_amount 
    FROM child 
    GROUP BY gp, status;

CREATE grandparent:one SET name = "The Patriarch";

CREATE parent:active_1 SET gp = grandparent:one, name = "Active Parent", status = "active";
CREATE parent:inactive_1 SET gp = grandparent:one, name = "Inactive Parent", status = "inactive";

INSERT INTO child [
    { id: child:1, parent: parent:active_1, amount: 100dec, qty: 2dec },
    { id: child:2, parent: parent:active_1, amount: 150dec, qty: 3dec },
    
    { id: child:3, parent: parent:inactive_1, amount: 500dec, qty: 1dec },
    { id: child:4, parent: parent:inactive_1, amount: 200dec, qty: 1dec }
];


SELECT id, name, c_totals.* FROM parent:active_1;
SELECT id, name, c_status_totals FROM grandparent:one;
SELECT id, amount FROM grandparent:one<~parent<~child;
