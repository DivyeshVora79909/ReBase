-- 1. SYSTEM TABLE VIEWS (Testing reactivity upward from custom data to system)
DEFINE TABLE OVERWRITE v_user_fav_prim AS 
    SELECT a_favorite_primitive AS primitive, count() AS total_users 
    FROM rebase_user GROUP BY primitive;

-- Group rebase_group by their associated primitive
DEFINE TABLE OVERWRITE v_group_assoc AS 
    SELECT a_associated_primitive AS primitive, count() AS total_groups 
    FROM rebase_group GROUP BY primitive;


-- 2. CUSTOM DATA VIEWS (Topological reductions)
-- Aggregating from Single Relation
DEFINE TABLE OVERWRITE v_test_prim AS 
    SELECT a_primitive AS target, count() AS total_relations, math::sum(a_primitive.a_decimal) AS sum_decimals 
    FROM test_relation GROUP BY target;

-- Aggregating from Polymorphic Relation (Will trigger pings on both primitive and rebase_user)
DEFINE TABLE OVERWRITE v_test_poly AS 
    SELECT a_polymorphic AS target, count() AS total_links 
    FROM test_relation GROUP BY target;

-- Aggregating from Multiple References pointing to the same table
DEFINE TABLE OVERWRITE v_test_creator AS 
    SELECT a_creator AS rebase_user, count() AS items_created FROM test_multiref GROUP BY rebase_user;

DEFINE TABLE OVERWRITE v_test_reviewer AS 
    SELECT a_reviewer AS rebase_user, count() AS items_reviewed FROM test_multiref GROUP BY rebase_user;

DEFINE TABLE OVERWRITE v_test_auditor AS 
    SELECT a_auditing_group AS audit_group, count() AS items_audited FROM test_multiref GROUP BY audit_group;

-- Tree Parent-Child Subtotals (Self-Referential Shadow State)
DEFINE TABLE OVERWRITE v_test_tree_children AS 
    SELECT a_parent AS parent_node, count() AS direct_children 
    FROM test_tree GROUP BY parent_node;
