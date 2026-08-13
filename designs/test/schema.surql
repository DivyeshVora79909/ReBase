USE NS main DB main;

-- 1. SYSTEM TABLES (Reactivity Registration via Lateral Data Links)
DEFINE TABLE user SCHEMAFULL;
DEFINE FIELD a_favorite_primitive ON user TYPE option<record<test_primitive>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_friends ON user TYPE array<record<user>> DEFAULT [];
DEFINE FIELD a_watched_items ON user TYPE option<array<record<test_primitive | test_tree>>> DEFAULT NONE;

DEFINE TABLE groups SCHEMAFULL;
DEFINE FIELD a_associated_primitive ON groups TYPE option<record<test_primitive>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_partner_groups ON groups TYPE array<record<groups>> DEFAULT [];

-- 2. PRIMITIVES & ENUMS (The Stateless Leaves)
DEFINE TABLE test_primitive SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_string ON test_primitive TYPE string;
DEFINE FIELD a_int ON test_primitive TYPE int DEFAULT 0;
DEFINE FIELD a_decimal ON test_primitive TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD a_bool ON test_primitive TYPE bool DEFAULT false;
DEFINE FIELD a_datetime ON test_primitive TYPE datetime DEFAULT time::now();
DEFINE FIELD a_object ON test_primitive TYPE object DEFAULT {};
DEFINE FIELD a_enum ON test_primitive TYPE string ASSERT $value IN ['pending', 'active', 'archived'] DEFAULT 'pending';



-- 3. RELATIONAL PERMUTATIONS (Edges, Arrays, and Polymorphism)
DEFINE TABLE test_relation SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_primitive ON test_relation TYPE record<test_primitive> REFERENCE ON DELETE CASCADE;
DEFINE FIELD a_polymorphic ON test_relation TYPE option<record<test_primitive | user>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_primitive_array ON test_relation TYPE array<record<test_primitive>> DEFAULT [];
DEFINE FIELD a_poly_array ON test_relation TYPE option<array<record<test_primitive | groups>>> DEFAULT NONE;


-- 4. MULTI-RELATION (Multiple FKs from ONE table to ONE target)
DEFINE TABLE test_multiref SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_name ON test_multiref TYPE string;
DEFINE FIELD a_creator ON test_multiref TYPE record<user> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_reviewer ON test_multiref TYPE option<record<user>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_approver ON test_multiref TYPE option<record<user>> REFERENCE ON DELETE REJECT DEFAULT NONE;
DEFINE FIELD a_owning_group ON test_multiref TYPE record<groups> REFERENCE ON DELETE REJECT;
DEFINE FIELD a_auditing_group ON test_multiref TYPE option<record<groups>> REFERENCE ON DELETE REJECT DEFAULT NONE;


-- 5. TREE / SELF-REFERENTIAL (Recursive DAG)
DEFINE TABLE test_tree SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD a_name ON test_tree TYPE string;
DEFINE FIELD a_parent ON test_tree TYPE option<record<test_tree>> REFERENCE ON DELETE CASCADE DEFAULT NONE;
DEFINE FIELD a_related_nodes ON test_tree TYPE array<record<test_tree>> DEFAULT [];

DEFINE FIELD e_guard ON test_tree TYPE bool VALUE {
    IF $this.a_parent = $this.id {
        THROW "TOPOLOGY_ERR: A node cannot be its own parent.";
    };
    RETURN true;
} ASSERT $value = true;
