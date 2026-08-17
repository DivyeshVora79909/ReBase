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
DEFINE FIELD a_primitive_array ON test_relation TYPE array<record<test_primitive>> DEFAULT [] REFERENCE ON DELETE IGNORE
    COMMENT '@rebase-readers';
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
DEFINE FIELD a_related_nodes ON test_tree TYPE array<record<test_tree>> DEFAULT [] REFERENCE ON DELETE IGNORE
    COMMENT '@rebase-readers';

DEFINE FIELD e_guard ON test_tree TYPE bool VALUE {
    IF $this.a_parent = $this.id {
        THROW "TOPOLOGY_ERR: A node cannot be its own parent.";
    };
    RETURN true;
} ASSERT $value = true;

-- 6. NATIVE EXTERNAL RESOURCE TABLES
DEFINE TABLE email_brevo_config SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD label ON email_brevo_config TYPE string;
DEFINE FIELD visibility ON email_brevo_config TYPE bool DEFAULT false;
DEFINE FIELD technical_owner ON email_brevo_config TYPE option<record<user | groups>> DEFAULT NONE REFERENCE ON DELETE REJECT;
DEFINE FIELD from_email ON email_brevo_config TYPE string ASSERT string::is_email($value);
DEFINE FIELD from_name ON email_brevo_config TYPE string;
DEFINE FIELD reply_to ON email_brevo_config TYPE option<string> DEFAULT NONE ASSERT $value = NONE OR string::is_email($value);
DEFINE FIELD api_secret_ref ON email_brevo_config TYPE string
    PERMISSIONS FOR select NONE FOR create, update WHERE true
    COMMENT '@rebase-audit-redact';
DEFINE FIELD compliance_note ON email_brevo_config TYPE option<string> DEFAULT NONE
    PERMISSIONS FOR select NONE FOR create, update WHERE true
    COMMENT '@rebase-audit-redact';
DEFINE FIELD sending_enabled ON email_brevo_config TYPE bool DEFAULT false;
DEFINE FIELD account_key ON email_brevo_config TYPE string READONLY;
DEFINE FIELD last_verified_at ON email_brevo_config TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE;

DEFINE TABLE email_campaign_profile SCHEMAFULL COMMENT '@rebase-audit';
DEFINE FIELD profile_key ON email_campaign_profile TYPE string READONLY;
DEFINE FIELD name ON email_campaign_profile TYPE string;
DEFINE FIELD visibility ON email_campaign_profile TYPE bool DEFAULT false;
DEFINE FIELD config ON email_campaign_profile TYPE record<email_brevo_config> REFERENCE ON DELETE REJECT;
DEFINE FIELD fallback_config ON email_campaign_profile TYPE option<record<email_brevo_config>> DEFAULT NONE REFERENCE ON DELETE IGNORE;
DEFINE FIELD parent_profile ON email_campaign_profile TYPE option<record<email_campaign_profile>> DEFAULT NONE REFERENCE ON DELETE CASCADE;
DEFINE FIELD related_profiles ON email_campaign_profile TYPE array<record<email_campaign_profile>> DEFAULT [] REFERENCE ON DELETE IGNORE
    COMMENT '@rebase-readers';
DEFINE FIELD reviewer ON email_campaign_profile TYPE option<record<user | groups>> DEFAULT NONE REFERENCE ON DELETE REJECT;
DEFINE FIELD subject ON email_campaign_profile TYPE string;
DEFINE FIELD html ON email_campaign_profile TYPE string;
DEFINE FIELD text ON email_campaign_profile TYPE option<string> DEFAULT NONE;
DEFINE FIELD recipients ON email_campaign_profile TYPE array<string> ASSERT array::all($value, |$email| string::is_email($email));
DEFINE FIELD delivery_count ON email_campaign_profile TYPE int DEFAULT 0
    PERMISSIONS FOR select WHERE true FOR create, update NONE;
