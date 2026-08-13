USE NS main DB main;

-- Keep credentials and environment-specific bootstrap records outside compiled schemas.

-- API-owned external context. This table is intentionally outside ReBase's
-- ownership, permissions, audit, and reactivity systems.
DEFINE TABLE api_context SCHEMAFULL PERMISSIONS NONE;
DEFINE FIELD contract ON api_context TYPE string;
DEFINE FIELD name ON api_context TYPE string;
DEFINE FIELD context ON api_context TYPE string;
DEFINE FIELD scope ON api_context TYPE option<string>;
DEFINE FIELD key ON api_context TYPE string;
DEFINE FIELD kind ON api_context TYPE string;
DEFINE FIELD table ON api_context TYPE string DEFAULT ""
    ASSERT $value = "" OR $value IN object::keys((INFO FOR DB).tables);
DEFINE FIELD owned_by ON api_context TYPE option<record<user | groups>>
    REFERENCE ON DELETE REJECT;
DEFINE FIELD reject_ref ON api_context TYPE option<record> REFERENCE ON DELETE REJECT;
DEFINE FIELD cascade_ref ON api_context TYPE option<record> REFERENCE ON DELETE CASCADE;
DEFINE FIELD cascade_refs ON api_context TYPE option<array<record>> REFERENCE ON DELETE CASCADE;
DEFINE FIELD data ON api_context TYPE object FLEXIBLE DEFAULT {};
DEFINE FIELD revision ON api_context TYPE uuid VALUE rand::uuid::v7();

DEFINE INDEX idx_api_context_contract ON api_context COLUMNS contract UNIQUE;
DEFINE INDEX idx_api_context_name ON api_context COLUMNS name;
DEFINE INDEX idx_api_context_table ON api_context COLUMNS table;
DEFINE INDEX idx_api_context_owned_by ON api_context COLUMNS owned_by;
