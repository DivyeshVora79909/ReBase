USE NS main DB main;

-- Append-only operational history. These tables are deliberately outside the
-- compiler's ownership, reader, cascade, and reactive systems.
DEFINE TABLE audit_mutation SCHEMAFULL PERMISSIONS NONE;
DEFINE FIELD at ON audit_mutation TYPE datetime;
DEFINE FIELD event ON audit_mutation TYPE string ASSERT $value IN ['CREATE', 'UPDATE', 'DELETE'];
DEFINE FIELD table_name ON audit_mutation TYPE string;
DEFINE FIELD target ON audit_mutation TYPE record;
DEFINE FIELD actor ON audit_mutation TYPE option<record>;
DEFINE FIELD changed_fields ON audit_mutation TYPE array<string> DEFAULT [];
DEFINE FIELD before ON audit_mutation TYPE option<object> FLEXIBLE DEFAULT NONE;
DEFINE FIELD after ON audit_mutation TYPE option<object> FLEXIBLE DEFAULT NONE;
DEFINE INDEX idx_audit_mutation_target ON audit_mutation COLUMNS target;

DEFINE TABLE audit_action SCHEMAFULL PERMISSIONS NONE;
DEFINE FIELD at ON audit_action TYPE datetime;
DEFINE FIELD source ON audit_action TYPE string;
DEFINE FIELD action ON audit_action TYPE string;
DEFINE FIELD status ON audit_action TYPE string;
DEFINE FIELD actor ON audit_action TYPE option<record>;
DEFINE FIELD target ON audit_action TYPE option<record>;
DEFINE FIELD correlation ON audit_action TYPE option<string>;
DEFINE FIELD data ON audit_action TYPE object FLEXIBLE DEFAULT {};
DEFINE INDEX idx_audit_action_target ON audit_action COLUMNS target;
