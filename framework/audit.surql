-- Append-only operational history. These tables are deliberately outside the
-- compiler's ownership, reader, cascade, and reactive systems.
DEFINE TABLE OVERWRITE audit_mutation SCHEMAFULL PERMISSIONS NONE;
DEFINE FIELD OVERWRITE at ON audit_mutation TYPE datetime;
DEFINE FIELD OVERWRITE event ON audit_mutation TYPE string ASSERT $value IN ['CREATE', 'UPDATE', 'DELETE'];
DEFINE FIELD OVERWRITE table_name ON audit_mutation TYPE string;
DEFINE FIELD OVERWRITE target ON audit_mutation TYPE record;
DEFINE FIELD OVERWRITE actor ON audit_mutation TYPE option<record>;
DEFINE FIELD OVERWRITE changed_fields ON audit_mutation TYPE array<string> DEFAULT [];
DEFINE FIELD OVERWRITE before ON audit_mutation TYPE option<object> FLEXIBLE DEFAULT NONE;
DEFINE FIELD OVERWRITE after ON audit_mutation TYPE option<object> FLEXIBLE DEFAULT NONE;
DEFINE INDEX OVERWRITE idx_audit_mutation_target ON audit_mutation COLUMNS target;
