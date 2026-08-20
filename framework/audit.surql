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

-- Small, client-facing state history for fields marked with
-- @rebase-change-log. This is independent from table-level mutation audit.
-- Framework targets use the existing node_select permission; business targets
-- use the select permission named by the target table. Deleted targets fail the
-- existence check and therefore expose no historical row to record users.
DEFINE TABLE change_logs SCHEMAFULL PERMISSIONS
    FOR select WHERE record::exists(target)
        AND (
            IF record::tb(target) IN ['user', 'groups'] 
            THEN 'node_select'
            ELSE string::concat(record::tb(target), '_select')
            END
        ) IN $auth.permissions
        AND <string>(
            IF record::tb(target) IN ['user', 'groups']
            THEN target
            ELSE target.owned_by
            END
        ) IN $auth.z_access_index
    FOR create, update, delete NONE;
DEFINE FIELD at ON change_logs TYPE datetime;
DEFINE FIELD table_name ON change_logs TYPE string;
DEFINE FIELD target ON change_logs TYPE record;
DEFINE FIELD actor ON change_logs TYPE option<record>;
DEFINE FIELD before ON change_logs TYPE object FLEXIBLE;
DEFINE INDEX idx_change_logs_target_at ON change_logs COLUMNS target, at;
