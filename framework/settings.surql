USE NS main DB main;

-- Scoped Configuration Registry
-- Flexible values belong here; relations and queryable business state do not.
DEFINE TABLE setting SCHEMAFULL;

DEFINE FIELD scope ON setting TYPE record
    REFERENCE ON DELETE CASCADE
    READONLY
    PERMISSIONS
        FOR select WHERE true
        FOR create WHERE
            $value = $auth
            OR $value IN $auth.parents
            OR $value IN $auth.dominates
            OR ($value.readers_index ?? []) CONTAINSANY $auth.z_access_index
        FOR update NONE;

DEFINE FIELD key ON setting TYPE string
    READONLY
    VALUE string::lowercase(string::trim($value))
    ASSERT string::len($value) > 0
        AND string::len($value) <= 80
        AND $value = string::slug($value);

DEFINE FIELD schema_version ON setting TYPE int DEFAULT 1 ASSERT $value > 0;
DEFINE FIELD enabled ON setting TYPE bool DEFAULT true;
DEFINE FIELD values ON setting TYPE object FLEXIBLE DEFAULT {};

-- Record users may write secrets through normal table RLS but can never read them.
-- System users used by trusted edge actions can read them after an RLS authorization probe.
DEFINE FIELD secrets ON setting TYPE object FLEXIBLE DEFAULT {}
    PERMISSIONS
        FOR select NONE
        FOR create WHERE true
        FOR update WHERE true;

DEFINE INDEX setting_scope_key ON setting FIELDS scope, key UNIQUE;
