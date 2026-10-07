-- Explicit design analytics. Adding these fields alone enrolls no records.
-- Tenant-wide aggregates are private; owner aggregates follow the principal.
DEFINE FIELD OVERWRITE z_created ON rebase_tenant TYPE object PERMISSIONS NONE
    COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_effective ON rebase_tenant TYPE object PERMISSIONS NONE
    COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_owner_created ON rebase_tenant TYPE object PERMISSIONS NONE
    COMMENT '@rebase-tree-root @rebase-tree-key record,datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_owned_created ON rebase_tenant TYPE object PERMISSIONS NONE
    COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_owned_effective ON rebase_tenant TYPE object PERMISSIONS NONE
    COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_owned_created ON rebase_user TYPE object PERMISSIONS FOR select WHERE $auth != NONE AND fn::rebase::can_access($auth, id)
    COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_owned_effective ON rebase_user TYPE object PERMISSIONS FOR select WHERE $auth != NONE AND fn::rebase::can_access($auth, id)
    COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_owned_created ON rebase_group TYPE object PERMISSIONS FOR select WHERE $auth != NONE AND fn::rebase::can_access($auth, id)
    COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
DEFINE FIELD OVERWRITE z_owned_effective ON rebase_group TYPE object PERMISSIONS FOR select WHERE $auth != NONE AND fn::rebase::can_access($auth, id)
    COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
