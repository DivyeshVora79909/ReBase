DEFINE TABLE OVERWRITE activity SCHEMAFULL COMMENT '@rebase-members fn::analytics::members';
DEFINE FIELD OVERWRITE title ON activity TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit value';
DEFINE FIELD OVERWRITE points ON activity TYPE decimal DEFAULT 1dec ASSERT $value >= 0dec COMMENT '@rebase-audit value';
DEFINE FIELD OVERWRITE effective_at ON activity TYPE option<datetime> COMMENT '@rebase-audit value';
DEFINE FIELD OVERWRITE include_analytics ON activity TYPE bool DEFAULT true;

DEFINE FIELD OVERWRITE z_tenant_created ON activity TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner rebase_tenant.z_created @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_tenant_effective ON activity TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner rebase_tenant.z_effective @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_owner_created ON activity TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record,datetime @rebase-tree-owner rebase_tenant.z_owner_created @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_owned_created ON activity TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner rebase_tenant.z_owned_created @rebase-tree-owner rebase_user.z_owned_created @rebase-tree-owner rebase_group.z_owned_created @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_owned_effective ON activity TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner rebase_tenant.z_owned_effective @rebase-tree-owner rebase_user.z_owned_effective @rebase-tree-owner rebase_group.z_owned_effective @rebase-tree-no-reader';
DEFINE TABLE OVERWRITE annotation SCHEMAFULL COMMENT '@rebase-members fn::analytics::members';
DEFINE FIELD OVERWRITE title ON annotation TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit value';
DEFINE FIELD OVERWRITE points ON annotation TYPE decimal DEFAULT 1dec ASSERT $value >= 0dec COMMENT '@rebase-audit value';
DEFINE FIELD OVERWRITE effective_at ON annotation TYPE option<datetime> COMMENT '@rebase-audit value';
DEFINE FIELD OVERWRITE include_analytics ON annotation TYPE bool DEFAULT true;

DEFINE FIELD OVERWRITE z_tenant_created ON annotation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner rebase_tenant.z_created @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_tenant_effective ON annotation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner rebase_tenant.z_effective @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_owner_created ON annotation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key record,datetime @rebase-tree-owner rebase_tenant.z_owner_created @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_owned_created ON annotation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner rebase_tenant.z_owned_created @rebase-tree-owner rebase_user.z_owned_created @rebase-tree-owner rebase_group.z_owned_created @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_owned_effective ON annotation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner rebase_tenant.z_owned_effective @rebase-tree-owner rebase_user.z_owned_effective @rebase-tree-owner rebase_group.z_owned_effective @rebase-tree-no-reader';

-- All points share one declared unit. Measures never come from another root's
-- subtotal; each source contributes its own value exactly once per index.
DEFINE FUNCTION OVERWRITE fn::analytics::members($row: object) {
    IF !$row.include_analytics { RETURN []; };
    LET $measure = { points: $row.points };
    RETURN [
        fn::tree::ordered_member($row.id, 'z_tenant_created', $row.tenant,
            'z_created', [$row.created_at], $measure, {}),
        IF $row.effective_at = NONE THEN NONE ELSE
            fn::tree::ordered_member($row.id, 'z_tenant_effective', $row.tenant,
                'z_effective', [$row.effective_at], $measure, {}) END,
        fn::tree::ordered_member($row.id, 'z_owner_created', $row.tenant,
            'z_owner_created', [$row.owned_by, $row.created_at], $measure, {}),
        fn::tree::ordered_member($row.id, 'z_owned_created', $row.owned_by,
            'z_owned_created', [$row.created_at], $measure, {}),
        IF $row.effective_at = NONE THEN NONE ELSE
            fn::tree::ordered_member($row.id, 'z_owned_effective', $row.owned_by,
                'z_owned_effective', [$row.effective_at], $measure, {}) END
    ];
} PERMISSIONS NONE;

