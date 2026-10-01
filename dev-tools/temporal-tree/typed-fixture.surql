-- Compiled contract fixture: immutable stage scales, independent time and rank
-- memberships, two exact rank-owner pairs and two source-slot pairs.
DEFINE TABLE OVERWRITE rebase_user SCHEMAFULL ;
DEFINE TABLE OVERWRITE rebase_group SCHEMAFULL ;

DEFINE TABLE OVERWRITE stage_scale SCHEMAFULL;
DEFINE FIELD OVERWRITE a_name ON stage_scale TYPE string READONLY;
DEFINE FIELD OVERWRITE a_version ON stage_scale TYPE number READONLY
    ASSERT type::is_int($value) AND $value >= 1 AND $value <= 9007199254740991;
DEFINE INDEX OVERWRITE scale_version ON stage_scale FIELDS a_name, a_version UNIQUE;

DEFINE TABLE OVERWRITE stage_code SCHEMAFULL;
DEFINE FIELD OVERWRITE a_scale ON stage_code TYPE record<stage_scale> REFERENCE ON DELETE REJECT READONLY;
-- Guard BEFORE int storage: SurrealDB 3.2.0 can abort on fractional option<int>.
DEFINE FIELD OVERWRITE a_code ON stage_code TYPE number READONLY
    ASSERT fn::tree::valid_key([$value], 'int', false);
DEFINE FIELD OVERWRITE a_label ON stage_code TYPE string READONLY;
DEFINE INDEX OVERWRITE stage_identity ON stage_code FIELDS a_scale, a_code UNIQUE;

DEFINE TABLE OVERWRITE stage_board SCHEMAFULL COMMENT '@rebase-validate fn::typed::owner';
DEFINE FIELD OVERWRITE visibility ON stage_board TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE a_scale ON stage_board TYPE record<stage_scale> REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD OVERWRITE a_limit ON stage_board TYPE number DEFAULT 100
    ASSERT type::is_int($value) AND $value >= 0;
DEFINE FIELD OVERWRITE rb_history ON stage_board TYPE object
    COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE rb_rank ON stage_board TYPE object
    COMMENT '@rebase-tree-root @rebase-tree-key int';

DEFINE TABLE OVERWRITE stage_archive SCHEMAFULL COMMENT '@rebase-validate fn::typed::owner';
DEFINE FIELD OVERWRITE visibility ON stage_archive TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE a_scale ON stage_archive TYPE record<stage_scale> REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD OVERWRITE a_limit ON stage_archive TYPE number DEFAULT 100
    ASSERT type::is_int($value) AND $value >= 0;
DEFINE FIELD OVERWRITE rb_priority ON stage_archive TYPE object
    COMMENT '@rebase-tree-root @rebase-tree-key int';

DEFINE FUNCTION OVERWRITE fn::typed::owner($row: object) {
    LET $s = ($row.rb_rank ?? $row.rb_priority).summary;
    IF $s.count > $row.a_limit { THROW 'TYPED_OWNER_LIMIT'; };
    IF $s.tags.scale != NONE AND (!$s.tags.scale.uniform OR $s.tags.scale.value != $row.a_scale) {
        THROW 'TYPED_SCALE_MISMATCH';
    };
    -- A constant-sized guard covers source edits AND owner policy edits.
    -- Table/field publication permissions remain an explicit domain policy.
    FOR $summary IN [$s, $row.rb_history.summary].filter(|$value| $value != NONE AND $value.count > 0) {
        IF !$summary.tags.scope.uniform OR $summary.tags.scope.value != $row.owned_by
            OR !$summary.tags.visible.uniform OR $summary.tags.visible.value != $row.visibility {
            THROW 'TYPED_READ_SCOPE';
        };
    };
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE stage_fact SCHEMAFULL
    COMMENT '@rebase-members fn::typed::members @rebase-validate fn::typed::fact';
DEFINE FIELD OVERWRITE visibility ON stage_fact TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE a_history ON stage_fact TYPE option<record<stage_board>> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_ranking ON stage_fact TYPE option<record<stage_board | stage_archive>> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_stage ON stage_fact TYPE option<record<stage_code>> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_effective_at ON stage_fact TYPE option<datetime>;
DEFINE FIELD OVERWRITE a_weight ON stage_fact TYPE decimal DEFAULT 1dec;
DEFINE FIELD OVERWRITE z10_scale ON stage_fact TYPE option<record<stage_scale>> REFERENCE ON DELETE REJECT
    VALUE $this.a_stage.a_scale COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z20_code ON stage_fact TYPE option<number> VALUE $this.a_stage.a_code
    ASSERT $value = NONE OR fn::tree::valid_key([$value], 'int', false) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE rb_history ON stage_fact TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stage_board.rb_history';
DEFINE FIELD OVERWRITE rb_rank ON stage_fact TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner stage_board.rb_rank @rebase-tree-owner stage_archive.rb_priority';

DEFINE FUNCTION OVERWRITE fn::typed::members($row: object) {
    LET $scope = { scope: $row.owned_by, visible: $row.visibility };
    RETURN [
        IF $row.a_effective_at = NONE THEN NONE ELSE
            fn::tree::member($row.id, 'rb_history', $row.a_history, 'rb_history', $row.a_effective_at,
                { weight: $row.a_weight }, $scope, { occurred: $row.a_effective_at }, false) END,
        IF $row.a_ranking = NONE THEN NONE ELSE fn::tree::int_member($row.id, 'rb_rank', $row.a_ranking,
            IF record::tb($row.a_ranking) = 'stage_archive' THEN 'rb_priority' ELSE 'rb_rank' END,
            $row.z20_code, { weight: $row.a_weight }, object::extend($scope, { scale: $row.z10_scale })) END
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::typed::fact($row: object) {
    IF $row.a_stage != NONE AND $row.a_history != NONE AND $row.z10_scale != $row.a_history.a_scale {
        THROW 'TYPED_SCALE_MISMATCH';
    };
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE archive_fact SCHEMAFULL COMMENT '@rebase-members fn::typed::archive';
DEFINE FIELD OVERWRITE visibility ON archive_fact TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE a_owner ON archive_fact TYPE record<stage_archive> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_code ON archive_fact TYPE option<number>
    ASSERT $value = NONE OR fn::tree::valid_key([$value], 'int', false);
DEFINE FIELD OVERWRITE rb_archive ON archive_fact TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner stage_archive.rb_priority';
DEFINE FUNCTION OVERWRITE fn::typed::archive($row: object) {
    RETURN [fn::tree::int_member($row.id, 'rb_archive', $row.a_owner, 'rb_priority',
        $row.a_code, { weight: 1dec }, { scale: $row.a_owner.a_scale, scope: $row.owned_by, visible: $row.visibility })];
} PERMISSIONS NONE;

-- Explicit publication examples. Hidden and conditional roots retain their
-- field policies. rb_public deliberately publishes an aggregate of private
-- slots; native traversal must still refuse those slots to ordinary readers.
DEFINE TABLE OVERWRITE private_board SCHEMAFULL;
DEFINE FIELD OVERWRITE visibility ON private_board TYPE bool DEFAULT true;
DEFINE FIELD OVERWRITE rb_hidden ON private_board TYPE object PERMISSIONS NONE
    COMMENT '@rebase-tree-root @rebase-tree-key int';
DEFINE FIELD OVERWRITE rb_owner ON private_board TYPE object
    PERMISSIONS FOR select WHERE $auth.id = $this.owned_by
    COMMENT '@rebase-tree-root @rebase-tree-key int';
DEFINE FIELD OVERWRITE rb_public ON private_board TYPE object
    COMMENT '@rebase-tree-root @rebase-tree-key int';
DEFINE TABLE OVERWRITE private_fact SCHEMAFULL COMMENT '@rebase-members fn::typed::private';
DEFINE FIELD OVERWRITE visibility ON private_fact TYPE bool DEFAULT true;
DEFINE FIELD OVERWRITE a_owner ON private_fact TYPE record<private_board> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE rb_hidden ON private_fact TYPE option<object> PERMISSIONS NONE
    COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner private_board.rb_hidden';
DEFINE FIELD OVERWRITE rb_owner ON private_fact TYPE option<object> PERMISSIONS NONE
    COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner private_board.rb_owner';
DEFINE FIELD OVERWRITE rb_private ON private_fact TYPE option<object> PERMISSIONS NONE
    COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner private_board.rb_public';
DEFINE FUNCTION OVERWRITE fn::typed::private($row: object) {
    RETURN [
        fn::tree::int_member($row.id, 'rb_hidden', $row.a_owner, 'rb_hidden', 1, {}, {}),
        fn::tree::int_member($row.id, 'rb_owner', $row.a_owner, 'rb_owner', 1, {}, {}),
        fn::tree::int_member($row.id, 'rb_private', $row.a_owner, 'rb_public', 1, {}, {})
    ];
} PERMISSIONS NONE;
