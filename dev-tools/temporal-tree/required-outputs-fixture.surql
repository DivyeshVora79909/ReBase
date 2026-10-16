DEFINE TABLE OVERWRITE rebase_user SCHEMAFULL ;
DEFINE TABLE OVERWRITE rebase_group SCHEMAFULL ;

DEFINE TABLE OVERWRITE recipe_owner SCHEMAFULL
    COMMENT '@rebase-validate fn::recipe::validate_owner';
DEFINE FIELD OVERWRITE a_floor ON recipe_owner TYPE decimal DEFAULT 0dec;
DEFINE FIELD OVERWRITE rb_position ON recipe_owner TYPE object
    COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';

DEFINE TABLE OVERWRITE recipe_seed SCHEMAFULL
    COMMENT '@rebase-members fn::recipe::seed_members';
DEFINE FIELD OVERWRITE a_owner ON recipe_seed TYPE record<recipe_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers';
DEFINE FIELD OVERWRITE a_at ON recipe_seed TYPE datetime;
DEFINE FIELD OVERWRITE a_amount ON recipe_seed TYPE decimal;
DEFINE FIELD OVERWRITE rb_position ON recipe_seed TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner recipe_owner.rb_position';

DEFINE TABLE OVERWRITE recipe_source SCHEMAFULL
    COMMENT '@rebase-required-outputs fn::recipe::outputs @rebase-validate fn::recipe::validate_source';
DEFINE FIELD OVERWRITE a_owner ON recipe_source TYPE record<recipe_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers';
DEFINE FIELD OVERWRITE a_at ON recipe_source TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_amount ON recipe_source TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_base ON recipe_source TYPE bool DEFAULT true COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_pair ON recipe_source TYPE bool COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_note ON recipe_source TYPE string DEFAULT '';

-- The consumer sorts before its prerequisite by both table name and file
-- declaration. The recipe below also lists the consumer first.
DEFINE TABLE OVERWRITE a_recipe_compound SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::recipe::leg_members @rebase-validate fn::recipe::validate_leg';
DEFINE FIELD OVERWRITE rebase_managed_source ON a_recipe_compound TYPE string
    COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON a_recipe_compound TYPE string
    COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE a_prerequisite ON a_recipe_compound TYPE record<z_recipe_base>
    REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_owner ON a_recipe_compound TYPE record<recipe_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers';
DEFINE FIELD OVERWRITE a_at ON a_recipe_compound TYPE datetime;
DEFINE FIELD OVERWRITE a_amount ON a_recipe_compound TYPE decimal;
DEFINE FIELD OVERWRITE rb_position ON a_recipe_compound TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner recipe_owner.rb_position';
DEFINE FIELD OVERWRITE rb_prerequisite ON a_recipe_compound TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner z_recipe_base.rb_children';

DEFINE TABLE OVERWRITE z_recipe_base SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::recipe::leg_members @rebase-validate fn::recipe::validate_leg';
DEFINE FIELD OVERWRITE rebase_managed_source ON z_recipe_base TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON z_recipe_base TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE a_owner ON z_recipe_base TYPE record<recipe_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers';
DEFINE FIELD OVERWRITE a_at ON z_recipe_base TYPE datetime;
DEFINE FIELD OVERWRITE a_amount ON z_recipe_base TYPE decimal;
DEFINE FIELD OVERWRITE rb_position ON z_recipe_base TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner recipe_owner.rb_position';
DEFINE FIELD OVERWRITE rb_children ON z_recipe_base TYPE object
    COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';

DEFINE TABLE OVERWRITE required_use SCHEMAFULL;
DEFINE FIELD OVERWRITE target ON required_use TYPE record<a_recipe_compound> REFERENCE ON DELETE REJECT;

DEFINE FUNCTION OVERWRITE fn::recipe::seed_members($row: object) {
    RETURN [fn::tree::member($row.id, 'rb_position', $row.a_owner, 'rb_position',
        $row.a_at, { amount: $row.a_amount }, {}, {})];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::recipe::outputs($row: object) {
    LET $base = {
        id: type::record('z_recipe_base', [$row.id, 'a_debit']), role: 'a_debit',
        data: { owned_by: $row.owned_by, a_owner: $row.a_owner,
            a_at: $row.a_at, a_amount: -$row.a_amount }
    };
    LET $compound = {
        id: type::record('a_recipe_compound', [$row.id, 'z_credit']), role: 'z_credit',
        data: { owned_by: $row.owned_by, a_owner: $row.a_owner,
            a_prerequisite: $base.id, a_at: $row.a_at, a_amount: $row.a_amount }
    };
    RETURN array::concat(IF $row.a_pair THEN [$compound] ELSE [] END,
        IF $row.a_base THEN [$base] ELSE [] END);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::recipe::leg_members($row: object) {
    RETURN [fn::tree::member($row.id, 'rb_position', $row.a_owner, 'rb_position',
        $row.a_at, { amount: $row.a_amount }, {}, {}),
        IF record::tb($row.id) = 'a_recipe_compound' THEN
            fn::tree::member($row.id, 'rb_prerequisite', $row.a_prerequisite, 'rb_children',
                $row.a_at, { amount: $row.a_amount }, {}, {})
        ELSE NONE END];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::recipe::validate_owner($row: object) {
    IF ($row.rb_position.summary.measures.amount.instant_min ?? 0dec) < $row.a_floor {
        THROW 'C2C_COMPLETE_BALANCE_FLOOR';
    };
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::recipe::validate_leg($row: object) {
    IF $row.rebase_managed_source = NONE OR $row.rebase_managed_role = NONE {
        THROW 'C2C_UNMANAGED_OUTPUT';
    };
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::recipe::validate_source($row: object) {
    IF $row.a_pair AND !$row.a_base { THROW 'C2C_COMPOUND_REQUIRES_BASE'; };
} PERMISSIONS NONE;
