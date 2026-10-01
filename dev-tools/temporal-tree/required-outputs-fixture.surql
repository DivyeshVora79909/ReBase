DEFINE TABLE OVERWRITE rebase_user SCHEMAFULL ;
DEFINE TABLE OVERWRITE rebase_group SCHEMAFULL ;

DEFINE TABLE OVERWRITE recipe_owner SCHEMAFULL
    COMMENT '@rebase-validate fn::recipe::validate_owner';
DEFINE FIELD OVERWRITE a_floor ON recipe_owner TYPE decimal DEFAULT 0dec;
DEFINE FIELD OVERWRITE rb_position ON recipe_owner TYPE object
    COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE TABLE OVERWRITE recipe_seed SCHEMAFULL
    COMMENT '@rebase-members fn::recipe::seed_members';
DEFINE FIELD OVERWRITE a_owner ON recipe_seed TYPE record<recipe_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers';
DEFINE FIELD OVERWRITE a_at ON recipe_seed TYPE datetime;
DEFINE FIELD OVERWRITE a_amount ON recipe_seed TYPE decimal;
DEFINE FIELD OVERWRITE rb_position ON recipe_seed TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner recipe_owner.rb_position';

DEFINE TABLE OVERWRITE recipe_source SCHEMAFULL
    COMMENT '@rebase-required-outputs fn::recipe::outputs';
DEFINE FIELD OVERWRITE a_owner ON recipe_source TYPE record<recipe_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers';
DEFINE FIELD OVERWRITE a_at ON recipe_source TYPE datetime;
DEFINE FIELD OVERWRITE a_amount ON recipe_source TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD OVERWRITE a_pair ON recipe_source TYPE bool;
DEFINE FIELD OVERWRITE a_note ON recipe_source TYPE string DEFAULT '';

DEFINE TABLE OVERWRITE required_leg SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::recipe::leg_members @rebase-validate fn::recipe::validate_leg';
DEFINE FIELD OVERWRITE rebase_managed_source ON required_leg TYPE string
    COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON required_leg TYPE string
    COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE a_owner ON required_leg TYPE record<recipe_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers';
DEFINE FIELD OVERWRITE a_at ON required_leg TYPE datetime;
DEFINE FIELD OVERWRITE a_amount ON required_leg TYPE decimal;
DEFINE FIELD OVERWRITE rb_position ON required_leg TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner recipe_owner.rb_position';

DEFINE FUNCTION OVERWRITE fn::recipe::seed_members($row: object) {
    RETURN [fn::tree::member($row.id, 'rb_position', $row.a_owner, 'rb_position',
        $row.a_at, { amount: $row.a_amount }, {}, {}, false)];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::recipe::outputs($row: object) {
    LET $debit = {
        id: type::record('required_leg', [$row.id, 'a_debit']), role: 'a_debit',
        data: { owned_by: $row.owned_by, a_owner: $row.a_owner,
            a_at: $row.a_at, a_amount: -$row.a_amount }
    };
    LET $credit = {
        id: type::record('required_leg', [$row.id, 'z_credit']), role: 'z_credit',
        data: { owned_by: $row.owned_by, a_owner: $row.a_owner,
            a_at: $row.a_at, a_amount: $row.a_amount }
    };
    RETURN IF $row.a_pair THEN [$debit, $credit] ELSE [$debit] END;
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::recipe::leg_members($row: object) {
    RETURN [fn::tree::member($row.id, 'rb_position', $row.a_owner, 'rb_position',
        $row.a_at, { amount: $row.a_amount }, {}, {}, false)];
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
