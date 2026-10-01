DEFINE TABLE OVERWRITE rebase_user SCHEMAFULL ;
DEFINE TABLE OVERWRITE rebase_group SCHEMAFULL ;

DEFINE TABLE OVERWRITE calc_owner SCHEMAFULL
    COMMENT '@rebase-validate fn::c2d::validate_owner';
DEFINE FIELD OVERWRITE a_floor ON calc_owner TYPE decimal DEFAULT 0dec;
DEFINE FIELD OVERWRITE z_history ON calc_owner TYPE object
    COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE TABLE OVERWRITE input_seed SCHEMAFULL
    COMMENT '@rebase-members fn::c2d::seed_members';
DEFINE FIELD OVERWRITE a_owner ON input_seed TYPE record<calc_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers';
DEFINE FIELD OVERWRITE a_at ON input_seed TYPE datetime;
DEFINE FIELD OVERWRITE a_amount ON input_seed TYPE decimal;
DEFINE FIELD OVERWRITE rb_seed ON input_seed TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner calc_owner.z_history';

DEFINE TABLE OVERWRITE batch_source SCHEMAFULL
    COMMENT '@rebase-required-outputs fn::c2d::batch_outputs';
DEFINE FIELD OVERWRITE a_input_a ON batch_source TYPE record<calc_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers @rebase-audit';
DEFINE FIELD OVERWRITE a_input_b ON batch_source TYPE record<calc_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers @rebase-audit';
DEFINE FIELD OVERWRITE a_at ON batch_source TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_delta_a ON batch_source TYPE decimal COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_delta_b ON batch_source TYPE decimal COMMENT '@rebase-audit';

DEFINE TABLE OVERWRITE input_leg SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::c2d::input_members';
DEFINE FIELD OVERWRITE rebase_managed_source ON input_leg TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON input_leg TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE a_owner ON input_leg TYPE record<calc_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers @rebase-audit';
DEFINE FIELD OVERWRITE a_at ON input_leg TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_amount ON input_leg TYPE decimal COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE rb_input ON input_leg TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner calc_owner.z_history';

DEFINE TABLE OVERWRITE calc_basis SCHEMAFULL
    COMMENT '@rebase-required-outputs fn::c2d::basis_outputs';
DEFINE FIELD OVERWRITE a_input_a ON calc_basis TYPE record<calc_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers @rebase-audit';
DEFINE FIELD OVERWRITE a_input_b ON calc_basis TYPE record<calc_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers @rebase-audit';
DEFINE FIELD OVERWRITE a_left_owner ON calc_basis TYPE record<calc_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_right_owner ON calc_basis TYPE record<calc_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_feedback ON calc_basis TYPE bool DEFAULT false COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_amount ON calc_basis TYPE decimal VALUE
    ($this.a_input_a.z_history.summary.measures.amount.sum ?? 0dec)
    + ($this.a_input_b.z_history.summary.measures.amount.sum ?? 0dec)
    COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_at ON calc_basis TYPE datetime VALUE
    IF $this.a_input_a.z_history.summary.last[0] >= $this.a_input_b.z_history.summary.last[0]
        THEN $this.a_input_a.z_history.summary.last[0]
        ELSE $this.a_input_b.z_history.summary.last[0] END
    COMMENT '@rebase-derived';

DEFINE TABLE OVERWRITE branch_left_leg SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::c2d::left_members';
DEFINE FIELD OVERWRITE rebase_managed_source ON branch_left_leg TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON branch_left_leg TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE a_owner ON branch_left_leg TYPE record<calc_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers @rebase-audit';
DEFINE FIELD OVERWRITE a_at ON branch_left_leg TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_amount ON branch_left_leg TYPE decimal COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE rb_left ON branch_left_leg TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner calc_owner.z_history';

DEFINE TABLE OVERWRITE branch_right_leg SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::c2d::right_members';
DEFINE FIELD OVERWRITE rebase_managed_source ON branch_right_leg TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON branch_right_leg TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE a_owner ON branch_right_leg TYPE record<calc_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers @rebase-audit';
DEFINE FIELD OVERWRITE a_at ON branch_right_leg TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_amount ON branch_right_leg TYPE decimal COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE rb_right ON branch_right_leg TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner calc_owner.z_history';

DEFINE TABLE OVERWRITE diamond_basis SCHEMAFULL
    COMMENT '@rebase-required-outputs fn::c2d::diamond_outputs';
DEFINE FIELD OVERWRITE a_left_owner ON diamond_basis TYPE record<calc_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers @rebase-audit';
DEFINE FIELD OVERWRITE a_right_owner ON diamond_basis TYPE record<calc_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers @rebase-audit';
DEFINE FIELD OVERWRITE a_final_owner ON diamond_basis TYPE record<calc_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_amount ON diamond_basis TYPE decimal VALUE
    ($this.a_left_owner.z_history.summary.measures.amount.sum ?? 0dec)
    + ($this.a_right_owner.z_history.summary.measures.amount.sum ?? 0dec)
    COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_at ON diamond_basis TYPE datetime VALUE
    IF $this.a_left_owner.z_history.summary.last[0] >= $this.a_right_owner.z_history.summary.last[0]
        THEN $this.a_left_owner.z_history.summary.last[0]
        ELSE $this.a_right_owner.z_history.summary.last[0] END
    COMMENT '@rebase-derived';

DEFINE TABLE OVERWRITE final_leg SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::c2d::final_members';
DEFINE FIELD OVERWRITE rebase_managed_source ON final_leg TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON final_leg TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE a_owner ON final_leg TYPE record<calc_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers @rebase-audit';
DEFINE FIELD OVERWRITE a_at ON final_leg TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_amount ON final_leg TYPE decimal COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE rb_final ON final_leg TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner calc_owner.z_history';

DEFINE TABLE OVERWRITE feedback_leg SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::c2d::feedback_members';
DEFINE FIELD OVERWRITE rebase_managed_source ON feedback_leg TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON feedback_leg TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE a_owner ON feedback_leg TYPE record<calc_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers @rebase-audit';
DEFINE FIELD OVERWRITE a_at ON feedback_leg TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_amount ON feedback_leg TYPE decimal COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE rb_feedback ON feedback_leg TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner calc_owner.z_history';

DEFINE FUNCTION OVERWRITE fn::c2d::member($row: object, $slot: string) {
    RETURN fn::tree::member($row.id, $slot, $row.a_owner, 'z_history',
        $row.a_at, { amount: $row.a_amount }, {}, {}, false);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::c2d::seed_members($row: object) {
    RETURN [fn::c2d::member($row, 'rb_seed')];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::c2d::input_members($row: object) {
    RETURN [fn::c2d::member($row, 'rb_input')];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::c2d::left_members($row: object) {
    RETURN [fn::c2d::member($row, 'rb_left')];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::c2d::right_members($row: object) {
    RETURN [fn::c2d::member($row, 'rb_right')];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::c2d::final_members($row: object) {
    RETURN [fn::c2d::member($row, 'rb_final')];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::c2d::feedback_members($row: object) {
    RETURN [fn::c2d::member($row, 'rb_feedback')];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::c2d::batch_outputs($row: object) {
    RETURN [
        { id: type::record('input_leg', [$row.id, 'input_a']), role: 'input_a',
          data: { owned_by: $row.owned_by, a_owner: $row.a_input_a,
              a_at: $row.a_at, a_amount: $row.a_delta_a } },
        { id: type::record('input_leg', [$row.id, 'input_b']), role: 'input_b',
          data: { owned_by: $row.owned_by, a_owner: $row.a_input_b,
              a_at: $row.a_at, a_amount: $row.a_delta_b } }
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::c2d::basis_outputs($row: object) {
    LET $branches = [
        { id: type::record('branch_left_leg', [$row.id, 'left']), role: 'left',
          data: { owned_by: $row.owned_by, a_owner: $row.a_left_owner,
              a_at: $row.z_at, a_amount: $row.z_amount } },
        { id: type::record('branch_right_leg', [$row.id, 'right']), role: 'right',
          data: { owned_by: $row.owned_by, a_owner: $row.a_right_owner,
              a_at: $row.z_at, a_amount: $row.z_amount * 2dec } }
    ];
    LET $feedback = { id: type::record('feedback_leg', [$row.id, 'feedback']), role: 'feedback',
        data: { owned_by: $row.owned_by, a_owner: $row.a_input_a,
            a_at: $row.z_at, a_amount: 0dec } };
    RETURN IF $row.a_feedback THEN array::concat($branches, [$feedback]) ELSE $branches END;
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::c2d::diamond_outputs($row: object) {
    RETURN [{ id: type::record('final_leg', [$row.id, 'final']), role: 'final',
        data: { owned_by: $row.owned_by, a_owner: $row.a_final_owner,
            a_at: $row.z_at, a_amount: $row.z_amount } }];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::c2d::validate_owner($row: object) {
    IF ($row.z_history.summary.count > 0
        AND ($row.z_history.summary.measures.amount.sum ?? 0dec) < $row.a_floor) {
        THROW 'C2D_OWNER_FLOOR';
    };
} PERMISSIONS NONE;
