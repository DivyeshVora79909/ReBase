DEFINE TABLE OVERWRITE rebase_user SCHEMAFULL ;
DEFINE TABLE OVERWRITE rebase_group SCHEMAFULL ;

DEFINE TABLE OVERWRITE tree_owner SCHEMAFULL
    COMMENT '@rebase-validate fn::c3::validate_owner';
DEFINE FIELD OVERWRITE z_history ON tree_owner TYPE object
    COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE TABLE OVERWRITE natural_rule SCHEMAFULL;
DEFINE FIELD OVERWRITE a_add ON natural_rule TYPE decimal;

DEFINE TABLE OVERWRITE natural_fact SCHEMAFULL
    COMMENT '@rebase-members fn::c3::fact_members';
DEFINE FIELD OVERWRITE a_owner ON natural_fact TYPE record<tree_owner>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-readers @rebase-audit';
DEFINE FIELD OVERWRITE a_rule ON natural_fact TYPE record<natural_rule>
    REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_at ON natural_fact TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_quantity ON natural_fact TYPE decimal COMMENT '@rebase-audit';

-- The field names and declaration order are deliberately unrelated to the
-- formula order: z_factor and m_double both feed a_total.
DEFINE FIELD OVERWRITE a_total ON natural_fact TYPE decimal
    VALUE $this.m_double + $this.z_factor
    ASSERT $value >= 0dec
    COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE m_double ON natural_fact TYPE decimal
    VALUE $this.a_quantity * 2dec
    ASSERT $value >= 0dec
    COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_factor ON natural_fact TYPE decimal
    VALUE $this.a_quantity + fn::c3::rule_add($this.a_rule)
    ASSERT $value >= 0dec
    COMMENT '@rebase-derived @rebase-depends a_rule.a_add';
DEFINE FIELD OVERWRITE rb_fact ON natural_fact TYPE option<object>
    COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner tree_owner.z_history';

DEFINE FUNCTION OVERWRITE fn::c3::rule_add($rule: record<natural_rule>) {
    RETURN $rule.a_add;
} PERMISSIONS WHERE $auth != NONE;

DEFINE FUNCTION OVERWRITE fn::c3::fact_members($row: object) {
    RETURN [fn::tree::member($row.id, 'rb_fact', $row.a_owner, 'z_history',
        $row.a_at, { amount: $row.a_total }, {}, {}, false)];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::c3::validate_owner($row: object) {
    IF ($row.z_history.summary.measures.amount.min_prefix ?? 0dec) < 0dec {
        THROW 'C3_NEGATIVE_HISTORY';
    };
} PERMISSIONS NONE;

-- Only the explicitly marked nested leaf may enter the audit projection.
DEFINE TABLE OVERWRITE c3_profile SCHEMAFULL;
DEFINE FIELD OVERWRITE profile ON c3_profile TYPE object;
DEFINE FIELD OVERWRITE profile.email ON c3_profile TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE profile.secret ON c3_profile TYPE string;
DEFINE FIELD OVERWRITE private_note ON c3_profile TYPE string;
