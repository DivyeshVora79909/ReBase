-- Strict, small, domain-independent integration fixture.
DEFINE TABLE OVERWRITE rebase_user SCHEMAFULL ;
DEFINE TABLE OVERWRITE rebase_group SCHEMAFULL ;
DEFINE TABLE OVERWRITE tree_owner SCHEMAFULL COMMENT '@rebase-validate fn::fixture::owner';
DEFINE FIELD OVERWRITE a_nonnegative ON tree_owner TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE z_book ON tree_owner TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE FUNCTION OVERWRITE fn::fixture::owner($row: object) {
    IF $row.a_nonnegative AND ($row.z_book.summary.measures.amount.min_prefix ?? 0dec) < 0dec {
        THROW 'FIXTURE_NEGATIVE_HISTORY';
    };
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE rule SCHEMAFULL;
DEFINE FIELD OVERWRITE a_rate ON rule TYPE decimal DEFAULT 0.1dec;
DEFINE FIELD OVERWRITE a_cap ON rule TYPE decimal DEFAULT 1000000dec;

DEFINE TABLE OVERWRITE fact SCHEMAFULL COMMENT '@rebase-members fn::fixture::fact';
DEFINE FIELD OVERWRITE a_owner ON fact TYPE record<tree_owner> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_mirror ON fact TYPE option<record<tree_owner>> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_amount ON fact TYPE decimal ASSERT $value >= -1000000dec;
DEFINE FIELD OVERWRITE a_quantity ON fact TYPE decimal DEFAULT 1dec;
DEFINE FIELD OVERWRITE a_effective_at ON fact TYPE datetime;
DEFINE FIELD OVERWRITE a_note ON fact TYPE string DEFAULT '';
DEFINE FIELD OVERWRITE z_leg ON fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner tree_owner.z_book';
DEFINE FIELD OVERWRITE z_mirror ON fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner tree_owner.z_book';
DEFINE FUNCTION OVERWRITE fn::fixture::fact($row: object) {
    RETURN [fn::tree::member($row.id, 'z_leg', $row.a_owner, 'z_book', $row.a_effective_at,
        { amount: $row.a_amount, quantity: $row.a_quantity },
        { currency: 'USD' }, { fact: $row.a_effective_at }, false),
        fn::tree::member($row.id, 'z_mirror', $row.a_mirror,
            'z_book', $row.a_effective_at, { amount: -$row.a_amount }, {}, {}, false)];
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE charge SCHEMAFULL COMMENT '@rebase-members fn::fixture::charge';
DEFINE FIELD OVERWRITE a_owner ON charge TYPE record<tree_owner> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_mirror ON charge TYPE option<record<tree_owner>> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_rule ON charge TYPE record<rule> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_effective_at ON charge TYPE datetime;
DEFINE FIELD OVERWRITE z10_rate ON charge TYPE decimal VALUE $this.a_rule.a_rate COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z11_cap ON charge TYPE decimal VALUE $this.a_rule.a_cap COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z20_basis ON charge TYPE decimal VALUE
    fn::tree::before({ rid: $this.a_owner, slot: 'z_book' }, [$this.a_effective_at, <string>$this.id, 'z_leg']).measures.amount.sum ?? 0dec
    COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z30_amount ON charge TYPE decimal VALUE math::min([$this.z11_cap, $this.z10_rate * $this.z20_basis]) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_leg ON charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner tree_owner.z_book';
DEFINE FIELD OVERWRITE z_mirror ON charge TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner tree_owner.z_book';
DEFINE FUNCTION OVERWRITE fn::fixture::charge($row: object) {
    RETURN [fn::tree::member($row.id, 'z_leg', $row.a_owner, 'z_book', $row.a_effective_at,
        { amount: $row.z30_amount }, { currency: 'USD' }, { charge: $row.a_effective_at }, true),
        fn::tree::member($row.id, 'z_mirror', $row.a_mirror, 'z_book', $row.a_effective_at,
            { amount: -$row.z30_amount }, {}, {}, false)];
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE inherited_fact SCHEMAFULL COMMENT '@rebase-members fn::fixture::inherited @rebase-validate fn::fixture::inherited_guard';
DEFINE FIELD OVERWRITE a_parent ON inherited_fact TYPE record<fact> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_effective_at ON inherited_fact TYPE datetime;
DEFINE FIELD OVERWRITE a_factor ON inherited_fact TYPE decimal DEFAULT 0.5dec;
DEFINE FIELD OVERWRITE z10_owner ON inherited_fact TYPE record<tree_owner> VALUE $this.a_parent.a_owner REFERENCE ON DELETE REJECT COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z11_parent_at ON inherited_fact TYPE datetime VALUE $this.a_parent.a_effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z20_amount ON inherited_fact TYPE decimal VALUE $this.a_parent.a_amount * $this.a_factor COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_leg ON inherited_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner tree_owner.z_book';
DEFINE FUNCTION OVERWRITE fn::fixture::inherited($row: object) {
    RETURN [fn::tree::member($row.id, 'z_leg', $row.z10_owner, 'z_book', $row.a_effective_at,
        { amount: $row.z20_amount }, {}, { inherited: $row.a_effective_at }, false)];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::fixture::inherited_guard($row: object) {
    IF $row.a_effective_at < $row.z11_parent_at { THROW 'FIXTURE_CHILD_BEFORE_PARENT'; };
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE chained_fact SCHEMAFULL COMMENT '@rebase-members fn::fixture::inherited @rebase-validate fn::fixture::inherited_guard';
DEFINE FIELD OVERWRITE a_parent ON chained_fact TYPE record<inherited_fact> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE a_effective_at ON chained_fact TYPE datetime;
DEFINE FIELD OVERWRITE z10_owner ON chained_fact TYPE record<tree_owner> VALUE $this.a_parent.z10_owner REFERENCE ON DELETE REJECT COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z11_parent_at ON chained_fact TYPE datetime VALUE $this.a_parent.a_effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z20_amount ON chained_fact TYPE decimal VALUE $this.a_parent.z20_amount * 2dec COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_leg ON chained_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner tree_owner.z_book';

DEFINE TABLE OVERWRITE unlinked_fact SCHEMAFULL COMMENT '@rebase-members fn::fixture::singleton';
DEFINE FIELD OVERWRITE a_amount ON unlinked_fact TYPE decimal;
DEFINE FIELD OVERWRITE a_effective_at ON unlinked_fact TYPE datetime;
DEFINE FIELD OVERWRITE z_leg ON unlinked_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner tree_owner.z_book';
DEFINE FUNCTION OVERWRITE fn::fixture::singleton($row: object) {
    RETURN [fn::tree::member($row.id, 'z_leg', tree_owner:singleton, 'z_book', $row.a_effective_at,
        { amount: $row.a_amount }, {}, {}, false)];
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE report SCHEMAFULL;
DEFINE FIELD OVERWRITE a_owner ON report TYPE record<tree_owner> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE z_total ON report TYPE decimal VALUE $this.a_owner.z_book.summary.measures.amount.sum ?? 0dec COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_private ON report TYPE decimal VALUE $this.a_owner.z_book.summary.measures.amount.sum ?? 0dec
    PERMISSIONS FOR select NONE COMMENT '@rebase-derived';

DEFINE TABLE OVERWRITE principal_report SCHEMAFULL;
DEFINE FIELD OVERWRITE a_user ON principal_report TYPE record<rebase_user> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE z_name ON principal_report TYPE string VALUE $this.a_user.name COMMENT '@rebase-derived';
