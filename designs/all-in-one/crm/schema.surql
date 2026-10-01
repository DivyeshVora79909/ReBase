-- Cases and their dated interactions demonstrate state/capacity algebra without
-- money. One open unit is created with the case; transitions consume/restore it.
DEFINE FIELD OVERWRITE z_cases ON organization TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE FUNCTION OVERWRITE fn::crm::members($row: object) {
    LET $c = $row.z20_ctx;
    RETURN [
        fn::tree::member($row.id, 'z_case', $c.origin, 'z_history', $row.a_effective_at,
            { open: $c.open, effort_minutes: $c.effort }, {}, {}, false),
        fn::tree::member($row.id, 'z_party', $c.party, 'z_cases', $row.a_effective_at,
            { open_cases: $c.open, effort_minutes: $c.effort }, {}, {}, false)
    ];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::crm::validate($row: object) {
    IF $row.a_effective_at < $row.z20_ctx.opened_at { THROW 'CRM_BEFORE_CASE'; };
    IF $row.z_history != NONE {
        LET $s = $row.z_history.summary;
        IF $s.count > 0 AND $s.first[0] < $row.a_effective_at { THROW 'CRM_BEFORE_CASE'; };
        IF ($s.measures.open.min_prefix ?? 0dec) < 0dec OR ($s.measures.open.max_prefix ?? 0dec) > 1dec { THROW 'CRM_INVALID_TRANSITION'; };
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE crm_case SCHEMAFULL COMMENT '@rebase-members fn::crm::members @rebase-validate fn::crm::validate';
DEFINE FIELD OVERWRITE a_organization ON crm_case TYPE record<organization> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_subject ON crm_case TYPE string ASSERT string::len(string::trim($value)) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_effective_at ON crm_case TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z20_ctx ON crm_case TYPE { origin: record<crm_case>, party: record<organization>, opened_at: datetime, open: decimal, effort: decimal } VALUE { origin: $this.id, party: $this.a_organization, opened_at: $this.a_effective_at, open: 1dec, effort: 0dec } COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_history ON crm_case TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_case ON crm_case TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner crm_case.z_history';
DEFINE FIELD OVERWRITE z_party ON crm_case TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_cases';

DEFINE TABLE OVERWRITE crm_transition SCHEMAFULL COMMENT '@rebase-members fn::crm::members @rebase-validate fn::crm::validate';
DEFINE FIELD OVERWRITE a_case ON crm_transition TYPE record<crm_case> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_effective_at ON crm_transition TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_open_delta ON crm_transition TYPE decimal ASSERT $value IN [-1dec, 1dec] COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_reason ON crm_transition TYPE string ASSERT string::len(string::trim($value)) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z20_ctx ON crm_transition TYPE { origin: record<crm_case>, party: record<organization>, opened_at: datetime, open: decimal, effort: decimal } VALUE object::extend($this.a_case.z20_ctx, { open: $this.a_open_delta, effort: 0dec }) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_case ON crm_transition TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner crm_case.z_history';
DEFINE FIELD OVERWRITE z_party ON crm_transition TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_cases';

DEFINE TABLE OVERWRITE crm_interaction SCHEMAFULL COMMENT '@rebase-members fn::crm::members @rebase-validate fn::crm::validate';
DEFINE FIELD OVERWRITE a_case ON crm_interaction TYPE record<crm_case> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_effective_at ON crm_interaction TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_description ON crm_interaction TYPE string ASSERT string::len(string::trim($value)) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_effort_minutes ON crm_interaction TYPE decimal DEFAULT 0dec ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z20_ctx ON crm_interaction TYPE { origin: record<crm_case>, party: record<organization>, opened_at: datetime, open: decimal, effort: decimal } VALUE object::extend($this.a_case.z20_ctx, { open: 0dec, effort: $this.a_effort_minutes }) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_case ON crm_interaction TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner crm_case.z_history';
DEFINE FIELD OVERWRITE z_party ON crm_interaction TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_cases';
