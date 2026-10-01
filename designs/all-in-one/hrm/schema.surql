-- A leave allowance is employment + service/unit, analogous to stock + resource.
-- Grants and approved usage are dated facts. No implicit accrual, payroll, or clock
-- events: a scheduler/client creates grants through the same ordinary write path.
DEFINE TABLE OVERWRITE employment SCHEMAFULL COMMENT '@rebase-validate fn::hrm::employment';
DEFINE FIELD OVERWRITE a_person ON employment TYPE record<rebase_user> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_unit ON employment TYPE record<operating_unit> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_effective_at ON employment TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_until ON employment TYPE option<datetime> ASSERT $value = NONE OR $value >= $this.a_effective_at COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_history ON employment TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FUNCTION OVERWRITE fn::hrm::employment($row: object) {
    LET $s = $row.z_history.summary;
    IF $s.count > 0 AND ($s.first[0] < $row.a_effective_at OR ($row.a_until != NONE AND $s.last[0] > $row.a_until)) { THROW 'HRM_OUTSIDE_EMPLOYMENT'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE leave_account SCHEMAFULL COMMENT '@rebase-validate fn::hrm::capacity';
DEFINE FIELD OVERWRITE a_employment ON leave_account TYPE record<employment> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_service ON leave_account TYPE record<service> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z20_ctx ON leave_account TYPE { employment: record<employment>, unit: record<operating_unit>, service: record<service>, start: datetime, until: option<datetime> } VALUE { employment: $this.a_employment, unit: $this.a_employment.a_unit, service: $this.a_service, start: $this.a_employment.a_effective_at, until: $this.a_employment.a_until } COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_book ON leave_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE INDEX OVERWRITE leave_account_dimension ON leave_account FIELDS a_employment, a_service UNIQUE;
DEFINE FUNCTION OVERWRITE fn::hrm::capacity($row: object) {
    IF ($row.z_book.summary.measures.quantity.min_prefix ?? 0dec) < 0dec { THROW 'HRM_INSUFFICIENT_ALLOWANCE'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::hrm::members($row: object) {
    LET $c = $row.z20_ctx;
    LET $usage = record::tb($row.id) = 'leave_use';
    RETURN [
        fn::tree::member($row.id, 'z_allowance', $row.a_account, 'z_book', $row.a_effective_at,
            { quantity: IF $usage THEN -$row.a_quantity ELSE $row.a_quantity END }, { service: $c.service }, {}, false),
        fn::tree::member($row.id, 'z_employment', $c.employment, 'z_history', $row.a_effective_at,
            IF $usage THEN { uses: 1dec } ELSE { grants: 1dec } END, {}, {}, false),
        fn::tree::member($row.id, 'z_unit', $c.unit, 'z_activity', $row.a_effective_at,
            { hr_interactions: 1dec }, {}, {}, false)
    ];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::hrm::fact($row: object) {
    LET $c = $row.z20_ctx;
    IF $row.a_effective_at < $c.start OR ($c.until != NONE AND $row.a_effective_at > $c.until) { THROW 'HRM_OUTSIDE_EMPLOYMENT'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE leave_grant SCHEMAFULL COMMENT '@rebase-members fn::hrm::members @rebase-validate fn::hrm::fact';
DEFINE FIELD OVERWRITE a_account ON leave_grant TYPE record<leave_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_quantity ON leave_grant TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_effective_at ON leave_grant TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_reason ON leave_grant TYPE string ASSERT string::len(string::trim($value)) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z20_ctx ON leave_grant TYPE { employment: record<employment>, unit: record<operating_unit>, service: record<service>, start: datetime, until: option<datetime> } VALUE $this.a_account.z20_ctx COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_allowance ON leave_grant TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner leave_account.z_book';
DEFINE FIELD OVERWRITE z_employment ON leave_grant TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner employment.z_history';
DEFINE FIELD OVERWRITE z_unit ON leave_grant TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_activity';

DEFINE TABLE OVERWRITE leave_use SCHEMAFULL COMMENT '@rebase-members fn::hrm::members @rebase-validate fn::hrm::fact';
DEFINE FIELD OVERWRITE a_account ON leave_use TYPE record<leave_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_quantity ON leave_use TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_effective_at ON leave_use TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE a_reason ON leave_use TYPE string ASSERT string::len(string::trim($value)) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z20_ctx ON leave_use TYPE { employment: record<employment>, unit: record<operating_unit>, service: record<service>, start: datetime, until: option<datetime> } VALUE $this.a_account.z20_ctx COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_allowance ON leave_use TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner leave_account.z_book';
DEFINE FIELD OVERWRITE z_employment ON leave_use TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner employment.z_history';
DEFINE FIELD OVERWRITE z_unit ON leave_use TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_activity';
