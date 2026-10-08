-- Production rows are authored facts. No recipe arrays, status workflow or generated children.

DEFINE FUNCTION OVERWRITE fn::accounting::production_validate($row: object) {
    IF $row.ends_at <= $row.starts_at { THROW 'PRODUCTION_INTERVAL'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::window_validate($start: datetime, $end: datetime, $from: option<datetime>, $until: option<datetime>, $minimum: option<duration>, $maximum: option<duration>) {
    IF $from != NONE AND $start < $from OR $until != NONE AND $end > $until { THROW 'RESOURCE_AVAILABILITY'; };
    IF $minimum != NONE AND $end - $start < $minimum OR $maximum != NONE AND $end - $start > $maximum { THROW 'RESOURCE_DURATION'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::production_line($row: object, $at: datetime, $kind: string) {
    RETURN fn::tree::member($row.id, 'z_production', $row.production, 'z_lines', $at, { lines: 1dec }, { kind: $kind }, {}, false);
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE production SCHEMAFULL COMMENT '@rebase-validate fn::accounting::production_validate';
DEFINE FIELD OVERWRITE name ON production TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE starts_at ON production TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE ends_at ON production TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_lines ON production TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_capacity ON operating_unit TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_gross ON stock_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_gross ON misc_stock_account TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';

DEFINE FUNCTION OVERWRITE fn::accounting::production_input_validate($row: object) {
    fn::accounting::window_validate($row.starts_at, $row.ends_at, $row.available_from, $row.available_until, $row.minimum_duration, $row.maximum_duration);
    LET $free = fn::tree::before({ rid: $row.stock_account, slot: 'z_history' }, [$row.starts_at]).measures.available.sum ?? 0dec;
    LET $demand = fn::tree::range({ rid: $row.stock_account, slot: 'z_gross' }, [$row.starts_at], [$row.starts_at + 1ns]).measures.quantity.sum ?? 0dec;
    IF $demand > $free { THROW 'PRODUCTION_GROSS_INPUT'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::production_input_members($row: object) {
    RETURN [fn::accounting::balance_member($row, 'z_start', $row.stock_account, $row.starts_at, fn::accounting::effects(0dec, 0dec, $row.quantity), true),
        fn::accounting::balance_member($row, 'z_end', $row.stock_account, $row.ends_at, fn::accounting::effects(-$row.quantity, 0dec, -$row.quantity), false),
        fn::tree::member($row.id, 'z_gross', $row.stock_account, 'z_gross', $row.starts_at, { quantity: $row.quantity }, {}, {}, false),
        fn::accounting::production_line($row, $row.starts_at, 'input')];
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE production_input SCHEMAFULL COMMENT '@rebase-members fn::accounting::production_input_members @rebase-validate fn::accounting::production_input_validate';
DEFINE FIELD OVERWRITE production ON production_input TYPE record<production> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE starts_at ON production_input TYPE datetime VALUE $this.production.starts_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE ends_at ON production_input TYPE datetime VALUE $this.production.ends_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_production ON production_input TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner production.z_lines';
DEFINE FIELD OVERWRITE stock_account ON production_input TYPE record<stock_account | misc_stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE quantity ON production_input TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE resource ON production_input TYPE record<item | service> REFERENCE ON DELETE REJECT VALUE $this.stock_account.resource COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE available_from ON production_input TYPE option<datetime> VALUE $this.resource.available_from COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE available_until ON production_input TYPE option<datetime> VALUE $this.resource.available_until COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE minimum_duration ON production_input TYPE option<duration> VALUE $this.resource.minimum_duration COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE maximum_duration ON production_input TYPE option<duration> VALUE $this.resource.maximum_duration COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_start ON production_input TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history';
DEFINE FIELD OVERWRITE z_end ON production_input TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history';
DEFINE FIELD OVERWRITE z_gross ON production_input TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_gross @rebase-tree-owner misc_stock_account.z_gross';

DEFINE FUNCTION OVERWRITE fn::accounting::production_output_validate($row: object) {
    IF ($row.z_capacity.summary.measures.quantity.instant_min ?? 0dec) < 0dec { THROW 'PRODUCTION_OUTPUT_CAPACITY'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::production_output_members($row: object) {
    RETURN [fn::accounting::balance_member($row, 'z_start', $row.stock_account, $row.starts_at, fn::accounting::effects(0dec, $row.quantity, 0dec), false),
        fn::accounting::balance_member($row, 'z_end', $row.stock_account, $row.ends_at, fn::accounting::effects($row.quantity, -$row.quantity, 0dec), false),
        fn::tree::member($row.id, 'z_self', $row.id, 'z_capacity', $row.ends_at, { quantity: $row.quantity }, {}, {}, false),
        fn::accounting::production_line($row, $row.ends_at, 'output')];
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE production_output SCHEMAFULL COMMENT '@rebase-members fn::accounting::production_output_members @rebase-validate fn::accounting::production_output_validate';
DEFINE FIELD OVERWRITE production ON production_output TYPE record<production> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE starts_at ON production_output TYPE datetime VALUE $this.production.starts_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE ends_at ON production_output TYPE datetime VALUE $this.production.ends_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_production ON production_output TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner production.z_lines';
DEFINE FIELD OVERWRITE stock_account ON production_output TYPE record<stock_account | misc_stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE quantity ON production_output TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_capacity ON production_output TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_start ON production_output TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history';
DEFINE FIELD OVERWRITE z_end ON production_output TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history';
DEFINE FIELD OVERWRITE z_self ON production_output TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner production_output.z_capacity';

DEFINE FUNCTION OVERWRITE fn::accounting::production_cost_validate($row: object) {
    fn::accounting::fee_validate($row);
    fn::accounting::precision_validate($row.amount, $row.currency);
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::production_cost_members($row: object) {
    RETURN array::concat([fn::accounting::balance_member($row, 'z_start', $row.treasury, $row.starts_at, fn::accounting::effects(0dec, 0dec, $row.amount), false),
        fn::accounting::balance_member($row, 'z_end', $row.treasury, $row.ends_at, fn::accounting::effects(-$row.amount, 0dec, -$row.amount), false),
        fn::accounting::production_line($row, $row.ends_at, 'cost')], fn::accounting::fee_members($row));
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE production_cost SCHEMAFULL COMMENT '@rebase-members fn::accounting::production_cost_members @rebase-validate fn::accounting::production_cost_validate';
DEFINE FIELD OVERWRITE production ON production_cost TYPE record<production> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE starts_at ON production_cost TYPE datetime VALUE $this.production.starts_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE ends_at ON production_cost TYPE datetime VALUE $this.production.ends_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_production ON production_cost TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner production.z_lines';
DEFINE FIELD OVERWRITE treasury ON production_cost TYPE record<treasury | misc_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON production_cost TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON production_cost TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.treasury.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_start ON production_cost TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';
DEFINE FIELD OVERWRITE z_end ON production_cost TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner treasury.z_history @rebase-tree-owner misc_currency_account.z_history';

DEFINE FUNCTION OVERWRITE fn::accounting::production_capacity_validate($row: object) {
    fn::accounting::window_validate($row.starts_at, $row.ends_at, $row.available_from, $row.available_until, $row.minimum_duration, $row.maximum_duration);
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::production_capacity_members($row: object) {
    RETURN [fn::tree::member($row.id, 'z_start', $row.operating_unit, 'z_capacity', $row.starts_at, { used: $row.quantity }, {}, {}, false),
        fn::tree::member($row.id, 'z_end', $row.operating_unit, 'z_capacity', $row.ends_at, { used: -$row.quantity }, {}, {}, false),
        fn::accounting::production_line($row, $row.starts_at, 'capacity')];
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE production_capacity SCHEMAFULL COMMENT '@rebase-members fn::accounting::production_capacity_members @rebase-validate fn::accounting::production_capacity_validate';
DEFINE FIELD OVERWRITE production ON production_capacity TYPE record<production> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE starts_at ON production_capacity TYPE datetime VALUE $this.production.starts_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE ends_at ON production_capacity TYPE datetime VALUE $this.production.ends_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_production ON production_capacity TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner production.z_lines';
DEFINE FIELD OVERWRITE operating_unit ON production_capacity TYPE record<operating_unit> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE service ON production_capacity TYPE record<service> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE quantity ON production_capacity TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE available_from ON production_capacity TYPE option<datetime> VALUE $this.service.available_from COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE available_until ON production_capacity TYPE option<datetime> VALUE $this.service.available_until COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE minimum_duration ON production_capacity TYPE option<duration> VALUE $this.service.minimum_duration COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE maximum_duration ON production_capacity TYPE option<duration> VALUE $this.service.maximum_duration COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_start ON production_capacity TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_capacity';
DEFINE FIELD OVERWRITE z_end ON production_capacity TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner operating_unit.z_capacity';
