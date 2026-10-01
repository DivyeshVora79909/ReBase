-- H8 bounded timed production. The immediate H7 assembly route remains
-- separate; scheduled runs reserve free stock at start and post physical
-- consumption/coproduct effects at the immutable-duration end.

DEFINE FUNCTION OVERWRITE fn::accounting::production_recipe_validate($row: object) {
    IF $row.input_a_account.economic_entity != $row.economic_entity
        OR $row.input_b_account.economic_entity != $row.economic_entity
        OR $row.output_a_account.economic_entity != $row.economic_entity
        OR $row.output_b_account.economic_entity != $row.economic_entity {
        THROW 'ACCOUNTING_PRODUCTION_RECIPE_ENTITY_MISMATCH';
    };
    IF $row.input_a_account.unit.dimension != 'count'
        OR $row.input_b_account.unit.dimension != 'count'
        OR $row.output_a_account.unit.dimension != 'count'
        OR $row.output_b_account.unit.dimension != 'count' {
        THROW 'ACCOUNTING_PRODUCTION_RECIPE_COUNT_UNIT_REQUIRED';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE production_recipe_version SCHEMAFULL
    COMMENT '@rebase-validate fn::accounting::production_recipe_validate';
DEFINE FIELD OVERWRITE recipe_key ON production_recipe_version TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE version ON production_recipe_version TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE economic_entity ON production_recipe_version TYPE record<rebase_user | organization> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE duration ON production_recipe_version TYPE duration ASSERT $value > 0s READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE input_a_account ON production_recipe_version TYPE record<stock_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE input_a_quantity ON production_recipe_version TYPE int ASSERT $value > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE input_b_account ON production_recipe_version TYPE record<stock_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE input_b_quantity ON production_recipe_version TYPE int ASSERT $value > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE output_a_account ON production_recipe_version TYPE record<stock_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE output_a_quantity ON production_recipe_version TYPE int ASSERT $value > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE output_b_account ON production_recipe_version TYPE record<stock_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE output_b_quantity ON production_recipe_version TYPE int ASSERT $value > 0 READONLY COMMENT '@rebase-audit';
DEFINE INDEX OVERWRITE production_recipe_version_key ON production_recipe_version FIELDS economic_entity, recipe_key, version UNIQUE;

DEFINE FUNCTION OVERWRITE fn::accounting::production_run_outputs($row: object) {
    IF $row.status = 'draft' OR ($row.status = 'cancelled' AND $row.cancelled_at <= $row.planned_start) {
        RETURN [];
    };
    LET $recipe = $row.recipe_version;
    LET $count = $row.batch_count;
    LET $end = $row.planned_start + $recipe.duration;
    LET $inputs = [
        { id: type::record('production_input', [$row.id, 'input_a']), role: 'input_a', data: {
            owned_by: $row.owned_by, stock_account: $recipe.input_a_account,
            quantity: $count * $recipe.input_a_quantity, planned_start: $row.planned_start,
            end_at: $end, status: $row.status, cancelled_at: $row.cancelled_at
        } },
        { id: type::record('production_input', [$row.id, 'input_b']), role: 'input_b', data: {
            owned_by: $row.owned_by, stock_account: $recipe.input_b_account,
            quantity: $count * $recipe.input_b_quantity, planned_start: $row.planned_start,
            end_at: $end, status: $row.status, cancelled_at: $row.cancelled_at
        } }
    ];
    IF $row.status = 'cancelled' { RETURN $inputs; };
    RETURN array::concat($inputs, [
        { id: type::record('production_output', [$row.id, 'output_a']), role: 'output_a', data: {
            owned_by: $row.owned_by, stock_account: $recipe.output_a_account,
            quantity: $count * $recipe.output_a_quantity, effective_at: $end
        } },
        { id: type::record('production_output', [$row.id, 'output_b']), role: 'output_b', data: {
            owned_by: $row.owned_by, stock_account: $recipe.output_b_account,
            quantity: $count * $recipe.output_b_quantity, effective_at: $end
        } }
    ]);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::production_run_validate($row: object) {
    LET $end = $row.planned_start + $row.recipe_version.duration;
    IF $row.recipe_version.owned_by != $row.owned_by {
        THROW 'ACCOUNTING_PRODUCTION_RECIPE_OWNER_MISMATCH';
    };
    IF $row.status = 'cancelled' AND $row.cancelled_at = NONE {
        THROW 'ACCOUNTING_PRODUCTION_CANCEL_TIME_REQUIRED';
    };
    IF $row.status != 'cancelled' AND $row.cancelled_at != NONE {
        THROW 'ACCOUNTING_PRODUCTION_CANCEL_TIME_UNEXPECTED';
    };
    IF $row.status = 'cancelled' AND $row.cancelled_at >= $end {
        THROW 'ACCOUNTING_PRODUCTION_CANCEL_AFTER_END';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE production_run SCHEMAFULL
    COMMENT '@rebase-required-outputs fn::accounting::production_run_outputs @rebase-validate fn::accounting::production_run_validate';
DEFINE FIELD OVERWRITE recipe_version ON production_run TYPE record<production_recipe_version> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE batch_count ON production_run TYPE int ASSERT $value > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE planned_start ON production_run TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE status ON production_run TYPE string DEFAULT 'draft' ASSERT $value IN ['draft', 'scheduled', 'cancelled'] COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE cancelled_at ON production_run TYPE option<datetime> DEFAULT NONE COMMENT '@rebase-audit';

DEFINE FUNCTION OVERWRITE fn::accounting::production_input_members($row: object) {
    IF $row.status = 'cancelled' AND $row.cancelled_at <= $row.planned_start { RETURN []; };
    LET $reserve = fn::tree::member($row.id, 'z_reserve', $row.stock_account, 'z_history', $row.planned_start,
        { available: -<decimal>$row.quantity }, { resource: $row.stock_account.resource, unit: $row.stock_account.unit }, {}, true);
    IF $row.status = 'cancelled' {
        RETURN [$reserve, fn::tree::member($row.id, 'z_cancel_release', $row.stock_account, 'z_history', $row.cancelled_at,
            { available: <decimal>$row.quantity }, { resource: $row.stock_account.resource, unit: $row.stock_account.unit }, {}, true)];
    };
    RETURN [
        $reserve,
        fn::tree::member($row.id, 'z_consume', $row.stock_account, 'z_history', $row.end_at,
            { quantity: -<decimal>$row.quantity, available: 0dec }, { resource: $row.stock_account.resource, unit: $row.stock_account.unit }, {}, true),
        fn::tree::member($row.id, 'z_gross_input', $row.stock_account, 'z_gross_input', $row.end_at,
            { gross_input: <decimal>$row.quantity }, { resource: $row.stock_account.resource, unit: $row.stock_account.unit }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::production_input_validate($row: object) {
    IF ($row.stock_account.z_history.summary.measures.available.instant_min ?? 0dec) < 0dec {
        THROW 'ACCOUNTING_PRODUCTION_RESERVATION_CAPACITY';
    };
    IF $row.status = 'scheduled' {
        LET $prior = fn::tree::before({ rid: $row.stock_account, slot: 'z_history' }, [$row.end_at]);
        LET $upper = $row.end_at + 1ns;
        LET $gross = fn::tree::range({ rid: $row.stock_account, slot: 'z_gross_input' }, [$row.end_at], [$upper]);
        IF ($gross.measures.gross_input.sum ?? 0dec) > ($prior.measures.quantity.sum ?? 0dec) {
            THROW 'ACCOUNTING_PRODUCTION_GROSS_INPUT_CAPACITY';
        };
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE production_input SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::accounting::production_input_members @rebase-validate fn::accounting::production_input_validate';
DEFINE FIELD OVERWRITE rebase_managed_source ON production_input TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON production_input TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE stock_account ON production_input TYPE record<stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE quantity ON production_input TYPE int ASSERT $value > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE planned_start ON production_input TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE end_at ON production_input TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE status ON production_input TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE cancelled_at ON production_input TYPE option<datetime> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_reserve ON production_input TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';
DEFINE FIELD OVERWRITE z_cancel_release ON production_input TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';
DEFINE FIELD OVERWRITE z_consume ON production_input TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';
DEFINE FIELD OVERWRITE z_gross_input ON production_input TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_gross_input';

DEFINE FUNCTION OVERWRITE fn::accounting::production_output_members($row: object) {
    RETURN [fn::movement::stock_position($row.id, 'z_stock', $row.stock_account, $row.effective_at, <decimal>$row.quantity)];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::accounting::production_output_validate($row: object) {
    LET $used = -($row.z_capacity.summary.measures.quantity.instant_min ?? 0dec);
    IF $used > <decimal>$row.quantity { THROW 'ACCOUNTING_PRODUCTION_OUTPUT_CAPACITY'; };
} PERMISSIONS FULL;
DEFINE TABLE OVERWRITE production_output SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::accounting::production_output_members @rebase-validate fn::accounting::production_output_validate';
DEFINE FIELD OVERWRITE rebase_managed_source ON production_output TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON production_output TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE stock_account ON production_output TYPE record<stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE quantity ON production_output TYPE int ASSERT $value > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON production_output TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_stock ON production_output TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';
DEFINE FIELD OVERWRITE z_capacity ON production_output TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

-- Preserve H7's managed assembly link and add one independent production link.
DEFINE FUNCTION OVERWRITE fn::accounting::stock_out_members($row: object) {
    RETURN [
        fn::movement::stock_position($row.id, 'z_from', $row.from_account, $row.effective_at, -$row.quantity),
        fn::tree::member($row.id, 'z_return_grant', $row.id, 'z_returns', $row.effective_at,
            { quantity: $row.quantity }, { resource: $row.from_account.resource, unit: $row.from_account.unit }, {}, false),
        IF $row.assembly_output = NONE THEN NONE ELSE
            fn::tree::member($row.id, 'z_assembly_output', $row.assembly_output, 'z_capacity', $row.effective_at,
                { quantity: -$row.quantity }, {}, {}, false) END,
        IF $row.production_output = NONE THEN NONE ELSE
            fn::tree::member($row.id, 'z_production_output', $row.production_output, 'z_capacity', $row.effective_at,
                { quantity: -$row.quantity }, {}, {}, false) END
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::stock_out_validate($row: object) {
    IF ($row.z_billing.summary.measures.billed.max_prefix ?? 0dec) > $row.quantity { THROW 'ACCOUNTING_STOCK_OUT_OVERBILLED'; };
    IF ($row.z_returns.summary.measures.quantity.instant_min ?? 0dec) < 0dec { THROW 'ACCOUNTING_STOCK_OUT_RETURN_CAPACITY'; };
    IF $row.assembly_output != NONE AND $row.production_output != NONE { THROW 'ACCOUNTING_STOCK_OUT_MULTIPLE_OUTPUT_LINKS'; };
    IF $row.assembly_output != NONE {
        IF $row.assembly_output_account != $row.from_account { THROW 'ACCOUNTING_STOCK_OUT_ASSEMBLY_ACCOUNT_MISMATCH'; };
        IF $row.assembly_output_entity != $row.from_account.economic_entity
            OR $row.assembly_output_resource != $row.from_account.resource
            OR $row.assembly_output_unit != $row.from_account.unit { THROW 'ACCOUNTING_STOCK_OUT_ASSEMBLY_DIMENSION_MISMATCH'; };
        IF $row.effective_at < $row.assembly_output_at { THROW 'ACCOUNTING_STOCK_OUT_BEFORE_ASSEMBLY_OUTPUT'; };
    };
    IF $row.production_output != NONE {
        IF $row.production_output_account != $row.from_account { THROW 'ACCOUNTING_STOCK_OUT_PRODUCTION_ACCOUNT_MISMATCH'; };
        IF $row.production_output_entity != $row.from_account.economic_entity
            OR $row.production_output_resource != $row.from_account.resource
            OR $row.production_output_unit != $row.from_account.unit { THROW 'ACCOUNTING_STOCK_OUT_PRODUCTION_DIMENSION_MISMATCH'; };
        IF $row.effective_at < $row.production_output_at { THROW 'ACCOUNTING_STOCK_OUT_BEFORE_PRODUCTION_OUTPUT'; };
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE stock_out SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::stock_out_members @rebase-validate fn::accounting::stock_out_validate';
DEFINE FIELD OVERWRITE production_output ON stock_out TYPE option<record<production_output>> DEFAULT NONE REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE production_output_account ON stock_out TYPE option<record<stock_account>> REFERENCE ON DELETE REJECT VALUE IF $this.production_output = NONE THEN NONE ELSE $this.production_output.stock_account END COMMENT '@rebase-derived @rebase-depends production_output.stock_account';
DEFINE FIELD OVERWRITE production_output_entity ON stock_out TYPE option<record<rebase_user | organization>> VALUE IF $this.production_output_account = NONE THEN NONE ELSE $this.production_output_account.economic_entity END COMMENT '@rebase-derived @rebase-depends production_output_account.economic_entity';
DEFINE FIELD OVERWRITE production_output_resource ON stock_out TYPE option<record<item | service | work_type>> VALUE IF $this.production_output_account = NONE THEN NONE ELSE $this.production_output_account.resource END COMMENT '@rebase-derived @rebase-depends production_output_account.resource';
DEFINE FIELD OVERWRITE production_output_unit ON stock_out TYPE option<record<measure_unit>> VALUE IF $this.production_output_account = NONE THEN NONE ELSE $this.production_output_account.unit END COMMENT '@rebase-derived @rebase-depends production_output_account.unit';
DEFINE FIELD OVERWRITE production_output_at ON stock_out TYPE option<datetime> VALUE IF $this.production_output = NONE THEN NONE ELSE $this.production_output.effective_at END COMMENT '@rebase-derived @rebase-depends production_output.effective_at';
DEFINE FIELD OVERWRITE z_production_output ON stock_out TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner production_output.z_capacity';
