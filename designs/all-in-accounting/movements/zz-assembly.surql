-- H7 finite immediate recipe. Each typed role is a stable managed child; the
-- per-output use root records downstream draws against that output's quantity.

DEFINE FUNCTION OVERWRITE fn::accounting::assembly_recipe_validate($row: object) {
    IF $row.input_a_account.economic_entity != $row.economic_entity
        OR $row.input_b_account.economic_entity != $row.economic_entity
        OR $row.output_a_account.economic_entity != $row.economic_entity
        OR $row.output_b_account.economic_entity != $row.economic_entity {
        THROW 'ACCOUNTING_ASSEMBLY_RECIPE_ENTITY_MISMATCH';
    };
    IF $row.input_a_account.unit.dimension != 'count'
        OR $row.input_b_account.unit.dimension != 'count'
        OR $row.output_a_account.unit.dimension != 'count'
        OR $row.output_b_account.unit.dimension != 'count' {
        THROW 'ACCOUNTING_ASSEMBLY_RECIPE_COUNT_UNIT_REQUIRED';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE assembly_recipe_version SCHEMAFULL
    COMMENT '@rebase-validate fn::accounting::assembly_recipe_validate';
DEFINE FIELD OVERWRITE recipe_key ON assembly_recipe_version TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE version ON assembly_recipe_version TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE economic_entity ON assembly_recipe_version TYPE record<rebase_user | organization> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE input_a_account ON assembly_recipe_version TYPE record<stock_account> ASSERT $value != NONE REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE input_a_quantity ON assembly_recipe_version TYPE int ASSERT $value > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE input_b_account ON assembly_recipe_version TYPE record<stock_account> ASSERT $value != NONE REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE input_b_quantity ON assembly_recipe_version TYPE int ASSERT $value > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE output_a_account ON assembly_recipe_version TYPE record<stock_account> ASSERT $value != NONE REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE output_a_quantity ON assembly_recipe_version TYPE int ASSERT $value > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE output_b_account ON assembly_recipe_version TYPE record<stock_account> ASSERT $value != NONE REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE output_b_quantity ON assembly_recipe_version TYPE int ASSERT $value > 0 READONLY COMMENT '@rebase-audit';
DEFINE INDEX OVERWRITE assembly_recipe_version_key ON assembly_recipe_version FIELDS economic_entity, recipe_key, version UNIQUE;

DEFINE FUNCTION OVERWRITE fn::accounting::assembly_batch_outputs($row: object) {
    IF $row.state != 'complete' { RETURN []; };
    LET $recipe = $row.recipe_version;
    RETURN [
        { id: type::record('assembly_input', [$row.id, 'input_a']), role: 'input_a', data: {
            owned_by: $row.owned_by, stock_account: $recipe.input_a_account,
            quantity: $row.batch_count * $recipe.input_a_quantity, effective_at: $row.effective_at
        } },
        { id: type::record('assembly_input', [$row.id, 'input_b']), role: 'input_b', data: {
            owned_by: $row.owned_by, stock_account: $recipe.input_b_account,
            quantity: $row.batch_count * $recipe.input_b_quantity, effective_at: $row.effective_at
        } },
        { id: type::record('assembly_output', [$row.id, 'output_a']), role: 'output_a', data: {
            owned_by: $row.owned_by, stock_account: $recipe.output_a_account,
            quantity: $row.batch_count * $recipe.output_a_quantity, effective_at: $row.effective_at
        } },
        { id: type::record('assembly_output', [$row.id, 'output_b']), role: 'output_b', data: {
            owned_by: $row.owned_by, stock_account: $recipe.output_b_account,
            quantity: $row.batch_count * $recipe.output_b_quantity, effective_at: $row.effective_at
        } }
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::assembly_batch_validate($row: object) {
    IF $row.recipe_version.owned_by != $row.owned_by {
        THROW 'ACCOUNTING_ASSEMBLY_RECIPE_OWNER_MISMATCH';
    };
    IF $row.state = 'complete' AND ($row.recipe_version.input_a_account = NONE
        OR $row.recipe_version.input_b_account = NONE OR $row.recipe_version.output_a_account = NONE
        OR $row.recipe_version.output_b_account = NONE) {
        THROW 'ACCOUNTING_ASSEMBLY_COMPLETE_RECIPE_REQUIRED';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE assembly_batch SCHEMAFULL
    COMMENT '@rebase-required-outputs fn::accounting::assembly_batch_outputs @rebase-validate fn::accounting::assembly_batch_validate';
DEFINE FIELD OVERWRITE recipe_version ON assembly_batch TYPE record<assembly_recipe_version> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE batch_count ON assembly_batch TYPE int ASSERT $value > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE state ON assembly_batch TYPE string DEFAULT 'draft' ASSERT $value IN ['draft', 'complete'] COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON assembly_batch TYPE datetime COMMENT '@rebase-audit';

DEFINE FUNCTION OVERWRITE fn::accounting::assembly_input_members($row: object) {
    RETURN [
        fn::tree::member($row.id, 'z_stock', $row.stock_account, 'z_history', $row.effective_at,
            { quantity: -<decimal>$row.quantity, available: -<decimal>$row.quantity }, { resource: $row.stock_account.resource, unit: $row.stock_account.unit }, {}, true),
        fn::tree::member($row.id, 'z_gross_input', $row.stock_account, 'z_gross_input', $row.effective_at,
            { gross_input: <decimal>$row.quantity }, { resource: $row.stock_account.resource, unit: $row.stock_account.unit }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::assembly_input_validate($row: object) {
    LET $prior = fn::tree::before({ rid: $row.stock_account, slot: 'z_history' }, [$row.effective_at]);
    LET $upper = $row.effective_at + 1ns;
    LET $gross = fn::tree::range({ rid: $row.stock_account, slot: 'z_gross_input' }, [$row.effective_at], [$upper]);
    IF ($gross.measures.gross_input.sum ?? 0dec) > ($prior.measures.quantity.sum ?? 0dec) {
        THROW 'ACCOUNTING_ASSEMBLY_GROSS_INPUT_CAPACITY';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE assembly_input SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::accounting::assembly_input_members @rebase-validate fn::accounting::assembly_input_validate';
DEFINE FIELD OVERWRITE rebase_managed_source ON assembly_input TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON assembly_input TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE stock_account ON assembly_input TYPE record<stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE quantity ON assembly_input TYPE int ASSERT $value > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON assembly_input TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_stock ON assembly_input TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';
DEFINE FIELD OVERWRITE z_gross_input ON assembly_input TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_gross_input';

DEFINE FUNCTION OVERWRITE fn::accounting::assembly_output_members($row: object) {
    RETURN [fn::tree::member($row.id, 'z_stock', $row.stock_account, 'z_history', $row.effective_at,
        { quantity: <decimal>$row.quantity, available: <decimal>$row.quantity }, { resource: $row.stock_account.resource, unit: $row.stock_account.unit }, {}, true)];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::assembly_output_validate($row: object) {
    LET $used = -($row.z_capacity.summary.measures.quantity.instant_min ?? 0dec);
    IF $used > <decimal>$row.quantity { THROW 'ACCOUNTING_ASSEMBLY_OUTPUT_CAPACITY'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE assembly_output SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::accounting::assembly_output_members @rebase-validate fn::accounting::assembly_output_validate';
DEFINE FIELD OVERWRITE rebase_managed_source ON assembly_output TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON assembly_output TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE stock_account ON assembly_output TYPE record<stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE economic_entity ON assembly_output TYPE record<rebase_user | organization> VALUE $this.stock_account.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends stock_account.economic_entity';
DEFINE FIELD OVERWRITE resource ON assembly_output TYPE record<item | service | work_type> VALUE $this.stock_account.resource READONLY COMMENT '@rebase-derived @rebase-depends stock_account.resource';
DEFINE FIELD OVERWRITE unit ON assembly_output TYPE record<measure_unit> VALUE $this.stock_account.unit READONLY COMMENT '@rebase-derived @rebase-depends stock_account.unit';
DEFINE FIELD OVERWRITE quantity ON assembly_output TYPE int ASSERT $value > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON assembly_output TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_stock ON assembly_output TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';
DEFINE FIELD OVERWRITE z_capacity ON assembly_output TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

-- Existing stock_out remains the one physical/capacity debit. H7 adds only a
-- typed optional link and a second, non-stock usage tree for that output role.
DEFINE FUNCTION OVERWRITE fn::accounting::stock_out_members($row: object) {
    RETURN [
        fn::movement::stock_position($row.id, 'z_from', $row.from_account, $row.effective_at, -$row.quantity),
        fn::tree::member($row.id, 'z_return_grant', $row.id, 'z_returns', $row.effective_at,
            { quantity: $row.quantity }, { resource: $row.from_account.resource, unit: $row.from_account.unit }, {}, false),
        IF $row.assembly_output = NONE THEN NONE ELSE
            fn::tree::member($row.id, 'z_assembly_output', $row.assembly_output, 'z_capacity', $row.effective_at,
                { quantity: -$row.quantity }, {}, {}, false) END
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::stock_out_validate($row: object) {
    IF ($row.z_billing.summary.measures.billed.max_prefix ?? 0dec) > $row.quantity {
        THROW 'ACCOUNTING_STOCK_OUT_OVERBILLED';
    };
    IF ($row.z_returns.summary.measures.quantity.instant_min ?? 0dec) < 0dec {
        THROW 'ACCOUNTING_STOCK_OUT_RETURN_CAPACITY';
    };
    IF $row.assembly_output != NONE {
        IF $row.assembly_output_account != $row.from_account {
            THROW 'ACCOUNTING_STOCK_OUT_ASSEMBLY_ACCOUNT_MISMATCH';
        };
        IF $row.assembly_output_entity != $row.from_account.economic_entity
            OR $row.assembly_output_resource != $row.from_account.resource
            OR $row.assembly_output_unit != $row.from_account.unit {
            THROW 'ACCOUNTING_STOCK_OUT_ASSEMBLY_DIMENSION_MISMATCH';
        };
        IF $row.effective_at < $row.assembly_output_at {
            THROW 'ACCOUNTING_STOCK_OUT_BEFORE_ASSEMBLY_OUTPUT';
        };
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE stock_out SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::stock_out_members @rebase-validate fn::accounting::stock_out_validate';
DEFINE FIELD OVERWRITE assembly_output ON stock_out TYPE option<record<assembly_output>> DEFAULT NONE REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE assembly_output_account ON stock_out TYPE option<record<stock_account>> VALUE IF $this.assembly_output = NONE THEN NONE ELSE $this.assembly_output.stock_account END COMMENT '@rebase-derived @rebase-depends assembly_output.stock_account';
DEFINE FIELD OVERWRITE assembly_output_entity ON stock_out TYPE option<record<rebase_user | organization>> VALUE IF $this.assembly_output = NONE THEN NONE ELSE $this.assembly_output.economic_entity END COMMENT '@rebase-derived @rebase-depends assembly_output.economic_entity';
DEFINE FIELD OVERWRITE assembly_output_resource ON stock_out TYPE option<record<item | service | work_type>> VALUE IF $this.assembly_output = NONE THEN NONE ELSE $this.assembly_output.resource END COMMENT '@rebase-derived @rebase-depends assembly_output.resource';
DEFINE FIELD OVERWRITE assembly_output_unit ON stock_out TYPE option<record<measure_unit>> VALUE IF $this.assembly_output = NONE THEN NONE ELSE $this.assembly_output.unit END COMMENT '@rebase-derived @rebase-depends assembly_output.unit';
DEFINE FIELD OVERWRITE assembly_output_at ON stock_out TYPE option<datetime> VALUE IF $this.assembly_output = NONE THEN NONE ELSE $this.assembly_output.effective_at END COMMENT '@rebase-derived @rebase-depends assembly_output.effective_at';
DEFINE FIELD OVERWRITE z_assembly_output ON stock_out TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner assembly_output.z_capacity';
