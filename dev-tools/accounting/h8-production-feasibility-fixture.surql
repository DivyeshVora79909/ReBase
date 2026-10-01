-- H8 pre-code feasibility fixture only. Quantity and available are separate
-- measures on the existing stock history root; gross_input is a same-time guard.
DEFINE TABLE OVERWRITE h8_recipe SCHEMAFULL;
DEFINE FIELD OVERWRITE duration ON h8_recipe TYPE duration ASSERT $value > 0s READONLY;

DEFINE FUNCTION OVERWRITE fn::h8::grant_members($row: object) {
    RETURN [fn::tree::member($row.id, 'z_stock', $row.stock_account, 'z_history', $row.effective_at,
        { quantity: $row.quantity, available: $row.quantity }, { resource: $row.stock_account.resource, unit: $row.stock_account.unit }, {}, true)];
} PERMISSIONS NONE;
DEFINE TABLE OVERWRITE h8_stock_grant SCHEMAFULL COMMENT '@rebase-members fn::h8::grant_members';
DEFINE FIELD OVERWRITE stock_account ON h8_stock_grant TYPE record<stock_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE quantity ON h8_stock_grant TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD OVERWRITE effective_at ON h8_stock_grant TYPE datetime;
DEFINE FIELD OVERWRITE z_stock ON h8_stock_grant TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';

DEFINE FUNCTION OVERWRITE fn::h8::debit_members($row: object) {
    RETURN [fn::tree::member($row.id, 'z_stock', $row.stock_account, 'z_history', $row.effective_at,
        { quantity: -$row.quantity, available: -$row.quantity }, { resource: $row.stock_account.resource, unit: $row.stock_account.unit }, {}, true)];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::h8::debit_validate($row: object) {
    IF ($row.stock_account.z_history.summary.measures.available.instant_min ?? 0dec) < 0dec {
        THROW 'H8_AVAILABLE_STOCK_CAPACITY';
    };
} PERMISSIONS FULL;
DEFINE TABLE OVERWRITE h8_stock_debit SCHEMAFULL COMMENT '@rebase-members fn::h8::debit_members @rebase-validate fn::h8::debit_validate';
DEFINE FIELD OVERWRITE stock_account ON h8_stock_debit TYPE record<stock_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE quantity ON h8_stock_debit TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD OVERWRITE effective_at ON h8_stock_debit TYPE datetime;
DEFINE FIELD OVERWRITE z_stock ON h8_stock_debit TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';

DEFINE FUNCTION OVERWRITE fn::h8::run_members($row: object) {
    IF $row.status = 'draft' OR ($row.status = 'cancelled' AND $row.cancelled_at <= $row.planned_start) { RETURN []; };
    LET $reserve = fn::tree::member($row.id, 'z_reserve', $row.stock_account, 'z_history', $row.planned_start,
        { available: -$row.input_quantity }, { resource: $row.stock_account.resource, unit: $row.stock_account.unit }, {}, true);
    IF $row.status = 'cancelled' {
        RETURN [$reserve, fn::tree::member($row.id, 'z_cancel_release', $row.stock_account, 'z_history', $row.cancelled_at,
            { available: $row.input_quantity }, { resource: $row.stock_account.resource, unit: $row.stock_account.unit }, {}, true)];
    };
    RETURN [
        $reserve,
        fn::tree::member($row.id, 'z_end', $row.stock_account, 'z_history', $row.end_at,
            { quantity: $row.output_quantity - $row.input_quantity,
              available: $row.output_quantity, gross_input: $row.input_quantity },
            { resource: $row.stock_account.resource, unit: $row.stock_account.unit }, {}, true)
    ];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::h8::run_validate($row: object) {
    IF $row.status = 'cancelled' AND $row.cancelled_at = NONE { THROW 'H8_CANCEL_TIME_REQUIRED'; };
    IF $row.status != 'cancelled' AND $row.cancelled_at != NONE { THROW 'H8_CANCEL_TIME_UNEXPECTED'; };
    IF $row.status = 'cancelled' AND $row.cancelled_at >= $row.end_at { THROW 'H8_CANCEL_AFTER_END'; };
    IF ($row.stock_account.z_history.summary.measures.available.instant_min ?? 0dec) < 0dec {
        THROW 'H8_RESERVATION_CAPACITY';
    };
    IF $row.status = 'scheduled' {
        LET $prior = fn::tree::before({ rid: $row.stock_account, slot: 'z_history' }, [$row.end_at]);
        LET $upper = $row.end_at + 1ns;
        LET $gross = fn::tree::range({ rid: $row.stock_account, slot: 'z_history' }, [$row.end_at], [$upper]);
        IF ($gross.measures.gross_input.sum ?? 0dec) > ($prior.measures.quantity.sum ?? 0dec) {
            THROW 'H8_GROSS_END_CAPACITY';
        };
    };
} PERMISSIONS FULL;
DEFINE TABLE OVERWRITE h8_run_fact SCHEMAFULL
    COMMENT '@rebase-members fn::h8::run_members @rebase-validate fn::h8::run_validate';
DEFINE FIELD OVERWRITE recipe ON h8_run_fact TYPE record<h8_recipe> REFERENCE ON DELETE REJECT READONLY;
DEFINE FIELD OVERWRITE stock_account ON h8_run_fact TYPE record<stock_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE input_quantity ON h8_run_fact TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD OVERWRITE output_quantity ON h8_run_fact TYPE decimal ASSERT $value >= 0dec;
DEFINE FIELD OVERWRITE planned_start ON h8_run_fact TYPE datetime;
DEFINE FIELD OVERWRITE end_at ON h8_run_fact TYPE datetime VALUE $this.planned_start + $this.recipe.duration COMMENT '@rebase-derived @rebase-depends planned_start recipe.duration';
DEFINE FIELD OVERWRITE status ON h8_run_fact TYPE string ASSERT $value IN ['draft', 'scheduled', 'cancelled'];
DEFINE FIELD OVERWRITE cancelled_at ON h8_run_fact TYPE option<datetime> DEFAULT NONE;
DEFINE FIELD OVERWRITE z_reserve ON h8_run_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';
DEFINE FIELD OVERWRITE z_cancel_release ON h8_run_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';
DEFINE FIELD OVERWRITE z_end ON h8_run_fact TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';

-- Disposable equivalents of the compiler-generated refresh events. Defining
-- table handlers alone does not attach those events to newly added fixture tables.
DEFINE EVENT OVERWRITE rebase_refresh ON h8_stock_grant
WHEN $event != 'UPDATE' OR ($before.stock_account != $after.stock_account OR $before.quantity != $after.quantity OR $before.effective_at != $after.effective_at) THEN {
    LET $before_image = IF $event = 'CREATE' THEN NONE ELSE $before END;
    fn::rebase::finish(fn::rebase::refresh($after.id ?? $before.id, $before_image, true));
};
DEFINE EVENT OVERWRITE rebase_refresh ON h8_stock_debit
WHEN $event != 'UPDATE' OR ($before.stock_account != $after.stock_account OR $before.quantity != $after.quantity OR $before.effective_at != $after.effective_at) THEN {
    LET $before_image = IF $event = 'CREATE' THEN NONE ELSE $before END;
    fn::rebase::finish(fn::rebase::refresh($after.id ?? $before.id, $before_image, true));
};
DEFINE EVENT OVERWRITE rebase_refresh ON h8_run_fact
WHEN $event != 'UPDATE' OR ($before.recipe != $after.recipe OR $before.stock_account != $after.stock_account OR $before.input_quantity != $after.input_quantity OR $before.output_quantity != $after.output_quantity OR $before.planned_start != $after.planned_start OR $before.status != $after.status OR $before.cancelled_at != $after.cancelled_at) THEN {
    LET $before_image = IF $event = 'CREATE' THEN NONE ELSE $before END;
    fn::rebase::finish(fn::rebase::refresh($after.id ?? $before.id, $before_image, true));
};
