USE NS main DB main;

DEFINE TABLE OVERWRITE acc SCHEMAFULL PERMISSIONS
    FOR select WHERE 'acc_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'acc_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'acc_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'acc_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE adjustment_line SCHEMAFULL PERMISSIONS
    FOR select WHERE 'adjustment_line_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'adjustment_line_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'adjustment_line_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'adjustment_line_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE adjustment_note SCHEMAFULL PERMISSIONS
    FOR select WHERE 'adjustment_note_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'adjustment_note_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'adjustment_note_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'adjustment_note_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE invoice SCHEMAFULL PERMISSIONS
    FOR select WHERE 'invoice_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'invoice_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'invoice_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'invoice_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE invoice_line SCHEMAFULL PERMISSIONS
    FOR select WHERE 'invoice_line_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'invoice_line_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'invoice_line_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'invoice_line_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE item SCHEMAFULL PERMISSIONS
    FOR select WHERE 'item_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'item_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'item_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'item_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE org SCHEMAFULL PERMISSIONS
    FOR select WHERE 'org_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'org_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'org_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'org_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE package_note SCHEMAFULL PERMISSIONS
    FOR select WHERE 'package_note_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'package_note_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'package_note_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'package_note_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE payment SCHEMAFULL PERMISSIONS
    FOR select WHERE 'payment_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'payment_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'payment_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'payment_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE payment_allocation SCHEMAFULL PERMISSIONS
    FOR select WHERE 'payment_allocation_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'payment_allocation_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'payment_allocation_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'payment_allocation_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE sl SCHEMAFULL PERMISSIONS
    FOR select WHERE 'sl_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'sl_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'sl_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'sl_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE stock_acc SCHEMAFULL PERMISSIONS
    FOR select WHERE 'stock_acc_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'stock_acc_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'stock_acc_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'stock_acc_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE tax_account SCHEMAFULL PERMISSIONS
    FOR select WHERE 'tax_account_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'tax_account_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'tax_account_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'tax_account_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE tax_line SCHEMAFULL PERMISSIONS
    FOR select WHERE 'tax_line_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'tax_line_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'tax_line_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'tax_line_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE treasury SCHEMAFULL PERMISSIONS
    FOR select WHERE 'treasury_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'treasury_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'treasury_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'treasury_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE warehouse SCHEMAFULL PERMISSIONS
    FOR select WHERE 'warehouse_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)
    FOR create WHERE 'warehouse_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE 'warehouse_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE 'warehouse_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

