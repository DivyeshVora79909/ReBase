USE NS main DB main;

-- 1. PARENT / STATELESS NODES
DEFINE TABLE OVERWRITE org SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'org_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'org_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'org_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'org_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE treasury SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'treasury_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'treasury_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'treasury_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'treasury_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE acc SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'acc_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'acc_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'acc_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'acc_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE warehouse SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'warehouse_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'warehouse_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'warehouse_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'warehouse_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE stock_acc SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'stock_acc_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'stock_acc_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'stock_acc_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'stock_acc_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE item SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'item_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'item_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'item_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'item_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

-- 2. DEPENDENT NODES
DEFINE TABLE OVERWRITE payment SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'payment_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'payment_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'payment_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'payment_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE invoice SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'invoice_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'invoice_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'invoice_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'invoice_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE sl SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'sl_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'sl_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'sl_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'sl_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE invoice_line SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'invoice_line_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'invoice_line_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'invoice_line_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'invoice_line_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE payment_allocation SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'payment_allocation_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'payment_allocation_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'payment_allocation_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'payment_allocation_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);