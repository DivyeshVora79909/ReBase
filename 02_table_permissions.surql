USE NS main DB main;

-- 1. SINGLETONS
DEFINE TABLE OVERWRITE company_settings SCHEMAFULL PERMISSIONS
    FOR select WHERE 'company_settings_select' IN $auth.permissions
    FOR create, update, delete WHERE 'company_settings_manage' IN $auth.permissions;

-- 2. MASTER NODES
DEFINE TABLE OVERWRITE treasury_account SCHEMAFULL PERMISSIONS
    FOR select WHERE 'treasury_account_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'treasury_account_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'treasury_account_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'treasury_account_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE trade_account SCHEMAFULL PERMISSIONS
    FOR select WHERE 'trade_account_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'trade_account_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'trade_account_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'trade_account_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE expense_account SCHEMAFULL PERMISSIONS
    FOR select WHERE 'expense_account_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'expense_account_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'expense_account_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'expense_account_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE equity_account SCHEMAFULL PERMISSIONS
    FOR select WHERE 'equity_account_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'equity_account_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'equity_account_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'equity_account_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE inventory_node SCHEMAFULL PERMISSIONS
    FOR select WHERE 'inventory_node_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'inventory_node_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'inventory_node_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'inventory_node_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE catalog_node SCHEMAFULL PERMISSIONS
    FOR select WHERE 'catalog_node_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'catalog_node_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'catalog_node_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'catalog_node_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE location_node SCHEMAFULL PERMISSIONS
    FOR select WHERE 'location_node_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'location_node_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'location_node_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'location_node_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE tax_node SCHEMAFULL PERMISSIONS
    FOR select WHERE 'tax_node_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'tax_node_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'tax_node_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'tax_node_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

-- 3. PARENT DOCUMENTS
DEFINE TABLE OVERWRITE order SCHEMAFULL PERMISSIONS
    FOR select WHERE 'order_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'order_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'order_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'order_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE invoice SCHEMAFULL PERMISSIONS
    FOR select WHERE 'invoice_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'invoice_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'invoice_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'invoice_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE vendor_bill SCHEMAFULL PERMISSIONS
    FOR select WHERE 'vendor_bill_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'vendor_bill_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'vendor_bill_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'vendor_bill_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE adjustment_note SCHEMAFULL PERMISSIONS
    FOR select WHERE 'adjustment_note_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'adjustment_note_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'adjustment_note_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'adjustment_note_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE payment SCHEMAFULL PERMISSIONS
    FOR select WHERE 'payment_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'payment_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'payment_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'payment_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE financial_adjustment SCHEMAFULL PERMISSIONS
    FOR select WHERE 'financial_adjustment_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'financial_adjustment_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'financial_adjustment_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'financial_adjustment_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE exchange SCHEMAFULL PERMISSIONS
    FOR select WHERE 'exchange_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'exchange_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'exchange_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'exchange_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE production_run SCHEMAFULL PERMISSIONS
    FOR select WHERE 'production_run_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR create WHERE 'production_run_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR update WHERE 'production_run_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents)
    FOR delete WHERE 'production_run_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

-- 4. CHILD EDGES (Inherits Parent's Ownership)
DEFINE TABLE OVERWRITE order_line SCHEMAFULL PERMISSIONS
    FOR select WHERE 'order_select' IN $auth.permissions AND (order_ref.owned_by IN $auth.dominates OR order_ref.owned_by IN $auth.parents)
    FOR create WHERE 'order_create' IN $auth.permissions AND (order_ref.owned_by IN $auth.dominates OR order_ref.owned_by IN $auth.parents)
    FOR update WHERE 'order_update' IN $auth.permissions AND (order_ref.owned_by IN $auth.dominates OR order_ref.owned_by IN $auth.parents)
    FOR delete WHERE 'order_delete' IN $auth.permissions AND (order_ref.owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE invoice_line SCHEMAFULL PERMISSIONS
    FOR select WHERE 'invoice_select' IN $auth.permissions AND (invoice_ref.owned_by IN $auth.dominates OR invoice_ref.owned_by IN $auth.parents)
    FOR create WHERE 'invoice_create' IN $auth.permissions AND (invoice_ref.owned_by IN $auth.dominates OR invoice_ref.owned_by IN $auth.parents)
    FOR update WHERE 'invoice_update' IN $auth.permissions AND (invoice_ref.owned_by IN $auth.dominates OR invoice_ref.owned_by IN $auth.parents)
    FOR delete WHERE 'invoice_delete' IN $auth.permissions AND (invoice_ref.owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE vendor_bill_line SCHEMAFULL PERMISSIONS
    FOR select WHERE 'vendor_bill_select' IN $auth.permissions AND (bill_ref.owned_by IN $auth.dominates OR bill_ref.owned_by IN $auth.parents)
    FOR create WHERE 'vendor_bill_create' IN $auth.permissions AND (bill_ref.owned_by IN $auth.dominates OR bill_ref.owned_by IN $auth.parents)
    FOR update WHERE 'vendor_bill_update' IN $auth.permissions AND (bill_ref.owned_by IN $auth.dominates OR bill_ref.owned_by IN $auth.parents)
    FOR delete WHERE 'vendor_bill_delete' IN $auth.permissions AND (bill_ref.owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE adjustment_note_line SCHEMAFULL PERMISSIONS
    FOR select WHERE 'adjustment_note_select' IN $auth.permissions AND (note_ref.owned_by IN $auth.dominates OR note_ref.owned_by IN $auth.parents)
    FOR create WHERE 'adjustment_note_create' IN $auth.permissions AND (note_ref.owned_by IN $auth.dominates OR note_ref.owned_by IN $auth.parents)
    FOR update WHERE 'adjustment_note_update' IN $auth.permissions AND (note_ref.owned_by IN $auth.dominates OR note_ref.owned_by IN $auth.parents)
    FOR delete WHERE 'adjustment_note_delete' IN $auth.permissions AND (note_ref.owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE payment_allocation SCHEMAFULL PERMISSIONS
    FOR select WHERE 'payment_select' IN $auth.permissions AND (payment_ref.owned_by IN $auth.dominates OR payment_ref.owned_by IN $auth.parents)
    FOR create WHERE 'payment_create' IN $auth.permissions AND (payment_ref.owned_by IN $auth.dominates OR payment_ref.owned_by IN $auth.parents)
    FOR update WHERE 'payment_update' IN $auth.permissions AND (payment_ref.owned_by IN $auth.dominates OR payment_ref.owned_by IN $auth.parents)
    FOR delete WHERE 'payment_delete' IN $auth.permissions AND (payment_ref.owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE exchange_line SCHEMAFULL PERMISSIONS
    FOR select WHERE 'exchange_select' IN $auth.permissions AND (exchange_ref.owned_by IN $auth.dominates OR exchange_ref.owned_by IN $auth.parents)
    FOR create WHERE 'exchange_create' IN $auth.permissions AND (exchange_ref.owned_by IN $auth.dominates OR exchange_ref.owned_by IN $auth.parents)
    FOR update WHERE 'exchange_update' IN $auth.permissions AND (exchange_ref.owned_by IN $auth.dominates OR exchange_ref.owned_by IN $auth.parents)
    FOR delete WHERE 'exchange_delete' IN $auth.permissions AND (exchange_ref.owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE production_line SCHEMAFULL PERMISSIONS
    FOR select WHERE 'production_run_select' IN $auth.permissions AND (run_ref.owned_by IN $auth.dominates OR run_ref.owned_by IN $auth.parents)
    FOR create WHERE 'production_run_create' IN $auth.permissions AND (run_ref.owned_by IN $auth.dominates OR run_ref.owned_by IN $auth.parents)
    FOR update WHERE 'production_run_update' IN $auth.permissions AND (run_ref.owned_by IN $auth.dominates OR run_ref.owned_by IN $auth.parents)
    FOR delete WHERE 'production_run_delete' IN $auth.permissions AND (run_ref.owned_by IN $auth.dominates);
