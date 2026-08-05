-- ================================================================
-- 1. SINGLETONS & SYSTEM TABLES
-- ================================================================
DEFINE TABLE OVERWRITE company_settings SCHEMAFULL PERMISSIONS 
    FOR select WHERE TRUE 
    FOR create, update, delete WHERE 'settings_manage' IN $auth.permissions;
    
DEFINE TABLE OVERWRITE document_sequence SCHEMAFULL PERMISSIONS 
    FOR select WHERE TRUE 
    FOR create, update, delete WHERE 'settings_manage' IN $auth.permissions;

-- ================================================================
-- 2. MASTER DATA (Dictionaries & Ledgers)
-- ================================================================
LET $master_tables = ['account', 'contact', 'item', 'tax_rate', 'bank_account', 'location', 'tracking_tag'];
FOR $tb IN $master_tables {
    DEFINE TABLE OVERWRITE $tb SCHEMAFULL PERMISSIONS 
        FOR select WHERE (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
        FOR create, update WHERE 'master_data_manage' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
        FOR delete WHERE 'master_data_manage' IN $auth.permissions AND (owned_by IN $auth.dominates);
};

-- ================================================================
-- 3. PARENT DOCUMENTS (Top-Level Intent Nodes)
-- ================================================================
LET $sales_tables = ['sales_order', 'sales_invoice'];
FOR $tb IN $sales_tables {
    DEFINE TABLE OVERWRITE $tb SCHEMAFULL PERMISSIONS 
        FOR select WHERE (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
        FOR create, update WHERE 'sales_manage' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
        FOR delete WHERE 'sales_manage' IN $auth.permissions AND (owned_by IN $auth.dominates);
};

LET $purchase_tables = ['purchase_order', 'vendor_bill'];
FOR $tb IN $purchase_tables {
    DEFINE TABLE OVERWRITE $tb SCHEMAFULL PERMISSIONS 
        FOR select WHERE (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
        FOR create, update WHERE 'purchase_manage' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
        FOR delete WHERE 'purchase_manage' IN $auth.permissions AND (owned_by IN $auth.dominates);
};

DEFINE TABLE OVERWRITE adjustment SCHEMAFULL PERMISSIONS 
    FOR select WHERE (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create, update WHERE 'adjustment_manage' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'adjustment_manage' IN $auth.permissions AND (owned_by IN $auth.dominates);

LET $treasury_tables = ['payment', 'financial_adjustment'];
FOR $tb IN $treasury_tables {
    DEFINE TABLE OVERWRITE $tb SCHEMAFULL PERMISSIONS 
        FOR select WHERE (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
        FOR create, update WHERE 'treasury_manage' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
        FOR delete WHERE 'treasury_manage' IN $auth.permissions AND (owned_by IN $auth.dominates);
};

LET $inventory_tables = ['exchange', 'production_run'];
FOR $tb IN $inventory_tables {
    DEFINE TABLE OVERWRITE $tb SCHEMAFULL PERMISSIONS 
        FOR select WHERE (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
        FOR create, update WHERE 'inventory_manage' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
        FOR delete WHERE 'inventory_manage' IN $auth.permissions AND (owned_by IN $auth.dominates);
};

DEFINE TABLE OVERWRITE journal_entry SCHEMAFULL PERMISSIONS 
    FOR select WHERE (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create, update WHERE 'journal_manage' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'journal_manage' IN $auth.permissions AND (owned_by IN $auth.dominates);

-- ================================================================
-- 4. CHILD EDGES & IMMUTABLE LEDGERS (Traversal Permissions)
-- ================================================================
-- These tables don't need their own group ownership. They ask their parent.
DEFINE TABLE OVERWRITE sales_order_line SCHEMAFULL PERMISSIONS 
    FOR select, create, update, delete WHERE (order_ref.owned_by IN $auth.dominates OR order_ref.owned_by IN $auth.parents);

DEFINE TABLE OVERWRITE sales_invoice_line SCHEMAFULL PERMISSIONS 
    FOR select, create, update, delete WHERE (invoice_ref.owned_by IN $auth.dominates OR invoice_ref.owned_by IN $auth.parents);

DEFINE TABLE OVERWRITE purchase_order_line SCHEMAFULL PERMISSIONS 
    FOR select, create, update, delete WHERE (order_ref.owned_by IN $auth.dominates OR order_ref.owned_by IN $auth.parents);

DEFINE TABLE OVERWRITE vendor_bill_line SCHEMAFULL PERMISSIONS 
    FOR select, create, update, delete WHERE (bill_ref.owned_by IN $auth.dominates OR bill_ref.owned_by IN $auth.parents);

DEFINE TABLE OVERWRITE adjustment_line SCHEMAFULL PERMISSIONS 
    FOR select, create, update, delete WHERE (adjustment_ref.owned_by IN $auth.dominates OR adjustment_ref.owned_by IN $auth.parents);

DEFINE TABLE OVERWRITE payment_allocation SCHEMAFULL PERMISSIONS 
    FOR select, create, update, delete WHERE (payment_ref.owned_by IN $auth.dominates OR payment_ref.owned_by IN $auth.parents);

DEFINE TABLE OVERWRITE exchange_line SCHEMAFULL PERMISSIONS 
    FOR select, create, update, delete WHERE (exchange_ref.owned_by IN $auth.dominates OR exchange_ref.owned_by IN $auth.parents);

DEFINE TABLE OVERWRITE production_line SCHEMAFULL PERMISSIONS 
    FOR select, create, update, delete WHERE (run_ref.owned_by IN $auth.dominates OR run_ref.owned_by IN $auth.parents);

DEFINE TABLE OVERWRITE journal_line SCHEMAFULL PERMISSIONS 
    FOR select, create, update, delete WHERE (journal_ref.owned_by IN $auth.dominates OR journal_ref.owned_by IN $auth.parents);

-- Physical movements derive permission from whatever document triggered them
DEFINE TABLE OVERWRITE stock_movement SCHEMAFULL PERMISSIONS 
    FOR select, create, update, delete WHERE (source_doc.owned_by IN $auth.dominates OR source_doc.owned_by IN $auth.parents);

INFO FOR DB;