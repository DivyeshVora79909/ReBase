USE NS main DB main;

-- 1. SINGLETONS
DEFINE TABLE OVERWRITE company_settings SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'company_settings_select' IN $auth.permissions 
    FOR create, update, delete WHERE 'company_settings_manage' IN $auth.permissions;

-- 2. MASTER NODES & CONFIG
DEFINE TABLE OVERWRITE account SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'account_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'account_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'account_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'account_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE tracking_tag SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'tracking_tag_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'tracking_tag_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'tracking_tag_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'tracking_tag_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE tax_rate SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'tax_rate_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'tax_rate_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'tax_rate_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'tax_rate_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE contact SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'contact_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'contact_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'contact_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'contact_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE item SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'item_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'item_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'item_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'item_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE bank_account SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'bank_account_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'bank_account_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'bank_account_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'bank_account_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

-- 3. PARENT DOCUMENTS & LEDGERS
DEFINE TABLE OVERWRITE document SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'document_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'document_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'document_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'document_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE payment SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'payment_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'payment_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'payment_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'payment_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE journal_entry SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'journal_select' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR create WHERE 'journal_create' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR update WHERE 'journal_update' IN $auth.permissions AND (owned_by IN $auth.dominates OR owned_by IN $auth.parents) 
    FOR delete WHERE 'journal_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);

-- 4. CHILD EDGES (Traverse to Parent Ownership)
DEFINE TABLE OVERWRITE document_line SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'document_select' IN $auth.permissions AND (document_ref.owned_by IN $auth.dominates OR document_ref.owned_by IN $auth.parents) 
    FOR create WHERE 'document_create' IN $auth.permissions AND (document_ref.owned_by IN $auth.dominates OR document_ref.owned_by IN $auth.parents) 
    FOR update WHERE 'document_update' IN $auth.permissions AND (document_ref.owned_by IN $auth.dominates OR document_ref.owned_by IN $auth.parents) 
    FOR delete WHERE 'document_delete' IN $auth.permissions AND (document_ref.owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE payment_allocation SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'payment_select' IN $auth.permissions AND (payment_ref.owned_by IN $auth.dominates OR payment_ref.owned_by IN $auth.parents) 
    FOR create WHERE 'payment_create' IN $auth.permissions AND (payment_ref.owned_by IN $auth.dominates OR payment_ref.owned_by IN $auth.parents) 
    FOR update WHERE 'payment_update' IN $auth.permissions AND (payment_ref.owned_by IN $auth.dominates OR payment_ref.owned_by IN $auth.parents) 
    FOR delete WHERE 'payment_delete' IN $auth.permissions AND (payment_ref.owned_by IN $auth.dominates);

DEFINE TABLE OVERWRITE journal_line SCHEMAFULL PERMISSIONS 
    FOR select WHERE 'journal_select' IN $auth.permissions AND (journal_entry_ref.owned_by IN $auth.dominates OR journal_entry_ref.owned_by IN $auth.parents) 
    FOR create WHERE 'journal_create' IN $auth.permissions AND (journal_entry_ref.owned_by IN $auth.dominates OR journal_entry_ref.owned_by IN $auth.parents) 
    FOR update WHERE 'journal_update' IN $auth.permissions AND (journal_entry_ref.owned_by IN $auth.dominates OR journal_entry_ref.owned_by IN $auth.parents) 
    FOR delete WHERE 'journal_delete' IN $auth.permissions AND (journal_entry_ref.owned_by IN $auth.dominates);