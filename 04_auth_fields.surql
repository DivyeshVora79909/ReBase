USE NS main DB main;

DEFINE FIELD OVERWRITE owned_by ON equity_account TYPE record<groups> REFERENCE ON DELETE REJECT
    PERMISSIONS 
        FOR select WHERE TRUE 
        FOR create WHERE $value IN $auth.dominates 
        FOR update WHERE $value = $before OR $value IN $auth.dominates;

DEFINE FIELD OVERWRITE owned_by ON icce TYPE record<groups> REFERENCE ON DELETE REJECT
    PERMISSIONS 
        FOR select WHERE TRUE 
        FOR create WHERE $value IN $auth.dominates 
        FOR update WHERE $value = $before OR $value IN $auth.dominates;

DEFINE FIELD OVERWRITE owned_by ON organization_account TYPE record<groups> REFERENCE ON DELETE REJECT
    PERMISSIONS 
        FOR select WHERE TRUE 
        FOR create WHERE $value IN $auth.dominates 
        FOR update WHERE $value = $before OR $value IN $auth.dominates;

DEFINE FIELD OVERWRITE owned_by ON tax_account TYPE record<groups> REFERENCE ON DELETE REJECT
    PERMISSIONS 
        FOR select WHERE TRUE 
        FOR create WHERE $value IN $auth.dominates 
        FOR update WHERE $value = $before OR $value IN $auth.dominates;

DEFINE FIELD OVERWRITE owned_by ON catalog_item TYPE record<groups> REFERENCE ON DELETE REJECT
    PERMISSIONS 
        FOR select WHERE TRUE 
        FOR create WHERE $value IN $auth.dominates 
        FOR update WHERE $value = $before OR $value IN $auth.dominates;

DEFINE FIELD OVERWRITE owned_by ON inventory TYPE record<groups> REFERENCE ON DELETE REJECT
    PERMISSIONS 
        FOR select WHERE TRUE 
        FOR create WHERE $value IN $auth.dominates 
        FOR update WHERE $value = $before OR $value IN $auth.dominates;

-- ==========================================
-- B. THE VERBS (ACTION DOCUMENTS)
-- ==========================================

DEFINE FIELD OVERWRITE owned_by ON invoice TYPE record<groups> REFERENCE ON DELETE REJECT
    PERMISSIONS 
        FOR select WHERE TRUE 
        FOR create WHERE $value IN $auth.dominates 
        FOR update WHERE $value = $before OR $value IN $auth.dominates;

DEFINE FIELD OVERWRITE owned_by ON vendor_bill TYPE record<groups> REFERENCE ON DELETE REJECT
    PERMISSIONS 
        FOR select WHERE TRUE 
        FOR create WHERE $value IN $auth.dominates 
        FOR update WHERE $value = $before OR $value IN $auth.dominates;

DEFINE FIELD OVERWRITE owned_by ON payment TYPE record<groups> REFERENCE ON DELETE REJECT
    PERMISSIONS 
        FOR select WHERE TRUE 
        FOR create WHERE $value IN $auth.dominates 
        FOR update WHERE $value = $before OR $value IN $auth.dominates;

DEFINE FIELD OVERWRITE owned_by ON financial_adjustment TYPE record<groups> REFERENCE ON DELETE REJECT
    PERMISSIONS 
        FOR select WHERE TRUE 
        FOR create WHERE $value IN $auth.dominates 
        FOR update WHERE $value = $before OR $value IN $auth.dominates;

DEFINE FIELD OVERWRITE owned_by ON exchange TYPE record<groups> REFERENCE ON DELETE REJECT
    PERMISSIONS 
        FOR select WHERE TRUE 
        FOR create WHERE $value IN $auth.dominates 
        FOR update WHERE $value = $before OR $value IN $auth.dominates;