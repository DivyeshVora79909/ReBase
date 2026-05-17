USE NS main DB main;

LET $tables =[
    'account', 
    'tracking_tag', 
    'tax_rate', 
    'contact', 
    'item', 
    'bank_account', 
    'document', 
    'payment', 
    'journal_entry'
];

FOR $tb IN $tables {
    DEFINE FIELD OVERWRITE owned_by ON TABLE $tb TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS 
        FOR select WHERE TRUE 
        FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates 
        FOR update WHERE $value = $before OR $value IN $auth.dominates;
};

-- DEFINE FIELD OVERWRITE owned_by ON TABLE journal_entry TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS 
--     FOR select WHERE TRUE 
--     FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates 
--     FOR update WHERE $value = $before OR $value IN $auth.dominates;