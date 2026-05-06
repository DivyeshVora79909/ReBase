USE NS main DB main;

LET $tables =[
    'treasury_account', 'trade_account', 'expense_account', 'equity_account',
    'inventory_node', 'catalog_node', 'location_node', 'tax_node',
    'order', 'invoice', 'vendor_bill', 'adjustment_note', 'payment',
    'exchange', 'production_run', 'financial_adjustment'
];

FOR $tb IN $tables {
    DEFINE FIELD OVERWRITE owned_by ON TABLE $tb TYPE record<groups> REFERENCE ON DELETE REJECT
    PERMISSIONS
        FOR select WHERE TRUE
        FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates
        FOR update WHERE
            $value = $before
            OR $value IN $auth.dominates;
};

-- DEFINE FIELD OVERWRITE owned_by ON treasury_account TYPE record<groups> REFERENCE ON DELETE REJECT
--     PERMISSIONS 
--         FOR select WHERE TRUE 
--         FOR create WHERE $value IN $auth.dominates 
--         FOR update WHERE 
--             $value = $before 
--             OR $value IN $auth.dominates;