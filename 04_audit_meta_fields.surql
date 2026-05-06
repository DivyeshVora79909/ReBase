USE NS main DB main;

LET $tables =[
    'company_settings', 'treasury_account', 'trade_account', 'expense_account',
    'equity_account', 'inventory_node', 'catalog_node', 'tax_node',
    'invoice', 'vendor_bill', 'payment', 'adjustment_note',
    'production_run', 'financial_adjustment', 'exchange'
];

FOR $tb IN $tables {
    DEFINE FIELD OVERWRITE created_at ON TABLE $tb TYPE datetime VALUE $before OR time::now() READONLY;
    DEFINE FIELD OVERWRITE updated_at ON TABLE $tb TYPE datetime VALUE time::now();
    DEFINE FIELD OVERWRITE created_by ON TABLE $tb TYPE option<record<user>> VALUE $before OR $auth READONLY;
    DEFINE FIELD OVERWRITE updated_by ON TABLE $tb TYPE option<record<user>> VALUE $auth;
};

-- DEFINE FIELD OVERWRITE created_at ON company_settings TYPE datetime VALUE $before OR time::now() READONLY;
-- DEFINE FIELD OVERWRITE updated_at ON company_settings TYPE datetime VALUE time::now();
-- DEFINE FIELD OVERWRITE created_by ON company_settings TYPE option<record<user>> VALUE $before OR $auth READONLY;
-- DEFINE FIELD OVERWRITE updated_by ON company_settings TYPE option<record<user>> VALUE $auth;
