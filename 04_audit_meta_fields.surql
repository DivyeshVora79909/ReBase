USE NS main DB main;

LET $tables =[
    'company_settings', 
    'account', 
    'tracking_tag', 
    'tax_rate', 
    'contact', 
    'item', 
    'bank_account', 
    'document', 
    'document_line', 
    'payment', 
    'payment_allocation', 
    'journal_entry', 
    'journal_line'
];

FOR $tb IN $tables {
    DEFINE FIELD OVERWRITE created_at ON TABLE $tb TYPE datetime VALUE $before OR time::now() READONLY;
    DEFINE FIELD OVERWRITE updated_at ON TABLE $tb TYPE datetime VALUE time::now();
    DEFINE FIELD OVERWRITE created_by ON TABLE $tb TYPE option<record<user>> VALUE $before OR $auth READONLY;
    DEFINE FIELD OVERWRITE updated_by ON TABLE $tb TYPE option<record<user>> VALUE $auth;
};

-- DEFINE FIELD OVERWRITE created_at ON TABLE payment_allocation TYPE datetime VALUE $before OR time::now() READONLY;
-- DEFINE FIELD OVERWRITE updated_at ON TABLE payment_allocation TYPE datetime VALUE time::now();
-- DEFINE FIELD OVERWRITE created_by ON TABLE payment_allocation TYPE option<record<user>> VALUE $before OR $auth READONLY;
-- DEFINE FIELD OVERWRITE updated_by ON TABLE payment_allocation TYPE option<record<user>> VALUE $auth;