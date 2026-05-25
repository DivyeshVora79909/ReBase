USE NS main DB main;

-- UNIVERSAL AUDIT TRAILS & PING RECEIVERS
LET $tables = [
    -- 1. Parent / Stateless Nodes
    'org', 'treasury', 'acc', 
    'warehouse', 'stock_acc', 'item',
    -- 2. Dependent Nodes
    'payment', 'invoice', 'sl', 
    'invoice_line', 'payment_allocation'
];

FOR $tb IN $tables {
    -- Timestamps
    DEFINE FIELD OVERWRITE created_at ON TABLE $tb TYPE datetime 
        VALUE $before OR time::now() READONLY;
        
    DEFINE FIELD OVERWRITE updated_at ON TABLE $tb TYPE datetime 
        VALUE time::now();
        
    -- User Traceability
    DEFINE FIELD OVERWRITE created_by ON TABLE $tb TYPE option<record<user>> 
        VALUE $before OR $auth READONLY;
        
    DEFINE FIELD OVERWRITE updated_by ON TABLE $tb TYPE option<record<user>> 
        VALUE $auth;
};