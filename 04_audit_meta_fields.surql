USE NS main DB main;

LET $all_tables = [
    'org', 'treasury', 'acc', 'tax_account', 'item', 'stock_acc', 'warehouse',
    'payment', 'invoice', 'adjustment_note',
    'payment_allocation', 'invoice_line', 'package_note',
    'sl', 'tax_line',
    'adjustment_line'
];

-- Apply universal tracking to every table in the architecture
FOR $tb IN $all_tables {
    DEFINE FIELD OVERWRITE created_at ON TABLE $tb TYPE datetime 
        VALUE $before OR time::now() READONLY;
        
    DEFINE FIELD OVERWRITE updated_at ON TABLE $tb TYPE datetime 
        VALUE time::now();
        
    DEFINE FIELD OVERWRITE created_by ON TABLE $tb TYPE option<record<user>> 
        VALUE $before OR $auth READONLY;
        
    DEFINE FIELD OVERWRITE updated_by ON TABLE $tb TYPE option<record<user>> 
        VALUE $auth;
};