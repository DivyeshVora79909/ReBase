USE NS main DB main;

LET $all_tables = [
    'org', 'treasury', 'acc', 'tax_account', 'item', 'stock_acc', 'warehouse',
    'payment', 'invoice', 'adjustment_note',
    'payment_allocation', 'invoice_line', 'package_note',
    'sl', 'tax_line',
    'adjustment_line'
];

-- ==========================================
-- 1. UNIVERSAL CLUTCH (Performance Optimizer)
-- ==========================================
-- Prevents human metadata updates from triggering heavy mathematical subqueries.
-- Only system events (Direct Pings) are permitted to update this field.
FOR $tb IN $all_tables {
    DEFINE FIELD OVERWRITE system_ping ON TABLE $tb TYPE datetime 
        DEFAULT time::now() 
        PERMISSIONS FOR update NONE;
};

-- ==========================================
-- 2. THE STATE VECTORS (Strictly Limited)
-- ==========================================
-- By architectural decree, only these three tables are permitted to hold state.
-- All other tables must pull lock/suspend status via `za_parent` at runtime.
LET $state_tables = ['payment', 'invoice', 'sl'];

FOR $tb IN $state_tables {
    DEFINE FIELD OVERWRITE suspended ON TABLE $tb TYPE bool DEFAULT false;
    DEFINE FIELD OVERWRITE locked ON TABLE $tb TYPE bool DEFAULT false;
};