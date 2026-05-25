USE NS main DB main;

-- 1. ROOT NODES (Manual / Dominated Assignment)
LET $root_tables = [
    'org', 'treasury', 'acc', 'item', 'stock_acc', 'warehouse',
    'payment', 'invoice', 'sl'
];

FOR $tb IN $root_tables {
    DEFINE FIELD OVERWRITE owned_by ON TABLE $tb TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS 
        FOR select WHERE TRUE 
        FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates 
        FOR update WHERE $value = $before OR $value IN $auth.dominates;
};

-- 2. CHILD EDGES (Immutable Inheritance)
-- O(1) Inheritance. No traversal needed during auth queries.

DEFINE FIELD OVERWRITE owned_by ON TABLE invoice_line TYPE option<record<groups>> 
    VALUE $this.inv.owned_by;

DEFINE FIELD OVERWRITE owned_by ON TABLE payment_allocation TYPE option<record<groups>> 
    VALUE $this.payment.owned_by;