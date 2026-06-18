USE NS main DB main;

-- 1. ROOT NODES (Manual / Dominated Assignment)
LET $root_tables = [
    'org', 'treasury', 'acc', 'tax_account', 
    'item', 'stock_acc', 'warehouse',
    'payment', 'invoice', 'adjustment_note'
];

FOR $tb IN $root_tables {
    DEFINE FIELD OVERWRITE owned_by ON TABLE $tb TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS
        FOR select WHERE TRUE
        FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates
        FOR update WHERE $value = $before OR $value IN $auth.dominates;
};

-- 2. CHILD EDGES & DELTAS (Immutable Inheritance)
DEFINE FIELD OVERWRITE owned_by ON TABLE payment_allocation TYPE option<record<groups>> VALUE $this.payment.owned_by;
DEFINE FIELD OVERWRITE owned_by ON TABLE invoice_line TYPE option<record<groups>> VALUE $this.invoice.owned_by;
DEFINE FIELD OVERWRITE owned_by ON TABLE package_note TYPE option<record<groups>> VALUE $this.invoice.owned_by;

DEFINE FIELD OVERWRITE owned_by ON TABLE sl TYPE option<record<groups>> VALUE $this.inv_line.owned_by ?? $this.pkg.owned_by ?? $this.from.owned_by;
DEFINE FIELD OVERWRITE owned_by ON TABLE tax_line TYPE option<record<groups>> VALUE $this.invoice_line.owned_by;

DEFINE FIELD OVERWRITE owned_by ON TABLE adjustment_line TYPE option<record<groups>> VALUE $this.adjustment_note.owned_by;
DEFINE FIELD OVERWRITE owned_by ON TABLE adjustment_tax_line TYPE option<record<groups>> VALUE $this.adjustment_note.owned_by;
DEFINE FIELD OVERWRITE owned_by ON TABLE adjustment_stock_line TYPE option<record<groups>> VALUE $this.adjustment_note.owned_by;