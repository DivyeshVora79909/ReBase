USE NS main DB main;

-- ==========================================
-- 1. ROOT NODES (Manual / Dominated Assignment)
-- ==========================================
LET $root_tables = [
    'org', 'treasury', 'acc', 'tax_account', 'item', 'stock_acc', 'warehouse',
    'payment', 'invoice', 'adjustment_note'
];

FOR $tb IN $root_tables {
    -- Roots must be explicitly assigned to an RBAC group the user has rights to.
    DEFINE FIELD OVERWRITE owned_by ON TABLE $tb TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS
        FOR select WHERE TRUE
        FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates
        FOR update WHERE $value = $before OR $value IN $auth.dominates;
};

-- ==========================================
-- 2. BRANCH & LEAF NODES (Immutable Inheritance)
-- ==========================================
-- Branches and leaves inherit their security perimeter in O(1) time at creation.
-- This ensures that querying a leaf node instantly resolves its access control.

DEFINE FIELD OVERWRITE owned_by ON TABLE invoice_line TYPE option<record<groups>> 
    VALUE $this.invoice.owned_by;

DEFINE FIELD OVERWRITE owned_by ON TABLE package_note TYPE option<record<groups>> 
    VALUE $this.invoice.owned_by;

DEFINE FIELD OVERWRITE owned_by ON TABLE payment_allocation TYPE option<record<groups>> 
    VALUE $this.payment.owned_by;

DEFINE FIELD OVERWRITE owned_by ON TABLE tax_line TYPE option<record<groups>> 
    VALUE $this.invoice_line.owned_by;

DEFINE FIELD OVERWRITE owned_by ON TABLE adjustment_line TYPE option<record<groups>> 
    VALUE $this.adjustment_note.owned_by;

-- SL uses fallback traversal due to its polymorphic nature. 
-- It traces up through the contract (inv_line) first, then the package, then the physical source.
DEFINE FIELD OVERWRITE owned_by ON TABLE sl TYPE option<record<groups>> 
    VALUE $this.inv_line.owned_by ?? $this.pkg.owned_by ?? $this.from.owned_by;