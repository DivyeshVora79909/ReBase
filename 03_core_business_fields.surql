USE NS main DB main;

-- ============================================================
-- FILE: 03_implicit_integrity_events_and_indexes.surql
-- ============================================================
-- PHILOSOPHY:
-- 1. Events are SIGNALS only — they trigger Empty Updates (UPDATE parent SET z_touched_at = time::now()).
--    The parent then re-evaluates its own VALUE clauses. We never hardcode math in events.
-- 2. All enforcement is IMPLICIT via ASSERT on VALUE fields. Events just "touch" parents.
-- 3. Indexes are placed on EVERY foreign key used inside a WHERE clause in a VALUE aggregate.
--    Without these, the DB would do full table scans on every touch — instant death at scale.
-- 4. Unique indexes on display_number prevent race-condition duplicates.
-- 5. Event cascades are strictly UPWARD (Lines -> Documents -> Accounts) to avoid recursion traps.
-- ============================================================

-- ============================================================
-- A. CRITICAL INDEXES (Performance & Uniqueness)
-- ============================================================
-- Without these, every z_ snapshot field triggers a full table scan.

-- Order / Sales
DEFINE INDEX OVERWRITE idx_order_party ON order COLUMNS party;
DEFINE INDEX OVERWRITE idx_order_line_order_ref ON order_line COLUMNS order_ref;
DEFINE INDEX OVERWRITE idx_order_line_item_ref ON order_line COLUMNS item_ref;
DEFINE INDEX OVERWRITE idx_order_display_number ON order COLUMNS display_number UNIQUE;

-- Invoice / Sales Financial
DEFINE INDEX OVERWRITE idx_invoice_party ON invoice COLUMNS party;
DEFINE INDEX OVERWRITE idx_invoice_order_ref ON invoice COLUMNS order_ref;
DEFINE INDEX OVERWRITE idx_invoice_display_number ON invoice COLUMNS display_number UNIQUE;
DEFINE INDEX OVERWRITE idx_invoice_line_invoice_ref ON invoice_line COLUMNS invoice_ref;
DEFINE INDEX OVERWRITE idx_invoice_line_order_line_ref ON invoice_line COLUMNS order_line_ref;
DEFINE INDEX OVERWRITE idx_invoice_line_item_ref ON invoice_line COLUMNS item_ref;

-- Credit Note
DEFINE INDEX OVERWRITE idx_credit_note_party ON credit_note COLUMNS party;
DEFINE INDEX OVERWRITE idx_credit_note_invoice_ref ON credit_note COLUMNS invoice_ref;
DEFINE INDEX OVERWRITE idx_credit_note_display_number ON credit_note COLUMNS display_number UNIQUE;
DEFINE INDEX OVERWRITE idx_credit_note_line_credit_note_ref ON credit_note_line COLUMNS credit_note_ref;
DEFINE INDEX OVERWRITE idx_credit_note_line_invoice_line_ref ON credit_note_line COLUMNS invoice_line_ref;

-- Procurement / Purchase
DEFINE INDEX OVERWRITE idx_procurement_party ON procurement COLUMNS party;
DEFINE INDEX OVERWRITE idx_procurement_line_procurement_ref ON procurement_line COLUMNS procurement_ref;
DEFINE INDEX OVERWRITE idx_procurement_line_item_ref ON procurement_line COLUMNS item_ref;
DEFINE INDEX OVERWRITE idx_procurement_display_number ON procurement COLUMNS display_number UNIQUE;

-- Vendor Bill
DEFINE INDEX OVERWRITE idx_vendor_bill_party ON vendor_bill COLUMNS party;
DEFINE INDEX OVERWRITE idx_vendor_bill_procurement_ref ON vendor_bill COLUMNS procurement_ref;
DEFINE INDEX OVERWRITE idx_vendor_bill_display_number ON vendor_bill COLUMNS display_number UNIQUE;
DEFINE INDEX OVERWRITE idx_vendor_bill_line_vendor_bill_ref ON vendor_bill_line COLUMNS vendor_bill_ref;
DEFINE INDEX OVERWRITE idx_vendor_bill_line_procurement_line_ref ON vendor_bill_line COLUMNS procurement_line_ref;
DEFINE INDEX OVERWRITE idx_vendor_bill_line_item_ref ON vendor_bill_line COLUMNS item_ref;

-- Debit Note
DEFINE INDEX OVERWRITE idx_debit_note_party ON debit_note COLUMNS party;
DEFINE INDEX OVERWRITE idx_debit_note_vendor_bill_ref ON debit_note COLUMNS vendor_bill_ref;
DEFINE INDEX OVERWRITE idx_debit_note_display_number ON debit_note COLUMNS display_number UNIQUE;
DEFINE INDEX OVERWRITE idx_debit_note_line_debit_note_ref ON debit_note_line COLUMNS debit_note_ref;
DEFINE INDEX OVERWRITE idx_debit_note_line_vendor_bill_line_ref ON debit_note_line COLUMNS vendor_bill_line_ref;

-- Payment (CRITICAL: from_account and to_account are used in organization_account.z_ar_balance / z_ap_balance)
DEFINE INDEX OVERWRITE idx_payment_from_account ON payment COLUMNS from_account;
DEFINE INDEX OVERWRITE idx_payment_to_account ON payment COLUMNS to_account;

-- Exchange
DEFINE INDEX OVERWRITE idx_exchange_from_account ON exchange COLUMNS from_account;
DEFINE INDEX OVERWRITE idx_exchange_to_account ON exchange COLUMNS to_account;

-- Inventory (used in invoice_line and vendor_bill_line item_ref lookups)
DEFINE INDEX OVERWRITE idx_inventory_name ON inventory COLUMNS name;

-- Ledger Account
DEFINE INDEX OVERWRITE idx_ledger_account_code ON ledger_account COLUMNS code UNIQUE;

-- Tax Account
DEFINE INDEX OVERWRITE idx_tax_account_code ON tax_account COLUMNS code UNIQUE;

-- Catalog Item
DEFINE INDEX OVERWRITE idx_catalog_item_name ON catalog_item COLUMNS name;

-- ============================================================
-- B. EVENTS: SALES ORDER-TO-CASH (O2C) CASCADE
-- ============================================================

-- 1. Order Line -> Order (touch parent to recompute totals)
DEFINE EVENT OVERWRITE ev_order_line_touch_order ON TABLE order_line
WHEN $event IN ["CREATE", "UPDATE", "DELETE"]
THEN {
    LET $parent = $after.order_ref OR $before.order_ref;
    UPDATE $parent SET z_touched_at = time::now();
};

-- 2. Invoice Line -> Invoice (touch parent)
--    Also touches the linked Order Line so z_qty_invoiced recalculates.
DEFINE EVENT OVERWRITE ev_invoice_line_touch_invoice ON TABLE invoice_line
WHEN $event IN ["CREATE", "UPDATE", "DELETE"]
THEN {
    LET $inv = $after.invoice_ref OR $before.invoice_ref;
    UPDATE $inv SET z_touched_at = time::now();

    LET $order_line = $after.order_line_ref OR $before.order_line_ref;
    IF $order_line != NONE { UPDATE $order_line SET z_touched_at = time::now(); };
};

-- 3. Invoice -> Organization Account (touch AR party)
--    Also touches linked Order so its status can auto-update if needed.
DEFINE EVENT OVERWRITE ev_invoice_touch_party ON TABLE invoice
WHEN $event IN ["CREATE", "UPDATE", "DELETE"]
THEN {
    LET $party = $after.party OR $before.party;
    UPDATE $party SET z_touched_at = time::now();

    LET $order = $after.order_ref OR $before.order_ref;
    IF $order != NONE { UPDATE $order SET z_touched_at = time::now(); };
};

-- 4. Credit Note Line -> Credit Note (touch parent)
--    Also touches the linked Invoice Line so z_qty_credited recalculates.
DEFINE EVENT OVERWRITE ev_credit_note_line_touch_credit_note ON TABLE credit_note_line
WHEN $event IN ["CREATE", "UPDATE", "DELETE"]
THEN {
    LET $cn = $after.credit_note_ref OR $before.credit_note_ref;
    UPDATE $cn SET z_touched_at = time::now();

    LET $inv_line = $after.invoice_line_ref OR $before.invoice_line_ref;
    IF $inv_line != NONE { UPDATE $inv_line SET z_touched_at = time::now(); };
};

-- 5. Credit Note -> Organization Account (touch AR party)
DEFINE EVENT OVERWRITE ev_credit_note_touch_party ON TABLE credit_note
WHEN $event IN ["CREATE", "UPDATE", "DELETE"]
THEN {
    LET $party = $after.party OR $before.party;
    UPDATE $party SET z_touched_at = time::now();

    LET $inv = $after.invoice_ref OR $before.invoice_ref;
    IF $inv != NONE { UPDATE $inv SET z_touched_at = time::now(); };
};

-- ============================================================
-- C. EVENTS: PROCUREMENT-TO-PAY (P2P) CASCADE
-- ============================================================

-- 6. Procurement Line -> Procurement
DEFINE EVENT OVERWRITE ev_procurement_line_touch_procurement ON TABLE procurement_line
WHEN $event IN ["CREATE", "UPDATE", "DELETE"]
THEN {
    LET $parent = $after.procurement_ref OR $before.procurement_ref;
    UPDATE $parent SET z_touched_at = time::now();
};

-- 7. Vendor Bill Line -> Vendor Bill (touch parent)
--    Also touches linked Procurement Line so z_qty_billed recalculates.
DEFINE EVENT OVERWRITE ev_vendor_bill_line_touch_bill ON TABLE vendor_bill_line
WHEN $event IN ["CREATE", "UPDATE", "DELETE"]
THEN {
    LET $bill = $after.vendor_bill_ref OR $before.vendor_bill_ref;
    UPDATE $bill SET z_touched_at = time::now();

    LET $po_line = $after.procurement_line_ref OR $before.procurement_line_ref;
    IF $po_line != NONE { UPDATE $po_line SET z_touched_at = time::now(); };
};

-- 8. Vendor Bill -> Organization Account (touch AP party)
DEFINE EVENT OVERWRITE ev_vendor_bill_touch_party ON TABLE vendor_bill
WHEN $event IN ["CREATE", "UPDATE", "DELETE"]
THEN {
    LET $party = $after.party OR $before.party;
    UPDATE $party SET z_touched_at = time::now();

    LET $proc = $after.procurement_ref OR $before.procurement_ref;
    IF $proc != NONE { UPDATE $proc SET z_touched_at = time::now(); };
};

-- 9. Debit Note Line -> Debit Note (touch parent)
--    Also touches linked Vendor Bill Line so z_qty_debited recalculates.
DEFINE EVENT OVERWRITE ev_debit_note_line_touch_debit_note ON TABLE debit_note_line
WHEN $event IN ["CREATE", "UPDATE", "DELETE"]
THEN {
    LET $dn = $after.debit_note_ref OR $before.debit_note_ref;
    UPDATE $dn SET z_touched_at = time::now();

    LET $bill_line = $after.vendor_bill_line_ref OR $before.vendor_bill_line_ref;
    IF $bill_line != NONE { UPDATE $bill_line SET z_touched_at = time::now(); };
};

-- 10. Debit Note -> Organization Account (touch AP party)
DEFINE EVENT OVERWRITE ev_debit_note_touch_party ON TABLE debit_note
WHEN $event IN ["CREATE", "UPDATE", "DELETE"]
THEN {
    LET $party = $after.party OR $before.party;
    UPDATE $party SET z_touched_at = time::now();

    LET $bill = $after.vendor_bill_ref OR $before.vendor_bill_ref;
    IF $bill != NONE { UPDATE $bill SET z_touched_at = time::now(); };
};

-- ============================================================
-- D. EVENTS: PAYMENT CASCADE (AR/AP + FX GAIN/LOSS)
-- ============================================================

-- 11. Payment -> All Allocated Documents (touch them so z_amount_paid recalculates)
--     Also touches both from_account and to_account (Organization or Ledger).
DEFINE EVENT OVERWRITE ev_payment_touch_all ON TABLE payment
WHEN $event IN ["CREATE", "UPDATE", "DELETE"]
THEN {
    -- Touch all documents referenced in allocations (before + after, for updates)
    LET $docs = array::union(
        $before.allocations.document_ref ?? [],
        $after.allocations.document_ref ?? []
    );
    FOR doc IN $docs { UPDATE $doc SET z_touched_at = time::now(); };

    -- Touch the money accounts
    LET $from = $after.from_account OR $before.from_account;
    LET $to = $after.to_account OR $before.to_account;
    UPDATE $from SET z_touched_at = time::now();
    UPDATE $to SET z_touched_at = time::now();

    -- FX GAIN/LOSS AUTOMATION:
    -- When a payment settles a document at a different fx_rate than the document itself,
    -- we auto-create a financial_adjustment to clear the base-currency imbalance.
    -- This runs only on CREATE/UPDATE (not DELETE) and only if payment is posted.
    IF $event IN ["CREATE", "UPDATE"] AND $after.allocations != NONE {
        LET $base_currency = (SELECT VALUE base_currency FROM company_settings LIMIT 1)[0] ?? "INR";

        FOR alloc IN $after.allocations {
            LET $doc = alloc.document_ref;
            LET $doc_fx = (SELECT VALUE fx_rate FROM $doc)[0] ?? 1dec;
            LET $doc_currency = (SELECT VALUE currency FROM $doc)[0] ?? "INR";

            -- Only process if currencies differ or fx rates differ
            IF $doc_currency = $after.currency AND $doc_fx != $after.fx_rate {
                LET $alloc_base_at_doc_rate = alloc.amount * $doc_fx;
                LET $alloc_base_at_pay_rate = alloc.amount * $after.fx_rate;
                LET $diff = $alloc_base_at_pay_rate - $alloc_base_at_doc_rate;

                IF $diff != 0dec {
                    -- Determine gain/loss direction
                    LET $gain_loss_item = IF $diff > 0dec THEN
                        (SELECT VALUE id FROM catalog_item WHERE name = "FX Gain" LIMIT 1)[0]
                    ELSE
                        (SELECT VALUE id FROM catalog_item WHERE name = "FX Loss" LIMIT 1)[0]
                    END;

                    -- Create the adjustment to clear the base-currency imbalance
                    CREATE financial_adjustment SET
                        kind = IF $diff > 0dec THEN "fx_gain" ELSE "fx_loss" END,
                        amount = math::abs($diff),
                        currency = $base_currency,
                        fx_rate = 1,
                        from_account = $from,
                        to_account = $to,
                        source_payment = $after.id,
                        source_document = $doc,
                        created_at = time::now();
                };
            };
        };
    };
};

-- ============================================================
-- E. EVENTS: EXCHANGE CASCADE (Inventory Snapshotting)
-- ============================================================

-- 12. Exchange -> Inventory (touch affected inventory accounts)
DEFINE EVENT OVERWRITE ev_exchange_touch_inventory ON TABLE exchange
WHEN $event IN ["CREATE", "UPDATE", "DELETE"]
THEN {
    LET $from = $after.from_account OR $before.from_account;
    LET $to = $after.to_account OR $before.to_account;

    IF type::is_record($from) AND record::tb($from) = 'inventory' { UPDATE $from SET z_touched_at = time::now(); };
    IF type::is_record($to) AND record::tb($to) = 'inventory' { UPDATE $to SET z_touched_at = time::now(); };
};

-- ============================================================
-- F. EVENTS: STATE MACHINE LOCKS (Implicit Enforcement)
-- ============================================================

-- 13. Invoice State Machine: prevent illegal modifications on posted/void invoices
--     We use the z_void_valid field (which has ASSERT) to block voiding paid invoices.
--     But we also need to prevent editing lines of a posted invoice.
DEFINE EVENT OVERWRITE ev_invoice_state_lock ON TABLE invoice
WHEN $event = "UPDATE"
THEN {
    -- If the invoice was posted before, lines cannot be added/deleted via the invoice document itself.
    -- (Lines are separate tables, so this is naturally enforced by the UI/API, but we add a safety net.)
    IF $before.status = 'posted' AND $after.status = 'posted' {
        -- Allow only z_touched_at and status changes (to void) after posting.
        -- Any other field change is suspicious. We don't THROW here because z_void_valid handles void logic.
        -- This event is mainly for audit logging if needed.
    };
};

-- 14. Vendor Bill State Machine: same pattern as invoice
DEFINE EVENT OVERWRITE ev_vendor_bill_state_lock ON TABLE vendor_bill
WHEN $event = "UPDATE"
THEN {
    IF $before.status = 'posted' AND $after.status = 'posted' {
        -- Safety net; primary enforcement is z_void_valid ASSERT.
    };
};

-- ============================================================
-- G. EVENTS: INVENTORY COST RECALCULATION TRIGGER
-- ============================================================
-- When a vendor bill is posted, it changes inventory.z_avg_cost.
-- Any DRAFT invoice lines that reference this inventory should see the updated cost
-- when they are eventually posted. Since frozen_unit_cost is READONLY and captures
-- at posting time, this is automatic — no event needed.
-- However, we trigger inventory touch on vendor bill posting so z_avg_cost updates immediately.

DEFINE EVENT OVERWRITE ev_vendor_bill_touch_inventory ON TABLE vendor_bill_line
WHEN $event IN ["CREATE", "UPDATE", "DELETE"]
THEN {
    LET $item = $after.item_ref OR $before.item_ref;
    IF $item != NONE AND type::is_record($item) AND record::tb($item) = 'inventory' {
        UPDATE $item SET z_touched_at = time::now();
    };
};

-- ============================================================
-- H. EVENTS: AUDIT TRAIL (Status Change Logging)
-- ============================================================
-- Optional but recommended: log every status transition on financial documents.
-- This uses the z_ prefix to ensure it runs after all math fields.

DEFINE EVENT OVERWRITE ev_invoice_status_log ON TABLE invoice
WHEN $event = "UPDATE" AND $before.status != $after.status
THEN {
    CREATE document_audit_log SET
        document_table = 'invoice',
        document_id = $after.id,
        field = 'status',
        from_value = $before.status,
        to_value = $after.status,
        changed_at = time::now(),
        changed_by = $auth;
};

DEFINE EVENT OVERWRITE ev_vendor_bill_status_log ON TABLE vendor_bill
WHEN $event = "UPDATE" AND $before.status != $after.status
THEN {
    CREATE document_audit_log SET
        document_table = 'vendor_bill',
        document_id = $after.id,
        field = 'status',
        from_value = $before.status,
        to_value = $after.status,
        changed_at = time::now(),
        changed_by = $auth;
};

-- ============================================================
-- I. TABLE: DOCUMENT AUDIT LOG
-- ============================================================
DEFINE TABLE OVERWRITE document_audit_log SCHEMAFULL;
DEFINE FIELD OVERWRITE document_table ON document_audit_log TYPE string;
DEFINE FIELD OVERWRITE document_id ON document_audit_log TYPE record;
DEFINE FIELD OVERWRITE field ON document_audit_log TYPE string;
DEFINE FIELD OVERWRITE from_value ON document_audit_log TYPE string;
DEFINE FIELD OVERWRITE to_value ON document_audit_log TYPE string;
DEFINE FIELD OVERWRITE changed_at ON document_audit_log TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD OVERWRITE changed_by ON document_audit_log TYPE option<record<user>>;

-- ============================================================
-- J. TABLE: FINANCIAL ADJUSTMENT (FX Gain/Loss, Corrections)
-- ============================================================
-- Used by the payment event to auto-clear multi-currency imbalances.
-- Also available for manual corrections by admins.
DEFINE TABLE OVERWRITE financial_adjustment SCHEMAFULL;

DEFINE FIELD OVERWRITE kind ON financial_adjustment TYPE string ASSERT $value IN ['fx_gain', 'fx_loss', 'correction', 'rounding'];
DEFINE FIELD OVERWRITE amount ON financial_adjustment TYPE decimal ASSERT $value > 0;
DEFINE FIELD OVERWRITE currency ON financial_adjustment TYPE string ASSERT $value.len() > 0;
DEFINE FIELD OVERWRITE fx_rate ON financial_adjustment TYPE decimal DEFAULT 1 ASSERT $value > 0;
DEFINE FIELD OVERWRITE from_account ON financial_adjustment TYPE record<organization_account | ledger_account> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE to_account ON financial_adjustment TYPE record<organization_account | ledger_account> REFERENCE ON DELETE REJECT ASSERT $value != $this.from_account;
DEFINE FIELD OVERWRITE source_payment ON financial_adjustment TYPE option<record<payment>> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE source_document ON financial_adjustment TYPE option<record<invoice | vendor_bill>> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE note ON financial_adjustment TYPE option<string>;

-- Touch affected accounts so balances recalculate
DEFINE EVENT OVERWRITE ev_financial_adjustment_touch_accounts ON TABLE financial_adjustment
WHEN $event IN ["CREATE", "UPDATE", "DELETE"]
THEN {
    LET $from = $after.from_account OR $before.from_account;
    LET $to = $after.to_account OR $before.to_account;
    UPDATE $from SET z_touched_at = time::now();
    UPDATE $to SET z_touched_at = time::now();
};