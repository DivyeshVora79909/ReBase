USE NS main DB main;

-- 1. THE UNIVERSAL LEDGER OBSERVERS (Real-time balances)
-- General Ledger (Trial Balance)
DEFINE TABLE OVERWRITE v_account_balance AS
    SELECT 
        account_ref, 
        math::sum(z_amount_base) AS total_base_balance,
        count() AS transaction_count
    FROM journal_line 
    GROUP BY account_ref
PERMISSIONS FOR select WHERE 'account_select' IN $auth.permissions;

-- AR/AP Sub-Ledger (Real-time Contact Balances / Aging Base)
-- Positive = Customer owes us (AR). Negative = We owe Vendor (AP).
DEFINE TABLE OVERWRITE v_contact_balance AS
    SELECT 
        contact_ref, 
        math::sum(z_amount_base) AS net_balance 
    FROM journal_line 
    WHERE contact_ref != NONE
    GROUP BY contact_ref
PERMISSIONS FOR select WHERE 'contact_select' IN $auth.permissions;

-- Dimension / Tracking Ledger (Project & Department tracking)
DEFINE TABLE OVERWRITE v_tracking_balance AS
    SELECT 
        tracking_tag_ref, 
        account_ref,
        math::sum(z_amount_base) AS total_balance 
    FROM journal_line 
    WHERE tracking_tag_ref != NONE
    GROUP BY tracking_tag_ref, account_ref
PERMISSIONS FOR select WHERE 'tracking_tag_select' IN $auth.permissions;


-- 2. CQRS GATEKEEPER VIEWS (For Event Validations)
-- Document Totals (Aggregates the document_line VALUE fields)
DEFINE TABLE OVERWRITE v_document_totals AS 
    SELECT 
        document_ref, 
        math::sum(z_base_amount) AS total_base,
        math::sum(z_tax_amount) AS total_tax,
        math::sum(z_total_amount) AS total_amount
    FROM document_line 
    GROUP BY document_ref
PERMISSIONS FOR select WHERE 'document_select' IN $auth.permissions;

-- Payment Outbound Limit (How much of the Payment has been allocated to documents)
DEFINE TABLE OVERWRITE v_payment_outbound AS
    SELECT 
        payment_ref, 
        math::sum(pay_currency_amount) AS total_allocated 
    FROM payment_allocation 
    GROUP BY payment_ref
PERMISSIONS FOR select WHERE 'payment_select' IN $auth.permissions;

-- Document Settlement Status (How much of a Document has been paid off)
DEFINE TABLE OVERWRITE v_payment_allocations AS
    SELECT 
        document_ref, 
        math::sum(doc_currency_amount) AS total_paid 
    FROM payment_allocation 
    GROUP BY document_ref
PERMISSIONS FOR select WHERE 'document_select' IN $auth.permissions;