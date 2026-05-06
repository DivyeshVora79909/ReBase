USE NS main DB main;

-- 1. DOCUMENT TOTAL VIEWS (Financial)
DEFINE TABLE OVERWRITE v_invoice_totals AS 
    SELECT
        invoice_ref,
        math::sum(z_base_amount) AS total_base,
        math::sum(z_tax_amount) AS total_tax,
        math::sum(z_base_amount + z_tax_amount) AS total_amount
    FROM invoice_line
    GROUP BY invoice_ref
PERMISSIONS
    FOR select WHERE 'invoice_select' IN $auth.permissions;

DEFINE TABLE OVERWRITE v_vendor_bill_totals AS 
    SELECT
        bill_ref,
        math::sum(z_base_amount) AS total_base,
        math::sum(z_tax_amount) AS total_tax,
        math::sum(z_base_amount + z_tax_amount) AS total_amount
    FROM vendor_bill_line
    GROUP BY bill_ref
PERMISSIONS
    FOR select WHERE 'vendor_bill_select' IN $auth.permissions;

DEFINE TABLE OVERWRITE v_payment_outbound AS
    SELECT
        payment_ref,
        math::sum(pay_currency_amount) AS total_allocated
    FROM payment_allocation
    GROUP BY payment_ref
PERMISSIONS
    FOR select WHERE 'payment_select' IN $auth.permissions;

DEFINE TABLE OVERWRITE v_payment_allocations AS
    SELECT
        target_ref,
        math::sum(doc_currency_amount) AS total_paid
    FROM payment_allocation
    GROUP BY target_ref
PERMISSIONS
    FOR select WHERE
        'invoice_select' IN $auth.permissions
        OR 'vendor_bill_select' IN $auth.permissions
        OR 'trade_account_select' IN $auth.permissions;

DEFINE TABLE OVERWRITE v_line_adjustments AS 
    SELECT
        target_line_ref,
        math::sum(delta_qty) AS net_qty_delta,
        math::sum(delta_base_amount) AS net_amount_delta
    FROM adjustment_note_line
    GROUP BY target_line_ref
PERMISSIONS
    FOR select WHERE 'adjustment_note_select' IN $auth.permissions;

-- 2. INVENTORY VIEWS (Physical Stock grouped by Location)
DEFINE TABLE OVERWRITE v_stock_out AS 
    SELECT
        item_ref,
        location_ref,
        math::sum(qty) AS total_out 
    FROM invoice_line
    GROUP BY item_ref, location_ref
PERMISSIONS
    FOR select WHERE 'invoice_select' IN $auth.permissions;

DEFINE TABLE OVERWRITE v_stock_in AS 
    SELECT
        item_ref,
        location_ref,
        math::sum(qty) AS total_in 
    FROM vendor_bill_line
    GROUP BY item_ref, location_ref
PERMISSIONS
    FOR select WHERE 'vendor_bill_select' IN $auth.permissions;

DEFINE TABLE OVERWRITE v_exchange_out AS
    SELECT
        item_ref,
        from_location_ref,
        math::sum(qty) AS total_out
    FROM exchange_line
    GROUP BY item_ref, from_location_ref
PERMISSIONS
    FOR select WHERE 'exchange_select' IN $auth.permissions;

DEFINE TABLE OVERWRITE v_exchange_in AS
    SELECT
        item_ref,
        to_location_ref,
        math::sum(qty) AS total_in
    FROM exchange_line
    GROUP BY item_ref, to_location_ref
PERMISSIONS
    FOR select WHERE 'exchange_select' IN $auth.permissions;

DEFINE TABLE OVERWRITE v_production_totals AS
    SELECT
        item_ref,
        location_ref,
        direction,
        math::sum(qty) AS total_qty
    FROM production_line
    GROUP BY item_ref, location_ref, direction
PERMISSIONS
    FOR select WHERE 'production_run_select' IN $auth.permissions;