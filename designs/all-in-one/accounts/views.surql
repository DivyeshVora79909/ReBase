-- Sparse projections maintained by SurrealDB.  They intentionally cover only
-- guard inputs and common one/two-dimensional reads, never a universal cube.

DEFINE TABLE OVERWRITE v_accounts_money_adjustment AS
    SELECT a_target AS movement, math::sum(a_delta) AS amount
    FROM money_adjustment_line
    GROUP BY movement;

DEFINE TABLE OVERWRITE v_accounts_inventory_adjustment AS
    SELECT a_target AS movement, math::sum(a_delta) AS quantity
    FROM inventory_adjustment_line
    GROUP BY movement;

DEFINE TABLE OVERWRITE v_accounts_tax_adjustment AS
    SELECT a_target AS tax, math::sum(a_delta) AS amount
    FROM tax_adjustment_line
    GROUP BY tax;

DEFINE TABLE OVERWRITE v_accounts_money_in AS
    SELECT a_to AS endpoint, a_currency AS currency,
        math::sum(d4_net_amount ?? 0dec) AS amount
    FROM money_movement
    WHERE d2_to_is_position = true
    GROUP BY endpoint, currency;

DEFINE TABLE OVERWRITE v_accounts_money_out AS
    SELECT a_from AS endpoint, a_currency AS currency,
        math::sum(d4_net_amount ?? 0dec) AS amount
    FROM money_movement
    WHERE d1_from_is_position = true
    GROUP BY endpoint, currency;

DEFINE TABLE OVERWRITE v_accounts_exchange_out AS
    SELECT a_from AS endpoint, a_from_currency AS currency,
        math::sum(a_from_amount ?? 0dec) AS amount
    FROM money_exchange
    WHERE d1_from_is_position = true
    GROUP BY endpoint, currency;

DEFINE TABLE OVERWRITE v_accounts_exchange_in AS
    SELECT a_to AS endpoint, a_to_currency AS currency,
        math::sum(a_to_amount ?? 0dec) AS amount
    FROM money_exchange
    WHERE d2_to_is_position = true
    GROUP BY endpoint, currency;

DEFINE TABLE OVERWRITE v_accounts_inventory_in AS
    SELECT a_to AS operating_unit, a_item AS item,
        math::sum(d4_net_quantity ?? 0dec) AS quantity
    FROM inventory_movement
    WHERE d2_to_is_position = true
    GROUP BY operating_unit, item;

DEFINE TABLE OVERWRITE v_accounts_inventory_out AS
    SELECT a_from AS operating_unit, a_item AS item,
        math::sum(d4_net_quantity ?? 0dec) AS quantity
    FROM inventory_movement
    WHERE d1_from_is_position = true
    GROUP BY operating_unit, item;

DEFINE TABLE OVERWRITE v_accounts_service_capacity AS
    SELECT a_operating_unit AS operating_unit, a_service AS service,
        math::sum(a_quantity) AS quantity
    FROM service_capacity
    GROUP BY operating_unit, service;

DEFINE TABLE OVERWRITE v_accounts_service_delivery AS
    SELECT a_operating_unit AS operating_unit, a_service AS service,
        math::sum(a_quantity) AS quantity
    FROM service_delivery
    GROUP BY operating_unit, service;

DEFINE TABLE OVERWRITE v_accounts_tax_input_by_line AS
    SELECT a_invoice_line AS invoice_line, math::sum(d3_amount ?? 0dec) AS amount
    FROM tax_input
    GROUP BY invoice_line;

DEFINE TABLE OVERWRITE v_accounts_tax_output_by_line AS
    SELECT a_invoice_line AS invoice_line, math::sum(d3_amount ?? 0dec) AS amount
    FROM tax_output
    GROUP BY invoice_line;

DEFINE TABLE OVERWRITE v_accounts_invoice_claim AS
    SELECT a_invoice AS invoice,
        math::sum(d4_base_amount ?? 0dec) AS base_amount,
        math::sum(d5_tax_amount ?? 0dec) AS tax_amount,
        math::sum(d6_gross_amount ?? 0dec) AS gross_amount
    FROM invoice_line
    GROUP BY invoice;

DEFINE TABLE OVERWRITE v_accounts_application_by_payment AS
    SELECT a_payment AS payment, math::sum(a_amount) AS amount
    FROM payment_application
    GROUP BY payment;

DEFINE TABLE OVERWRITE v_accounts_application_by_invoice AS
    SELECT a_invoice AS invoice, math::sum(a_amount) AS amount
    FROM payment_application
    GROUP BY invoice;

DEFINE TABLE OVERWRITE v_accounts_refund_by_payment AS
    SELECT a_original_payment AS payment, math::sum(a_amount) AS amount
    FROM money_refund
    GROUP BY payment;

DEFINE TABLE OVERWRITE v_accounts_return_by_movement AS
    SELECT a_original_movement AS movement, math::sum(a_quantity) AS quantity
    FROM inventory_return
    GROUP BY movement;

DEFINE TABLE OVERWRITE v_accounts_claim_by_organization AS
    SELECT d1_organization AS organization, d2_currency AS currency,
        math::sum(d6_gross_amount ?? 0dec) AS gross_amount
    FROM invoice_line
    GROUP BY organization, currency;
