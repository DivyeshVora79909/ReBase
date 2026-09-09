-- Position application and cross-record invalidation.  These events execute in
-- the source transaction: a failed assertion rolls back the source fact, all
-- position writes, and all view changes together.

DEFINE EVENT OVERWRITE accounts_money_opening_position ON TABLE money_opening_balance
    WHEN $event IN ['CREATE', 'DELETE'] OR ($event = 'UPDATE' AND $before.a_amount != $after.a_amount) THEN {
        LET $old_amount = IF $event = 'CREATE' THEN 0dec ELSE $before.a_amount END;
        LET $new_amount = IF $event = 'DELETE' THEN 0dec ELSE $after.a_amount END;
        LET $endpoint = IF $event = 'DELETE' THEN $before.a_endpoint ELSE $after.a_endpoint END;
        LET $currency = IF $event = 'DELETE' THEN $before.a_currency ELSE $after.a_currency END;
        UPSERT type::record('money_position', [$endpoint, $currency])
            SET endpoint = $endpoint, currency = $currency;
        UPDATE type::record('money_position', [$endpoint, $currency]) SET
            balance = (balance ?? 0dec) + $new_amount - $old_amount,
            revision += 1;
    };

DEFINE EVENT OVERWRITE accounts_inventory_opening_position ON TABLE inventory_opening_balance
    WHEN $event IN ['CREATE', 'DELETE'] OR ($event = 'UPDATE' AND $before.a_quantity != $after.a_quantity) THEN {
        LET $old_quantity = IF $event = 'CREATE' THEN 0dec ELSE ($before.a_quantity ?? 0dec) END;
        LET $new_quantity = IF $event = 'DELETE' THEN 0dec ELSE ($after.a_quantity ?? 0dec) END;
        LET $unit = IF $event = 'DELETE' THEN $before.a_operating_unit ELSE $after.a_operating_unit END;
        LET $item = IF $event = 'DELETE' THEN $before.a_item ELSE $after.a_item END;
        UPSERT type::record('inventory_position', [$unit, $item])
            SET operating_unit = $unit, item = $item;
        UPDATE type::record('inventory_position', [$unit, $item]) SET
            opening_quantity = $new_quantity,
            quantity = (quantity ?? 0dec) + $new_quantity - $old_quantity,
            revision += 1;
    };

DEFINE EVENT OVERWRITE accounts_money_movement_position ON TABLE money_movement
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE']
        AND ($event != 'UPDATE' OR $before.a_amount != $after.a_amount) THEN {
        LET $old_amount = IF $event = 'CREATE' THEN 0dec ELSE ($before.a_amount ?? 0dec) END;
        LET $new_amount = IF $event = 'DELETE' THEN 0dec ELSE ($after.a_amount ?? 0dec) END;
        LET $from = IF $event = 'DELETE' THEN $before.a_from ELSE $after.a_from END;
        LET $to = IF $event = 'DELETE' THEN $before.a_to ELSE $after.a_to END;
        LET $currency = IF $event = 'DELETE' THEN $before.a_currency ELSE $after.a_currency END;
        LET $from_is_position = IF $event = 'DELETE' THEN $before.d1_from_is_position ELSE $after.d1_from_is_position END;
        LET $to_is_position = IF $event = 'DELETE' THEN $before.d2_to_is_position ELSE $after.d2_to_is_position END;
        IF $old_amount != 0dec {
            IF $from_is_position {
                LET $position = type::record('money_position', [$from, $currency]);
                UPSERT $position SET endpoint = $from, currency = $currency;
                UPDATE $position SET
                    balance = (balance ?? 0dec) + $old_amount,
                    total_out = (total_out ?? 0dec) - $old_amount,
                    revision += 1;
            };
            IF $to_is_position {
                LET $position = type::record('money_position', [$to, $currency]);
                UPSERT $position SET endpoint = $to, currency = $currency;
                UPDATE $position SET
                    balance = (balance ?? 0dec) - $old_amount,
                    total_in = (total_in ?? 0dec) - $old_amount,
                    revision += 1;
            };
        };
        IF $new_amount != 0dec {
            IF $from_is_position {
                LET $position = type::record('money_position', [$from, $currency]);
                UPSERT $position SET endpoint = $from, currency = $currency;
                UPDATE $position SET
                    balance = (balance ?? 0dec) - $new_amount,
                    total_out = (total_out ?? 0dec) + $new_amount,
                    revision += 1;
            };
            IF $to_is_position {
                LET $position = type::record('money_position', [$to, $currency]);
                UPSERT $position SET endpoint = $to, currency = $currency;
                UPDATE $position SET
                    balance = (balance ?? 0dec) + $new_amount,
                    total_in = (total_in ?? 0dec) + $new_amount,
                    revision += 1;
            };
        };
    };

DEFINE EVENT OVERWRITE accounts_money_exchange_position ON TABLE money_exchange
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE']
        AND ($event != 'UPDATE'
            OR $before.a_from_amount != $after.a_from_amount
            OR $before.a_to_amount != $after.a_to_amount) THEN {
        LET $old_from_amount = IF $event = 'CREATE' THEN 0dec ELSE ($before.a_from_amount ?? 0dec) END;
        LET $old_to_amount = IF $event = 'CREATE' THEN 0dec ELSE ($before.a_to_amount ?? 0dec) END;
        LET $new_from_amount = IF $event = 'DELETE' THEN 0dec ELSE ($after.a_from_amount ?? 0dec) END;
        LET $new_to_amount = IF $event = 'DELETE' THEN 0dec ELSE ($after.a_to_amount ?? 0dec) END;
        LET $from = IF $event = 'DELETE' THEN $before.a_from ELSE $after.a_from END;
        LET $to = IF $event = 'DELETE' THEN $before.a_to ELSE $after.a_to END;
        LET $from_currency = IF $event = 'DELETE' THEN $before.a_from_currency ELSE $after.a_from_currency END;
        LET $to_currency = IF $event = 'DELETE' THEN $before.a_to_currency ELSE $after.a_to_currency END;
        LET $from_is_position = IF $event = 'DELETE' THEN $before.d1_from_is_position ELSE $after.d1_from_is_position END;
        LET $to_is_position = IF $event = 'DELETE' THEN $before.d2_to_is_position ELSE $after.d2_to_is_position END;
        IF $old_from_amount != 0dec AND $from_is_position {
            LET $position = type::record('money_position', [$from, $from_currency]);
            UPSERT $position SET endpoint = $from, currency = $from_currency;
            UPDATE $position SET
                balance = (balance ?? 0dec) + $old_from_amount,
                total_out = (total_out ?? 0dec) - $old_from_amount,
                revision += 1;
        };
        IF $old_to_amount != 0dec AND $to_is_position {
            LET $position = type::record('money_position', [$to, $to_currency]);
            UPSERT $position SET endpoint = $to, currency = $to_currency;
            UPDATE $position SET
                balance = (balance ?? 0dec) - $old_to_amount,
                total_in = (total_in ?? 0dec) - $old_to_amount,
                revision += 1;
        };
        IF $new_from_amount != 0dec AND $from_is_position {
            LET $position = type::record('money_position', [$from, $from_currency]);
            UPSERT $position SET endpoint = $from, currency = $from_currency;
            UPDATE $position SET
                balance = (balance ?? 0dec) - $new_from_amount,
                total_out = (total_out ?? 0dec) + $new_from_amount,
                revision += 1;
        };
        IF $new_to_amount != 0dec AND $to_is_position {
            LET $position = type::record('money_position', [$to, $to_currency]);
            UPSERT $position SET endpoint = $to, currency = $to_currency;
            UPDATE $position SET
                balance = (balance ?? 0dec) + $new_to_amount,
                total_in = (total_in ?? 0dec) + $new_to_amount,
                revision += 1;
        };
    };

-- A mutable movement amount can lower the cap of existing settlement and
-- reversal edges.  Ping those edges in the same transaction so their guards
-- re-evaluate before the source edit commits.
DEFINE EVENT OVERWRITE accounts_money_movement_revalidate ON TABLE money_movement
    WHEN $event = 'UPDATE' AND $before.a_amount != $after.a_amount THEN {
        LET $applications = (SELECT VALUE id FROM payment_application WHERE a_payment = $after.id);
        IF $applications { UPDATE $applications SET system_ping = time::now(); };
        LET $refunds = (SELECT VALUE id FROM money_refund WHERE a_original_payment = $after.id);
        IF $refunds { UPDATE $refunds SET system_ping = time::now(); };
    };

-- Adjustment facts change the effective amount of their target movement. The
-- signed delta is applied to the same position anchors as the target so the
-- adjustment, net amount, and guarded current balance commit atomically.
DEFINE EVENT OVERWRITE accounts_money_adjustment_position ON TABLE money_adjustment_line
    WHEN $event IN ['CREATE', 'DELETE'] OR ($event = 'UPDATE' AND ($before.a_delta != $after.a_delta OR $before.a_target != $after.a_target)) THEN {
        LET $old_delta = IF $event = 'CREATE' THEN 0dec ELSE ($before.a_delta ?? 0dec) END;
        LET $new_delta = IF $event = 'DELETE' THEN 0dec ELSE ($after.a_delta ?? 0dec) END;
        LET $old_target = IF $event = 'CREATE' THEN NONE ELSE $before.a_target END;
        LET $new_target = IF $event = 'DELETE' THEN NONE ELSE $after.a_target END;
        IF $old_target != NONE {
            IF $old_target.d1_from_is_position {
                LET $position = type::record('money_position', [$old_target.a_from, $old_target.a_currency]);
                UPSERT $position SET endpoint = $old_target.a_from, currency = $old_target.a_currency;
                UPDATE $position SET
                    balance = (balance ?? 0dec) + $old_delta,
                    total_out = (total_out ?? 0dec) - $old_delta,
                    revision += 1;
            };
            IF $old_target.d2_to_is_position {
                LET $position = type::record('money_position', [$old_target.a_to, $old_target.a_currency]);
                UPSERT $position SET endpoint = $old_target.a_to, currency = $old_target.a_currency;
                UPDATE $position SET
                    balance = (balance ?? 0dec) - $old_delta,
                    total_in = (total_in ?? 0dec) - $old_delta,
                    revision += 1;
            };
        };
        IF $new_target != NONE {
            IF $new_target.d1_from_is_position {
                LET $position = type::record('money_position', [$new_target.a_from, $new_target.a_currency]);
                UPSERT $position SET endpoint = $new_target.a_from, currency = $new_target.a_currency;
                UPDATE $position SET
                    balance = (balance ?? 0dec) - $new_delta,
                    total_out = (total_out ?? 0dec) + $new_delta,
                    revision += 1;
            };
            IF $new_target.d2_to_is_position {
                LET $position = type::record('money_position', [$new_target.a_to, $new_target.a_currency]);
                UPSERT $position SET endpoint = $new_target.a_to, currency = $new_target.a_currency;
                UPDATE $position SET
                    balance = (balance ?? 0dec) + $new_delta,
                    total_in = (total_in ?? 0dec) + $new_delta,
                    revision += 1;
            };
        };
    };

DEFINE EVENT OVERWRITE accounts_money_refund_position ON TABLE money_refund
    WHEN $event IN ['CREATE', 'DELETE'] OR ($event = 'UPDATE' AND $before.a_amount != $after.a_amount) THEN {
        LET $old_amount = IF $event = 'CREATE' THEN 0dec ELSE $before.a_amount END;
        LET $new_amount = IF $event = 'DELETE' THEN 0dec ELSE $after.a_amount END;
        LET $delta = $new_amount - $old_amount;
        LET $source = IF $event = 'DELETE' THEN $before.d1_source_endpoint ELSE $after.d1_source_endpoint END;
        LET $destination = IF $event = 'DELETE' THEN $before.d2_destination_endpoint ELSE $after.d2_destination_endpoint END;
        LET $currency = IF $event = 'DELETE' THEN $before.d3_currency ELSE $after.d3_currency END;
        LET $source_is_position = IF $event = 'DELETE' THEN $before.d4_source_is_position ELSE $after.d4_source_is_position END;
        LET $destination_is_position = IF $event = 'DELETE' THEN $before.d5_destination_is_position ELSE $after.d5_destination_is_position END;
        IF $destination_is_position {
            LET $position = type::record('money_position', [$destination, $currency]);
            UPSERT $position SET endpoint = $destination, currency = $currency;
            UPDATE $position SET
                balance = (balance ?? 0dec) - $delta,
                total_in = (total_in ?? 0dec) - $delta,
                revision += 1;
        };
        IF $source_is_position {
            LET $position = type::record('money_position', [$source, $currency]);
            UPSERT $position SET endpoint = $source, currency = $currency;
            UPDATE $position SET
                balance = (balance ?? 0dec) + $delta,
                total_out = (total_out ?? 0dec) - $delta,
                revision += 1;
        };
    };

DEFINE EVENT OVERWRITE accounts_inventory_movement_position ON TABLE inventory_movement
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE']
        AND ($event != 'UPDATE' OR $before.a_quantity != $after.a_quantity) THEN {
        LET $old_quantity = IF $event = 'CREATE' THEN 0dec ELSE ($before.a_quantity ?? 0dec) END;
        LET $new_quantity = IF $event = 'DELETE' THEN 0dec ELSE ($after.a_quantity ?? 0dec) END;
        LET $from = IF $event = 'DELETE' THEN $before.a_from ELSE $after.a_from END;
        LET $to = IF $event = 'DELETE' THEN $before.a_to ELSE $after.a_to END;
        LET $item = IF $event = 'DELETE' THEN $before.a_item ELSE $after.a_item END;
        LET $from_is_position = IF $event = 'DELETE' THEN $before.d1_from_is_position ELSE $after.d1_from_is_position END;
        LET $to_is_position = IF $event = 'DELETE' THEN $before.d2_to_is_position ELSE $after.d2_to_is_position END;
        IF $old_quantity != 0dec {
            IF $from_is_position {
                LET $position = type::record('inventory_position', [$from, $item]);
                UPSERT $position SET operating_unit = $from, item = $item;
                UPDATE $position SET
                    quantity = (quantity ?? 0dec) + $old_quantity,
                    total_out = (total_out ?? 0dec) - $old_quantity,
                    revision += 1;
            };
            IF $to_is_position {
                LET $position = type::record('inventory_position', [$to, $item]);
                UPSERT $position SET operating_unit = $to, item = $item;
                UPDATE $position SET
                    quantity = (quantity ?? 0dec) - $old_quantity,
                    total_in = (total_in ?? 0dec) - $old_quantity,
                    revision += 1;
            };
        };
        IF $new_quantity != 0dec {
            IF $from_is_position {
                LET $position = type::record('inventory_position', [$from, $item]);
                UPSERT $position SET operating_unit = $from, item = $item;
                UPDATE $position SET
                    quantity = (quantity ?? 0dec) - $new_quantity,
                    total_out = (total_out ?? 0dec) + $new_quantity,
                    revision += 1;
            };
            IF $to_is_position {
                LET $position = type::record('inventory_position', [$to, $item]);
                UPSERT $position SET operating_unit = $to, item = $item;
                UPDATE $position SET
                    quantity = (quantity ?? 0dec) + $new_quantity,
                    total_in = (total_in ?? 0dec) + $new_quantity,
                    revision += 1;
            };
        };
    };

DEFINE EVENT OVERWRITE accounts_inventory_movement_revalidate ON TABLE inventory_movement
    WHEN $event = 'UPDATE' AND $before.a_quantity != $after.a_quantity THEN {
        LET $returns = (SELECT VALUE id FROM inventory_return WHERE a_original_movement = $after.id);
        IF $returns { UPDATE $returns SET system_ping = time::now(); };
    };

DEFINE EVENT OVERWRITE accounts_inventory_adjustment_position ON TABLE inventory_adjustment_line
    WHEN $event IN ['CREATE', 'DELETE'] OR ($event = 'UPDATE' AND ($before.a_delta != $after.a_delta OR $before.a_target != $after.a_target)) THEN {
        LET $old_delta = IF $event = 'CREATE' THEN 0dec ELSE ($before.a_delta ?? 0dec) END;
        LET $new_delta = IF $event = 'DELETE' THEN 0dec ELSE ($after.a_delta ?? 0dec) END;
        LET $old_target = IF $event = 'CREATE' THEN NONE ELSE $before.a_target END;
        LET $new_target = IF $event = 'DELETE' THEN NONE ELSE $after.a_target END;
        IF $old_target != NONE {
            IF $old_target.d1_from_is_position {
                LET $position = type::record('inventory_position', [$old_target.a_from, $old_target.a_item]);
                UPSERT $position SET operating_unit = $old_target.a_from, item = $old_target.a_item;
                UPDATE $position SET
                    quantity = (quantity ?? 0dec) + $old_delta,
                    total_out = (total_out ?? 0dec) - $old_delta,
                    revision += 1;
            };
            IF $old_target.d2_to_is_position {
                LET $position = type::record('inventory_position', [$old_target.a_to, $old_target.a_item]);
                UPSERT $position SET operating_unit = $old_target.a_to, item = $old_target.a_item;
                UPDATE $position SET
                    quantity = (quantity ?? 0dec) - $old_delta,
                    total_in = (total_in ?? 0dec) - $old_delta,
                    revision += 1;
            };
        };
        IF $new_target != NONE {
            IF $new_target.d1_from_is_position {
                LET $position = type::record('inventory_position', [$new_target.a_from, $new_target.a_item]);
                UPSERT $position SET operating_unit = $new_target.a_from, item = $new_target.a_item;
                UPDATE $position SET
                    quantity = (quantity ?? 0dec) - $new_delta,
                    total_out = (total_out ?? 0dec) + $new_delta,
                    revision += 1;
            };
            IF $new_target.d2_to_is_position {
                LET $position = type::record('inventory_position', [$new_target.a_to, $new_target.a_item]);
                UPSERT $position SET operating_unit = $new_target.a_to, item = $new_target.a_item;
                UPDATE $position SET
                    quantity = (quantity ?? 0dec) + $new_delta,
                    total_in = (total_in ?? 0dec) + $new_delta,
                    revision += 1;
            };
        };
    };

DEFINE EVENT OVERWRITE accounts_inventory_return_position ON TABLE inventory_return
    WHEN $event IN ['CREATE', 'DELETE'] OR ($event = 'UPDATE' AND $before.a_quantity != $after.a_quantity) THEN {
        LET $old_quantity = IF $event = 'CREATE' THEN 0dec ELSE ($before.a_quantity ?? 0dec) END;
        LET $new_quantity = IF $event = 'DELETE' THEN 0dec ELSE ($after.a_quantity ?? 0dec) END;
        LET $delta = $new_quantity - $old_quantity;
        LET $source = IF $event = 'DELETE' THEN $before.d1_source_endpoint ELSE $after.d1_source_endpoint END;
        LET $destination = IF $event = 'DELETE' THEN $before.d2_destination_endpoint ELSE $after.d2_destination_endpoint END;
        LET $item = IF $event = 'DELETE' THEN $before.d3_item ELSE $after.d3_item END;
        LET $source_is_position = IF $event = 'DELETE' THEN $before.d4_source_is_position ELSE $after.d4_source_is_position END;
        LET $destination_is_position = IF $event = 'DELETE' THEN $before.d5_destination_is_position ELSE $after.d5_destination_is_position END;
        IF $destination_is_position {
            LET $position = type::record('inventory_position', [$destination, $item]);
            UPSERT $position SET operating_unit = $destination, item = $item;
            UPDATE $position SET
                quantity = (quantity ?? 0dec) - $delta,
                total_in = (total_in ?? 0dec) - $delta,
                revision += 1;
        };
        IF $source_is_position {
            LET $position = type::record('inventory_position', [$source, $item]);
            UPSERT $position SET operating_unit = $source, item = $item;
            UPDATE $position SET
                quantity = (quantity ?? 0dec) + $delta,
                total_out = (total_out ?? 0dec) - $delta,
                revision += 1;
        };
    };

DEFINE EVENT OVERWRITE accounts_service_capacity_position ON TABLE service_capacity
    WHEN $event IN ['CREATE', 'DELETE'] OR ($event = 'UPDATE' AND $before.a_quantity != $after.a_quantity) THEN {
        LET $position = type::record('service_position', [
            IF $event = 'DELETE' THEN $before.a_operating_unit ELSE $after.a_operating_unit END,
            IF $event = 'DELETE' THEN $before.a_service ELSE $after.a_service END
        ]);
        LET $old_quantity = IF $event = 'CREATE' THEN 0dec ELSE ($before.a_quantity ?? 0dec) END;
        LET $new_quantity = IF $event = 'DELETE' THEN 0dec ELSE ($after.a_quantity ?? 0dec) END;
        LET $unit = IF $event = 'DELETE' THEN $before.a_operating_unit ELSE $after.a_operating_unit END;
        LET $service = IF $event = 'DELETE' THEN $before.a_service ELSE $after.a_service END;
        LET $delta = $new_quantity - $old_quantity;
        UPSERT $position SET operating_unit = $unit, service = $service;
        UPDATE $position SET
            granted = (granted ?? 0dec) + $delta,
            remaining = (remaining ?? 0dec) + $delta,
            revision += 1;
    };

DEFINE EVENT OVERWRITE accounts_service_delivery_position ON TABLE service_delivery
    WHEN $event IN ['CREATE', 'DELETE'] OR ($event = 'UPDATE' AND $before.a_quantity != $after.a_quantity) THEN {
        LET $position = type::record('service_position', [
            IF $event = 'DELETE' THEN $before.a_operating_unit ELSE $after.a_operating_unit END,
            IF $event = 'DELETE' THEN $before.a_service ELSE $after.a_service END
        ]);
        LET $old_quantity = IF $event = 'CREATE' THEN 0dec ELSE ($before.a_quantity ?? 0dec) END;
        LET $new_quantity = IF $event = 'DELETE' THEN 0dec ELSE ($after.a_quantity ?? 0dec) END;
        LET $unit = IF $event = 'DELETE' THEN $before.a_operating_unit ELSE $after.a_operating_unit END;
        LET $service = IF $event = 'DELETE' THEN $before.a_service ELSE $after.a_service END;
        LET $delta = $new_quantity - $old_quantity;
        UPSERT $position SET operating_unit = $unit, service = $service;
        UPDATE $position SET
            consumed = (consumed ?? 0dec) + $delta,
            remaining = (remaining ?? 0dec) - $delta,
            revision += 1;
    };

-- Cross-record caps run in synchronous events. Event queries are internal and
-- therefore do not depend on the caller's row-level read permissions.
DEFINE EVENT OVERWRITE accounts_payment_application_guard ON TABLE payment_application
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
        IF $event != 'DELETE' {
            LET $payment = $after.a_payment;
            LET $invoice = $after.a_invoice;
            LET $payment_cap = ((SELECT VALUE d4_net_amount FROM money_movement WHERE id = $payment)[0] ?? 0dec);
            LET $payment_rows = (SELECT VALUE a_amount FROM payment_application WHERE a_payment = $payment);
            LET $payment_total = array::fold($payment_rows, 0dec, |$total, $amount| $total + ($amount ?? 0dec));
            LET $refund_rows = (SELECT VALUE a_amount FROM money_refund WHERE a_original_payment = $payment);
            LET $refund_total = array::fold($refund_rows, 0dec, |$total, $amount| $total + ($amount ?? 0dec));
            IF $payment_total + $refund_total > $payment_cap {
                THROW 'ACCOUNTS_PAYMENT_OVER_APPLIED';
            };

            LET $claim_rows = (SELECT VALUE d6_gross_amount FROM invoice_line WHERE a_invoice = $invoice);
            LET $claim = array::fold($claim_rows, 0dec, |$total, $amount| $total + ($amount ?? 0dec));
            LET $settled_rows = (SELECT VALUE a_amount FROM payment_application WHERE a_invoice = $invoice);
            LET $settled = array::fold($settled_rows, 0dec, |$total, $amount| $total + ($amount ?? 0dec));
            IF $settled > $claim { THROW 'ACCOUNTS_INVOICE_OVER_SETTLED'; };
        };
    };

DEFINE EVENT OVERWRITE accounts_money_refund_guard ON TABLE money_refund
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
        IF $event != 'DELETE' {
            LET $payment = $after.a_original_payment;
            LET $cap = ((SELECT VALUE d4_net_amount FROM money_movement WHERE id = $payment)[0] ?? 0dec);
            LET $rows = (SELECT VALUE a_amount FROM money_refund WHERE a_original_payment = $payment);
            LET $total = array::fold($rows, 0dec, |$sum, $amount| $sum + ($amount ?? 0dec));
            IF $total > $cap { THROW 'ACCOUNTS_REFUND_EXCEEDS_PAYMENT'; };
        };
    };

DEFINE EVENT OVERWRITE accounts_inventory_return_guard ON TABLE inventory_return
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
        IF $event != 'DELETE' {
            LET $movement = $after.a_original_movement;
            LET $cap = ((SELECT VALUE d4_net_quantity FROM inventory_movement WHERE id = $movement)[0] ?? 0dec);
            LET $rows = (SELECT VALUE a_quantity FROM inventory_return WHERE a_original_movement = $movement);
            LET $total = array::fold($rows, 0dec, |$sum, $quantity| $sum + ($quantity ?? 0dec));
            IF $total > $cap { THROW 'ACCOUNTS_RETURN_EXCEEDS_MOVEMENT'; };
        };
    };

-- A line, tax, or adjustment edit can lower a claim below applications that
-- already exist. Re-run the aggregate-backed invoice invariant whenever its
-- children ping the parent.
DEFINE EVENT OVERWRITE accounts_invoice_settlement_guard ON TABLE invoice
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
        IF $event != 'DELETE' {
            LET $claim_rows = (SELECT VALUE d6_gross_amount FROM invoice_line WHERE a_invoice = $after.id);
            LET $claim = array::fold($claim_rows, 0dec, |$total, $amount| $total + ($amount ?? 0dec));
            LET $settled_rows = (SELECT VALUE a_amount FROM payment_application WHERE a_invoice = $after.id);
            LET $settled = array::fold($settled_rows, 0dec, |$total, $amount| $total + ($amount ?? 0dec));
            IF $settled > $claim { THROW 'ACCOUNTS_INVOICE_OVER_SETTLED'; };
        };
    };

-- Aggregate-backed guards need their parents re-evaluated after child writes.
DEFINE EVENT OVERWRITE accounts_application_revalidate ON TABLE payment_application
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
        LET $payments = array::distinct([
            IF $event = 'CREATE' THEN NONE ELSE $before.a_payment END,
            IF $event = 'DELETE' THEN NONE ELSE $after.a_payment END
        ]).filter(|$record| $record != NONE);
        LET $invoices = array::distinct([
            IF $event = 'CREATE' THEN NONE ELSE $before.a_invoice END,
            IF $event = 'DELETE' THEN NONE ELSE $after.a_invoice END
        ]).filter(|$record| $record != NONE);
        IF $payments { UPDATE $payments SET system_ping = time::now(); };
        IF $invoices { UPDATE $invoices SET system_ping = time::now(); };
    };

DEFINE EVENT OVERWRITE accounts_invoice_line_revalidate ON TABLE invoice_line
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
        LET $invoices = array::distinct([
            IF $event = 'CREATE' THEN NONE ELSE $before.a_invoice END,
            IF $event = 'DELETE' THEN NONE ELSE $after.a_invoice END
        ]).filter(|$record| $record != NONE);
        IF $invoices { UPDATE $invoices SET system_ping = time::now(); };
        IF $event != 'DELETE' AND ($event = 'CREATE'
            OR $before.a_quantity != $after.a_quantity
            OR $before.a_unit_price != $after.a_unit_price) {
            LET $taxes = (SELECT VALUE id FROM tax_input WHERE a_invoice_line = $after.id);
            IF $taxes { UPDATE $taxes SET system_ping = time::now(); };
            LET $output_taxes = (SELECT VALUE id FROM tax_output WHERE a_invoice_line = $after.id);
            IF $output_taxes { UPDATE $output_taxes SET system_ping = time::now(); };
        };
    };

DEFINE EVENT OVERWRITE accounts_money_adjustment_revalidate ON TABLE money_adjustment_line
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
        LET $targets = array::distinct([
            IF $event = 'CREATE' THEN NONE ELSE $before.a_target END,
            IF $event = 'DELETE' THEN NONE ELSE $after.a_target END
        ]).filter(|$record| $record != NONE);
        IF $targets { UPDATE $targets SET system_ping = time::now(); };
        LET $applications = (SELECT VALUE id FROM payment_application WHERE a_payment IN $targets);
        IF $applications { UPDATE $applications SET system_ping = time::now(); };
        LET $refunds = (SELECT VALUE id FROM money_refund WHERE a_original_payment IN $targets);
        IF $refunds { UPDATE $refunds SET system_ping = time::now(); };
    };

DEFINE EVENT OVERWRITE accounts_money_refund_revalidate ON TABLE money_refund
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
        LET $targets = array::distinct([
            IF $event = 'CREATE' THEN NONE ELSE $before.a_original_payment END,
            IF $event = 'DELETE' THEN NONE ELSE $after.a_original_payment END
        ]).filter(|$record| $record != NONE);
        IF $targets { UPDATE $targets SET system_ping = time::now(); };
        LET $applications = (SELECT VALUE id FROM payment_application WHERE a_payment IN $targets);
        IF $applications { UPDATE $applications SET system_ping = time::now(); };
    };

DEFINE EVENT OVERWRITE accounts_inventory_adjustment_revalidate ON TABLE inventory_adjustment_line
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
        LET $targets = array::distinct([
            IF $event = 'CREATE' THEN NONE ELSE $before.a_target END,
            IF $event = 'DELETE' THEN NONE ELSE $after.a_target END
        ]).filter(|$record| $record != NONE);
        IF $targets { UPDATE $targets SET system_ping = time::now(); };
        LET $returns = (SELECT VALUE id FROM inventory_return WHERE a_original_movement IN $targets);
        IF $returns { UPDATE $returns SET system_ping = time::now(); };
    };

DEFINE EVENT OVERWRITE accounts_inventory_return_revalidate ON TABLE inventory_return
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
        LET $targets = array::distinct([
            IF $event = 'CREATE' THEN NONE ELSE $before.a_original_movement END,
            IF $event = 'DELETE' THEN NONE ELSE $after.a_original_movement END
        ]).filter(|$record| $record != NONE);
        IF $targets { UPDATE $targets SET system_ping = time::now(); };
    };

DEFINE EVENT OVERWRITE accounts_tax_adjustment_revalidate ON TABLE tax_adjustment_line
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
        LET $targets = array::distinct([
            IF $event = 'CREATE' THEN NONE ELSE $before.a_target END,
            IF $event = 'DELETE' THEN NONE ELSE $after.a_target END
        ]).filter(|$record| $record != NONE);
        IF $targets { UPDATE $targets SET system_ping = time::now(); };
    };

DEFINE EVENT OVERWRITE accounts_tax_input_line_revalidate ON TABLE tax_input
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
        LET $lines = array::distinct([
            IF $event = 'CREATE' THEN NONE ELSE $before.a_invoice_line END,
            IF $event = 'DELETE' THEN NONE ELSE $after.a_invoice_line END
        ]).filter(|$record| $record != NONE);
        IF $lines { UPDATE $lines SET system_ping = time::now(); };
    };

DEFINE EVENT OVERWRITE accounts_tax_output_line_revalidate ON TABLE tax_output
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
        LET $lines = array::distinct([
            IF $event = 'CREATE' THEN NONE ELSE $before.a_invoice_line END,
            IF $event = 'DELETE' THEN NONE ELSE $after.a_invoice_line END
        ]).filter(|$record| $record != NONE);
        IF $lines { UPDATE $lines SET system_ping = time::now(); };
    };

-- -------------------------------------------------------------------------
-- Effective-time replay ledger
-- -------------------------------------------------------------------------
-- Each source fact owns one deterministic entry per affected position.  The
-- position_entry event folds the ordered entries synchronously, so a late edit
-- cannot hide a negative historical prefix behind a positive final sum.

DEFINE EVENT OVERWRITE accounts_position_entry_replay_guard ON TABLE position_entry
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE'] THEN {
        LET $position = IF $event = 'DELETE' THEN $before.position ELSE $after.position END;
        LET $rows = (SELECT VALUE delta FROM position_entry
            WHERE position = $position ORDER BY effective_at, id);
        LET $state = array::fold(
            $rows,
            { total: 0dec, min_prefix: 0dec },
            |$state, $delta| {
                LET $next = $state.total + ($delta ?? 0dec);
                RETURN {
                    total: $next,
                    min_prefix: math::min([$state.min_prefix, $next])
                };
            }
        );
        LET $guarded = IF record::tb($position) = 'money_position'
            THEN (
                record::tb($position.endpoint) = 'treasury_account'
                OR (record::tb($position.endpoint) = 'misc_account'
                    AND $position.endpoint.a_guard_non_negative = true)
            )
            ELSE true END;
        IF $guarded AND $state.min_prefix < 0dec {
            THROW 'ACCOUNTS_HISTORICAL_NEGATIVE_PREFIX';
        };
    };

DEFINE EVENT OVERWRITE accounts_replay_money_opening ON TABLE money_opening_balance
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE']
        AND ($event != 'UPDATE' OR $before.a_amount != $after.a_amount) THEN {
        LET $source = IF $event = 'DELETE' THEN $before.id ELSE $after.id END;
        LET $endpoint = IF $event = 'DELETE' THEN $before.a_endpoint ELSE $after.a_endpoint END;
        LET $currency = IF $event = 'DELETE' THEN $before.a_currency ELSE $after.a_currency END;
        LET $position = type::record('money_position', [$endpoint, $currency]);
        LET $entry = type::record('position_entry', [$position, $source]);
        UPSERT $position SET endpoint = $endpoint, currency = $currency;
        IF $event = 'DELETE' OR ($event != 'DELETE' AND $after.a_amount = 0dec) {
            DELETE $entry;
        } ELSE {
            UPSERT $entry SET
                position = $position,
                source = $source,
                effective_at = $after.a_effective_at,
                delta = $after.a_amount;
        };
    };

DEFINE EVENT OVERWRITE accounts_replay_money_movement ON TABLE money_movement
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE']
        AND ($event != 'UPDATE' OR $before.a_amount != $after.a_amount) THEN {
        LET $source = IF $event = 'DELETE' THEN $before.id ELSE $after.id END;
        LET $from = IF $event = 'DELETE' THEN $before.a_from ELSE $after.a_from END;
        LET $to = IF $event = 'DELETE' THEN $before.a_to ELSE $after.a_to END;
        LET $currency = IF $event = 'DELETE' THEN $before.a_currency ELSE $after.a_currency END;
        LET $from_is_position = IF $event = 'DELETE' THEN $before.d1_from_is_position ELSE $after.d1_from_is_position END;
        LET $to_is_position = IF $event = 'DELETE' THEN $before.d2_to_is_position ELSE $after.d2_to_is_position END;
        LET $amount = IF $event = 'DELETE' THEN $before.a_amount ELSE $after.a_amount END;
        IF $from_is_position {
            LET $position = type::record('money_position', [$from, $currency]);
            LET $entry = type::record('position_entry', [$position, $source]);
            UPSERT $position SET endpoint = $from, currency = $currency;
            IF $event = 'DELETE' {
                DELETE $entry;
            } ELSE {
                UPSERT $entry SET
                    position = $position,
                    source = $source,
                    effective_at = $after.a_effective_at,
                    delta = -$amount;
            };
        };
        IF $to_is_position {
            LET $position = type::record('money_position', [$to, $currency]);
            LET $entry = type::record('position_entry', [$position, $source]);
            UPSERT $position SET endpoint = $to, currency = $currency;
            IF $event = 'DELETE' {
                DELETE $entry;
            } ELSE {
                UPSERT $entry SET
                    position = $position,
                    source = $source,
                    effective_at = $after.a_effective_at,
                    delta = $amount;
            };
        };
    };

DEFINE EVENT OVERWRITE accounts_replay_money_exchange ON TABLE money_exchange
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE']
        AND ($event != 'UPDATE'
            OR $before.a_from_amount != $after.a_from_amount
            OR $before.a_to_amount != $after.a_to_amount) THEN {
        LET $source = IF $event = 'DELETE' THEN $before.id ELSE $after.id END;
        LET $from = IF $event = 'DELETE' THEN $before.a_from ELSE $after.a_from END;
        LET $to = IF $event = 'DELETE' THEN $before.a_to ELSE $after.a_to END;
        LET $from_currency = IF $event = 'DELETE' THEN $before.a_from_currency ELSE $after.a_from_currency END;
        LET $to_currency = IF $event = 'DELETE' THEN $before.a_to_currency ELSE $after.a_to_currency END;
        LET $from_is_position = IF $event = 'DELETE' THEN $before.d1_from_is_position ELSE $after.d1_from_is_position END;
        LET $to_is_position = IF $event = 'DELETE' THEN $before.d2_to_is_position ELSE $after.d2_to_is_position END;
        LET $from_amount = IF $event = 'DELETE' THEN $before.a_from_amount ELSE $after.a_from_amount END;
        LET $to_amount = IF $event = 'DELETE' THEN $before.a_to_amount ELSE $after.a_to_amount END;
        IF $from_is_position {
            LET $position = type::record('money_position', [$from, $from_currency]);
            LET $entry = type::record('position_entry', [$position, $source]);
            UPSERT $position SET endpoint = $from, currency = $from_currency;
            IF $event = 'DELETE' {
                DELETE $entry;
            } ELSE {
                UPSERT $entry SET
                    position = $position,
                    source = $source,
                    effective_at = $after.a_effective_at,
                    delta = -$from_amount;
            };
        };
        IF $to_is_position {
            LET $position = type::record('money_position', [$to, $to_currency]);
            LET $entry = type::record('position_entry', [$position, $source]);
            UPSERT $position SET endpoint = $to, currency = $to_currency;
            IF $event = 'DELETE' {
                DELETE $entry;
            } ELSE {
                UPSERT $entry SET
                    position = $position,
                    source = $source,
                    effective_at = $after.a_effective_at,
                    delta = $to_amount;
            };
        };
    };

DEFINE EVENT OVERWRITE accounts_replay_money_adjustment ON TABLE money_adjustment_line
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE']
        AND ($event != 'UPDATE' OR $before.a_delta != $after.a_delta) THEN {
        LET $source = IF $event = 'DELETE' THEN $before.id ELSE $after.id END;
        LET $target = IF $event = 'DELETE' THEN $before.a_target ELSE $after.a_target END;
        LET $delta = IF $event = 'DELETE' THEN $before.a_delta ELSE $after.a_delta END;
        LET $effective_at = $target.a_effective_at;
        LET $from_is_position = $target.d1_from_is_position;
        LET $to_is_position = $target.d2_to_is_position;
        IF $from_is_position {
            LET $position = type::record('money_position', [$target.a_from, $target.a_currency]);
            LET $entry = type::record('position_entry', [$position, $source]);
            UPSERT $position SET endpoint = $target.a_from, currency = $target.a_currency;
            IF $event = 'DELETE' { DELETE $entry; }
            ELSE { UPSERT $entry SET position = $position, source = $source, effective_at = $effective_at, delta = -$delta; };
        };
        IF $to_is_position {
            LET $position = type::record('money_position', [$target.a_to, $target.a_currency]);
            LET $entry = type::record('position_entry', [$position, $source]);
            UPSERT $position SET endpoint = $target.a_to, currency = $target.a_currency;
            IF $event = 'DELETE' { DELETE $entry; }
            ELSE { UPSERT $entry SET position = $position, source = $source, effective_at = $effective_at, delta = $delta; };
        };
    };

DEFINE EVENT OVERWRITE accounts_replay_money_refund ON TABLE money_refund
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE']
        AND ($event != 'UPDATE' OR $before.a_amount != $after.a_amount) THEN {
        LET $source = IF $event = 'DELETE' THEN $before.id ELSE $after.id END;
        LET $payment = IF $event = 'DELETE' THEN $before.a_original_payment ELSE $after.a_original_payment END;
        LET $amount = IF $event = 'DELETE' THEN $before.a_amount ELSE $after.a_amount END;
        LET $from_is_position = $payment.d1_from_is_position;
        LET $to_is_position = $payment.d2_to_is_position;
        IF $to_is_position {
            LET $position = type::record('money_position', [$payment.a_to, $payment.a_currency]);
            LET $entry = type::record('position_entry', [$position, $source]);
            UPSERT $position SET endpoint = $payment.a_to, currency = $payment.a_currency;
            IF $event = 'DELETE' { DELETE $entry; }
            ELSE { UPSERT $entry SET position = $position, source = $source, effective_at = $after.a_effective_at, delta = -$amount; };
        };
        IF $from_is_position {
            LET $position = type::record('money_position', [$payment.a_from, $payment.a_currency]);
            LET $entry = type::record('position_entry', [$position, $source]);
            UPSERT $position SET endpoint = $payment.a_from, currency = $payment.a_currency;
            IF $event = 'DELETE' { DELETE $entry; }
            ELSE { UPSERT $entry SET position = $position, source = $source, effective_at = $after.a_effective_at, delta = $amount; };
        };
    };

DEFINE EVENT OVERWRITE accounts_replay_inventory_opening ON TABLE inventory_opening_balance
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE']
        AND ($event != 'UPDATE' OR $before.a_quantity != $after.a_quantity) THEN {
        LET $source = IF $event = 'DELETE' THEN $before.id ELSE $after.id END;
        LET $unit = IF $event = 'DELETE' THEN $before.a_operating_unit ELSE $after.a_operating_unit END;
        LET $item = IF $event = 'DELETE' THEN $before.a_item ELSE $after.a_item END;
        LET $quantity = IF $event = 'DELETE' THEN $before.a_quantity ELSE $after.a_quantity END;
        LET $position = type::record('inventory_position', [$unit, $item]);
        LET $entry = type::record('position_entry', [$position, $source]);
        UPSERT $position SET operating_unit = $unit, item = $item;
        IF $event = 'DELETE' OR ($event != 'DELETE' AND $quantity = 0dec) { DELETE $entry; }
        ELSE { UPSERT $entry SET position = $position, source = $source, effective_at = $after.a_effective_at, delta = $quantity; };
    };

DEFINE EVENT OVERWRITE accounts_replay_inventory_movement ON TABLE inventory_movement
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE']
        AND ($event != 'UPDATE' OR $before.a_quantity != $after.a_quantity) THEN {
        LET $source = IF $event = 'DELETE' THEN $before.id ELSE $after.id END;
        LET $from = IF $event = 'DELETE' THEN $before.a_from ELSE $after.a_from END;
        LET $to = IF $event = 'DELETE' THEN $before.a_to ELSE $after.a_to END;
        LET $item = IF $event = 'DELETE' THEN $before.a_item ELSE $after.a_item END;
        LET $from_is_position = IF $event = 'DELETE' THEN $before.d1_from_is_position ELSE $after.d1_from_is_position END;
        LET $to_is_position = IF $event = 'DELETE' THEN $before.d2_to_is_position ELSE $after.d2_to_is_position END;
        LET $quantity = IF $event = 'DELETE' THEN $before.a_quantity ELSE $after.a_quantity END;
        IF $from_is_position {
            LET $position = type::record('inventory_position', [$from, $item]);
            LET $entry = type::record('position_entry', [$position, $source]);
            UPSERT $position SET operating_unit = $from, item = $item;
            IF $event = 'DELETE' { DELETE $entry; }
            ELSE { UPSERT $entry SET position = $position, source = $source, effective_at = $after.a_effective_at, delta = -$quantity; };
        };
        IF $to_is_position {
            LET $position = type::record('inventory_position', [$to, $item]);
            LET $entry = type::record('position_entry', [$position, $source]);
            UPSERT $position SET operating_unit = $to, item = $item;
            IF $event = 'DELETE' { DELETE $entry; }
            ELSE { UPSERT $entry SET position = $position, source = $source, effective_at = $after.a_effective_at, delta = $quantity; };
        };
    };

DEFINE EVENT OVERWRITE accounts_replay_inventory_adjustment ON TABLE inventory_adjustment_line
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE']
        AND ($event != 'UPDATE' OR $before.a_delta != $after.a_delta) THEN {
        LET $source = IF $event = 'DELETE' THEN $before.id ELSE $after.id END;
        LET $target = IF $event = 'DELETE' THEN $before.a_target ELSE $after.a_target END;
        LET $delta = IF $event = 'DELETE' THEN $before.a_delta ELSE $after.a_delta END;
        LET $effective_at = $target.a_effective_at;
        LET $from_is_position = $target.d1_from_is_position;
        LET $to_is_position = $target.d2_to_is_position;
        IF $from_is_position {
            LET $position = type::record('inventory_position', [$target.a_from, $target.a_item]);
            LET $entry = type::record('position_entry', [$position, $source]);
            UPSERT $position SET operating_unit = $target.a_from, item = $target.a_item;
            IF $event = 'DELETE' { DELETE $entry; }
            ELSE { UPSERT $entry SET position = $position, source = $source, effective_at = $effective_at, delta = -$delta; };
        };
        IF $to_is_position {
            LET $position = type::record('inventory_position', [$target.a_to, $target.a_item]);
            LET $entry = type::record('position_entry', [$position, $source]);
            UPSERT $position SET operating_unit = $target.a_to, item = $target.a_item;
            IF $event = 'DELETE' { DELETE $entry; }
            ELSE { UPSERT $entry SET position = $position, source = $source, effective_at = $effective_at, delta = $delta; };
        };
    };

DEFINE EVENT OVERWRITE accounts_replay_inventory_return ON TABLE inventory_return
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE']
        AND ($event != 'UPDATE' OR $before.a_quantity != $after.a_quantity) THEN {
        LET $source = IF $event = 'DELETE' THEN $before.id ELSE $after.id END;
        LET $movement = IF $event = 'DELETE' THEN $before.a_original_movement ELSE $after.a_original_movement END;
        LET $quantity = IF $event = 'DELETE' THEN $before.a_quantity ELSE $after.a_quantity END;
        LET $from_is_position = $movement.d1_from_is_position;
        LET $to_is_position = $movement.d2_to_is_position;
        IF $to_is_position {
            LET $position = type::record('inventory_position', [$movement.a_to, $movement.a_item]);
            LET $entry = type::record('position_entry', [$position, $source]);
            UPSERT $position SET operating_unit = $movement.a_to, item = $movement.a_item;
            IF $event = 'DELETE' { DELETE $entry; }
            ELSE { UPSERT $entry SET position = $position, source = $source, effective_at = $after.a_effective_at, delta = -$quantity; };
        };
        IF $from_is_position {
            LET $position = type::record('inventory_position', [$movement.a_from, $movement.a_item]);
            LET $entry = type::record('position_entry', [$position, $source]);
            UPSERT $position SET operating_unit = $movement.a_from, item = $movement.a_item;
            IF $event = 'DELETE' { DELETE $entry; }
            ELSE { UPSERT $entry SET position = $position, source = $source, effective_at = $after.a_effective_at, delta = $quantity; };
        };
    };

DEFINE EVENT OVERWRITE accounts_replay_service_capacity ON TABLE service_capacity
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE']
        AND ($event != 'UPDATE' OR $before.a_quantity != $after.a_quantity) THEN {
        LET $source = IF $event = 'DELETE' THEN $before.id ELSE $after.id END;
        LET $unit = IF $event = 'DELETE' THEN $before.a_operating_unit ELSE $after.a_operating_unit END;
        LET $service = IF $event = 'DELETE' THEN $before.a_service ELSE $after.a_service END;
        LET $quantity = IF $event = 'DELETE' THEN $before.a_quantity ELSE $after.a_quantity END;
        LET $position = type::record('service_position', [$unit, $service]);
        LET $entry = type::record('position_entry', [$position, $source]);
        UPSERT $position SET operating_unit = $unit, service = $service;
        IF $event = 'DELETE' { DELETE $entry; }
        ELSE { UPSERT $entry SET position = $position, source = $source, effective_at = $after.a_effective_at, delta = $quantity; };
    };

DEFINE EVENT OVERWRITE accounts_replay_service_delivery ON TABLE service_delivery
    WHEN $event IN ['CREATE', 'UPDATE', 'DELETE']
        AND ($event != 'UPDATE' OR $before.a_quantity != $after.a_quantity) THEN {
        LET $source = IF $event = 'DELETE' THEN $before.id ELSE $after.id END;
        LET $unit = IF $event = 'DELETE' THEN $before.a_operating_unit ELSE $after.a_operating_unit END;
        LET $service = IF $event = 'DELETE' THEN $before.a_service ELSE $after.a_service END;
        LET $quantity = IF $event = 'DELETE' THEN $before.a_quantity ELSE $after.a_quantity END;
        LET $position = type::record('service_position', [$unit, $service]);
        LET $entry = type::record('position_entry', [$position, $source]);
        UPSERT $position SET operating_unit = $unit, service = $service;
        IF $event = 'DELETE' { DELETE $entry; }
        ELSE { UPSERT $entry SET position = $position, source = $source, effective_at = $after.a_effective_at, delta = -$quantity; };
    };
