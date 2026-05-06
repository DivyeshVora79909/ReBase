USE NS main DB main;

-- 1. FINANCIAL INTEGRITY EVENTS
DEFINE EVENT OVERWRITE assert_credit_limits ON TABLE adjustment_note_line WHEN $event = 'CREATE' THEN {
    LET $origin = $after.target_line_ref;
    LET $historical = type::record('v_line_adjustments', [$origin]).{net_qty_delta, net_amount_delta} OR {net_qty_delta: 0dec, net_amount_delta: 0dec};
    
    IF ($origin.qty + $historical.net_qty_delta + $after.delta_qty) < 0dec {
        THROW "LIMIT_EXCEEDED: Adjustments push physical qty below zero.";
    };
    IF ($origin.z_base_amount + $historical.net_amount_delta + $after.delta_base_amount) < 0dec {
        THROW "LIMIT_EXCEEDED: Adjustments push base revenue below zero.";
    };
};

DEFINE EVENT OVERWRITE assert_payment_limits ON TABLE payment_allocation WHEN $event = 'CREATE' THEN {
    LET $target = $after.target_ref;
    
    IF record::tb($target) = 'invoice' {
        LET $paid = type::record('v_payment_allocations', [$target]).total_paid ?? 0dec;
        LET $billed = type::record('v_invoice_totals',[$target]).total_amount ?? 0dec;
        IF ($paid + $after.doc_currency_amount) > $billed { THROW "OVERPAYMENT: Cash exceeds invoice total."; };
    } ELSE IF record::tb($target) = 'vendor_bill' {
        LET $paid = type::record('v_payment_allocations', [$target]).total_paid ?? 0dec;
        LET $billed = type::record('v_vendor_bill_totals', [$target]).total_amount ?? 0dec;
        IF ($paid + $after.doc_currency_amount) > $billed { THROW "OVERPAYMENT: Cash exceeds bill total."; };
    };

    LET $pay = $after.payment_ref;
    LET $allocated = type::record('v_payment_outbound',[$pay]).total_allocated ?? 0dec;
    IF ($allocated + $after.pay_currency_amount) > $pay.amount {
        THROW "OVER_ALLOCATION: You cannot allocate more cash than the Payment contains.";
    };
};

DEFINE EVENT OVERWRITE auto_fx_gain_loss ON TABLE payment_allocation WHEN $event IN['CREATE', 'UPDATE'] THEN {
    LET $pay = $after.payment_ref; LET $doc = $after.target_ref;
    
    LET $doc_base = $after.doc_currency_amount * ($doc.fx_rate ?? 1dec);
    LET $pay_base = $after.pay_currency_amount * ($pay.fx_rate ?? 1dec);
    LET $diff = $pay_base - $doc_base;
    
    IF $diff != 0dec {
        LET $base_currency = (SELECT VALUE base_currency FROM company_settings LIMIT 1)[0] ?? 'USD';
        CREATE financial_adjustment SET
            kind = IF $diff > 0dec THEN 'fx_gain' ELSE 'fx_loss' END,
            from_node = IF record::tb($doc) = 'invoice' THEN $doc.party_ref ELSE $pay.treasury_ref END,
            to_node = (SELECT VALUE id FROM expense_account WHERE name = "FX Gains/Losses" LIMIT 1)[0],
            amount = math::abs($diff),
            currency = $base_currency;
    };
};

DEFINE EVENT OVERWRITE enforce_dynamic_lockout ON TABLE invoice WHEN $event = 'UPDATE' THEN {
    LET $lockout_duration = (SELECT VALUE invoice_lock_after FROM company_settings LIMIT 1)[0] ?? 30d;
    IF $before.status = 'posted' AND time::now() > ($before.created_at + $lockout_duration) {
        THROW "COMPLIANCE_LOCK: Grace period exceeded. Use an Adjustment Note instead.";
    };
};

-- 2. PHYSICAL INVENTORY POLICE
-- Reusable function to keep events DRY!
DEFINE FUNCTION OVERWRITE fn::get_available_stock($item: record<inventory_node>, $loc: record<location_node>) -> decimal {
    LET $in_bill = type::record('v_stock_in', [$item, $loc]).total_in ?? 0dec;
    LET $in_exch = type::record('v_exchange_in', [$item, $loc]).total_in ?? 0dec;
    LET $in_prod = type::record('v_production_totals', [$item, $loc, 'yield']).total_qty ?? 0dec;
    
    LET $out_inv = type::record('v_stock_out', [$item, $loc]).total_out ?? 0dec;
    LET $out_exch = type::record('v_exchange_out', [$item, $loc]).total_out ?? 0dec;
    LET $out_prod = type::record('v_production_totals', [$item, $loc, 'consume']).total_qty ?? 0dec;

    RETURN ($in_bill + $in_exch + $in_prod) - ($out_inv + $out_exch + $out_prod);
};

-- Protects Sales (Outbound)
DEFINE EVENT OVERWRITE assert_stock_invoice ON TABLE invoice_line WHEN $event = 'CREATE' THEN {
    IF (fn::get_available_stock($after.item_ref, $after.location_ref) - $after.qty) < 0dec {
        THROW "INSUFFICIENT_STOCK: Item unavailable at requested location for sale.";
    };
};

-- Protects Exchanges (Outbound)
DEFINE EVENT OVERWRITE assert_stock_exchange ON TABLE exchange_line WHEN $event = 'CREATE' THEN {
    IF $after.from_location_ref != NONE {
        IF (fn::get_available_stock($after.item_ref, $after.from_location_ref) - $after.qty) < 0dec {
            THROW "INSUFFICIENT_STOCK: Item unavailable at requested location for exchange.";
        };
    };
};

-- Protects Manufacturing (Outbound)
DEFINE EVENT OVERWRITE assert_stock_production ON TABLE production_line WHEN $event = 'CREATE' THEN {
    IF $after.direction = 'consume' AND record::tb($after.item_ref) = 'inventory_node' {
        IF (fn::get_available_stock($after.item_ref, $after.location_ref) - $after.qty) < 0dec {
            THROW "INSUFFICIENT_STOCK: Item unavailable at requested location for manufacturing consumption.";
        };
    };
};