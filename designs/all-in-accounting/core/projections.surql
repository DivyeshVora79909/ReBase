-- Every leg declares its native slot and desired reporting slots in the schema.
DEFINE FUNCTION OVERWRITE fn::accounting::scale($effects: object, $rate: decimal, $currency: record) {
    LET $r=fn::accounting::round(($effects.real??0dec)*$rate,$currency.precision);
    LET $a=fn::accounting::round(($effects.receivable??0dec)*$rate,$currency.precision);
    LET $b=fn::accounting::round(($effects.payable??0dec)*$rate,$currency.precision);
    LET $reserved=fn::accounting::round(($effects.reserved??0dec)*$rate,$currency.precision);
    RETURN object::extend(fn::accounting::effects($r,$a,$b),{reserved:$reserved,available:$r-$reserved,
        expected:fn::accounting::round(($effects.expected??0dec)*$rate,$currency.precision),
        sales_value:fn::accounting::round(($effects.sales_value??0dec)*$rate,$currency.precision),
        purchase_value:fn::accounting::round(($effects.purchase_value??0dec)*$rate,$currency.precision),
        payment_value:fn::accounting::round(($effects.payment_value??0dec)*$rate,$currency.precision),
        fees:fn::accounting::round(($effects.fees??0dec)*$rate,$currency.precision)});
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::post($row: object, $slot: string, $account: record, $at: datetime, $effects: object) {
    LET $a=SELECT * FROM ONLY $account;
    LET $native=object::extend($effects,{net:($effects.receivable??0dec)-($effects.payable??0dec),available:($effects.real??0dec)-($effects.reserved??0dec)});
    LET $rate=fn::accounting::rate_at($a.valuation_pair,$a.resource,$a.reporting_currency,$at);
    LET $v=fn::accounting::scale($native,$rate,$a.reporting_currency);
    LET $kind=record::tb($account);
    LET $report=IF $a.organization!=NONE {
        object::extend(fn::accounting::effects(0dec,$v.payable,$v.receivable),{counterparty_real:-$v.real,
            counterparty_receivable:$v.payable,counterparty_payable:$v.receivable,
            sales_value:$v.sales_value,purchase_value:$v.purchase_value,payment_value:$v.payment_value})
    } ELSE IF $kind IN ['direct_tax_account','indirect_tax_account'] {
        object::extend(fn::accounting::effects(0dec,$v.receivable,$v.payable),{tax_real:$v.real,tax_receivable:$v.receivable,tax_payable:$v.payable})
    } ELSE IF $kind IN ['misc_currency_account','misc_stock_account'] {
        object::extend(fn::accounting::effects(0dec,0dec,0dec),{misc_real:$v.real})
    } ELSE {object::extend(fn::accounting::effects($v.real,0dec,0dec),{owned_real:$v.real,fees:$v.fees})};
    LET $org=IF $a.organization=NONE THEN [] ELSE [
        fn::tree::member($row.id,$slot+'_organization',$a.organization,'z_history',$at,fn::accounting::scale($native,fn::accounting::rate_at($a.organization_pair,$a.resource,$a.organization_currency,$at),$a.organization_currency),{currency:$a.organization_currency,subsidiary:$a.subsidiary},{},false)] END;
    RETURN array::concat([
        fn::tree::member($row.id,$slot,$account,'z_history',$at,$native,{resource:$a.resource,subsidiary:$a.subsidiary},{},false),
        fn::tree::member($row.id,$slot+'_subsidiary',$a.subsidiary,'z_history',$at,$report,{currency:$a.reporting_currency},{},false)],$org);
} PERMISSIONS NONE;
