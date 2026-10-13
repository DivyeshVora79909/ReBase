-- Validators collect participants; no invoice or note repeats their postings.
DEFINE FUNCTION OVERWRITE fn::accounting::invoice_validate($row: object) {
    LET $s=$row.z_history.summary;
    IF $s.count=0 { RETURN NONE; };
    IF !$s.tags.account.uniform OR $s.tags.account.value!=$row.account OR !$s.tags.currency.uniform OR $s.tags.currency.value!=$row.currency { THROW 'INVOICE_DIMENSIONS'; };
    IF ($s.measures.amount.instant_min??0dec)<0dec OR ($s.measures.paid.instant_min??0dec)<0dec { THROW 'INVOICE_NEGATIVE_TOTAL'; };
    LET $boundary=$row.invoice_date+1ns;
    LET $closing=fn::tree::before({rid:$row.id,slot:'z_history'},[$boundary]).measures.balance.sum??0dec;
    IF $closing<0dec { THROW 'INVOICE_OVERSETTLED_AT_DATE'; };
    IF $s.last[0]>=$boundary {
        LET $later=fn::tree::range({rid:$row.id,slot:'z_history'},[$boundary],[$s.last[0]+1ns]);
        IF $closing+($later.measures.balance.instant_min??0dec)<0dec { THROW 'INVOICE_OVERSETTLED_AFTER_DATE'; };
    };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::note_validate($row: object) {
    LET $s=$row.z_lines.summary;
    IF $s.count=0 { RETURN NONE; };
    IF !$s.tags.account.uniform OR $s.tags.account.value!=$row.account OR !$s.tags.is_sale.uniform OR $s.tags.is_sale.value!=$row.is_sale { THROW 'ADJUSTMENT_NOTE_DIMENSIONS'; };
    IF ($s.measures.positive.sum??0dec)>0dec AND ($s.measures.negative.sum??0dec)>0dec { THROW 'ADJUSTMENT_NOTE_MIXED_SIGN'; };
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::accounting::commercial($row: object, $amount: decimal, $paid: decimal) {
    LET $value=$amount-$paid;
    LET $sign=IF $row.is_sale THEN 1dec ELSE -1dec END;
    LET $claim=fn::accounting::claim($sign*$value);
    LET $base=record::tb($row.id) IN ['sales_issue','purchase_issue','issue_adjustment'];
    RETURN array::concat(fn::accounting::post($row,'z_counterparty',$row.currency_account,$row.effective_at,
        object::extend(fn::accounting::claim(-$sign*$value),{real:-$sign*$paid,
            sales_value:IF $base AND $row.is_sale THEN $amount ELSE 0dec END,
            purchase_value:IF $base AND !$row.is_sale THEN $amount ELSE 0dec END,payment_value:$paid})),[
        fn::tree::member($row.id,'z_invoice',$row.invoice,'z_history',$row.effective_at,
            object::extend($claim,{amount:$amount,paid:$paid,balance:$value}),{account:$row.currency_account,currency:$row.currency},{},false),
        fn::tree::member($row.id,'z_note',$row.adjustment_note,'z_lines',$row.effective_at,
            {amount:$amount,paid:$paid,positive:IF $value>0dec THEN 1dec ELSE 0dec END,negative:IF $value<0dec THEN 1dec ELSE 0dec END},
            {account:$row.currency_account,is_sale:$row.is_sale},{},false)]);
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE sales_invoice SCHEMAFULL COMMENT '@rebase-validate fn::accounting::invoice_validate';

DEFINE FIELD OVERWRITE account ON sales_invoice TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE organization ON sales_invoice TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.account.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON sales_invoice TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.account.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON sales_invoice TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.account.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON sales_invoice TYPE bool VALUE true COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE number ON sales_invoice TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON sales_invoice TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE invoice_date ON sales_invoice TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_history ON sales_invoice TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE TABLE OVERWRITE purchase_invoice SCHEMAFULL COMMENT '@rebase-validate fn::accounting::invoice_validate';

DEFINE FIELD OVERWRITE account ON purchase_invoice TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE organization ON purchase_invoice TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.account.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON purchase_invoice TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.account.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON purchase_invoice TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.account.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON purchase_invoice TYPE bool VALUE false COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE number ON purchase_invoice TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON purchase_invoice TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE invoice_date ON purchase_invoice TYPE datetime COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_history ON purchase_invoice TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE TABLE OVERWRITE sales_adjustment_note SCHEMAFULL COMMENT '@rebase-validate fn::accounting::note_validate';

DEFINE FIELD OVERWRITE account ON sales_adjustment_note TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE organization ON sales_adjustment_note TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.account.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON sales_adjustment_note TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.account.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON sales_adjustment_note TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.account.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON sales_adjustment_note TYPE bool VALUE true COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE number ON sales_adjustment_note TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON sales_adjustment_note TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_lines ON sales_adjustment_note TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE TABLE OVERWRITE purchase_adjustment_note SCHEMAFULL COMMENT '@rebase-validate fn::accounting::note_validate';

DEFINE FIELD OVERWRITE account ON purchase_adjustment_note TYPE record<organization_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE organization ON purchase_adjustment_note TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.account.organization COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE subsidiary ON purchase_adjustment_note TYPE record<subsidiary> REFERENCE ON DELETE REJECT VALUE $this.account.subsidiary COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE currency ON purchase_adjustment_note TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.account.currency COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE is_sale ON purchase_adjustment_note TYPE bool VALUE false COMMENT '@rebase-derived';

DEFINE FIELD OVERWRITE number ON purchase_adjustment_note TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE description ON purchase_adjustment_note TYPE option<string> COMMENT '@rebase-audit';

DEFINE FIELD OVERWRITE z_lines ON purchase_adjustment_note TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';
