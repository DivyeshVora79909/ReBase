-- Invoices validate a dated commercial history and never post to accounts.

DEFINE FUNCTION OVERWRITE fn::accounting::invoice_validate($row: object) {
    LET $s = $row.z_history.summary;
    IF $s.count = 0 { RETURN NONE; };
    IF $s.tags.organization = NONE OR !$s.tags.organization.uniform OR $s.tags.organization.value != $row.organization
        OR $s.tags.currency = NONE OR !$s.tags.currency.uniform OR $s.tags.currency.value != $row.currency { THROW 'INVOICE_DIMENSIONS'; };
    LET $forbidden = IF record::tb($row.id) = 'sales_invoice' THEN $s.measures.payable ELSE $s.measures.receivable END;
    IF ($forbidden.min ?? 0dec) != 0dec OR ($forbidden.max ?? 0dec) != 0dec { THROW 'INVOICE_CLAIM_FAMILY'; };
    IF ($s.measures.amount.instant_min ?? 0dec) < 0dec OR ($s.measures.paid.instant_min ?? 0dec) < 0dec { THROW 'INVOICE_NEGATIVE_TOTAL'; };
    LET $boundary = $row.invoice_date + 1ns;
    LET $closing = fn::tree::before({ rid: $row.id, slot: 'z_history' }, [$boundary]).measures.balance.sum ?? 0dec;
    IF $closing < 0dec { THROW 'INVOICE_OVERSETTLED_AT_DATE'; };
    IF $s.last[0] >= $boundary {
        LET $later = fn::tree::range({ rid: $row.id, slot: 'z_history' }, [$boundary], [$s.last[0] + 1ns]);
        IF $closing + ($later.measures.balance.instant_min ?? 0dec) < 0dec { THROW 'INVOICE_OVERSETTLED_AFTER_DATE'; };
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE sales_invoice SCHEMAFULL COMMENT '@rebase-validate fn::accounting::invoice_validate';
DEFINE FIELD OVERWRITE organization ON sales_invoice TYPE record<organization> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE invoice_date ON sales_invoice TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE number ON sales_invoice TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON sales_invoice TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.organization.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_history ON sales_invoice TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';

DEFINE TABLE OVERWRITE purchase_invoice SCHEMAFULL COMMENT '@rebase-validate fn::accounting::invoice_validate';
DEFINE FIELD OVERWRITE organization ON purchase_invoice TYPE record<organization> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE invoice_date ON purchase_invoice TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE number ON purchase_invoice TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON purchase_invoice TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.organization.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_history ON purchase_invoice TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';

DEFINE FUNCTION OVERWRITE fn::accounting::issue_validate($row: object) {
    fn::accounting::phase($row.effective_at, $row.invoice_date, false);
    fn::accounting::rate_validate($row.stock_currency, $row.currency, $row.exchange_rate);
    IF ($row.z_basis.summary.measures.quantity.instant_min ?? 0dec) < 0dec { THROW 'ISSUE_QUANTITY_CAPACITY'; };
    IF ($row.z_basis.summary.measures.base.instant_min ?? 0dec) < 0dec { THROW 'ISSUE_VALUE_CAPACITY'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::issue_members($row: object) {
    RETURN array::concat(fn::accounting::commercial_members($row, $row.amount, 0dec), [
        fn::accounting::balance_member($row, 'z_stock', $row.stock_account, $row.effective_at,
            fn::accounting::effects(IF $row.is_sale THEN -$row.quantity ELSE $row.quantity END, 0dec, 0dec), false),
        fn::tree::member($row.id, 'z_base', $row.id, 'z_basis', $row.effective_at, { base: $row.amount, quantity: $row.quantity }, {}, {}, false),
        fn::tree::member($row.id, 'z_net_self', $row.id, 'z_net', $row.effective_at, { amount: $row.amount }, {}, {}, false)]);
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE sales_issue SCHEMAFULL COMMENT '@rebase-members fn::accounting::issue_members @rebase-validate fn::accounting::issue_validate';
DEFINE FIELD OVERWRITE invoice ON sales_issue TYPE record<sales_invoice> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE stock_account ON sales_issue TYPE record<stock_account | misc_stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE quantity ON sales_issue TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE price ON sales_issue TYPE decimal ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE exchange_rate ON sales_issue TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON sales_issue TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE organization ON sales_issue TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE currency ON sales_issue TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice_date ON sales_issue TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE stock_currency ON sales_issue TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.stock_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE is_sale ON sales_issue TYPE bool VALUE true COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE precision ON sales_issue TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE amount ON sales_issue TYPE decimal VALUE fn::accounting::round($this.quantity * $this.price * $this.exchange_rate, $this.precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_basis ON sales_issue TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_net ON sales_issue TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_organization ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';
DEFINE FIELD OVERWRITE z_invoice ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';
DEFINE FIELD OVERWRITE z_stock ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history';
DEFINE FIELD OVERWRITE z_base ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_basis';
DEFINE FIELD OVERWRITE z_net_self ON sales_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_issue.z_net';

DEFINE TABLE OVERWRITE purchase_issue SCHEMAFULL COMMENT '@rebase-members fn::accounting::issue_members @rebase-validate fn::accounting::issue_validate';
DEFINE FIELD OVERWRITE invoice ON purchase_issue TYPE record<purchase_invoice> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE stock_account ON purchase_issue TYPE record<stock_account | misc_stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE quantity ON purchase_issue TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE price ON purchase_issue TYPE decimal ASSERT $value >= 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE exchange_rate ON purchase_issue TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON purchase_issue TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE organization ON purchase_issue TYPE record<organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.organization COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE currency ON purchase_issue TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice_date ON purchase_issue TYPE datetime VALUE $this.invoice.invoice_date COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE stock_currency ON purchase_issue TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.stock_account.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE is_sale ON purchase_issue TYPE bool VALUE false COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE precision ON purchase_issue TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE amount ON purchase_issue TYPE decimal VALUE fn::accounting::round($this.quantity * $this.price * $this.exchange_rate, $this.precision) COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_basis ON purchase_issue TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_net ON purchase_issue TYPE object COMMENT '@rebase-tree-root @rebase-tree-duplicates @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_organization ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history';
DEFINE FIELD OVERWRITE z_invoice ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_history @rebase-tree-owner purchase_invoice.z_history';
DEFINE FIELD OVERWRITE z_stock ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history';
DEFINE FIELD OVERWRITE z_base ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner purchase_issue.z_basis';
DEFINE FIELD OVERWRITE z_net_self ON purchase_issue TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner purchase_issue.z_net';
