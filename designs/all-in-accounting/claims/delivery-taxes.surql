-- Delivery taxes are selected on a priced invoice line. The issue owns the
-- atomic recipe; each output names its line and underlying stock delivery.
    -- The compound row references its base predecessor; both tax rows reference
    -- their invoice line. Managed lifecycle order follows these declared edges.

DEFINE FUNCTION OVERWRITE fn::accounting::delivery_tax_role($kind: string, $line: string, $tax: string) {
    RETURN 'delivery:' + $kind + ':' + <string>[$line, $tax];
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::sales_delivery_inputs_validate($row: object) {
    FOR $line IN $row.lines {
        LET $base = $line.tax_components ?? [];
        LET $compound = $line.compound_tax_components ?? [];
        LET $all = array::concat($base, $compound);
        LET $keys = $all.map(|$component| $component.tax_key);
        IF array::len(array::distinct($keys)) != array::len($keys) { THROW 'ACCOUNTING_DELIVERY_TAX_KEY_DUPLICATE'; };
        IF array::len($compound) > 1 { THROW 'ACCOUNTING_DELIVERY_COMPOUND_SINGLE_STAGE'; };
        IF $base.any(|$component| ($component.amount = NONE) = ($component.rule_version = NONE)) {
            THROW 'ACCOUNTING_DELIVERY_TAX_SOURCE_EXCLUSIVE';
        };
        FOR $component IN $all {
            IF record::tb($component.tax_claim_account.opponent) != 'tax_account'
                OR $component.tax_claim_account.currency != $row.invoice.currency
                OR $component.tax_claim_account.economic_entity != $row.invoice.economic_entity {
                THROW 'ACCOUNTING_DELIVERY_TAX_DIMENSION_MISMATCH';
            };
            LET $rule = $component.rule_version;
            IF $rule != NONE AND (!record::exists($rule) OR $rule.component_key != $component.tax_key
                OR $rule.tax_claim_account != $component.tax_claim_account
                OR $row.issued_at < $rule.valid_from OR $row.issued_at >= $rule.valid_until) {
                THROW 'ACCOUNTING_DELIVERY_TAX_RULE_MISMATCH';
            };
        };
        IF $compound.any(|$component| $component.rule_version.kind != 'proportional'
            OR !$base.any(|$predecessor| $predecessor.tax_key = $component.predecessor_tax_key)) {
            THROW 'ACCOUNTING_DELIVERY_TAX_PREDECESSOR_MISMATCH';
        };
    };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::sales_delivery_tax_outputs($row: object) {
    LET $base = array::flatten($row.lines.map(|$line| ($line.tax_components ?? []).map(|$component| {
        LET $role = fn::accounting::delivery_tax_role('base', $line.line_key, $component.tax_key);
        RETURN {
            id: type::record('sales_delivery_tax', [$row.id, $role]), role: $role,
            data: { owned_by: $row.owned_by,
                line: type::record('sales_invoice_line', [$row.id, $line.line_key]),
                tax_key: $component.tax_key, tax_claim_account: $component.tax_claim_account,
                entered_amount: $component.amount, rule_version: $component.rule_version }
        };
    })));
    LET $compound = array::flatten($row.lines.map(|$line| ($line.compound_tax_components ?? []).map(|$component| {
        LET $role = fn::accounting::delivery_tax_role('compound', $line.line_key, $component.tax_key);
        RETURN {
            id: type::record('sales_delivery_compound_tax', [$row.id, $role]), role: $role,
            data: { owned_by: $row.owned_by,
                line: type::record('sales_invoice_line', [$row.id, $line.line_key]),
                tax_key: $component.tax_key, tax_claim_account: $component.tax_claim_account,
                rule_version: $component.rule_version,
                predecessor: type::record('sales_delivery_tax', [$row.id,
                    fn::accounting::delivery_tax_role('base', $line.line_key, $component.predecessor_tax_key)]) }
        };
    })));
    RETURN array::concat($base, $compound);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::sales_delivery_tax_members($row: object) {
    IF $row.amount = NONE { RETURN []; };
    RETURN [
        fn::tree::member($row.id, 'z_delivery', $row.line, 'z_taxes', $row.effective_at,
            { tax: $row.amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_invoice', $row.invoice, 'z_outstanding', $row.effective_at,
            { outstanding: $row.amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_customer', $row.claim_account, 'z_history', $row.effective_at,
            { receivable: $row.amount, net: $row.amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_tax', $row.tax_claim_account, 'z_history', $row.effective_at,
            { payable: $row.amount, net: -$row.amount }, { currency: $row.currency }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::sales_delivery_tax_validate($row: object) {
    -- A source replacement refreshes surviving lines before it removes obsolete
    -- tax siblings. Such a sibling may briefly round to zero in the new currency;
    -- require positive calculated amounts on the final managed population.
    IF $row.amount <= 0dec { THROW 'ACCOUNTING_DELIVERY_TAX_AMOUNT_POSITIVE'; };
    LET $issue_id = type::record($row.rebase_managed_source);
    LET $issue = SELECT * FROM ONLY $issue_id;
    LET $line_key = $row.line.rebase_managed_role;
    LET $line = ($issue.lines ?? []).filter(|$input| $input.line_key = $line_key)[0];
    LET $compound = record::tb($row.id) = 'sales_delivery_compound_tax';
    LET $inputs = IF $compound THEN $line.compound_tax_components ELSE $line.tax_components END;
    LET $input = ($inputs ?? []).filter(|$input| $input.tax_key = $row.tax_key)[0];
    IF record::tb($issue_id) != 'sales_invoice_issue' OR $issue = NONE OR $line = NONE OR $input = NONE
        OR $row.line.rebase_managed_source != $row.rebase_managed_source
        OR $row.line != type::record('sales_invoice_line', [$issue_id, $line_key])
        OR $row.invoice != $issue.invoice OR $row.invoice != $row.line.invoice
        OR $row.delivery != $line.source OR $row.delivery != $row.line.source
        OR $row.effective_at != $issue.issued_at OR $row.effective_at != $row.line.effective_at
        OR $input.tax_claim_account != $row.tax_claim_account OR $input.rule_version != $row.rule_version {
        THROW 'ACCOUNTING_DELIVERY_TAX_SOURCE_MISMATCH';
    };
    IF $row.claim_account != $row.invoice.claim_account OR $row.currency != $row.invoice.currency
        OR $row.tax_claim_account.currency != $row.currency
        OR $row.tax_claim_account.economic_entity != $row.invoice.economic_entity
        OR record::tb($row.tax_claim_account.opponent) != 'tax_account' {
        THROW 'ACCOUNTING_DELIVERY_TAX_DIMENSION_MISMATCH';
    };
    IF $row.rule_version != NONE AND ($row.rule_version.tax_claim_account != $row.tax_claim_account
        OR $row.rule_version.component_key != $row.tax_key
        OR $row.effective_at < $row.rule_version.valid_from OR $row.effective_at >= $row.rule_version.valid_until) {
        THROW 'ACCOUNTING_DELIVERY_TAX_RULE_MISMATCH';
    };
    IF !$compound AND ($input.amount != $row.entered_amount
        OR ($row.entered_amount = NONE) = ($row.rule_version = NONE)) { THROW 'ACCOUNTING_DELIVERY_TAX_SOURCE_EXCLUSIVE'; };
    IF $compound AND ($row.rule_version.kind != 'proportional'
        OR $row.predecessor.line != $row.line
        OR $row.predecessor.tax_key != $input.predecessor_tax_key
        OR $row.predecessor.rebase_managed_source != $row.rebase_managed_source) {
        THROW 'ACCOUNTING_DELIVERY_TAX_PREDECESSOR_MISMATCH';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE sales_delivery_compound_tax SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::accounting::sales_delivery_tax_members @rebase-validate fn::accounting::sales_delivery_tax_validate';
DEFINE FIELD OVERWRITE rebase_managed_source ON sales_delivery_compound_tax TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON sales_delivery_compound_tax TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE line ON sales_delivery_compound_tax TYPE record<sales_invoice_line> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE delivery ON sales_delivery_compound_tax TYPE record<stock_out> REFERENCE ON DELETE REJECT VALUE $this.line.source COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice ON sales_delivery_compound_tax TYPE record<sales_invoice> REFERENCE ON DELETE REJECT VALUE $this.line.invoice COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE claim_account ON sales_delivery_compound_tax TYPE record<claim_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.claim_account COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE currency ON sales_delivery_compound_tax TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE currency_precision ON sales_delivery_compound_tax TYPE int VALUE $this.invoice.currency_precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE effective_at ON sales_delivery_compound_tax TYPE datetime VALUE $this.line.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE tax_key ON sales_delivery_compound_tax TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE tax_claim_account ON sales_delivery_compound_tax TYPE record<claim_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE rule_version ON sales_delivery_compound_tax TYPE record<sales_tax_rule_version> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE predecessor ON sales_delivery_compound_tax TYPE record<sales_delivery_tax> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON sales_delivery_compound_tax TYPE decimal VALUE
    fn::accounting::currency_round(($this.line.amount + $this.predecessor.amount) * $this.rule_version.rate, $this.currency_precision)
    COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_delivery ON sales_delivery_compound_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice_line.z_taxes';
DEFINE FIELD OVERWRITE z_invoice ON sales_delivery_compound_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_outstanding';
DEFINE FIELD OVERWRITE z_customer ON sales_delivery_compound_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_tax ON sales_delivery_compound_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';

DEFINE TABLE OVERWRITE sales_delivery_tax SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::accounting::sales_delivery_tax_members @rebase-validate fn::accounting::sales_delivery_tax_validate';
DEFINE FIELD OVERWRITE rebase_managed_source ON sales_delivery_tax TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON sales_delivery_tax TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE line ON sales_delivery_tax TYPE record<sales_invoice_line> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE delivery ON sales_delivery_tax TYPE record<stock_out> REFERENCE ON DELETE REJECT VALUE $this.line.source COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE invoice ON sales_delivery_tax TYPE record<sales_invoice> REFERENCE ON DELETE REJECT VALUE $this.line.invoice COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE claim_account ON sales_delivery_tax TYPE record<claim_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.claim_account COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE currency ON sales_delivery_tax TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE currency_precision ON sales_delivery_tax TYPE int VALUE $this.invoice.currency_precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE effective_at ON sales_delivery_tax TYPE datetime VALUE $this.line.effective_at COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE tax_key ON sales_delivery_tax TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE tax_claim_account ON sales_delivery_tax TYPE record<claim_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE rule_version ON sales_delivery_tax TYPE option<record<sales_tax_rule_version>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE entered_amount ON sales_delivery_tax TYPE option<decimal> ASSERT $value = NONE OR $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON sales_delivery_tax TYPE decimal VALUE fn::accounting::currency_round(
    IF $this.entered_amount != NONE THEN $this.entered_amount
        ELSE IF $this.rule_version.kind = 'fixed' THEN $this.rule_version.fixed_amount
        ELSE $this.line.amount * $this.rule_version.rate END, $this.currency_precision)
    COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_delivery ON sales_delivery_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice_line.z_taxes';
DEFINE FIELD OVERWRITE z_invoice ON sales_delivery_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_outstanding';
DEFINE FIELD OVERWRITE z_customer ON sales_delivery_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_tax ON sales_delivery_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
