-- Issue-date invoice variants priced from real stock movements. A billed
-- quantity consumes its source movement once across all invoice groups.

DEFINE FUNCTION OVERWRITE fn::accounting::invoice_validate($row: object) {
    IF record::tb($row.claim_account.opponent) NOT IN ['rebase_user', 'organization'] {
        THROW 'ACCOUNTING_INVOICE_PARTY_MISMATCH';
    };
    LET $summary = $row.z_outstanding.summary;
    IF ($summary.measures.outstanding.min_prefix ?? 0dec) < 0dec {
        THROW 'ACCOUNTING_INVOICE_OVERSETTLED';
    };
    IF $summary.tags.currency != NONE AND
        (!$summary.tags.currency.uniform OR $summary.tags.currency.value != $row.claim_account.currency) {
        THROW 'ACCOUNTING_INVOICE_CURRENCY_MISMATCH';
    };
    LET $basis_tags = $row.z_taxable_input.summary.tags.currency;
    IF $basis_tags != NONE AND
        (!$basis_tags.uniform OR $basis_tags.value != $row.claim_account.currency) {
        THROW 'ACCOUNTING_INVOICE_BASIS_CURRENCY_MISMATCH';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE sales_invoice SCHEMAFULL
    COMMENT '@rebase-validate fn::accounting::invoice_validate';
DEFINE FIELD OVERWRITE economic_entity ON sales_invoice TYPE record<rebase_user | organization> VALUE $this.claim_account.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends claim_account.economic_entity';
DEFINE FIELD OVERWRITE claim_account ON sales_invoice TYPE record<claim_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE number ON sales_invoice TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON sales_invoice TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.claim_account.currency COMMENT '@rebase-derived @rebase-depends claim_account.currency';
DEFINE FIELD OVERWRITE currency_precision ON sales_invoice TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_outstanding ON sales_invoice TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE FIELD OVERWRITE z_taxable_input ON sales_invoice TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE INDEX OVERWRITE sales_invoice_number ON sales_invoice FIELDS economic_entity, number UNIQUE;

DEFINE TABLE OVERWRITE purchase_invoice SCHEMAFULL
    COMMENT '@rebase-validate fn::accounting::invoice_validate';
DEFINE FIELD OVERWRITE economic_entity ON purchase_invoice TYPE record<rebase_user | organization> VALUE $this.claim_account.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends claim_account.economic_entity';
DEFINE FIELD OVERWRITE claim_account ON purchase_invoice TYPE record<claim_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE number ON purchase_invoice TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON purchase_invoice TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.claim_account.currency COMMENT '@rebase-derived @rebase-depends claim_account.currency';
DEFINE FIELD OVERWRITE currency_precision ON purchase_invoice TYPE int VALUE $this.currency.precision COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_outstanding ON purchase_invoice TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';
DEFINE INDEX OVERWRITE purchase_invoice_number ON purchase_invoice FIELDS economic_entity, number UNIQUE;

DEFINE FUNCTION OVERWRITE fn::accounting::invoice_issue_validate($row: object) {
    IF array::len($row.lines) = 0 { THROW 'ACCOUNTING_INVOICE_ISSUE_LINES_REQUIRED'; };
    LET $keys = $row.lines.map(|$line| $line.line_key);
    IF $keys.any(|$key| $key = NONE OR string::len($key) = 0) {
        THROW 'ACCOUNTING_INVOICE_LINE_KEY_REQUIRED';
    };
    IF array::len(array::distinct($keys)) != array::len($keys) {
        THROW 'ACCOUNTING_INVOICE_LINE_KEY_DUPLICATE';
    };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::sales_invoice_issue_validate($row: object) {
    fn::accounting::invoice_issue_validate($row);
    IF $row.lines.any(|$line| string::matches($line.line_key, /^tax:/)) {
        THROW 'ACCOUNTING_INVOICE_LINE_KEY_RESERVED';
    };
    LET $keys = ($row.tax_components ?? []).map(|$component| $component.tax_key);
    IF $keys.any(|$key| $key = NONE OR string::len($key) = 0) {
        THROW 'ACCOUNTING_INVOICE_TAX_KEY_REQUIRED';
    };
    IF array::len(array::distinct($keys)) != array::len($keys) {
        THROW 'ACCOUNTING_INVOICE_TAX_KEY_DUPLICATE';
    };
    IF array::len(($row.tax_components ?? []).filter(|$component|
        $component.aggregate_rule_version != NONE)) > 1 {
        THROW 'ACCOUNTING_INVOICE_AGGREGATE_TAX_SINGLE_COMPONENT';
    };
    IF array::len(($row.compound_tax_components ?? [])) > 1 {
        THROW 'ACCOUNTING_INVOICE_COMPOUND_TAX_SINGLE_COMPONENT';
    };
    LET $component_keys = array::concat(
        ($row.tax_components ?? []).map(|$component| $component.tax_key),
        ($row.compound_tax_components ?? []).map(|$component| $component.tax_key));
    IF array::len(array::distinct($component_keys)) != array::len($component_keys) {
        THROW 'ACCOUNTING_INVOICE_TAX_COMPONENT_KEY_DUPLICATE';
    };
    IF ($row.tax_components ?? []).any(|$component| {
        LET $manual = $component.amount != NONE;
        LET $ruled = $component.rule_version != NONE;
        LET $aggregate = $component.aggregate_rule_version != NONE;
        RETURN !(($manual AND !$ruled AND !$aggregate)
            OR (!$manual AND $ruled AND !$aggregate)
            OR (!$manual AND !$ruled AND $aggregate));
    }) { THROW 'ACCOUNTING_INVOICE_TAX_SOURCE_EXCLUSIVE'; };
    IF ($row.tax_components ?? []).any(|$component| $component.amount != NONE AND $component.amount <= 0dec) {
        THROW 'ACCOUNTING_INVOICE_TAX_AMOUNT_POSITIVE';
    };
    IF ($row.tax_components ?? []).any(|$component| {
        LET $rule = IF $component.aggregate_rule_version != NONE
            THEN $component.aggregate_rule_version ELSE $component.rule_version END;
        IF $rule = NONE { RETURN false; };
        IF $component.aggregate_rule_version != NONE AND $rule.kind != 'proportional' {
            THROW 'ACCOUNTING_INVOICE_AGGREGATE_TAX_PROPORTIONAL_ONLY';
        };
        RETURN !record::exists($rule)
            OR $rule.component_key != $component.tax_key
            OR $rule.tax_claim_account != $component.tax_claim_account
            OR $rule.tax_claim_account.currency != $row.invoice.currency
            OR $row.issued_at < $rule.valid_from OR $row.issued_at >= $rule.valid_until;
    }) { THROW 'ACCOUNTING_INVOICE_TAX_RULE_MISMATCH'; };
    LET $aggregates = ($row.tax_components ?? []).filter(|$component|
        $component.aggregate_rule_version != NONE);
    IF array::len($row.compound_tax_components ?? []) > 0 AND array::len($aggregates) != 1 {
        THROW 'ACCOUNTING_INVOICE_COMPOUND_TAX_REQUIRES_ONE_AGGREGATE';
    };
    IF ($row.compound_tax_components ?? []).any(|$component| {
        IF $component.rule_version = NONE OR $component.rule_version.kind != 'proportional'
            OR $component.predecessor_tax_key = NONE OR string::len($component.predecessor_tax_key) = 0 {
            THROW 'ACCOUNTING_INVOICE_COMPOUND_TAX_SHAPE';
        };
        IF $component.rule_version.component_key != $component.tax_key
            OR $component.rule_version.tax_claim_account != $component.tax_claim_account
            OR $component.tax_claim_account.currency != $row.invoice.currency
            OR $row.issued_at < $component.rule_version.valid_from
            OR $row.issued_at >= $component.rule_version.valid_until {
            THROW 'ACCOUNTING_INVOICE_COMPOUND_TAX_RULE_MISMATCH';
        };
        LET $aggregate = $aggregates[0];
        RETURN $component.predecessor_tax_key != $aggregate.tax_key;
    }) { THROW 'ACCOUNTING_INVOICE_COMPOUND_TAX_PREDECESSOR_MISMATCH'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::currency_round($value: decimal, $precision: int) {
    RETURN IF $precision = 0 THEN <decimal>math::round($value)
        ELSE <decimal>math::fixed($value, $precision) END;
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::sales_invoice_issue_outputs($row: object) {
    LET $base = math::sum($row.lines.map(|$line|
        fn::accounting::currency_round($line.billed_quantity * $line.unit_price, $row.invoice.currency_precision)));
    LET $lines = $row.lines.map(|$line| {
        id: type::record('sales_invoice_line', [$row.id, $line.line_key]),
        role: $line.line_key,
        data: {
            owned_by: $row.owned_by, invoice: $row.invoice, source: $line.source,
            billed_quantity: $line.billed_quantity, unit_price: $line.unit_price,
            claim_account: $row.invoice.claim_account, source_at: $line.source.effective_at,
            effective_at: $row.issued_at,
            amount: fn::accounting::currency_round($line.billed_quantity * $line.unit_price, $row.invoice.currency_precision)
        }
    });
    LET $taxes = ($row.tax_components ?? []).filter(|$component|
        $component.aggregate_rule_version = NONE).map(|$component| {
        id: type::record('sales_invoice_tax_component', [$row.id, string::concat('tax:', $component.tax_key)]),
        role: string::concat('tax:', $component.tax_key),
        data: {
            owned_by: $row.owned_by, invoice: $row.invoice,
            tax_claim_account: $component.tax_claim_account,
            rule_version: $component.rule_version,
            amount: IF $component.rule_version = NONE { $component.amount }
                ELSE IF $component.rule_version.kind = 'fixed' { $component.rule_version.fixed_amount }
                ELSE { fn::accounting::currency_round($base * $component.rule_version.rate, $row.invoice.currency_precision) },
            effective_at: $row.issued_at
        }
    });
    LET $aggregate_bases = ($row.tax_components ?? []).filter(|$component|
        $component.aggregate_rule_version != NONE).map(|$component| {
        id: type::record('sales_invoice_aggregate_tax_basis', [$row.id,
            string::concat('aggregate:basis:', $component.tax_key)]),
        role: string::concat('aggregate:basis:', $component.tax_key),
        data: {
            owned_by: $row.owned_by, invoice: $row.invoice,
            issued_at: $row.issued_at, tax_key: $component.tax_key,
            tax_claim_account: $component.tax_claim_account,
            rule_version: $component.aggregate_rule_version
        }
    });
    LET $aggregate_taxes = ($row.tax_components ?? []).filter(|$component|
        $component.aggregate_rule_version != NONE).map(|$component| {
        LET $role = string::concat('aggregate:tax:', $component.tax_key);
        LET $basis_role = string::concat('aggregate:basis:', $component.tax_key);
        RETURN {
            id: type::record('sales_invoice_aggregate_tax_component', [$row.id, $role]),
            role: $role,
            data: {
                owned_by: $row.owned_by, invoice: $row.invoice,
                issued_at: $row.issued_at, tax_key: $component.tax_key,
                tax_claim_account: $component.tax_claim_account,
                rule_version: $component.aggregate_rule_version,
                basis: type::record('sales_invoice_aggregate_tax_basis', [$row.id, $basis_role])
            }
        };
    });
    LET $compound_taxes = ($row.compound_tax_components ?? []).map(|$component| {
        LET $role = string::concat('compound:tax:', $component.tax_key);
        LET $aggregate = ($row.tax_components ?? []).filter(|$aggregate|
            $aggregate.aggregate_rule_version != NONE)[0];
        RETURN {
            id: type::record('sales_invoice_compound_tax_component', [$row.id, $role]),
            role: $role,
            data: {
                owned_by: $row.owned_by, invoice: $row.invoice,
                issued_at: $row.issued_at, tax_key: $component.tax_key,
                tax_claim_account: $component.tax_claim_account,
                rule_version: $component.rule_version,
                basis: type::record('sales_invoice_aggregate_tax_basis', [$row.id,
                    string::concat('aggregate:basis:', $aggregate.tax_key)]),
                predecessor: type::record('sales_invoice_aggregate_tax_component',
                    [$row.id, string::concat('aggregate:tax:', $component.predecessor_tax_key)])
            }
        };
    });
    RETURN array::concat(array::concat(array::concat(array::concat($lines, $taxes),
        $aggregate_bases), $aggregate_taxes), $compound_taxes);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::purchase_invoice_issue_outputs($row: object) {
    RETURN $row.lines.map(|$line| {
        id: type::record('purchase_invoice_line', [$row.id, $line.line_key]),
        role: $line.line_key,
        data: {
            owned_by: $row.owned_by, invoice: $row.invoice, source: $line.source,
            billed_quantity: $line.billed_quantity, unit_price: $line.unit_price,
            claim_account: $row.invoice.claim_account, source_at: $line.source.effective_at,
            effective_at: $row.issued_at,
            amount: <decimal>math::fixed($line.billed_quantity * $line.unit_price, $row.invoice.currency_precision)
        }
    });
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE sales_invoice_issue SCHEMAFULL
    COMMENT '@rebase-required-outputs fn::accounting::sales_invoice_issue_outputs @rebase-validate fn::accounting::sales_invoice_issue_validate';
DEFINE FIELD OVERWRITE invoice ON sales_invoice_issue TYPE record<sales_invoice> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE issued_at ON sales_invoice_issue TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE lines ON sales_invoice_issue TYPE array<object> ASSERT array::len($value) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE lines.*.line_key ON sales_invoice_issue TYPE string ASSERT string::len($value) > 0;
DEFINE FIELD OVERWRITE lines.*.source ON sales_invoice_issue TYPE record<stock_out>;
DEFINE FIELD OVERWRITE lines.*.billed_quantity ON sales_invoice_issue TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD OVERWRITE lines.*.unit_price ON sales_invoice_issue TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD OVERWRITE tax_components ON sales_invoice_issue TYPE array<object> DEFAULT [] COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE compound_tax_components ON sales_invoice_issue TYPE array<object> DEFAULT [] COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE tax_components.*.tax_key ON sales_invoice_issue TYPE string ASSERT string::len($value) > 0;
DEFINE FIELD OVERWRITE tax_components.*.tax_claim_account ON sales_invoice_issue TYPE record<claim_account>;
DEFINE FIELD OVERWRITE tax_components.*.amount ON sales_invoice_issue TYPE option<decimal> ASSERT $value = NONE OR $value > 0dec;
DEFINE FIELD OVERWRITE tax_components.*.rule_version ON sales_invoice_issue TYPE option<record<sales_tax_rule_version>>;
DEFINE FIELD OVERWRITE tax_components.*.aggregate_rule_version ON sales_invoice_issue TYPE option<record<sales_tax_rule_version>>;
DEFINE FIELD OVERWRITE compound_tax_components.*.tax_key ON sales_invoice_issue TYPE string ASSERT string::len($value) > 0;
DEFINE FIELD OVERWRITE compound_tax_components.*.tax_claim_account ON sales_invoice_issue TYPE record<claim_account>;
DEFINE FIELD OVERWRITE compound_tax_components.*.rule_version ON sales_invoice_issue TYPE record<sales_tax_rule_version>;
DEFINE FIELD OVERWRITE compound_tax_components.*.predecessor_tax_key ON sales_invoice_issue TYPE string ASSERT string::len($value) > 0;
DEFINE INDEX OVERWRITE sales_invoice_issue_invoice ON sales_invoice_issue FIELDS invoice UNIQUE;

DEFINE TABLE OVERWRITE purchase_invoice_issue SCHEMAFULL
    COMMENT '@rebase-required-outputs fn::accounting::purchase_invoice_issue_outputs @rebase-validate fn::accounting::invoice_issue_validate';
DEFINE FIELD OVERWRITE invoice ON purchase_invoice_issue TYPE record<purchase_invoice> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE issued_at ON purchase_invoice_issue TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE lines ON purchase_invoice_issue TYPE array<object> ASSERT array::len($value) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE lines.*.line_key ON purchase_invoice_issue TYPE string ASSERT string::len($value) > 0;
DEFINE FIELD OVERWRITE lines.*.source ON purchase_invoice_issue TYPE record<stock_in>;
DEFINE FIELD OVERWRITE lines.*.billed_quantity ON purchase_invoice_issue TYPE decimal ASSERT $value > 0dec;
DEFINE FIELD OVERWRITE lines.*.unit_price ON purchase_invoice_issue TYPE decimal ASSERT $value > 0dec;
DEFINE INDEX OVERWRITE purchase_invoice_issue_invoice ON purchase_invoice_issue FIELDS invoice UNIQUE;

DEFINE FUNCTION OVERWRITE fn::accounting::sales_invoice_line_members($row: object) {
    RETURN [
        fn::tree::member($row.id, 'z_claim', $row.claim_account, 'z_history', $row.effective_at,
            { receivable: $row.amount, net: $row.amount }, { currency: $row.claim_account.currency }, {}, false),
        fn::tree::member($row.id, 'z_invoice', $row.invoice, 'z_outstanding', $row.effective_at,
            { outstanding: $row.amount }, { currency: $row.claim_account.currency }, {}, false),
        fn::tree::member($row.id, 'z_taxable_input', $row.invoice, 'z_taxable_input', $row.effective_at,
            { basis: $row.amount }, { currency: $row.claim_account.currency }, {}, false),
        fn::tree::member($row.id, 'z_source', $row.source, 'z_billing', $row.effective_at,
            { billed: $row.billed_quantity }, { resource: $row.source.from_account.resource }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::purchase_invoice_line_members($row: object) {
    RETURN [
        fn::tree::member($row.id, 'z_claim', $row.claim_account, 'z_history', $row.effective_at,
            { payable: $row.amount, net: -$row.amount }, { currency: $row.claim_account.currency }, {}, false),
        fn::tree::member($row.id, 'z_invoice', $row.invoice, 'z_outstanding', $row.effective_at,
            { outstanding: $row.amount }, { currency: $row.claim_account.currency }, {}, false),
        fn::tree::member($row.id, 'z_source', $row.source, 'z_billing', $row.effective_at,
            { billed: $row.billed_quantity }, { resource: $row.source.to_account.resource }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::sales_invoice_line_validate($row: object) {
    IF $row.source.economic_entity != $row.invoice.economic_entity OR $row.source.to_party != $row.claim_account.opponent {
        THROW 'ACCOUNTING_SALES_INVOICE_SOURCE_MISMATCH';
    };
    IF $row.effective_at < $row.source_at { THROW 'ACCOUNTING_SALES_INVOICE_BEFORE_DELIVERY'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::purchase_invoice_line_validate($row: object) {
    IF $row.source.economic_entity != $row.invoice.economic_entity OR $row.source.from_party != $row.claim_account.opponent {
        THROW 'ACCOUNTING_PURCHASE_INVOICE_SOURCE_MISMATCH';
    };
    IF $row.effective_at < $row.source_at { THROW 'ACCOUNTING_PURCHASE_INVOICE_BEFORE_RECEIPT'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE sales_invoice_line SCHEMAFULL
    PERMISSIONS NONE COMMENT '@rebase-managed-output @rebase-members fn::accounting::sales_invoice_line_members @rebase-validate fn::accounting::sales_invoice_line_validate';
DEFINE FIELD OVERWRITE rebase_managed_source ON sales_invoice_line TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON sales_invoice_line TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE invoice ON sales_invoice_line TYPE record<sales_invoice> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE source ON sales_invoice_line TYPE record<stock_out> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE billed_quantity ON sales_invoice_line TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE unit_price ON sales_invoice_line TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE claim_account ON sales_invoice_line TYPE record<claim_account> VALUE $this.invoice.claim_account COMMENT '@rebase-derived @rebase-depends invoice.claim_account';
DEFINE FIELD OVERWRITE source_at ON sales_invoice_line TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived @rebase-depends source.effective_at';
DEFINE FIELD OVERWRITE effective_at ON sales_invoice_line TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON sales_invoice_line TYPE decimal VALUE fn::accounting::currency_round($this.billed_quantity * $this.unit_price, $this.invoice.currency_precision) ASSERT $value > 0dec COMMENT '@rebase-derived @rebase-depends invoice.currency_precision';
DEFINE FIELD OVERWRITE z_claim ON sales_invoice_line TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_invoice ON sales_invoice_line TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_outstanding';
DEFINE FIELD OVERWRITE z_taxable_input ON sales_invoice_line TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_taxable_input';
DEFINE FIELD OVERWRITE z_source ON sales_invoice_line TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_out.z_billing';

-- The tree-less basis child reads only the input-only rounded-line root.
-- Its issue-owned tax sibling consumes the published value by typed reference.
DEFINE FUNCTION OVERWRITE fn::accounting::sales_invoice_aggregate_tax_members($row: object) {
    IF $row.amount = NONE { RETURN []; };
    RETURN [
        fn::tree::member($row.id, 'z_customer', $row.invoice.claim_account, 'z_history', $row.issued_at,
            { receivable: $row.amount, net: $row.amount }, { currency: $row.invoice.currency }, {}, false),
        fn::tree::member($row.id, 'z_invoice', $row.invoice, 'z_outstanding', $row.issued_at,
            { outstanding: $row.amount }, { currency: $row.invoice.currency }, {}, false),
        fn::tree::member($row.id, 'z_tax', $row.tax_claim_account, 'z_history', $row.issued_at,
            { payable: $row.amount, net: -$row.amount }, { currency: $row.invoice.currency }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::sales_invoice_aggregate_tax_validate($row: object) {
    LET $source = type::record($row.rebase_managed_source);
    LET $issue = SELECT * FROM ONLY $source;
    IF record::tb($source) != 'sales_invoice_issue' OR $issue = NONE
        OR $issue.invoice != $row.invoice OR $issue.issued_at != $row.issued_at
        OR !$issue.tax_components.any(|$component|
            $component.tax_key = $row.tax_key AND $component.aggregate_rule_version = $row.rule_version) {
        THROW 'ACCOUNTING_SALES_AGGREGATE_TAX_ANCESTOR_MISMATCH';
    };
    IF $row.basis.rebase_managed_source != $row.rebase_managed_source OR $row.basis.invoice != $row.invoice
        OR $row.basis.issued_at != $row.issued_at OR $row.basis.tax_key != $row.tax_key
        OR $row.basis.rule_version != $row.rule_version
        OR $row.rule_version.component_key != $row.tax_key
        OR $row.rule_version.kind != 'proportional'
        OR $row.rule_version.tax_claim_account != $row.tax_claim_account
        OR $row.rule_version.valid_from > $row.issued_at OR $row.issued_at >= $row.rule_version.valid_until
        OR $row.tax_claim_account.economic_entity != $row.invoice.economic_entity
        OR $row.tax_claim_account.currency != $row.invoice.currency {
        THROW 'ACCOUNTING_SALES_AGGREGATE_TAX_DIMENSION_MISMATCH';
    };
    IF $row.claim_account != $row.invoice.claim_account
        OR $row.commercial_party != $row.claim_account.opponent OR $row.direction != 'sales' {
        THROW 'ACCOUNTING_SALES_AGGREGATE_TAX_CUSTOMER_MISMATCH';
    };
    IF record::tb($row.tax_claim_account.opponent) != 'tax_account' {
        THROW 'ACCOUNTING_SALES_AGGREGATE_TAX_ACCOUNT_REQUIRED';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE sales_invoice_compound_tax_component SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::accounting::sales_invoice_compound_tax_members @rebase-validate fn::accounting::sales_invoice_compound_tax_validate';

DEFINE TABLE OVERWRITE sales_invoice_aggregate_tax_component SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::accounting::sales_invoice_aggregate_tax_members @rebase-validate fn::accounting::sales_invoice_aggregate_tax_validate';
DEFINE FIELD OVERWRITE rebase_managed_source ON sales_invoice_aggregate_tax_component TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON sales_invoice_aggregate_tax_component TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE invoice ON sales_invoice_aggregate_tax_component TYPE record<sales_invoice> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE issued_at ON sales_invoice_aggregate_tax_component TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE claim_account ON sales_invoice_aggregate_tax_component TYPE record<claim_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.claim_account COMMENT '@rebase-derived @rebase-depends invoice.claim_account';
DEFINE FIELD OVERWRITE commercial_party ON sales_invoice_aggregate_tax_component TYPE record<rebase_user | organization> VALUE $this.claim_account.opponent COMMENT '@rebase-derived @rebase-depends claim_account.opponent';
DEFINE FIELD OVERWRITE economic_entity ON sales_invoice_aggregate_tax_component TYPE record<rebase_user | organization> VALUE $this.claim_account.economic_entity COMMENT '@rebase-derived @rebase-depends claim_account.economic_entity';
DEFINE FIELD OVERWRITE currency ON sales_invoice_aggregate_tax_component TYPE record<currency> VALUE $this.invoice.currency COMMENT '@rebase-derived @rebase-depends invoice.currency';
DEFINE FIELD OVERWRITE direction ON sales_invoice_aggregate_tax_component TYPE string VALUE 'sales' COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE tax_key ON sales_invoice_aggregate_tax_component TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE tax_claim_account ON sales_invoice_aggregate_tax_component TYPE record<claim_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE rule_version ON sales_invoice_aggregate_tax_component TYPE record<sales_tax_rule_version> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE basis ON sales_invoice_aggregate_tax_component TYPE record<sales_invoice_aggregate_tax_basis> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit @rebase-readers';
DEFINE FIELD OVERWRITE amount ON sales_invoice_aggregate_tax_component TYPE option<decimal> VALUE
    IF $this.basis.z_base = NONE OR $this.basis.z_base = 0dec THEN NONE
        ELSE fn::accounting::currency_round($this.basis.z_base * $this.rule_version.rate, $this.invoice.currency_precision) END
    ASSERT $value = NONE OR $value > 0dec COMMENT '@rebase-derived @rebase-depends basis.z_base, rule_version.rate, invoice.currency_precision';
DEFINE FIELD OVERWRITE z_customer ON sales_invoice_aggregate_tax_component TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_invoice ON sales_invoice_aggregate_tax_component TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_outstanding';
DEFINE FIELD OVERWRITE z_tax ON sales_invoice_aggregate_tax_component TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';

-- One compound sibling consumes exactly one aggregate predecessor from the
-- same issue and the tree-less pre-tax basis. Both causal edges are typed.
DEFINE FUNCTION OVERWRITE fn::accounting::sales_invoice_compound_tax_members($row: object) {
    IF $row.amount = NONE { RETURN []; };
    RETURN [
        fn::tree::member($row.id, 'z_customer', $row.invoice.claim_account, 'z_history', $row.issued_at,
            { receivable: $row.amount, net: $row.amount }, { currency: $row.invoice.currency }, {}, false),
        fn::tree::member($row.id, 'z_invoice', $row.invoice, 'z_outstanding', $row.issued_at,
            { outstanding: $row.amount }, { currency: $row.invoice.currency }, {}, false),
        fn::tree::member($row.id, 'z_tax', $row.tax_claim_account, 'z_history', $row.issued_at,
            { payable: $row.amount, net: -$row.amount }, { currency: $row.invoice.currency }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::sales_invoice_compound_tax_validate($row: object) {
    LET $source = type::record($row.rebase_managed_source);
    LET $issue = SELECT * FROM ONLY $source;
    IF record::tb($source) != 'sales_invoice_issue' OR $issue = NONE
        OR $issue.invoice != $row.invoice OR $issue.issued_at != $row.issued_at
        OR !$issue.compound_tax_components.any(|$component|
            $component.tax_key = $row.tax_key AND $component.rule_version = $row.rule_version
                AND $component.tax_claim_account = $row.tax_claim_account
                AND $component.predecessor_tax_key = $row.predecessor.tax_key) {
        THROW 'ACCOUNTING_SALES_COMPOUND_TAX_ANCESTOR_MISMATCH';
    };
    LET $aggregates = $issue.tax_components.filter(|$component|
        $component.aggregate_rule_version != NONE);
    IF array::len($aggregates) != 1 OR
        $row.predecessor.id != type::record('sales_invoice_aggregate_tax_component',
            [$source, string::concat('aggregate:tax:', $aggregates[0].tax_key)]) OR
        $row.predecessor.rebase_managed_source != $row.rebase_managed_source OR
        $row.predecessor.invoice != $row.invoice OR $row.predecessor.issued_at != $row.issued_at OR
        $row.predecessor.tax_key != $aggregates[0].tax_key OR
        $row.basis.rebase_managed_source != $row.rebase_managed_source OR
        $row.basis.invoice != $row.invoice OR $row.basis.issued_at != $row.issued_at OR
        $row.basis.tax_key != $aggregates[0].tax_key OR
        $row.predecessor.basis != $row.basis OR $row.predecessor.amount = NONE {
        THROW 'ACCOUNTING_SALES_COMPOUND_TAX_PREDECESSOR_MISMATCH';
    };
    IF $row.rule_version.component_key != $row.tax_key OR $row.rule_version.kind != 'proportional'
        OR $row.rule_version.tax_claim_account != $row.tax_claim_account
        OR $row.rule_version.valid_from > $row.issued_at OR $row.issued_at >= $row.rule_version.valid_until
        OR $row.tax_claim_account.economic_entity != $row.invoice.economic_entity
        OR $row.tax_claim_account.currency != $row.invoice.currency {
        THROW 'ACCOUNTING_SALES_COMPOUND_TAX_DIMENSION_MISMATCH';
    };
    IF $row.claim_account != $row.invoice.claim_account
        OR $row.commercial_party != $row.claim_account.opponent OR $row.direction != 'sales' {
        THROW 'ACCOUNTING_SALES_COMPOUND_TAX_CUSTOMER_MISMATCH';
    };
    IF record::tb($row.tax_claim_account.opponent) != 'tax_account' {
        THROW 'ACCOUNTING_SALES_COMPOUND_TAX_ACCOUNT_REQUIRED';
    };
} PERMISSIONS FULL;

DEFINE FIELD OVERWRITE rebase_managed_source ON sales_invoice_compound_tax_component TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON sales_invoice_compound_tax_component TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE invoice ON sales_invoice_compound_tax_component TYPE record<sales_invoice> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE issued_at ON sales_invoice_compound_tax_component TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE claim_account ON sales_invoice_compound_tax_component TYPE record<claim_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.claim_account COMMENT '@rebase-derived @rebase-depends invoice.claim_account';
DEFINE FIELD OVERWRITE commercial_party ON sales_invoice_compound_tax_component TYPE record<rebase_user | organization> VALUE $this.claim_account.opponent COMMENT '@rebase-derived @rebase-depends claim_account.opponent';
DEFINE FIELD OVERWRITE economic_entity ON sales_invoice_compound_tax_component TYPE record<rebase_user | organization> VALUE $this.claim_account.economic_entity COMMENT '@rebase-derived @rebase-depends claim_account.economic_entity';
DEFINE FIELD OVERWRITE currency ON sales_invoice_compound_tax_component TYPE record<currency> VALUE $this.invoice.currency COMMENT '@rebase-derived @rebase-depends invoice.currency';
DEFINE FIELD OVERWRITE direction ON sales_invoice_compound_tax_component TYPE string VALUE 'sales' COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE tax_key ON sales_invoice_compound_tax_component TYPE string COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE tax_claim_account ON sales_invoice_compound_tax_component TYPE record<claim_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE rule_version ON sales_invoice_compound_tax_component TYPE record<sales_tax_rule_version> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE basis ON sales_invoice_compound_tax_component TYPE record<sales_invoice_aggregate_tax_basis> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit @rebase-readers';
DEFINE FIELD OVERWRITE predecessor ON sales_invoice_compound_tax_component TYPE record<sales_invoice_aggregate_tax_component> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit @rebase-readers';
DEFINE FIELD OVERWRITE amount ON sales_invoice_compound_tax_component TYPE option<decimal> VALUE
    IF $this.predecessor.amount = NONE THEN NONE ELSE
        fn::accounting::currency_round(($this.basis.z_base + $this.predecessor.amount) * $this.rule_version.rate,
            $this.invoice.currency_precision) END
    ASSERT $value = NONE OR $value > 0dec COMMENT '@rebase-derived @rebase-depends basis.z_base, predecessor.amount, rule_version.rate, invoice.currency_precision';
DEFINE FIELD OVERWRITE z_customer ON sales_invoice_compound_tax_component TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_invoice ON sales_invoice_compound_tax_component TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_outstanding';
DEFINE FIELD OVERWRITE z_tax ON sales_invoice_compound_tax_component TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';

DEFINE TABLE OVERWRITE sales_invoice_aggregate_tax_basis SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output';
DEFINE FIELD OVERWRITE rebase_managed_source ON sales_invoice_aggregate_tax_basis TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON sales_invoice_aggregate_tax_basis TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE invoice ON sales_invoice_aggregate_tax_basis TYPE record<sales_invoice> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit @rebase-readers';
DEFINE FIELD OVERWRITE issued_at ON sales_invoice_aggregate_tax_basis TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE tax_key ON sales_invoice_aggregate_tax_basis TYPE string ASSERT string::len($value) > 0 COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE tax_claim_account ON sales_invoice_aggregate_tax_basis TYPE record<claim_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE rule_version ON sales_invoice_aggregate_tax_basis TYPE record<sales_tax_rule_version> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_base ON sales_invoice_aggregate_tax_basis TYPE decimal VALUE
    ($this.invoice.z_taxable_input.summary.measures.basis.sum ?? 0dec) COMMENT '@rebase-derived @rebase-depends invoice.z_taxable_input.summary';


-- A variable source-owned tax fact posts to the customer, invoice, and one
-- tax-authority claim. H3a supports entered amounts; H4a adds selected versions.
DEFINE FUNCTION OVERWRITE fn::accounting::sales_invoice_tax_members($row: object) {
    RETURN [
        fn::tree::member($row.id, 'z_customer', $row.claim_account, 'z_history', $row.effective_at,
            { receivable: $row.amount, net: $row.amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_invoice', $row.invoice, 'z_outstanding', $row.effective_at,
            { outstanding: $row.amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_tax', $row.tax_claim_account, 'z_history', $row.effective_at,
            { payable: $row.amount, net: -$row.amount }, { currency: $row.currency }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::sales_invoice_tax_validate($row: object) {
    LET $source = type::record($row.rebase_managed_source);
    IF record::tb($source) != 'sales_invoice_issue' OR
        (record::exists($source) AND ($source.invoice != $row.invoice OR $source.issued_at != $row.effective_at)) {
        THROW 'ACCOUNTING_SALES_TAX_ANCESTOR_MISMATCH';
    };
    IF $row.claim_account != $row.invoice.claim_account
        OR $row.commercial_party != $row.claim_account.opponent OR $row.direction != 'sales' {
        THROW 'ACCOUNTING_SALES_TAX_CUSTOMER_MISMATCH';
    };
    IF record::tb($row.tax_claim_account.opponent) != 'tax_account' {
        THROW 'ACCOUNTING_SALES_TAX_ACCOUNT_REQUIRED';
    };
    IF $row.tax_claim_account.economic_entity != $row.economic_entity
        OR $row.tax_claim_account.currency != $row.currency {
        THROW 'ACCOUNTING_SALES_TAX_DIMENSION_MISMATCH';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE sales_invoice_tax_component SCHEMAFULL PERMISSIONS NONE
    COMMENT '@rebase-managed-output @rebase-members fn::accounting::sales_invoice_tax_members @rebase-validate fn::accounting::sales_invoice_tax_validate';
DEFINE FIELD OVERWRITE rebase_managed_source ON sales_invoice_tax_component TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON sales_invoice_tax_component TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE invoice ON sales_invoice_tax_component TYPE record<sales_invoice> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE claim_account ON sales_invoice_tax_component TYPE record<claim_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.claim_account COMMENT '@rebase-derived @rebase-depends invoice.claim_account';
DEFINE FIELD OVERWRITE commercial_party ON sales_invoice_tax_component TYPE record<rebase_user | organization> VALUE $this.claim_account.opponent COMMENT '@rebase-derived @rebase-depends claim_account.opponent';
DEFINE FIELD OVERWRITE economic_entity ON sales_invoice_tax_component TYPE record<rebase_user | organization> VALUE $this.claim_account.economic_entity COMMENT '@rebase-derived @rebase-depends claim_account.economic_entity';
DEFINE FIELD OVERWRITE currency ON sales_invoice_tax_component TYPE record<currency> VALUE $this.invoice.currency COMMENT '@rebase-derived @rebase-depends invoice.currency';
DEFINE FIELD OVERWRITE direction ON sales_invoice_tax_component TYPE string VALUE 'sales' COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE tax_claim_account ON sales_invoice_tax_component TYPE record<claim_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE rule_version ON sales_invoice_tax_component TYPE option<record<sales_tax_rule_version>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON sales_invoice_tax_component TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON sales_invoice_tax_component TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_customer ON sales_invoice_tax_component TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_invoice ON sales_invoice_tax_component TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_outstanding';
DEFINE FIELD OVERWRITE z_tax ON sales_invoice_tax_component TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';

DEFINE TABLE OVERWRITE purchase_invoice_line SCHEMAFULL
    PERMISSIONS NONE COMMENT '@rebase-managed-output @rebase-members fn::accounting::purchase_invoice_line_members @rebase-validate fn::accounting::purchase_invoice_line_validate';
DEFINE FIELD OVERWRITE rebase_managed_source ON purchase_invoice_line TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE rebase_managed_role ON purchase_invoice_line TYPE string COMMENT '@rebase-system';
DEFINE FIELD OVERWRITE invoice ON purchase_invoice_line TYPE record<purchase_invoice> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE source ON purchase_invoice_line TYPE record<stock_in> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE billed_quantity ON purchase_invoice_line TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE unit_price ON purchase_invoice_line TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE claim_account ON purchase_invoice_line TYPE record<claim_account> VALUE $this.invoice.claim_account COMMENT '@rebase-derived @rebase-depends invoice.claim_account';
DEFINE FIELD OVERWRITE source_at ON purchase_invoice_line TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived @rebase-depends source.effective_at';
DEFINE FIELD OVERWRITE effective_at ON purchase_invoice_line TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON purchase_invoice_line TYPE decimal VALUE <decimal>math::fixed($this.billed_quantity * $this.unit_price, $this.invoice.currency_precision) ASSERT $value > 0dec COMMENT '@rebase-derived @rebase-depends invoice.currency_precision';
DEFINE FIELD OVERWRITE z_claim ON purchase_invoice_line TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_invoice ON purchase_invoice_line TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner purchase_invoice.z_outstanding';
DEFINE FIELD OVERWRITE z_source ON purchase_invoice_line TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_in.z_billing';

DEFINE FUNCTION OVERWRITE fn::accounting::sales_invoice_cash_allocation_members($row: object) {
    RETURN [
        fn::tree::member($row.id, 'z_claim', $row.target.invoice.claim_account, 'z_history', $row.effective_at,
            { receivable: -$row.amount, net: -$row.amount }, { currency: $row.target.invoice.claim_account.currency }, {}, false),
        fn::tree::member($row.id, 'z_invoice', $row.target.invoice, 'z_outstanding', $row.effective_at,
            { outstanding: -$row.amount }, { currency: $row.target.invoice.claim_account.currency }, {}, false),
        fn::tree::member($row.id, 'z_source', $row.source, 'z_allocations', $row.effective_at,
            { allocated: $row.amount, available: -$row.amount }, { currency: $row.source.to_account.currency }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::purchase_invoice_cash_allocation_members($row: object) {
    RETURN [
        fn::tree::member($row.id, 'z_claim', $row.target.invoice.claim_account, 'z_history', $row.effective_at,
            { payable: -$row.amount, net: $row.amount }, { currency: $row.target.invoice.claim_account.currency }, {}, false),
        fn::tree::member($row.id, 'z_invoice', $row.target.invoice, 'z_outstanding', $row.effective_at,
            { outstanding: -$row.amount }, { currency: $row.target.invoice.claim_account.currency }, {}, false),
        fn::tree::member($row.id, 'z_source', $row.source, 'z_allocations', $row.effective_at,
            { allocated: $row.amount }, { currency: $row.source.from_account.currency }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::sales_invoice_cash_allocation_validate($row: object) {
    IF $row.source.economic_entity != $row.target.invoice.economic_entity OR $row.source.from_party != $row.target.invoice.claim_account.opponent {
        THROW 'ACCOUNTING_SALES_INVOICE_ALLOCATION_SOURCE_MISMATCH';
    };
    IF $row.source.to_account.currency != $row.target.invoice.claim_account.currency {
        THROW 'ACCOUNTING_SALES_INVOICE_ALLOCATION_CURRENCY_MISMATCH';
    };
    IF $row.effective_at < $row.source_at OR $row.effective_at < $row.target_at {
        THROW 'ACCOUNTING_SALES_INVOICE_ALLOCATION_BEFORE_SOURCE';
    };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::accounting::purchase_invoice_cash_allocation_validate($row: object) {
    IF $row.source.economic_entity != $row.target.invoice.economic_entity OR $row.source.to_party != $row.target.invoice.claim_account.opponent {
        THROW 'ACCOUNTING_PURCHASE_INVOICE_ALLOCATION_SOURCE_MISMATCH';
    };
    IF $row.source.from_account.currency != $row.target.invoice.claim_account.currency {
        THROW 'ACCOUNTING_PURCHASE_INVOICE_ALLOCATION_CURRENCY_MISMATCH';
    };
    IF $row.effective_at < $row.source_at OR $row.effective_at < $row.target_at {
        THROW 'ACCOUNTING_PURCHASE_INVOICE_ALLOCATION_BEFORE_SOURCE';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE sales_invoice_cash_allocation SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::sales_invoice_cash_allocation_members @rebase-validate fn::accounting::sales_invoice_cash_allocation_validate';
DEFINE FIELD OVERWRITE source ON sales_invoice_cash_allocation TYPE record<cash_in> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE target ON sales_invoice_cash_allocation TYPE record<sales_invoice_issue> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON sales_invoice_cash_allocation TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON sales_invoice_cash_allocation TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE source_at ON sales_invoice_cash_allocation TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived @rebase-depends source.effective_at';
DEFINE FIELD OVERWRITE target_at ON sales_invoice_cash_allocation TYPE datetime VALUE $this.target.issued_at COMMENT '@rebase-derived @rebase-depends target.issued_at';
DEFINE FIELD OVERWRITE z_claim ON sales_invoice_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_invoice ON sales_invoice_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_outstanding';
DEFINE FIELD OVERWRITE z_source ON sales_invoice_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner cash_in.z_allocations';

DEFINE TABLE OVERWRITE purchase_invoice_cash_allocation SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::purchase_invoice_cash_allocation_members @rebase-validate fn::accounting::purchase_invoice_cash_allocation_validate';
DEFINE FIELD OVERWRITE source ON purchase_invoice_cash_allocation TYPE record<cash_out> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE target ON purchase_invoice_cash_allocation TYPE record<purchase_invoice_issue> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON purchase_invoice_cash_allocation TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON purchase_invoice_cash_allocation TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE source_at ON purchase_invoice_cash_allocation TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived @rebase-depends source.effective_at';
DEFINE FIELD OVERWRITE target_at ON purchase_invoice_cash_allocation TYPE datetime VALUE $this.target.issued_at COMMENT '@rebase-derived @rebase-depends target.issued_at';
DEFINE FIELD OVERWRITE z_claim ON purchase_invoice_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_invoice ON purchase_invoice_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner purchase_invoice.z_outstanding';
DEFINE FIELD OVERWRITE z_source ON purchase_invoice_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner cash_out.z_allocations';

-- A purchase receipt is itself the invoice source. Its cash allocation reaches
-- the same invoice and supplier claim without an invented invoice-issue row.
DEFINE FUNCTION OVERWRITE fn::accounting::purchase_receipt_cash_allocation_members($row: object) {
    RETURN [
        fn::tree::member($row.id, 'z_claim', $row.target.invoice.claim_account, 'z_history', $row.effective_at,
            { payable: -$row.amount, net: $row.amount }, { currency: $row.target.invoice.currency }, {}, false),
        fn::tree::member($row.id, 'z_invoice', $row.target.invoice, 'z_outstanding', $row.effective_at,
            { outstanding: -$row.amount }, { currency: $row.target.invoice.currency }, {}, false),
        fn::tree::member($row.id, 'z_source', $row.source, 'z_allocations', $row.effective_at,
            { allocated: $row.amount }, { currency: $row.source.from_account.currency }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::purchase_receipt_cash_allocation_validate($row: object) {
    IF $row.source.economic_entity != $row.target.economic_entity
        OR $row.source.to_party != $row.target.from_party {
        THROW 'ACCOUNTING_PURCHASE_RECEIPT_ALLOCATION_SOURCE_MISMATCH';
    };
    IF $row.source.from_account.currency != $row.target.currency {
        THROW 'ACCOUNTING_PURCHASE_RECEIPT_ALLOCATION_CURRENCY_MISMATCH';
    };
    IF $row.effective_at < $row.source_at OR $row.effective_at < $row.target_at {
        THROW 'ACCOUNTING_PURCHASE_RECEIPT_ALLOCATION_BEFORE_SOURCE';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE purchase_receipt_cash_allocation SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::purchase_receipt_cash_allocation_members @rebase-validate fn::accounting::purchase_receipt_cash_allocation_validate';
DEFINE FIELD OVERWRITE source ON purchase_receipt_cash_allocation TYPE record<cash_out> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE target ON purchase_receipt_cash_allocation TYPE record<purchase_receipt> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON purchase_receipt_cash_allocation TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON purchase_receipt_cash_allocation TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE source_at ON purchase_receipt_cash_allocation TYPE datetime VALUE $this.source.effective_at COMMENT '@rebase-derived @rebase-depends source.effective_at';
DEFINE FIELD OVERWRITE target_at ON purchase_receipt_cash_allocation TYPE datetime VALUE $this.target.effective_at COMMENT '@rebase-derived @rebase-depends target.effective_at';
DEFINE FIELD OVERWRITE z_claim ON purchase_receipt_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_invoice ON purchase_receipt_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner purchase_invoice.z_outstanding';
DEFINE FIELD OVERWRITE z_source ON purchase_receipt_cash_allocation TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner cash_out.z_allocations';
