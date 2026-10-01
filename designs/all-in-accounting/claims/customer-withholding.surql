-- Customer-withheld tax clears part of an actual sales invoice settlement.
-- Cash remains owned by cash_in and sales_invoice_cash_allocation; this fact
-- clears the residual customer claim and records the explicit tax receivable.

DEFINE FUNCTION OVERWRITE fn::accounting::customer_withholding_policy_validate($row: object) {
    IF record::tb($row.tax_claim_account.opponent) != 'tax_account' {
        THROW 'ACCOUNTING_CUSTOMER_WITHHOLDING_POLICY_TAX_ACCOUNT_REQUIRED';
    };
    IF $row.valid_from >= $row.valid_until {
        THROW 'ACCOUNTING_CUSTOMER_WITHHOLDING_POLICY_INTERVAL_INVALID';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE customer_withholding_policy_version SCHEMAFULL
    COMMENT '@rebase-validate fn::accounting::customer_withholding_policy_validate';
DEFINE FIELD OVERWRITE tax_claim_account ON customer_withholding_policy_version TYPE record<claim_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE policy_key ON customer_withholding_policy_version TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE version ON customer_withholding_policy_version TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE valid_from ON customer_withholding_policy_version TYPE datetime READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE valid_until ON customer_withholding_policy_version TYPE datetime READONLY COMMENT '@rebase-audit';
DEFINE INDEX OVERWRITE customer_withholding_policy_identity ON customer_withholding_policy_version FIELDS tax_claim_account, policy_key, version UNIQUE;

DEFINE FUNCTION OVERWRITE fn::accounting::customer_withholding_members($row: object) {
    RETURN [
        fn::tree::member($row.id, 'z_customer', $row.customer_claim_account, 'z_history', $row.effective_at,
            { receivable: -$row.amount, net: -$row.amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_invoice', $row.invoice, 'z_outstanding', $row.effective_at,
            { outstanding: -$row.amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_tax_credit', $row.tax_claim_account, 'z_history', $row.effective_at,
            { receivable: $row.amount, net: $row.amount }, { currency: $row.currency }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::customer_withholding_validate($row: object) {
    LET $allocation = $row.allocation;
    LET $issue = $row.issue;
    LET $cash = $row.cash_in;
    LET $invoice = $row.invoice;
    LET $tax = $row.policy_version.tax_claim_account;
    IF $row.amount <= 0dec { THROW 'ACCOUNTING_CUSTOMER_WITHHOLDING_POSITIVE'; };
    IF fn::accounting::currency_round($row.amount, $row.currency.precision) != $row.amount {
        THROW 'ACCOUNTING_CUSTOMER_WITHHOLDING_CURRENCY_PRECISION';
    };
    IF $row.effective_at < $row.issue_at OR $row.effective_at < $row.allocation_at
        OR $row.effective_at < $row.cash_at {
        THROW 'ACCOUNTING_CUSTOMER_WITHHOLDING_PRECEDES_SETTLEMENT';
    };
    IF $row.effective_at < $row.policy_version.valid_from
        OR $row.effective_at >= $row.policy_version.valid_until {
        THROW 'ACCOUNTING_CUSTOMER_WITHHOLDING_OUTSIDE_POLICY';
    };
    IF $cash.economic_entity != $row.economic_entity
        OR $cash.from_party != $row.customer_claim_account.opponent
        OR $invoice.economic_entity != $row.economic_entity
        OR $invoice.claim_account != $row.customer_claim_account
        OR $issue.invoice != $invoice {
        THROW 'ACCOUNTING_CUSTOMER_WITHHOLDING_SOURCE_PARTY_ENTITY_MISMATCH';
    };
    IF $cash.to_account.currency != $row.currency
        OR $invoice.currency != $row.currency
        OR $tax.currency != $row.currency {
        THROW 'ACCOUNTING_CUSTOMER_WITHHOLDING_CURRENCY_MISMATCH';
    };
    IF $tax.economic_entity != $row.economic_entity
        OR record::tb($tax.opponent) != 'tax_account' {
        THROW 'ACCOUNTING_CUSTOMER_WITHHOLDING_TAX_IDENTITY_MISMATCH';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE customer_withholding SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::customer_withholding_members @rebase-validate fn::accounting::customer_withholding_validate';
DEFINE FIELD OVERWRITE allocation ON customer_withholding TYPE record<sales_invoice_cash_allocation> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE policy_version ON customer_withholding TYPE record<customer_withholding_policy_version> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON customer_withholding TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON customer_withholding TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE issue ON customer_withholding TYPE record<sales_invoice_issue> REFERENCE ON DELETE REJECT VALUE $this.allocation.target READONLY COMMENT '@rebase-derived @rebase-depends allocation.target';
DEFINE FIELD OVERWRITE invoice ON customer_withholding TYPE record<sales_invoice> REFERENCE ON DELETE REJECT VALUE $this.issue.invoice READONLY COMMENT '@rebase-derived @rebase-depends issue.invoice';
DEFINE FIELD OVERWRITE customer_claim_account ON customer_withholding TYPE record<claim_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.claim_account READONLY COMMENT '@rebase-derived @rebase-depends invoice.claim_account';
DEFINE FIELD OVERWRITE tax_claim_account ON customer_withholding TYPE record<claim_account> REFERENCE ON DELETE REJECT VALUE $this.policy_version.tax_claim_account READONLY COMMENT '@rebase-derived @rebase-depends policy_version.tax_claim_account';
DEFINE FIELD OVERWRITE economic_entity ON customer_withholding TYPE record<rebase_user | organization> REFERENCE ON DELETE REJECT VALUE $this.invoice.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends invoice.economic_entity';
DEFINE FIELD OVERWRITE currency ON customer_withholding TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.invoice.currency READONLY COMMENT '@rebase-derived @rebase-depends invoice.currency';
DEFINE FIELD OVERWRITE issue_at ON customer_withholding TYPE datetime VALUE $this.issue.issued_at READONLY COMMENT '@rebase-derived @rebase-depends issue.issued_at';
DEFINE FIELD OVERWRITE allocation_at ON customer_withholding TYPE datetime VALUE $this.allocation.effective_at READONLY COMMENT '@rebase-derived @rebase-depends allocation.effective_at';
DEFINE FIELD OVERWRITE cash_in ON customer_withholding TYPE record<cash_in> REFERENCE ON DELETE REJECT VALUE $this.allocation.source READONLY COMMENT '@rebase-derived @rebase-depends allocation.source';
DEFINE FIELD OVERWRITE cash_at ON customer_withholding TYPE datetime VALUE $this.cash_in.effective_at READONLY COMMENT '@rebase-derived @rebase-depends cash_in.effective_at';
DEFINE FIELD OVERWRITE z_customer ON customer_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_invoice ON customer_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_invoice.z_outstanding';
DEFINE FIELD OVERWRITE z_tax_credit ON customer_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE INDEX OVERWRITE customer_withholding_allocation ON customer_withholding FIELDS allocation UNIQUE;
