-- A payer-side supplier withholding is a noncash sibling of an actual
-- purchase-receipt cash allocation. It settles supplier/invoice claims and
-- opens the separate tax-authority payable without allocating more cash.

DEFINE FUNCTION OVERWRITE fn::accounting::supplier_withholding_policy_validate($row: object) {
    IF record::tb($row.tax_claim_account.opponent) != 'tax_account' {
        THROW 'ACCOUNTING_SUPPLIER_WITHHOLDING_POLICY_TAX_ACCOUNT_REQUIRED';
    };
    IF $row.valid_from >= $row.valid_until {
        THROW 'ACCOUNTING_SUPPLIER_WITHHOLDING_POLICY_INTERVAL_INVALID';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE supplier_withholding_policy_version SCHEMAFULL
    COMMENT '@rebase-validate fn::accounting::supplier_withholding_policy_validate';
DEFINE FIELD OVERWRITE tax_claim_account ON supplier_withholding_policy_version TYPE record<claim_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE policy_key ON supplier_withholding_policy_version TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE version ON supplier_withholding_policy_version TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE valid_from ON supplier_withholding_policy_version TYPE datetime READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE valid_until ON supplier_withholding_policy_version TYPE datetime READONLY COMMENT '@rebase-audit';
DEFINE INDEX OVERWRITE supplier_withholding_policy_identity ON supplier_withholding_policy_version FIELDS tax_claim_account, policy_key, version UNIQUE;

DEFINE FUNCTION OVERWRITE fn::accounting::supplier_withholding_members($row: object) {
    RETURN [
        fn::tree::member($row.id, 'z_claim', $row.supplier_claim_account, 'z_history', $row.effective_at,
            { payable: -$row.amount, net: $row.amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_invoice', $row.invoice, 'z_outstanding', $row.effective_at,
            { outstanding: -$row.amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_tax', $row.tax_claim_account, 'z_history', $row.effective_at,
            { payable: $row.amount, net: -$row.amount }, { currency: $row.currency }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::supplier_withholding_validate($row: object) {
    LET $allocation = $row.allocation;
    LET $receipt = $allocation.target;
    LET $payment = $row.payment;
    LET $invoice = $receipt.invoice;
    LET $tax_account = $row.policy_version.tax_claim_account;
    IF $row.amount <= 0dec { THROW 'ACCOUNTING_SUPPLIER_WITHHOLDING_POSITIVE'; };
    IF fn::accounting::currency_round($row.amount, $receipt.currency.precision) != $row.amount {
        THROW 'ACCOUNTING_SUPPLIER_WITHHOLDING_CURRENCY_PRECISION';
    };
    IF $row.effective_at < $row.receipt_at OR $row.effective_at < $row.allocation_at
        OR $row.effective_at < $row.payment_at {
        THROW 'ACCOUNTING_SUPPLIER_WITHHOLDING_PRECEDES_SETTLEMENT';
    };
    IF $row.effective_at < $row.policy_version.valid_from
        OR $row.effective_at >= $row.policy_version.valid_until {
        THROW 'ACCOUNTING_SUPPLIER_WITHHOLDING_OUTSIDE_POLICY';
    };
    IF $payment.economic_entity != $receipt.economic_entity
        OR $payment.to_party != $receipt.from_party
        OR $invoice.claim_account.opponent != $receipt.from_party
        OR $invoice.economic_entity != $receipt.economic_entity {
        THROW 'ACCOUNTING_SUPPLIER_WITHHOLDING_SOURCE_PARTY_ENTITY_MISMATCH';
    };
    IF $payment.from_account.currency != $receipt.currency
        OR $invoice.currency != $receipt.currency
        OR $receipt.supplier_claim_account.currency != $receipt.currency
        OR $tax_account.currency != $receipt.currency {
        THROW 'ACCOUNTING_SUPPLIER_WITHHOLDING_CURRENCY_MISMATCH';
    };
    IF $tax_account.economic_entity != $receipt.economic_entity
        OR record::tb($tax_account.opponent) != 'tax_account' {
        THROW 'ACCOUNTING_SUPPLIER_WITHHOLDING_TAX_IDENTITY_MISMATCH';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE supplier_withholding SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::supplier_withholding_members @rebase-validate fn::accounting::supplier_withholding_validate';
DEFINE FIELD OVERWRITE allocation ON supplier_withholding TYPE record<purchase_receipt_cash_allocation> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE policy_version ON supplier_withholding TYPE record<supplier_withholding_policy_version> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON supplier_withholding TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON supplier_withholding TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE receipt ON supplier_withholding TYPE record<purchase_receipt> REFERENCE ON DELETE REJECT VALUE $this.allocation.target READONLY COMMENT '@rebase-derived @rebase-depends allocation.target';
DEFINE FIELD OVERWRITE invoice ON supplier_withholding TYPE record<purchase_invoice> REFERENCE ON DELETE REJECT VALUE $this.receipt.invoice READONLY COMMENT '@rebase-derived @rebase-depends receipt.invoice';
DEFINE FIELD OVERWRITE supplier_claim_account ON supplier_withholding TYPE record<claim_account> REFERENCE ON DELETE REJECT VALUE $this.receipt.supplier_claim_account READONLY COMMENT '@rebase-derived @rebase-depends receipt.supplier_claim_account';
DEFINE FIELD OVERWRITE tax_claim_account ON supplier_withholding TYPE record<claim_account> REFERENCE ON DELETE REJECT VALUE $this.policy_version.tax_claim_account READONLY COMMENT '@rebase-derived @rebase-depends policy_version.tax_claim_account';
DEFINE FIELD OVERWRITE economic_entity ON supplier_withholding TYPE record<rebase_user | organization> REFERENCE ON DELETE REJECT VALUE $this.receipt.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends receipt.economic_entity';
DEFINE FIELD OVERWRITE currency ON supplier_withholding TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.receipt.currency READONLY COMMENT '@rebase-derived @rebase-depends receipt.currency';
DEFINE FIELD OVERWRITE allocation_at ON supplier_withholding TYPE datetime VALUE $this.allocation.effective_at READONLY COMMENT '@rebase-derived @rebase-depends allocation.effective_at';
DEFINE FIELD OVERWRITE receipt_at ON supplier_withholding TYPE datetime VALUE $this.receipt.effective_at READONLY COMMENT '@rebase-derived @rebase-depends receipt.effective_at';
DEFINE FIELD OVERWRITE payment ON supplier_withholding TYPE record<cash_out> REFERENCE ON DELETE REJECT VALUE $this.allocation.source READONLY COMMENT '@rebase-derived @rebase-depends allocation.source';
DEFINE FIELD OVERWRITE payment_at ON supplier_withholding TYPE datetime VALUE $this.payment.effective_at READONLY COMMENT '@rebase-derived @rebase-depends payment.effective_at';
DEFINE FIELD OVERWRITE z_claim ON supplier_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_invoice ON supplier_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner purchase_invoice.z_outstanding';
DEFINE FIELD OVERWRITE z_tax ON supplier_withholding TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE INDEX OVERWRITE supplier_withholding_allocation ON supplier_withholding FIELDS allocation UNIQUE;
