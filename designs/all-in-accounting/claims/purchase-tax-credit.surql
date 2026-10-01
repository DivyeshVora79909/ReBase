-- Explicit recognition of an assessed purchase receipt tax amount. This does
-- not change the receipt's assessed receivable, supplier payable, cash or stock.

DEFINE FUNCTION OVERWRITE fn::accounting::purchase_tax_credit_recognition_members($row: object) {
    RETURN [fn::tree::member($row.id, 'z_claim', $row.tax_claim_account, 'z_history', $row.effective_at,
        { recognized_credit: $row.amount }, { currency: $row.currency }, {}, false)];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::purchase_tax_credit_policy_validate($row: object) {
    IF record::tb($row.tax_claim_account.opponent) != 'tax_account' {
        THROW 'ACCOUNTING_PURCHASE_TAX_POLICY_TAX_ACCOUNT_REQUIRED';
    };
    IF $row.valid_from >= $row.valid_until {
        THROW 'ACCOUNTING_PURCHASE_TAX_POLICY_INTERVAL_INVALID';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE purchase_tax_credit_policy_version SCHEMAFULL
    COMMENT '@rebase-validate fn::accounting::purchase_tax_credit_policy_validate';
DEFINE FIELD OVERWRITE tax_claim_account ON purchase_tax_credit_policy_version TYPE record<claim_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE policy_key ON purchase_tax_credit_policy_version TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE version ON purchase_tax_credit_policy_version TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE valid_from ON purchase_tax_credit_policy_version TYPE datetime READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE valid_until ON purchase_tax_credit_policy_version TYPE datetime READONLY COMMENT '@rebase-audit';
DEFINE INDEX OVERWRITE purchase_tax_credit_policy_identity ON purchase_tax_credit_policy_version FIELDS tax_claim_account, policy_key, version UNIQUE;

DEFINE FUNCTION OVERWRITE fn::accounting::purchase_tax_credit_recognition_validate($row: object) {
    IF $row.amount <= 0dec { THROW 'ACCOUNTING_PURCHASE_TAX_RECOGNITION_POSITIVE'; };
    IF fn::accounting::currency_round($row.amount, $row.currency.precision) != $row.amount {
        THROW 'ACCOUNTING_PURCHASE_TAX_RECOGNITION_CURRENCY_PRECISION';
    };
    IF $row.amount > $row.assessed_tax_amount {
        THROW 'ACCOUNTING_PURCHASE_TAX_RECOGNITION_EXCEEDS_ASSESSMENT';
    };
    IF $row.effective_at < $row.receipt_at {
        THROW 'ACCOUNTING_PURCHASE_TAX_RECOGNITION_PRECEDES_RECEIPT';
    };
    IF $row.effective_at < $row.policy_version.valid_from
        OR $row.effective_at >= $row.policy_version.valid_until {
        THROW 'ACCOUNTING_PURCHASE_TAX_RECOGNITION_OUTSIDE_POLICY';
    };
    IF $row.tax_claim_account != $row.policy_version.tax_claim_account
        OR $row.economic_entity != $row.policy_version.tax_claim_account.economic_entity
        OR $row.currency != $row.policy_version.tax_claim_account.currency {
        THROW 'ACCOUNTING_PURCHASE_TAX_RECOGNITION_DIMENSION_MISMATCH';
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE purchase_tax_credit_recognition SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::purchase_tax_credit_recognition_members @rebase-validate fn::accounting::purchase_tax_credit_recognition_validate';
DEFINE FIELD OVERWRITE receipt ON purchase_tax_credit_recognition TYPE record<purchase_receipt> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE policy_version ON purchase_tax_credit_recognition TYPE record<purchase_tax_credit_policy_version> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE amount ON purchase_tax_credit_recognition TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON purchase_tax_credit_recognition TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE tax_claim_account ON purchase_tax_credit_recognition TYPE record<claim_account> VALUE $this.receipt.tax_claim_account READONLY COMMENT '@rebase-derived @rebase-depends receipt.tax_claim_account';
DEFINE FIELD OVERWRITE receipt_at ON purchase_tax_credit_recognition TYPE datetime VALUE $this.receipt.effective_at READONLY COMMENT '@rebase-derived @rebase-depends receipt.effective_at';
DEFINE FIELD OVERWRITE assessed_tax_amount ON purchase_tax_credit_recognition TYPE decimal VALUE $this.receipt.tax_amount READONLY COMMENT '@rebase-derived @rebase-depends receipt.tax_amount';
DEFINE FIELD OVERWRITE economic_entity ON purchase_tax_credit_recognition TYPE record<rebase_user | organization> VALUE $this.receipt.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends receipt.economic_entity';
DEFINE FIELD OVERWRITE currency ON purchase_tax_credit_recognition TYPE record<currency> VALUE $this.receipt.currency READONLY COMMENT '@rebase-derived @rebase-depends receipt.currency';
DEFINE FIELD OVERWRITE z_claim ON purchase_tax_credit_recognition TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE INDEX OVERWRITE purchase_tax_credit_recognition_receipt ON purchase_tax_credit_recognition FIELDS receipt UNIQUE;
