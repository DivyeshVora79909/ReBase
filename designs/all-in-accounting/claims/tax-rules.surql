-- Explicitly selected, immutable versions for parent-local sales tax components.
-- Probe rates are fixtures; each configured version is an issue-level input.

DEFINE FUNCTION OVERWRITE fn::accounting::sales_tax_rule_version_validate($row: object) {
    IF record::tb($row.tax_claim_account.opponent) != 'tax_account' {
        THROW 'ACCOUNTING_SALES_TAX_RULE_ACCOUNT_REQUIRED';
    };
    IF $row.valid_until <= $row.valid_from {
        THROW 'ACCOUNTING_SALES_TAX_RULE_INTERVAL';
    };
    IF $row.kind = 'fixed' {
        IF $row.fixed_amount = NONE OR $row.fixed_amount <= 0dec OR $row.rate != NONE {
            THROW 'ACCOUNTING_SALES_TAX_RULE_FIXED_SHAPE';
        };
        IF <decimal>math::fixed($row.fixed_amount, $row.tax_claim_account.currency.precision) != $row.fixed_amount {
            THROW 'ACCOUNTING_SALES_TAX_RULE_FIXED_PRECISION';
        };
    } ELSE IF $row.kind = 'proportional' {
        IF $row.rate = NONE OR $row.rate <= 0dec OR $row.fixed_amount != NONE {
            THROW 'ACCOUNTING_SALES_TAX_RULE_RATE_SHAPE';
        };
    };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE sales_tax_rule_version SCHEMAFULL
    COMMENT '@rebase-validate fn::accounting::sales_tax_rule_version_validate';
DEFINE FIELD OVERWRITE component_key ON sales_tax_rule_version TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE version ON sales_tax_rule_version TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE tax_claim_account ON sales_tax_rule_version TYPE record<claim_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE regime ON sales_tax_rule_version TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE provision ON sales_tax_rule_version TYPE string ASSERT string::len($value) > 0 READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE valid_from ON sales_tax_rule_version TYPE datetime READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE valid_until ON sales_tax_rule_version TYPE datetime READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE kind ON sales_tax_rule_version TYPE string ASSERT $value IN ['fixed', 'proportional'] READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE fixed_amount ON sales_tax_rule_version TYPE option<decimal> READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE rate ON sales_tax_rule_version TYPE option<decimal> READONLY COMMENT '@rebase-audit';
DEFINE INDEX OVERWRITE sales_tax_rule_version_key ON sales_tax_rule_version FIELDS tax_claim_account, component_key, version UNIQUE;
