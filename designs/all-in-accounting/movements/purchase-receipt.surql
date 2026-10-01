-- One received item invoice source owns its real, supplier, tax-credit, and
-- invoice effects. It does not create stock_in or purchase_invoice_issue rows.

DEFINE FUNCTION OVERWRITE fn::accounting::purchase_receipt_members($row: object) {
    RETURN [
        fn::tree::member($row.id, 'z_stock', $row.stock_account, 'z_history', $row.effective_at,
            { quantity: $row.quantity, available: $row.quantity }, { resource: $row.resource, unit: $row.unit }, {}, false),
        fn::tree::member($row.id, 'z_supplier_base', $row.supplier_claim_account, 'z_history', $row.effective_at,
            { payable: $row.base_amount, net: -$row.base_amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_supplier_tax', $row.supplier_claim_account, 'z_history', $row.effective_at,
            { payable: $row.tax_amount, net: -$row.tax_amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_tax_claim', $row.tax_claim_account, 'z_history', $row.effective_at,
            { receivable: $row.tax_amount, net: $row.tax_amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_invoice_base', $row.invoice, 'z_outstanding', $row.effective_at,
            { outstanding: $row.base_amount }, { currency: $row.currency }, {}, false),
        fn::tree::member($row.id, 'z_invoice_tax', $row.invoice, 'z_outstanding', $row.effective_at,
            { outstanding: $row.tax_amount }, { currency: $row.currency }, {}, false)
    ];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::purchase_receipt_validate($row: object) {
    IF $row.from_party != $row.invoice.claim_account.opponent {
        THROW 'ACCOUNTING_PURCHASE_RECEIPT_SUPPLIER_MISMATCH';
    };
    IF record::tb($row.tax_claim_account.opponent) != 'tax_account' {
        THROW 'ACCOUNTING_PURCHASE_RECEIPT_TAX_ACCOUNT_REQUIRED';
    };
    IF $row.stock_account.economic_entity != $row.invoice.economic_entity
        OR $row.tax_claim_account.economic_entity != $row.invoice.economic_entity {
        THROW 'ACCOUNTING_PURCHASE_RECEIPT_ENTITY_MISMATCH';
    };
    IF $row.stock_account.resource != $row.resource OR $row.stock_account.unit != $row.unit
        OR $row.resource.unit != $row.unit {
        THROW 'ACCOUNTING_PURCHASE_RECEIPT_RESOURCE_UNIT_MISMATCH';
    };
    IF $row.supplier_claim_account.currency != $row.currency
        OR $row.tax_claim_account.currency != $row.currency {
        THROW 'ACCOUNTING_PURCHASE_RECEIPT_CURRENCY_MISMATCH';
    };
    IF $row.base_amount <= 0dec { THROW 'ACCOUNTING_PURCHASE_RECEIPT_BASE_POSITIVE'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE purchase_receipt SCHEMAFULL
    COMMENT '@rebase-members fn::accounting::purchase_receipt_members @rebase-validate fn::accounting::purchase_receipt_validate';
DEFINE FIELD OVERWRITE invoice ON purchase_receipt TYPE record<purchase_invoice> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE from_party ON purchase_receipt TYPE record<rebase_user | organization> VALUE $this.supplier_claim_account.opponent READONLY COMMENT '@rebase-derived @rebase-depends supplier_claim_account.opponent';
DEFINE FIELD OVERWRITE stock_account ON purchase_receipt TYPE record<stock_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE resource ON purchase_receipt TYPE record<item | service | work_type> VALUE $this.stock_account.resource READONLY COMMENT '@rebase-derived @rebase-depends stock_account.resource';
DEFINE FIELD OVERWRITE unit ON purchase_receipt TYPE record<measure_unit> VALUE $this.stock_account.unit READONLY COMMENT '@rebase-derived @rebase-depends stock_account.unit';
DEFINE FIELD OVERWRITE tax_claim_account ON purchase_receipt TYPE record<claim_account> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE supplier_claim_account ON purchase_receipt TYPE record<claim_account> REFERENCE ON DELETE REJECT VALUE $this.invoice.claim_account READONLY COMMENT '@rebase-derived @rebase-depends invoice.claim_account';
DEFINE FIELD OVERWRITE economic_entity ON purchase_receipt TYPE record<rebase_user | organization> VALUE $this.stock_account.economic_entity READONLY COMMENT '@rebase-derived @rebase-depends stock_account.economic_entity';
DEFINE FIELD OVERWRITE currency ON purchase_receipt TYPE record<currency> VALUE $this.invoice.currency READONLY COMMENT '@rebase-derived @rebase-depends invoice.currency';
DEFINE FIELD OVERWRITE quantity ON purchase_receipt TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE unit_price ON purchase_receipt TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE tax_amount ON purchase_receipt TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE base_amount ON purchase_receipt TYPE decimal VALUE <decimal>math::fixed($this.quantity * $this.unit_price, $this.invoice.currency_precision) COMMENT '@rebase-derived @rebase-depends invoice.currency_precision';
DEFINE FIELD OVERWRITE gross_amount ON purchase_receipt TYPE decimal VALUE $this.base_amount + $this.tax_amount COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE effective_at ON purchase_receipt TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_stock ON purchase_receipt TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history';
DEFINE FIELD OVERWRITE z_supplier_base ON purchase_receipt TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_supplier_tax ON purchase_receipt TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_tax_claim ON purchase_receipt TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner claim_account.z_history';
DEFINE FIELD OVERWRITE z_invoice_base ON purchase_receipt TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner purchase_invoice.z_outstanding';
DEFINE FIELD OVERWRITE z_invoice_tax ON purchase_receipt TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner purchase_invoice.z_outstanding';
