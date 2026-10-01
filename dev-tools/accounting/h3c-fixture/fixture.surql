-- Disposable ten-level ancestry fixture. Compiled with the accounting profile
-- only for the in-memory H3c probe; never part of the target accounting build.

DEFINE FUNCTION OVERWRITE fn::h3c::header_validate($row: object) {
    IF $row.available_quantity <= 0dec OR $row.available_quantity > $row.source_quantity {
        THROW 'H3C_HEADER_QUANTITY';
    };
    IF $row.recognition_at < $row.dispatch_at { THROW 'H3C_RECOGNITION_BEFORE_DISPATCH'; };
    LET $summary = $row.z_deliveries.summary;
    IF ($summary.measures.quantity.max_prefix ?? 0dec) > $row.source_quantity
        OR ($summary.measures.quantity.max_prefix ?? 0dec) > $row.available_quantity {
        THROW 'H3C_DELIVERY_OVER_BILLED';
    };
    IF $summary.tags.invoice != NONE AND
        (!$summary.tags.invoice.uniform OR $summary.tags.invoice.value != $row.invoice) {
        THROW 'H3C_DELIVERY_DOCUMENT_MISMATCH';
    };
    IF $summary.tags.direction != NONE AND
        (!$summary.tags.direction.uniform OR $summary.tags.direction.value != $row.direction) {
        THROW 'H3C_DELIVERY_DIRECTION_MISMATCH';
    };
    IF $summary.tags.customer != NONE AND
        (!$summary.tags.customer.uniform OR $summary.tags.customer.value != $row.customer) {
        THROW 'H3C_DELIVERY_CUSTOMER_MISMATCH';
    };
    IF $summary.tags.economic_entity != NONE AND
        (!$summary.tags.economic_entity.uniform OR $summary.tags.economic_entity.value != $row.economic_entity) {
        THROW 'H3C_DELIVERY_ENTITY_MISMATCH';
    };
    IF $summary.tags.currency != NONE AND
        (!$summary.tags.currency.uniform OR $summary.tags.currency.value != $row.currency) {
        THROW 'H3C_DELIVERY_CURRENCY_MISMATCH';
    };
    IF $summary.tags.available_quantity != NONE AND
        (!$summary.tags.available_quantity.uniform OR $summary.tags.available_quantity.value != $row.available_quantity) {
        THROW 'H3C_DELIVERY_CAPACITY_MISMATCH';
    };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::h3c::package_validate($row: object) {
    IF $row.depth < 1 OR $row.depth > 8 { THROW 'H3C_PACKAGE_DEPTH'; };
    IF $row.declared_invoice != NONE AND $row.declared_invoice != $row.invoice {
        THROW 'H3C_PACKAGE_DOCUMENT_MISMATCH';
    };
    IF $row.recognition_at < $row.dispatch_at { THROW 'H3C_PACKAGE_DATE_ORDER'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::h3c::leaf_validate($row: object) {
    IF $row.parent.depth != 8 { THROW 'H3C_LEAF_DEPTH'; };
    IF $row.quantity <= 0dec OR $row.quantity > $row.available_quantity {
        THROW 'H3C_LEAF_QUANTITY';
    };
    IF $row.recognition_at < $row.dispatch_at { THROW 'H3C_LEAF_DATE_ORDER'; };
} PERMISSIONS FULL;

DEFINE FUNCTION OVERWRITE fn::h3c::leaf_members($row: object) {
    RETURN [fn::tree::member($row.id, 'z_delivery', $row.root, 'z_deliveries',
        $row.recognition_at, { quantity: $row.quantity },
        { invoice: $row.declared_invoice, customer: $row.customer,
          economic_entity: $row.economic_entity, currency: $row.currency,
          direction: $row.declared_direction,
          available_quantity: $row.available_quantity }, {}, false)];
} PERMISSIONS NONE;

DEFINE TABLE OVERWRITE h3c_header SCHEMAFULL COMMENT '@rebase-validate fn::h3c::header_validate';
DEFINE FIELD OVERWRITE line ON h3c_header TYPE record<sales_invoice_line> REFERENCE ON DELETE REJECT READONLY COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE invoice ON h3c_header TYPE record<sales_invoice> REFERENCE ON DELETE REJECT VALUE $this.line.invoice COMMENT '@rebase-derived @rebase-depends line.invoice';
DEFINE FIELD OVERWRITE claim_account ON h3c_header TYPE record<claim_account> REFERENCE ON DELETE REJECT VALUE $this.line.claim_account COMMENT '@rebase-derived @rebase-depends line.claim_account';
DEFINE FIELD OVERWRITE customer ON h3c_header TYPE record<rebase_user | organization> VALUE $this.claim_account.opponent COMMENT '@rebase-derived @rebase-depends claim_account.opponent';
DEFINE FIELD OVERWRITE economic_entity ON h3c_header TYPE record<rebase_user | organization> VALUE $this.claim_account.economic_entity COMMENT '@rebase-derived @rebase-depends claim_account.economic_entity';
DEFINE FIELD OVERWRITE currency ON h3c_header TYPE record<currency> VALUE $this.invoice.currency COMMENT '@rebase-derived @rebase-depends invoice.currency';
DEFINE FIELD OVERWRITE direction ON h3c_header TYPE string VALUE 'sales' COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE dispatch_at ON h3c_header TYPE datetime VALUE $this.line.source_at COMMENT '@rebase-derived @rebase-depends line.source_at';
DEFINE FIELD OVERWRITE recognition_at ON h3c_header TYPE datetime VALUE $this.line.effective_at COMMENT '@rebase-derived @rebase-depends line.effective_at';
DEFINE FIELD OVERWRITE source_quantity ON h3c_header TYPE decimal VALUE $this.line.billed_quantity COMMENT '@rebase-derived @rebase-depends line.billed_quantity';
DEFINE FIELD OVERWRITE available_quantity ON h3c_header TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE depth ON h3c_header TYPE int VALUE 0 COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE root ON h3c_header TYPE record<h3c_header> VALUE $this.id COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_deliveries ON h3c_header TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime';

DEFINE TABLE OVERWRITE h3c_package SCHEMAFULL COMMENT '@rebase-validate fn::h3c::package_validate';
DEFINE FIELD OVERWRITE parent ON h3c_package TYPE record<h3c_header | h3c_package> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE line ON h3c_package TYPE record<sales_invoice_line> VALUE $this.parent.line COMMENT '@rebase-derived @rebase-depends parent.line';
DEFINE FIELD OVERWRITE invoice ON h3c_package TYPE record<sales_invoice> VALUE $this.parent.invoice COMMENT '@rebase-derived @rebase-depends parent.invoice';
DEFINE FIELD OVERWRITE claim_account ON h3c_package TYPE record<claim_account> VALUE $this.parent.claim_account COMMENT '@rebase-derived @rebase-depends parent.claim_account';
DEFINE FIELD OVERWRITE customer ON h3c_package TYPE record<rebase_user | organization> VALUE $this.parent.customer COMMENT '@rebase-derived @rebase-depends parent.customer';
DEFINE FIELD OVERWRITE economic_entity ON h3c_package TYPE record<rebase_user | organization> VALUE $this.parent.economic_entity COMMENT '@rebase-derived @rebase-depends parent.economic_entity';
DEFINE FIELD OVERWRITE currency ON h3c_package TYPE record<currency> VALUE $this.parent.currency COMMENT '@rebase-derived @rebase-depends parent.currency';
DEFINE FIELD OVERWRITE direction ON h3c_package TYPE string VALUE $this.parent.direction COMMENT '@rebase-derived @rebase-depends parent.direction';
DEFINE FIELD OVERWRITE dispatch_at ON h3c_package TYPE datetime VALUE $this.parent.dispatch_at COMMENT '@rebase-derived @rebase-depends parent.dispatch_at';
DEFINE FIELD OVERWRITE recognition_at ON h3c_package TYPE datetime VALUE $this.parent.recognition_at COMMENT '@rebase-derived @rebase-depends parent.recognition_at';
DEFINE FIELD OVERWRITE source_quantity ON h3c_package TYPE decimal VALUE $this.parent.source_quantity COMMENT '@rebase-derived @rebase-depends parent.source_quantity';
DEFINE FIELD OVERWRITE available_quantity ON h3c_package TYPE decimal VALUE $this.parent.available_quantity COMMENT '@rebase-derived @rebase-depends parent.available_quantity';
DEFINE FIELD OVERWRITE depth ON h3c_package TYPE int VALUE $this.parent.depth + 1 COMMENT '@rebase-derived @rebase-depends parent.depth';
DEFINE FIELD OVERWRITE root ON h3c_package TYPE record<h3c_header> VALUE $this.parent.root COMMENT '@rebase-derived @rebase-depends parent.root';
DEFINE FIELD OVERWRITE declared_invoice ON h3c_package TYPE option<record<sales_invoice>> COMMENT '@rebase-audit';

DEFINE TABLE OVERWRITE h3c_delivery SCHEMAFULL COMMENT '@rebase-members fn::h3c::leaf_members @rebase-validate fn::h3c::leaf_validate';
DEFINE FIELD OVERWRITE parent ON h3c_delivery TYPE record<h3c_package> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE line ON h3c_delivery TYPE record<sales_invoice_line> VALUE $this.parent.line COMMENT '@rebase-derived @rebase-depends parent.line';
DEFINE FIELD OVERWRITE invoice ON h3c_delivery TYPE record<sales_invoice> VALUE $this.parent.invoice COMMENT '@rebase-derived @rebase-depends parent.invoice';
DEFINE FIELD OVERWRITE claim_account ON h3c_delivery TYPE record<claim_account> VALUE $this.parent.claim_account COMMENT '@rebase-derived @rebase-depends parent.claim_account';
DEFINE FIELD OVERWRITE customer ON h3c_delivery TYPE record<rebase_user | organization> VALUE $this.parent.customer COMMENT '@rebase-derived @rebase-depends parent.customer';
DEFINE FIELD OVERWRITE economic_entity ON h3c_delivery TYPE record<rebase_user | organization> VALUE $this.parent.economic_entity COMMENT '@rebase-derived @rebase-depends parent.economic_entity';
DEFINE FIELD OVERWRITE currency ON h3c_delivery TYPE record<currency> VALUE $this.parent.currency COMMENT '@rebase-derived @rebase-depends parent.currency';
DEFINE FIELD OVERWRITE direction ON h3c_delivery TYPE string VALUE $this.parent.direction COMMENT '@rebase-derived @rebase-depends parent.direction';
DEFINE FIELD OVERWRITE dispatch_at ON h3c_delivery TYPE datetime VALUE $this.parent.dispatch_at COMMENT '@rebase-derived @rebase-depends parent.dispatch_at';
DEFINE FIELD OVERWRITE recognition_at ON h3c_delivery TYPE datetime VALUE $this.parent.recognition_at COMMENT '@rebase-derived @rebase-depends parent.recognition_at';
DEFINE FIELD OVERWRITE source_quantity ON h3c_delivery TYPE decimal VALUE $this.parent.source_quantity COMMENT '@rebase-derived @rebase-depends parent.source_quantity';
DEFINE FIELD OVERWRITE available_quantity ON h3c_delivery TYPE decimal VALUE $this.parent.available_quantity COMMENT '@rebase-derived @rebase-depends parent.available_quantity';
DEFINE FIELD OVERWRITE quantity ON h3c_delivery TYPE decimal ASSERT $value > 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE depth ON h3c_delivery TYPE int VALUE $this.parent.depth + 1 COMMENT '@rebase-derived @rebase-depends parent.depth';
DEFINE FIELD OVERWRITE root ON h3c_delivery TYPE record<h3c_header> VALUE $this.parent.root COMMENT '@rebase-derived @rebase-depends parent.root';
DEFINE FIELD OVERWRITE declared_invoice ON h3c_delivery TYPE record<sales_invoice> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE declared_direction ON h3c_delivery TYPE string ASSERT $value IN ['sales', 'purchase'] COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_delivery ON h3c_delivery TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner h3c_header.z_deliveries';
