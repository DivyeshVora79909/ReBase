-- Document groups validate existing postings; they do not post a second ledger.
DEFINE FUNCTION OVERWRITE fn::accounting::adjustment_note_member($row: object, $amount: decimal, $paid: decimal) {
    IF $row.adjustment_note = NONE { RETURN NONE; };
    LET $signed = IF $amount != 0dec THEN $amount ELSE $paid END;
    RETURN fn::tree::member($row.id, 'z_note', $row.adjustment_note, 'z_lines', $row.effective_at,
        { amount: $amount, settlement: $paid, positive: IF $signed > 0dec THEN 1dec ELSE 0dec END,
          negative: IF $signed < 0dec THEN 1dec ELSE 0dec END },
        { organization: $row.organization, currency: $row.currency, is_sale: $row.is_sale }, {}, false);
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::adjustment_note_validate($row: object) {
    LET $s = $row.z_lines.summary;
    LET $positive = $s.measures.positive.sum ?? 0dec;
    LET $negative = $s.measures.negative.sum ?? 0dec;
    IF !$row.draft AND $positive + $negative = 0dec { THROW 'ADJUSTMENT_NOTE_EMPTY'; };
    IF $s.count = 0 { RETURN NONE; };
    IF !$s.tags.organization.uniform OR $s.tags.organization.value != $row.organization
        OR !$s.tags.currency.uniform OR $s.tags.currency.value != $row.currency
        OR !$s.tags.is_sale.uniform OR $s.tags.is_sale.value != (record::tb($row.id) = 'sales_adjustment_note') {
        THROW 'ADJUSTMENT_NOTE_DIMENSIONS';
    };
    IF $positive > 0dec AND $negative > 0dec { THROW 'ADJUSTMENT_NOTE_MIXED_SIGN'; };
} PERMISSIONS FULL;

DEFINE TABLE OVERWRITE sales_adjustment_note SCHEMAFULL COMMENT '@rebase-validate fn::accounting::adjustment_note_validate';
DEFINE FIELD OVERWRITE organization ON sales_adjustment_note TYPE record<organization> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON sales_adjustment_note TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.organization.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE number ON sales_adjustment_note TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE description ON sales_adjustment_note TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE draft ON sales_adjustment_note TYPE bool DEFAULT true COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_lines ON sales_adjustment_note TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE TABLE OVERWRITE purchase_adjustment_note SCHEMAFULL COMMENT '@rebase-validate fn::accounting::adjustment_note_validate';
DEFINE FIELD OVERWRITE organization ON purchase_adjustment_note TYPE record<organization> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE currency ON purchase_adjustment_note TYPE record<currency> REFERENCE ON DELETE REJECT VALUE $this.organization.currency COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE number ON purchase_adjustment_note TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE description ON purchase_adjustment_note TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE draft ON purchase_adjustment_note TYPE bool DEFAULT true COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_lines ON purchase_adjustment_note TYPE object COMMENT '@rebase-tree-root @rebase-tree-key datetime @rebase-tree-duplicates';

DEFINE FIELD OVERWRITE adjustment_note ON issue_adjustment TYPE option<record<sales_adjustment_note | purchase_adjustment_note>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE adjustment_note ON tax_adjustment TYPE option<record<sales_adjustment_note | purchase_adjustment_note>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE adjustment_note ON payment_adjustment TYPE option<record<sales_adjustment_note | purchase_adjustment_note>> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
-- Returns precede invoice_date and cannot belong to an adjustment document.
DEFINE FIELD OVERWRITE adjustment_note ON issue_return TYPE option<record<sales_adjustment_note | purchase_adjustment_note>> VALUE NONE COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE adjustment_note ON adjustment_tax TYPE option<record<sales_adjustment_note | purchase_adjustment_note>> REFERENCE ON DELETE REJECT VALUE $this.adjustment.adjustment_note COMMENT '@rebase-derived';
DEFINE FIELD OVERWRITE z_note ON issue_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_adjustment_note.z_lines @rebase-tree-owner purchase_adjustment_note.z_lines @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_note ON tax_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_adjustment_note.z_lines @rebase-tree-owner purchase_adjustment_note.z_lines @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_note ON payment_adjustment TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_adjustment_note.z_lines @rebase-tree-owner purchase_adjustment_note.z_lines @rebase-tree-no-reader';
DEFINE FIELD OVERWRITE z_note ON adjustment_tax TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner sales_adjustment_note.z_lines @rebase-tree-owner purchase_adjustment_note.z_lines @rebase-tree-no-reader';
