-- FILE 11: B-TREE INDEXES FOR ROOT RELATIONSHIPS
USE NS main DB main;

DEFINE INDEX idx_payment_a_from ON payment COLUMNS a_from;
DEFINE INDEX idx_payment_a_to ON payment COLUMNS a_to;
DEFINE INDEX idx_invoice_a_org ON invoice COLUMNS a_org;
DEFINE INDEX idx_adjustment_note_a_org ON adjustment_note COLUMNS a_org;
DEFINE INDEX idx_payment_allocation_a_payment ON payment_allocation COLUMNS a_payment;
DEFINE INDEX idx_payment_allocation_a_invoice ON payment_allocation COLUMNS a_invoice;
DEFINE INDEX idx_package_note_a_invoice ON package_note COLUMNS a_invoice;
DEFINE INDEX idx_invoice_line_a_invoice ON invoice_line COLUMNS a_invoice;
DEFINE INDEX idx_invoice_line_a_item ON invoice_line COLUMNS a_item;
DEFINE INDEX idx_sl_a_from ON sl COLUMNS a_from;
DEFINE INDEX idx_sl_a_to ON sl COLUMNS a_to;
DEFINE INDEX idx_sl_a_pkg ON sl COLUMNS a_pkg;
DEFINE INDEX idx_sl_a_item ON sl COLUMNS a_item;
DEFINE INDEX idx_tax_line_a_invoice_line ON tax_line COLUMNS a_invoice_line;
DEFINE INDEX idx_tax_line_a_tax_account ON tax_line COLUMNS a_tax_account;
DEFINE INDEX idx_adjustment_line_a_note ON adjustment_line COLUMNS a_note;
DEFINE INDEX idx_adjustment_line_a_target ON adjustment_line COLUMNS a_target;
