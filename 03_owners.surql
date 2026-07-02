-- FILE 03: DAG OWNERSHIP INHERITANCE
USE NS main DB main;

DEFINE FIELD OVERWRITE owned_by ON TABLE acc TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE owners ON TABLE acc TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

DEFINE FIELD OVERWRITE owned_by ON TABLE adjustment_line TYPE option<record<groups>> VALUE $this.a_note.owned_by;
DEFINE FIELD OVERWRITE owners ON TABLE adjustment_line TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_note.owners, $this.a_target.owners]))).filter(|$v| $v != NONE);

DEFINE FIELD OVERWRITE owned_by ON TABLE adjustment_note TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE owners ON TABLE adjustment_note TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

DEFINE FIELD OVERWRITE owned_by ON TABLE invoice TYPE option<record<groups>> VALUE $this.a_org.owned_by;
DEFINE FIELD OVERWRITE owners ON TABLE invoice TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_org.owners]))).filter(|$v| $v != NONE);

DEFINE FIELD OVERWRITE owned_by ON TABLE invoice_line TYPE option<record<groups>> VALUE $this.a_invoice.owned_by;
DEFINE FIELD OVERWRITE owners ON TABLE invoice_line TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_invoice.owners, $this.a_item.owners]))).filter(|$v| $v != NONE);

DEFINE FIELD OVERWRITE owned_by ON TABLE item TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE owners ON TABLE item TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

DEFINE FIELD OVERWRITE owned_by ON TABLE org TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE owners ON TABLE org TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

DEFINE FIELD OVERWRITE owned_by ON TABLE package_note TYPE option<record<groups>> VALUE $this.a_invoice.owned_by;
DEFINE FIELD OVERWRITE owners ON TABLE package_note TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_invoice.owners]))).filter(|$v| $v != NONE);

DEFINE FIELD OVERWRITE owned_by ON TABLE payment TYPE option<record<groups>> VALUE $this.a_from.owned_by;
DEFINE FIELD OVERWRITE owners ON TABLE payment TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_from.owners, $this.a_to.owners]))).filter(|$v| $v != NONE);

DEFINE FIELD OVERWRITE owned_by ON TABLE payment_allocation TYPE option<record<groups>> VALUE $this.a_payment.owned_by;
DEFINE FIELD OVERWRITE owners ON TABLE payment_allocation TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_payment.owners, $this.a_invoice.owners]))).filter(|$v| $v != NONE);

DEFINE FIELD OVERWRITE owned_by ON TABLE sl TYPE option<record<groups>> VALUE $this.a_from.owned_by ?? $this.a_to.owned_by ?? $this.a_pkg.owned_by;
DEFINE FIELD OVERWRITE owners ON TABLE sl TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_from.owners, $this.a_to.owners, $this.a_pkg.owners, $this.a_item.owners]))).filter(|$v| $v != NONE);

DEFINE FIELD OVERWRITE owned_by ON TABLE stock_acc TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE owners ON TABLE stock_acc TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

DEFINE FIELD OVERWRITE owned_by ON TABLE tax_account TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE owners ON TABLE tax_account TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

DEFINE FIELD OVERWRITE owned_by ON TABLE tax_line TYPE option<record<groups>> VALUE $this.a_invoice_line.owned_by;
DEFINE FIELD OVERWRITE owners ON TABLE tax_line TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_invoice_line.owners, $this.a_tax_account.owners]))).filter(|$v| $v != NONE);

DEFINE FIELD OVERWRITE owned_by ON TABLE treasury TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE owners ON TABLE treasury TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

DEFINE FIELD OVERWRITE owned_by ON TABLE warehouse TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE owners ON TABLE warehouse TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

