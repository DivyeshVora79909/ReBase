USE NS main DB main;

DEFINE FIELD OVERWRITE owned_by ON TABLE org TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE readers ON TABLE org TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

DEFINE FIELD OVERWRITE owned_by ON TABLE treasury TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE readers ON TABLE treasury TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

DEFINE FIELD OVERWRITE owned_by ON TABLE acc TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE readers ON TABLE acc TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

DEFINE FIELD OVERWRITE owned_by ON TABLE stock_acc TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE readers ON TABLE stock_acc TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

DEFINE FIELD OVERWRITE owned_by ON TABLE tax_account TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE readers ON TABLE tax_account TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

DEFINE FIELD OVERWRITE owned_by ON TABLE warehouse TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE readers ON TABLE warehouse TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

DEFINE FIELD OVERWRITE owned_by ON TABLE item TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE readers ON TABLE item TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

DEFINE FIELD OVERWRITE owned_by ON TABLE payment TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates VALUE $this.a_from.owned_by;
DEFINE FIELD OVERWRITE readers ON TABLE payment TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_from.readers, $this.a_to.readers]))).filter(|$v| $v != NONE);

DEFINE FIELD OVERWRITE owned_by ON TABLE invoice TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates VALUE $this.a_org.owned_by;
DEFINE FIELD OVERWRITE readers ON TABLE invoice TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_org.readers]))).filter(|$v| $v != NONE);

DEFINE FIELD OVERWRITE owned_by ON TABLE adjustment_note TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;
DEFINE FIELD OVERWRITE readers ON TABLE adjustment_note TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));

DEFINE FIELD OVERWRITE owned_by ON TABLE payment_allocation TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates VALUE $this.a_payment.owned_by;
DEFINE FIELD OVERWRITE readers ON TABLE payment_allocation TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_payment.readers, $this.a_invoice.readers]))).filter(|$v| $v != NONE);

DEFINE FIELD OVERWRITE owned_by ON TABLE package_note TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates VALUE $this.a_invoice.owned_by;
DEFINE FIELD OVERWRITE readers ON TABLE package_note TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_invoice.readers]))).filter(|$v| $v != NONE);

DEFINE FIELD OVERWRITE owned_by ON TABLE invoice_line TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates VALUE $this.a_invoice.owned_by;
DEFINE FIELD OVERWRITE readers ON TABLE invoice_line TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_invoice.readers, $this.a_item.readers]))).filter(|$v| $v != NONE);

DEFINE FIELD OVERWRITE owned_by ON TABLE sl TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates VALUE $this.a_from.owned_by ?? $this.a_to.owned_by ?? $this.a_pkg.owned_by;
DEFINE FIELD OVERWRITE readers ON TABLE sl TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_from.readers, $this.a_to.readers, $this.a_pkg.readers, $this.a_item.readers, $this.d4_item.readers]))).filter(|$v| $v != NONE);

DEFINE FIELD OVERWRITE owned_by ON TABLE tax_line TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates VALUE $this.a_invoice_line.owned_by;
DEFINE FIELD OVERWRITE readers ON TABLE tax_line TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_invoice_line.readers, $this.a_tax_account.readers]))).filter(|$v| $v != NONE);

DEFINE FIELD OVERWRITE owned_by ON TABLE adjustment_line TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates VALUE $this.a_note.owned_by;
DEFINE FIELD OVERWRITE readers ON TABLE adjustment_line TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, $this.a_note.readers, $this.a_target.readers]))).filter(|$v| $v != NONE);

