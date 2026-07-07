USE NS main DB main;

DEFINE FIELD OVERWRITE created_at ON TABLE org TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE org TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE org TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE org TYPE option<record<user>> VALUE $auth;

DEFINE FIELD OVERWRITE created_at ON TABLE treasury TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE treasury TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE treasury TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE treasury TYPE option<record<user>> VALUE $auth;

DEFINE FIELD OVERWRITE created_at ON TABLE acc TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE acc TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE acc TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE acc TYPE option<record<user>> VALUE $auth;

DEFINE FIELD OVERWRITE created_at ON TABLE stock_acc TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE stock_acc TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE stock_acc TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE stock_acc TYPE option<record<user>> VALUE $auth;

DEFINE FIELD OVERWRITE created_at ON TABLE tax_account TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE tax_account TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE tax_account TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE tax_account TYPE option<record<user>> VALUE $auth;

DEFINE FIELD OVERWRITE created_at ON TABLE warehouse TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE warehouse TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE warehouse TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE warehouse TYPE option<record<user>> VALUE $auth;

DEFINE FIELD OVERWRITE created_at ON TABLE item TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE item TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE item TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE item TYPE option<record<user>> VALUE $auth;

DEFINE FIELD OVERWRITE created_at ON TABLE payment TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE payment TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE payment TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE payment TYPE option<record<user>> VALUE $auth;

DEFINE FIELD OVERWRITE created_at ON TABLE invoice TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE invoice TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE invoice TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE invoice TYPE option<record<user>> VALUE $auth;

DEFINE FIELD OVERWRITE created_at ON TABLE adjustment_note TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE adjustment_note TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE adjustment_note TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE adjustment_note TYPE option<record<user>> VALUE $auth;

DEFINE FIELD OVERWRITE created_at ON TABLE payment_allocation TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE payment_allocation TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE payment_allocation TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE payment_allocation TYPE option<record<user>> VALUE $auth;

DEFINE FIELD OVERWRITE created_at ON TABLE package_note TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE package_note TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE package_note TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE package_note TYPE option<record<user>> VALUE $auth;

DEFINE FIELD OVERWRITE created_at ON TABLE invoice_line TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE invoice_line TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE invoice_line TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE invoice_line TYPE option<record<user>> VALUE $auth;

DEFINE FIELD OVERWRITE created_at ON TABLE sl TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE sl TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE sl TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE sl TYPE option<record<user>> VALUE $auth;

DEFINE FIELD OVERWRITE created_at ON TABLE tax_line TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE tax_line TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE tax_line TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE tax_line TYPE option<record<user>> VALUE $auth;

DEFINE FIELD OVERWRITE created_at ON TABLE adjustment_line TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE adjustment_line TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE adjustment_line TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE adjustment_line TYPE option<record<user>> VALUE $auth;

