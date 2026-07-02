-- FILE 05: SYSTEM FLAGS
USE NS main DB main;

DEFINE FIELD OVERWRITE system_ping ON TABLE acc TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE system_ping ON TABLE adjustment_line TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE system_ping ON TABLE adjustment_note TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE system_ping ON TABLE invoice TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE system_ping ON TABLE invoice_line TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE system_ping ON TABLE item TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE system_ping ON TABLE org TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE system_ping ON TABLE package_note TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE system_ping ON TABLE payment TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE system_ping ON TABLE payment_allocation TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE system_ping ON TABLE sl TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE system_ping ON TABLE stock_acc TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE system_ping ON TABLE tax_account TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE system_ping ON TABLE tax_line TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE system_ping ON TABLE treasury TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

DEFINE FIELD OVERWRITE system_ping ON TABLE warehouse TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;

