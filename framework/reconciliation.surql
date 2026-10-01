-- Private durable scan position shared by runtime instances in this database.
DEFINE TABLE OVERWRITE rebase_reconciliation_cursor SCHEMAFULL PERMISSIONS NONE;
DEFINE FIELD OVERWRITE cursors ON rebase_reconciliation_cursor TYPE object FLEXIBLE DEFAULT {};
DEFINE FIELD OVERWRITE high_water ON rebase_reconciliation_cursor TYPE object FLEXIBLE DEFAULT {};
DEFINE FIELD OVERWRITE retention_cursors ON rebase_reconciliation_cursor TYPE object FLEXIBLE DEFAULT {};
DEFINE FIELD OVERWRITE retention_high_water ON rebase_reconciliation_cursor TYPE object FLEXIBLE DEFAULT {};
DEFINE FIELD OVERWRITE table_offset ON rebase_reconciliation_cursor TYPE int DEFAULT 0 ASSERT $value >= 0;
DEFINE FIELD OVERWRITE version ON rebase_reconciliation_cursor TYPE int DEFAULT 0 ASSERT $value >= 0;
DEFINE FIELD OVERWRITE updated_at ON rebase_reconciliation_cursor TYPE datetime DEFAULT time::now();
