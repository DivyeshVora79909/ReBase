-- Independent entry records are the minimal extension examples.

DEFINE TABLE OVERWRITE account_entry SCHEMAFULL COMMENT '@rebase-members fn::accounting::entry_members @rebase-validate fn::accounting::entry_validate';
DEFINE FIELD OVERWRITE account ON account_entry TYPE record<organization | treasury | direct_tax_account | indirect_tax_account | misc_currency_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON account_entry TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE note ON account_entry TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE real ON account_entry TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE receivable ON account_entry TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE payable ON account_entry TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_account ON account_entry TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner organization.z_history @rebase-tree-owner treasury.z_history @rebase-tree-owner direct_tax_account.z_history @rebase-tree-owner indirect_tax_account.z_history @rebase-tree-owner misc_currency_account.z_history';

DEFINE TABLE OVERWRITE stock_entry SCHEMAFULL COMMENT '@rebase-members fn::accounting::entry_members @rebase-validate fn::accounting::entry_validate';
DEFINE FIELD OVERWRITE account ON stock_entry TYPE record<stock_account | misc_stock_account> REFERENCE ON DELETE REJECT COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE effective_at ON stock_entry TYPE datetime COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE note ON stock_entry TYPE option<string> COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE real ON stock_entry TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE receivable ON stock_entry TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE payable ON stock_entry TYPE decimal DEFAULT 0dec COMMENT '@rebase-audit';
DEFINE FIELD OVERWRITE z_account ON stock_entry TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key datetime @rebase-tree-owner stock_account.z_history @rebase-tree-owner misc_stock_account.z_history';

DEFINE FUNCTION OVERWRITE fn::accounting::entry_members($row: object) {
    RETURN [fn::accounting::balance_member($row, 'z_account', $row.account, $row.effective_at, fn::accounting::effects($row.real, $row.receivable, $row.payable), false)];
} PERMISSIONS NONE;

DEFINE FUNCTION OVERWRITE fn::accounting::entry_validate($row: object) {
    IF $row.real = 0dec AND $row.receivable = 0dec AND $row.payable = 0dec { THROW 'ENTRY_EMPTY'; };
} PERMISSIONS FULL;
