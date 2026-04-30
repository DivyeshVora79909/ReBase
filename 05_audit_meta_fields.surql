USE NS main DB main;

DEFINE FIELD OVERWRITE created_at ON company_settings TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON company_settings TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON company_settings TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON company_settings TYPE option<record<user>> VALUE $auth;
DEFINE FIELD OVERWRITE extra_info ON company_settings TYPE option<object>;

DEFINE FIELD OVERWRITE created_at ON document_sequence TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON document_sequence TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON document_sequence TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON document_sequence TYPE option<record<user>> VALUE $auth;
DEFINE FIELD OVERWRITE extra_info ON document_sequence TYPE option<object>;

-- 2. MASTER ACCOUNTS (THE NOUNS)
DEFINE FIELD OVERWRITE created_at ON equity_account TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON equity_account TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON equity_account TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON equity_account TYPE option<record<user>> VALUE $auth;
DEFINE FIELD OVERWRITE extra_info ON equity_account TYPE option<object>;

DEFINE FIELD OVERWRITE created_at ON icce TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON icce TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON icce TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON icce TYPE option<record<user>> VALUE $auth;
DEFINE FIELD OVERWRITE extra_info ON icce TYPE option<object>;

DEFINE FIELD OVERWRITE created_at ON organization_account TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON organization_account TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON organization_account TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON organization_account TYPE option<record<user>> VALUE $auth;
DEFINE FIELD OVERWRITE extra_info ON organization_account TYPE option<object>;

DEFINE FIELD OVERWRITE created_at ON tax_account TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON tax_account TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON tax_account TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON tax_account TYPE option<record<user>> VALUE $auth;
DEFINE FIELD OVERWRITE extra_info ON tax_account TYPE option<object>;

DEFINE FIELD OVERWRITE created_at ON catalog_item TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON catalog_item TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON catalog_item TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON catalog_item TYPE option<record<user>> VALUE $auth;
DEFINE FIELD OVERWRITE extra_info ON catalog_item TYPE option<object>;

DEFINE FIELD OVERWRITE created_at ON inventory TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON inventory TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON inventory TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON inventory TYPE option<record<user>> VALUE $auth;
DEFINE FIELD OVERWRITE extra_info ON inventory TYPE option<object>;

-- 3. DOCUMENTS & LEDGERS (THE VERBS)
DEFINE FIELD OVERWRITE created_at ON invoice TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON invoice TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON invoice TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON invoice TYPE option<record<user>> VALUE $auth;
DEFINE FIELD OVERWRITE extra_info ON invoice TYPE option<object>;

DEFINE FIELD OVERWRITE created_at ON invoice_line TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON invoice_line TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON invoice_line TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON invoice_line TYPE option<record<user>> VALUE $auth;
DEFINE FIELD OVERWRITE extra_info ON invoice_line TYPE option<object>;

DEFINE FIELD OVERWRITE created_at ON vendor_bill TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON vendor_bill TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON vendor_bill TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON vendor_bill TYPE option<record<user>> VALUE $auth;
DEFINE FIELD OVERWRITE extra_info ON vendor_bill TYPE option<object>;

DEFINE FIELD OVERWRITE created_at ON vendor_bill_line TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON vendor_bill_line TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON vendor_bill_line TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON vendor_bill_line TYPE option<record<user>> VALUE $auth;
DEFINE FIELD OVERWRITE extra_info ON vendor_bill_line TYPE option<object>;

DEFINE FIELD OVERWRITE created_at ON payment TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON payment TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON payment TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON payment TYPE option<record<user>> VALUE $auth;
DEFINE FIELD OVERWRITE extra_info ON payment TYPE option<object>;

DEFINE FIELD OVERWRITE created_at ON financial_adjustment TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON financial_adjustment TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON financial_adjustment TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON financial_adjustment TYPE option<record<user>> VALUE $auth;
DEFINE FIELD OVERWRITE extra_info ON financial_adjustment TYPE option<object>;

DEFINE FIELD OVERWRITE created_at ON exchange TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON exchange TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON exchange TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON exchange TYPE option<record<user>> VALUE $auth;
DEFINE FIELD OVERWRITE extra_info ON exchange TYPE option<object>;