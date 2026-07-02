{
  "user": [
    {
      "id": "user:root",
      "name": "Super Admin",
      "email": "test@admin.com",
      "password": null,
      "invite_token": null,
      "dominates": ["user:root", "groups:root", "groups:exec", "groups:ops", "groups:sales", "groups:hr"],
      "parents": ["groups:root"],
      "permissions": ["node_create", "node_select", "node_update", "node_delete", "link_create", "link_select", "link_delete", "acc_select", "acc_create", "acc_update", "acc_delete", "adjustment_line_select", "adjustment_line_create", "adjustment_line_update", "adjustment_line_delete", "adjustment_note_select", "adjustment_note_create", "adjustment_note_update", "adjustment_note_delete", "adjustment_stock_line_select", "adjustment_stock_line_create", "adjustment_stock_line_update", "adjustment_stock_line_delete", "adjustment_tax_line_select", "adjustment_tax_line_create", "adjustment_tax_line_update", "adjustment_tax_line_delete", "invoice_select", "invoice_create", "invoice_update", "invoice_delete", "invoice_line_select", "invoice_line_create", "invoice_line_update", "invoice_line_delete", "item_select", "item_create", "item_update", "item_delete", "org_select", "org_create", "org_update", "org_delete", "package_note_select", "package_note_create", "package_note_update", "package_note_delete", "payment_select", "payment_create", "payment_update", "payment_delete", "payment_allocation_select", "payment_allocation_create", "payment_allocation_update", "payment_allocation_delete", "sl_select", "sl_create", "sl_update", "sl_delete", "stock_acc_select", "stock_acc_create", "stock_acc_update", "stock_acc_delete", "tax_account_select", "tax_account_create", "tax_account_update", "tax_account_delete", "tax_line_select", "tax_line_create", "tax_line_update", "tax_line_delete", "treasury_select", "treasury_create", "treasury_update", "treasury_delete", "warehouse_select", "warehouse_create", "warehouse_update", "warehouse_delete"],
      "last_deactivated_at": null,
      "last_refreshed_at": "2026-01-01T00:00:00Z",
      "created_at": "2025-12-01T00:00:00Z",
      "updated_at": "2026-01-01T00:00:00Z",
      "created_by": null,
      "updated_by": "user:root",
      "system_ping": "2026-01-01T00:00:00Z"
    },
    {
      "id": "user:ceo",
      "name": "Alice CEO",
      "email": "alice@company.com",
      "password": null,
      "invite_token": null,
      "dominates": ["user:ceo", "groups:exec", "groups:ops", "groups:sales", "groups:hr"],
      "parents": ["groups:root"],
      "permissions": ["node_create", "node_select", "node_update", "node_delete", "link_create", "link_select", "link_delete", "acc_select", "acc_create", "acc_update", "acc_delete", "adjustment_line_select", "adjustment_line_create", "adjustment_line_update", "adjustment_line_delete", "adjustment_note_select", "adjustment_note_create", "adjustment_note_update", "adjustment_note_delete", "adjustment_stock_line_select", "adjustment_stock_line_create", "adjustment_stock_line_update", "adjustment_stock_line_delete", "adjustment_tax_line_select", "adjustment_tax_line_create", "adjustment_tax_line_update", "adjustment_tax_line_delete", "invoice_select", "invoice_create", "invoice_update", "invoice_delete", "invoice_line_select", "invoice_line_create", "invoice_line_update", "invoice_line_delete", "item_select", "item_create", "item_update", "item_delete", "org_select", "org_create", "org_update", "org_delete", "package_note_select", "package_note_create", "package_note_update", "package_note_delete", "payment_select", "payment_create", "payment_update", "payment_delete", "payment_allocation_select", "payment_allocation_create", "payment_allocation_update", "payment_allocation_delete", "sl_select", "sl_create", "sl_update", "sl_delete", "stock_acc_select", "stock_acc_create", "stock_acc_update", "stock_acc_delete", "tax_account_select", "tax_account_create", "tax_account_update", "tax_account_delete", "tax_line_select", "tax_line_create", "tax_line_update", "tax_line_delete", "treasury_select", "treasury_create", "treasury_update", "treasury_delete", "warehouse_select", "warehouse_create", "warehouse_update", "warehouse_delete"],
      "last_deactivated_at": null,
      "last_refreshed_at": "2026-01-01T00:00:01Z",
      "created_at": "2025-12-01T00:00:01Z",
      "updated_at": "2026-01-01T00:00:01Z",
      "created_by": "user:root",
      "updated_by": "user:root",
      "system_ping": "2026-01-01T00:00:01Z"
    },
    {
      "id": "user:coo",
      "name": "Bob COO",
      "email": "bob@company.com",
      "password": null,
      "invite_token": null,
      "dominates": ["user:coo", "groups:exec", "groups:ops", "groups:sales", "groups:hr"],
      "parents": ["groups:exec"],
      "permissions": ["node_create", "node_select", "node_update", "node_delete", "link_create", "link_select", "link_delete", "acc_select", "acc_create", "acc_update", "acc_delete", "adjustment_line_select", "adjustment_line_create", "adjustment_line_update", "adjustment_line_delete", "adjustment_note_select", "adjustment_note_create", "adjustment_note_update", "adjustment_note_delete", "adjustment_stock_line_select", "adjustment_stock_line_create", "adjustment_stock_line_update", "adjustment_stock_line_delete", "adjustment_tax_line_select", "adjustment_tax_line_create", "adjustment_tax_line_update", "adjustment_tax_line_delete", "invoice_select", "invoice_create", "invoice_update", "invoice_delete", "invoice_line_select", "invoice_line_create", "invoice_line_update", "invoice_line_delete", "item_select", "item_create", "item_update", "item_delete", "org_select", "org_create", "org_update", "org_delete", "package_note_select", "package_note_create", "package_note_update", "package_note_delete", "payment_select", "payment_create", "payment_update", "payment_delete", "payment_allocation_select", "payment_allocation_create", "payment_allocation_update", "payment_allocation_delete", "sl_select", "sl_create", "sl_update", "sl_delete", "stock_acc_select", "stock_acc_create", "stock_acc_update", "stock_acc_delete", "tax_account_select", "tax_account_create", "tax_account_update", "tax_account_delete", "tax_line_select", "tax_line_create", "tax_line_update", "tax_line_delete", "treasury_select", "treasury_create", "treasury_update", "treasury_delete", "warehouse_select", "warehouse_create", "warehouse_update", "warehouse_delete"],
      "last_deactivated_at": null,
      "last_refreshed_at": "2026-01-01T00:00:02Z",
      "created_at": "2025-12-01T00:00:02Z",
      "updated_at": "2026-01-01T00:00:02Z",
      "created_by": "user:root",
      "updated_by": "user:root",
      "system_ping": "2026-01-01T00:00:02Z"
    },
    {
      "id": "user:ops_mgr",
      "name": "Charlie Ops",
      "email": "charlie@company.com",
      "password": null,
      "invite_token": null,
      "dominates": ["user:ops_mgr", "groups:ops"],
      "parents": ["groups:exec"],
      "permissions": ["node_select","node_update","item_select","item_create","item_update","item_delete","sl_select","sl_create","sl_update","sl_delete","warehouse_select","warehouse_create","warehouse_update","warehouse_delete"],
      "last_deactivated_at": null,
      "last_refreshed_at": "2026-01-01T00:00:03Z",
      "created_at": "2025-12-01T00:00:03Z",
      "updated_at": "2026-01-01T00:00:03Z",
      "created_by": "user:root",
      "updated_by": "user:root",
      "system_ping": "2026-01-01T00:00:03Z"
    },
    {
      "id": "user:sales1",
      "name": "Diana Sales",
      "email": "diana@company.com",
      "password": null,
      "invite_token": null,
      "dominates": ["user:sales1", "groups:sales"],
      "parents": ["groups:exec"],
      "permissions": ["node_select","invoice_select","invoice_create","invoice_update","invoice_line_select","invoice_line_create","invoice_line_update"],
      "last_deactivated_at": null,
      "last_refreshed_at": "2026-01-01T00:00:04Z",
      "created_at": "2025-12-01T00:00:04Z",
      "updated_at": "2026-01-01T00:00:04Z",
      "created_by": "user:root",
      "updated_by": "user:root",
      "system_ping": "2026-01-01T00:00:04Z"
    },
    {
      "id": "user:sales2",
      "name": "Evan Sales",
      "email": "evan@company.com",
      "password": null,
      "invite_token": null,
      "dominates": ["user:sales2", "groups:sales"],
      "parents": ["groups:exec"],
      "permissions": ["node_select","invoice_select","invoice_create","invoice_update","invoice_line_select","invoice_line_create","invoice_line_update"],
      "last_deactivated_at": null,
      "last_refreshed_at": "2026-01-01T00:00:05Z",
      "created_at": "2025-12-01T00:00:05Z",
      "updated_at": "2026-01-01T00:00:05Z",
      "created_by": "user:root",
      "updated_by": "user:root",
      "system_ping": "2026-01-01T00:00:05Z"
    },
    {
      "id": "user:hr1",
      "name": "Fiona HR",
      "email": "fiona@company.com",
      "password": null,
      "invite_token": null,
      "dominates": ["user:hr1"],
      "parents": ["groups:exec"],
      "permissions": ["node_select"],
      "last_deactivated_at": null,
      "last_refreshed_at": "2026-01-01T00:00:06Z",
      "created_at": "2025-12-01T00:00:06Z",
      "updated_at": "2026-01-01T00:00:06Z",
      "created_by": "user:root",
      "updated_by": "user:root",
      "system_ping": "2026-01-01T00:00:06Z"
    }
  ],

  "groups": [
    {
      "id": "groups:root",
      "name": "System Admins",
      "role": [
        "node_create", "node_select", "node_update", "node_delete",
        "link_create", "link_select", "link_delete",
        "acc_select", "acc_create", "acc_update", "acc_delete",
        "adjustment_line_select", "adjustment_line_create", "adjustment_line_update", "adjustment_line_delete",
        "adjustment_note_select", "adjustment_note_create", "adjustment_note_update", "adjustment_note_delete",
        "adjustment_stock_line_select", "adjustment_stock_line_create", "adjustment_stock_line_update", "adjustment_stock_line_delete",
        "adjustment_tax_line_select", "adjustment_tax_line_create", "adjustment_tax_line_update", "adjustment_tax_line_delete",
        "invoice_select", "invoice_create", "invoice_update", "invoice_delete",
        "invoice_line_select", "invoice_line_create", "invoice_line_update", "invoice_line_delete",
        "item_select", "item_create", "item_update", "item_delete",
        "org_select", "org_create", "org_update", "org_delete",
        "package_note_select", "package_note_create", "package_note_update", "package_note_delete",
        "payment_select", "payment_create", "payment_update", "payment_delete",
        "payment_allocation_select", "payment_allocation_create", "payment_allocation_update", "payment_allocation_delete",
        "sl_select", "sl_create", "sl_update", "sl_delete",
        "stock_acc_select", "stock_acc_create", "stock_acc_update", "stock_acc_delete",
        "tax_account_select", "tax_account_create", "tax_account_update", "tax_account_delete",
        "tax_line_select", "tax_line_create", "tax_line_update", "tax_line_delete",
        "treasury_select", "treasury_create", "treasury_update", "treasury_delete",
        "warehouse_select", "warehouse_create", "warehouse_update", "warehouse_delete"
      ],
      "created_at": "2025-12-01T00:00:00Z",
      "updated_at": "2026-01-01T00:00:00Z",
      "created_by": null,
      "updated_by": "user:root"
    },
    {
      "id": "groups:exec",
      "name": "Executive",
      "role": [
        "node_create", "node_select", "node_update", "node_delete",
        "link_create", "link_select", "link_delete",
        "acc_select", "acc_create", "acc_update", "acc_delete",
        "adjustment_line_select", "adjustment_line_create", "adjustment_line_update", "adjustment_line_delete",
        "adjustment_note_select", "adjustment_note_create", "adjustment_note_update", "adjustment_note_delete",
        "invoice_select", "invoice_create", "invoice_update", "invoice_delete",
        "invoice_line_select", "invoice_line_create", "invoice_line_update", "invoice_line_delete",
        "item_select", "item_create", "item_update", "item_delete",
        "org_select", "org_create", "org_update", "org_delete",
        "package_note_select", "package_note_create", "package_note_update", "package_note_delete",
        "payment_select", "payment_create", "payment_update", "payment_delete",
        "payment_allocation_select", "payment_allocation_create", "payment_allocation_update", "payment_allocation_delete",
        "sl_select", "sl_create", "sl_update", "sl_delete",
        "stock_acc_select", "stock_acc_create", "stock_acc_update", "stock_acc_delete",
        "tax_account_select", "tax_account_create", "tax_account_update", "tax_account_delete",
        "tax_line_select", "tax_line_create", "tax_line_update", "tax_line_delete",
        "treasury_select", "treasury_create", "treasury_update", "treasury_delete",
        "warehouse_select", "warehouse_create", "warehouse_update", "warehouse_delete"
      ],
      "created_at": "2025-12-01T00:00:01Z",
      "updated_at": "2026-01-01T00:00:01Z",
      "created_by": "user:root",
      "updated_by": "user:root"
    },
    {
      "id": "groups:ops",
      "name": "Operations",
      "role": [
        "node_select","node_update","item_select","item_create","item_update","item_delete",
        "sl_select","sl_create","sl_update","sl_delete",
        "warehouse_select","warehouse_create","warehouse_update","warehouse_delete"
      ],
      "created_at": "2025-12-01T00:00:02Z",
      "updated_at": "2026-01-01T00:00:02Z",
      "created_by": "user:root",
      "updated_by": "user:root"
    },
    {
      "id": "groups:sales",
      "name": "Sales",
      "role": [
        "node_select","invoice_select","invoice_create","invoice_update",
        "invoice_line_select","invoice_line_create","invoice_line_update"
      ],
      "created_at": "2025-12-01T00:00:03Z",
      "updated_at": "2026-01-01T00:00:03Z",
      "created_by": "user:root",
      "updated_by": "user:root"
    },
    {
      "id": "groups:hr",
      "name": "HR",
      "role": ["node_select"],
      "created_at": "2025-12-01T00:00:04Z",
      "updated_at": "2026-01-01T00:00:04Z",
      "created_by": "user:root",
      "updated_by": "user:root"
    }
  ],

  "link": [
    {"in": "groups:root", "out": "user:root", "created_at": "2025-12-01T00:00:00Z", "created_by": null},
    {"in": "groups:root", "out": "groups:exec", "created_at": "2025-12-01T00:00:01Z", "created_by": "user:root"},
    {"in": "groups:exec", "out": "groups:ops", "created_at": "2025-12-01T00:00:02Z", "created_by": "user:root"},
    {"in": "groups:exec", "out": "groups:sales", "created_at": "2025-12-01T00:00:03Z", "created_by": "user:root"},
    {"in": "groups:exec", "out": "groups:hr", "created_at": "2025-12-01T00:00:04Z", "created_by": "user:root"},
    {"in": "groups:root", "out": "user:ceo", "created_at": "2025-12-01T00:00:05Z", "created_by": "user:root"},
    {"in": "groups:exec", "out": "user:coo", "created_at": "2025-12-01T00:00:06Z", "created_by": "user:root"},
    {"in": "groups:ops", "out": "user:ops_mgr", "created_at": "2025-12-01T00:00:07Z", "created_by": "user:root"},
    {"in": "groups:sales", "out": "user:sales1", "created_at": "2025-12-01T00:00:08Z", "created_by": "user:root"},
    {"in": "groups:sales", "out": "user:sales2", "created_at": "2025-12-01T00:00:09Z", "created_by": "user:root"},
    {"in": "groups:hr", "out": "user:hr1", "created_at": "2025-12-01T00:00:10Z", "created_by": "user:root"}
  ],

  "org": [
    {
      "id": "org:tech_supplier",
      "a_in_name": "Tech Distro Inc.",
      "a_in_currency": "USD",
      "owned_by": "groups:ops",
      "owners": ["groups:ops"],
      "c_vw_inv": "v_inv_org:['org:tech_supplier']",
      "c_vw_pay_to": "v_pay_node_to:['org:tech_supplier']",
      "c_vw_pay_from": "v_pay_node_from:['org:tech_supplier']",
      "d_c1_net_financial_position": -10000,
      "f_out": {
        "currency": "USD"
      },
      "created_at": "2025-12-02T00:00:00Z",
      "updated_at": "2026-05-20T08:00:01Z",
      "created_by": "user:ops_mgr",
      "updated_by": "user:ops_mgr",
      "system_ping": "2026-05-20T08:00:01Z"
    },
    {
      "id": "org:acme_customer",
      "a_in_name": "Acme Corp",
      "a_in_currency": "EUR",
      "owned_by": "groups:sales",
      "owners": ["groups:sales"],
      "c_vw_inv": "v_inv_org:['org:acme_customer']",
      "c_vw_pay_to": "v_pay_node_to:['org:acme_customer']",
      "c_vw_pay_from": "v_pay_node_from:['org:acme_customer']",
      "d_c1_net_financial_position": 0,
      "f_out": {
        "currency": "EUR"
      },
      "created_at": "2025-12-02T00:00:01Z",
      "updated_at": "2026-01-06T10:00:01Z",
      "created_by": "user:sales1",
      "updated_by": "user:sales1",
      "system_ping": "2026-01-06T10:00:01Z"
    },
    {
      "id": "org:globex",
      "a_in_name": "Globex Inc.",
      "a_in_currency": "USD",
      "owned_by": "groups:sales",
      "owners": ["groups:sales"],
      "c_vw_inv": "v_inv_org:['org:globex']",
      "c_vw_pay_to": "v_pay_node_to:['org:globex']",
      "c_vw_pay_from": "v_pay_node_from:['org:globex']",
      "d_c1_net_financial_position": 400,
      "f_out": {
        "currency": "USD"
      },
      "created_at": "2025-12-02T00:00:02Z",
      "updated_at": "2026-05-15T09:00:01Z",
      "created_by": "user:sales2",
      "updated_by": "user:sales2",
      "system_ping": "2026-05-15T09:00:01Z"
    }
  ],

  "treasury": [
    {
      "id": "treasury:main",
      "a_in_name": "Central Bank",
      "owned_by": "groups:exec",
      "owners": ["groups:exec"],
      "c_vw_pay_to": "v_pay_node_to:['treasury:main']",
      "c_vw_pay_from": "v_pay_node_from:['treasury:main']",
      "d_c1_balance": 4900,
      "e_guard_state": true,
      "f_out": {},
      "created_at": "2025-12-02T00:00:03Z",
      "updated_at": "2026-01-06T10:00:02Z",
      "created_by": "user:ceo",
      "updated_by": "user:ceo",
      "system_ping": "2026-01-06T10:00:02Z"
    }
  ],

  "acc": [
    {
      "id": "acc:cogs",
      "a_in_name": "Cost of Goods Sold",
      "owned_by": "groups:ops",
      "owners": ["groups:ops"],
      "c_vw_pay_to": "v_pay_node_to:['acc:cogs']",
      "c_vw_pay_from": "v_pay_node_from:['acc:cogs']",
      "d_c1_balance": 4000,
      "e_guard_state": true,
      "f_out": {},
      "created_at": "2025-12-02T00:00:04Z",
      "updated_at": "2026-01-05T12:00:01Z",
      "created_by": "user:ops_mgr",
      "updated_by": "user:ops_mgr",
      "system_ping": "2026-01-05T12:00:01Z"
    },
    {
      "id": "acc:income_a",
      "a_in_name": "Alpha Income",
      "owned_by": "groups:exec",
      "owners": ["groups:exec"],
      "c_vw_pay_to": "v_pay_node_to:['acc:income_a']",
      "c_vw_pay_from": "v_pay_node_from:['acc:income_a']",
      "d_c1_balance": 500,
      "e_guard_state": true,
      "f_out": {},
      "created_at": "2025-12-02T00:00:05Z",
      "updated_at": "2026-01-06T10:00:03Z",
      "created_by": "user:ceo",
      "updated_by": "user:ceo",
      "system_ping": "2026-01-06T10:00:03Z"
    }
  ],

  "stock_acc": [
    {
      "id": "stock_acc:damaged_a",
      "a_in_name": "Damaged Stock",
      "owned_by": "groups:ops",
      "owners": ["groups:ops"],
      "c_vw_sl_in": "v_sl_node_in:['stock_acc:damaged_a']",
      "c_vw_sl_out": "v_sl_node_out:['stock_acc:damaged_a']",
      "d_c1_net_qty": 0,
      "f_out": {},
      "created_at": "2025-12-02T00:00:06Z",
      "updated_at": "2026-05-20T08:00:02Z",
      "created_by": "user:ops_mgr",
      "updated_by": "user:ops_mgr",
      "system_ping": "2026-05-20T08:00:02Z"
    }
  ],

  "tax_account": [
    {
      "id": "tax:sales_tax",
      "a_in_name": "Sales Tax Payable",
      "owned_by": "groups:exec",
      "owners": ["groups:exec"],
      "c_vw_pay_to": "v_pay_node_to:['tax:sales_tax']",
      "c_vw_pay_from": "v_pay_node_from:['tax:sales_tax']",
      "c_vw_tl": "v_tl_acc:['tax:sales_tax']",
      "d_c1_liability": 400,
      "f_out": {},
      "created_at": "2025-12-02T00:00:07Z",
      "updated_at": "2026-01-05T10:00:01Z",
      "created_by": "user:ceo",
      "updated_by": "user:ceo",
      "system_ping": "2026-01-05T10:00:01Z"
    }
  ],

  "item": [
    {
      "id": "item:laptop",
      "a_in_name": "Pro Laptop",
      "a_in_is_service": false,
      "a_in_default_cogs": 1000,
      "owned_by": "groups:ops",
      "owners": ["groups:ops"],
      "c_vw_invl": "v_invl_item:['item:laptop']",
      "d_c1_turnover": 6,
      "d_c2_avg_cogs": 1000,
      "f_out": {
        "actual_unit_cogs": 1000,
        "is_service": false
      },
      "created_at": "2025-12-02T00:00:08Z",
      "updated_at": "2026-05-20T08:00:03Z",
      "created_by": "user:ops_mgr",
      "updated_by": "user:ops_mgr",
      "system_ping": "2026-05-20T08:00:03Z"
    },
    {
      "id": "item:setup_service",
      "a_in_name": "Installation Service",
      "a_in_is_service": true,
      "a_in_default_cogs": 0,
      "owned_by": "groups:sales",
      "owners": ["groups:sales"],
      "c_vw_invl": "v_invl_item:['item:setup_service']",
      "d_c1_turnover": 1,
      "d_c2_avg_cogs": 0,
      "f_out": {
        "actual_unit_cogs": 0,
        "is_service": true
      },
      "created_at": "2025-12-02T00:00:09Z",
      "updated_at": "2026-01-05T10:00:02Z",
      "created_by": "user:sales1",
      "updated_by": "user:sales1",
      "system_ping": "2026-01-05T10:00:02Z"
    }
  ],

  "warehouse": [
    {
      "id": "warehouse:main",
      "a_in_name": "Central Fulfillment",
      "owned_by": "groups:ops",
      "owners": ["groups:ops"],
      "c_vw_sl_in": "v_sl_node_in:['warehouse:main']",
      "c_vw_sl_out": "v_sl_node_out:['warehouse:main']",
      "d_c1_global_matrix_stock": 6,
      "f_out": {},
      "created_at": "2025-12-02T00:00:10Z",
      "updated_at": "2026-05-15T12:00:01Z",
      "created_by": "user:ops_mgr",
      "updated_by": "user:ops_mgr",
      "system_ping": "2026-05-15T12:00:01Z"
    }
  ],

  "invoice": [
    {
      "id": "invoice:purchase_1",
      "a_in_org": "org:tech_supplier",
      "a_in_type": "purchase",
      "a_in_fx_rate": 1.0,
      "owned_by": "groups:ops",
      "owners": ["groups:ops"],
      "c_vw_invl": "v_invl_inv:['invoice:purchase_1']",
      "c_vw_pa": "v_pa_inv:['invoice:purchase_1']",
      "d_c1_raw_grand_total": 10000,
      "d_c2_adjusted_grand_total": 10000,
      "d_c3_allocation_shield": 10000,
      "e_guard_state": true,
      "f_out": {
        "inv_sales_raw_total": 0,
        "inv_sales_adjusted_total": 0,
        "inv_purchase_raw_total": 10000,
        "inv_purchase_adjusted_total": 10000,
        "fx_rate": 1.0,
        "type": "purchase",
        "org": "org:tech_supplier"
      },
      "created_at": "2026-01-01T10:00:00Z",
      "updated_at": "2026-05-20T08:00:04Z",
      "created_by": "user:ops_mgr",
      "updated_by": "user:ops_mgr",
      "system_ping": "2026-05-20T08:00:04Z"
    },
    {
      "id": "invoice:sales_1",
      "a_in_org": "org:acme_customer",
      "a_in_type": "sales",
      "a_in_fx_rate": 1.0,
      "owned_by": "groups:sales",
      "owners": ["groups:sales"],
      "c_vw_invl": "v_invl_inv:['invoice:sales_1']",
      "c_vw_pa": "v_pa_inv:['invoice:sales_1']",
      "d_c1_raw_grand_total": 4500,
      "d_c2_adjusted_grand_total": 4900,
      "d_c3_allocation_shield": 0,
      "e_guard_state": true,
      "f_out": {
        "inv_sales_raw_total": 4500,
        "inv_sales_adjusted_total": 4900,
        "inv_purchase_raw_total": 0,
        "inv_purchase_adjusted_total": 0,
        "fx_rate": 1.0,
        "type": "sales",
        "org": "org:acme_customer"
      },
      "created_at": "2026-01-05T10:00:00Z",
      "updated_at": "2026-01-06T10:00:04Z",
      "created_by": "user:sales1",
      "updated_by": "user:sales1",
      "system_ping": "2026-01-06T10:00:04Z"
    },
    {
      "id": "invoice:sales_2",
      "a_in_org": "org:globex",
      "a_in_type": "sales",
      "a_in_fx_rate": 1.0,
      "owned_by": "groups:sales",
      "owners": ["groups:sales"],
      "c_vw_invl": "v_invl_inv:['invoice:sales_2']",
      "c_vw_pa": "v_pa_inv:['invoice:sales_2']",
      "d_c1_raw_grand_total": 400,
      "d_c2_adjusted_grand_total": 400,
      "d_c3_allocation_shield": 400,
      "e_guard_state": true,
      "f_out": {
        "inv_sales_raw_total": 400,
        "inv_sales_adjusted_total": 400,
        "inv_purchase_raw_total": 0,
        "inv_purchase_adjusted_total": 0,
        "fx_rate": 1.0,
        "type": "sales",
        "org": "org:globex"
      },
      "created_at": "2026-05-15T09:00:00Z",
      "updated_at": "2026-05-15T09:00:02Z",
      "created_by": "user:sales2",
      "updated_by": "user:sales2",
      "system_ping": "2026-05-15T09:00:02Z"
    }
  ],

  "adjustment_note": [
    {
      "id": "adjustment_note:adjn01",
      "a_in_org": "org:tech_supplier",
      "owned_by": "groups:ops",
      "owners": ["groups:ops"],
      "d_c1_details": [
        {
          "invoice_line": "invoice_line:pur_laptop",
          "diff_price": -2000,
          "diff_tax": 0,
          "diff_total": -2000
        }
      ],
      "d_c2_total_amount_delta": -2000,
      "d_c3_total_tax_delta": 0,
      "d_c4_derived_type": "credit",
      "e_guard_sign_match": true,
      "f_out": {
        "adj_debit_val": 0,
        "adj_credit_val": 2000,
        "org": "org:tech_supplier"
      },
      "created_at": "2026-05-20T08:00:00Z",
      "updated_at": "2026-05-20T08:00:05Z",
      "created_by": "user:ops_mgr",
      "updated_by": "user:ops_mgr",
      "system_ping": "2026-05-20T08:00:05Z"
    }
  ],

  "invoice_line": [
    {
      "id": "invoice_line:pur_laptop",
      "a_in_invoice": "invoice:purchase_1",
      "a_in_item": "item:laptop",
      "a_in_qty": 10,
      "a_in_price": 1000,
      "owned_by": "groups:ops",
      "owners": ["groups:ops", "org:tech_supplier"],
      "b_ctx_inv_type": "purchase",
      "b_ctx_inv_fx": 1.0,
      "b_ctx_inv_org": "org:tech_supplier",
      "b_ctx_item_cogs": 1000,
      "b_ctx_item_service": false,
      "c_vw_sl_from": "v_sl_invl_from:['invoice_line:pur_laptop']",
      "c_vw_sl_to": "v_sl_invl_to:['invoice_line:pur_laptop']",
      "c_vw_al": "v_al_invl:['invoice_line:pur_laptop']",
      "c_vw_tl": "v_tl_invl:['invoice_line:pur_laptop']",
      "d_c1_raw_base_val": 10000,
      "d_c2_adjusted_base_val": 8000,
      "d_c3_raw_tax_val": 0,
      "d_c4_adjusted_tax_val": 0,
      "d_c5_raw_gross_val": 10000,
      "d_c6_adjusted_gross_val": 8000,
      "d_c7_actual_cogs": 1000,
      "d_c8_delivered_qty": 10,
      "e_guard_state": true,
      "f_out": {
        "invl_raw_gross_val": 10000,
        "invl_adjusted_gross_val": 8000,
        "invl_purchase_qty": 10,
        "invl_sales_qty": 0,
        "invl_purchase_adjusted_val": 8000,
        "actual_unit_cogs": 1000,
        "inv_fx_rate": 1.0,
        "type": "purchase",
        "item": "item:laptop",
        "org": "org:tech_supplier",
        "invoice": "invoice:purchase_1"
      },
      "created_at": "2026-01-01T10:00:00Z",
      "updated_at": "2026-05-20T08:00:06Z",
      "created_by": "user:ops_mgr",
      "updated_by": "user:ops_mgr",
      "system_ping": "2026-05-20T08:00:06Z"
    },
    {
      "id": "invoice_line:sale_laptop",
      "a_in_invoice": "invoice:sales_1",
      "a_in_item": "item:laptop",
      "a_in_qty": 2,
      "a_in_price": 2000,
      "owned_by": "groups:sales",
      "owners": ["groups:sales", "org:acme_customer"],
      "b_ctx_inv_type": "sales",
      "b_ctx_inv_fx": 1.0,
      "b_ctx_inv_org": "org:acme_customer",
      "b_ctx_item_cogs": 1000,
      "b_ctx_item_service": false,
      "c_vw_sl_from": "v_sl_invl_from:['invoice_line:sale_laptop']",
      "c_vw_sl_to": "v_sl_invl_to:['invoice_line:sale_laptop']",
      "c_vw_al": "v_al_invl:['invoice_line:sale_laptop']",
      "c_vw_tl": "v_tl_invl:['invoice_line:sale_laptop']",
      "d_c1_raw_base_val": 4000,
      "d_c2_adjusted_base_val": 4000,
      "d_c3_raw_tax_val": 400,
      "d_c4_adjusted_tax_val": 400,
      "d_c5_raw_gross_val": 4400,
      "d_c6_adjusted_gross_val": 4400,
      "d_c7_actual_cogs": 1000,
      "d_c8_delivered_qty": 2,
      "e_guard_state": true,
      "f_out": {
        "invl_raw_gross_val": 4400,
        "invl_adjusted_gross_val": 4400,
        "invl_purchase_qty": 0,
        "invl_sales_qty": 2,
        "invl_purchase_adjusted_val": 0,
        "actual_unit_cogs": 1000,
        "inv_fx_rate": 1.0,
        "type": "sales",
        "item": "item:laptop",
        "org": "org:acme_customer",
        "invoice": "invoice:sales_1"
      },
      "created_at": "2026-01-05T10:00:00Z",
      "updated_at": "2026-01-05T10:00:03Z",
      "created_by": "user:sales1",
      "updated_by": "user:sales1",
      "system_ping": "2026-01-05T10:00:03Z"
    },
    {
      "id": "invoice_line:sale_service",
      "a_in_invoice": "invoice:sales_1",
      "a_in_item": "item:setup_service",
      "a_in_qty": 1,
      "a_in_price": 500,
      "owned_by": "groups:sales",
      "owners": ["groups:sales", "org:acme_customer"],
      "b_ctx_inv_type": "sales",
      "b_ctx_inv_fx": 1.0,
      "b_ctx_inv_org": "org:acme_customer",
      "b_ctx_item_cogs": 0,
      "b_ctx_item_service": true,
      "c_vw_sl_from": "v_sl_invl_from:['invoice_line:sale_service']",
      "c_vw_sl_to": "v_sl_invl_to:['invoice_line:sale_service']",
      "c_vw_al": "v_al_invl:['invoice_line:sale_service']",
      "c_vw_tl": "v_tl_invl:['invoice_line:sale_service']",
      "d_c1_raw_base_val": 500,
      "d_c2_adjusted_base_val": 500,
      "d_c3_raw_tax_val": 0,
      "d_c4_adjusted_tax_val": 0,
      "d_c5_raw_gross_val": 500,
      "d_c6_adjusted_gross_val": 500,
      "d_c7_actual_cogs": 0,
      "d_c8_delivered_qty": 0,
      "e_guard_state": true,
      "f_out": {
        "invl_raw_gross_val": 500,
        "invl_adjusted_gross_val": 500,
        "invl_purchase_qty": 0,
        "invl_sales_qty": 1,
        "invl_purchase_adjusted_val": 0,
        "actual_unit_cogs": 0,
        "inv_fx_rate": 1.0,
        "type": "sales",
        "item": "item:setup_service",
        "org": "org:acme_customer",
        "invoice": "invoice:sales_1"
      },
      "created_at": "2026-01-05T10:00:01Z",
      "updated_at": "2026-01-05T10:00:04Z",
      "created_by": "user:sales1",
      "updated_by": "user:sales1",
      "system_ping": "2026-01-05T10:00:04Z"
    },
    {
      "id": "invoice_line:il3",
      "a_in_invoice": "invoice:sales_2",
      "a_in_item": "item:laptop",
      "a_in_qty": 2,
      "a_in_price": 200,
      "owned_by": "groups:sales",
      "owners": ["groups:sales", "org:globex"],
      "b_ctx_inv_type": "sales",
      "b_ctx_inv_fx": 1.0,
      "b_ctx_inv_org": "org:globex",
      "b_ctx_item_cogs": 1000,
      "b_ctx_item_service": false,
      "c_vw_sl_from": "v_sl_invl_from:['invoice_line:il3']",
      "c_vw_sl_to": "v_sl_invl_to:['invoice_line:il3']",
      "c_vw_al": "v_al_invl:['invoice_line:il3']",
      "c_vw_tl": "v_tl_invl:['invoice_line:il3']",
      "d_c1_raw_base_val": 400,
      "d_c2_adjusted_base_val": 400,
      "d_c3_raw_tax_val": 0,
      "d_c4_adjusted_tax_val": 0,
      "d_c5_raw_gross_val": 400,
      "d_c6_adjusted_gross_val": 400,
      "d_c7_actual_cogs": 1000,
      "d_c8_delivered_qty": 2,
      "e_guard_state": true,
      "f_out": {
        "invl_raw_gross_val": 400,
        "invl_adjusted_gross_val": 400,
        "invl_purchase_qty": 0,
        "invl_sales_qty": 2,
        "invl_purchase_adjusted_val": 0,
        "actual_unit_cogs": 1000,
        "inv_fx_rate": 1.0,
        "type": "sales",
        "item": "item:laptop",
        "org": "org:globex",
        "invoice": "invoice:sales_2"
      },
      "created_at": "2026-05-15T09:00:00Z",
      "updated_at": "2026-05-15T12:00:02Z",
      "created_by": "user:sales2",
      "updated_by": "user:sales2",
      "system_ping": "2026-05-15T12:00:02Z"
    }
  ],

  "payment": [
    {
      "id": "payment:pay_1",
      "a_in_from": "org:acme_customer",
      "a_in_to": "treasury:main",
      "a_in_amount": 4900,
      "a_in_fx_rate": 1.0,
      "owned_by": "groups:sales",
      "owners": ["groups:sales", "org:acme_customer", "treasury:main"],
      "b_ctx_from_curr": "EUR",
      "b_ctx_to_curr": "USD",
      "b_ctx_sys_curr": "USD",
      "c_vw_pa": "v_pa_pay:['payment:pay_1']",
      "d_c1_currency": "EUR",
      "d_c2_active_amount": 4900,
      "d_c3_allocation_shield": 0,
      "e_guard_state": true,
      "f_out": {
        "pay_inbound_val": 4900,
        "pay_outbound_val": 4900,
        "fx_rate": 1.0,
        "from_node": "org:acme_customer",
        "to_node": "treasury:main"
      },
      "created_at": "2026-01-06T10:00:00Z",
      "updated_at": "2026-01-06T10:00:05Z",
      "created_by": "user:sales1",
      "updated_by": "user:sales1",
      "system_ping": "2026-01-06T10:00:05Z"
    }
  ],

  "payment_allocation": [
    {
      "id": "payment_allocation:pa1",
      "a_in_payment": "payment:pay_1",
      "a_in_invoice": "invoice:sales_1",
      "a_in_amount": 4900,
      "owned_by": "groups:sales",
      "owners": ["groups:sales", "org:acme_customer", "treasury:main", "invoice:sales_1"],
      "b_ctx_pay_fx": 1.0,
      "b_ctx_pay_from": "org:acme_customer",
      "b_ctx_pay_to": "treasury:main",
      "b_ctx_inv_org": "org:acme_customer",
      "e_guard_dag": true,
      "f_out": {
        "pa_alloc_pay_amount": 4900,
        "pa_alloc_inv_amount": 4900
      },
      "created_at": "2026-01-06T10:00:01Z",
      "updated_at": "2026-01-06T10:00:06Z",
      "created_by": "user:sales1",
      "updated_by": "user:sales1",
      "system_ping": "2026-01-06T10:00:06Z"
    }
  ],

  "package_note": [
    {
      "id": "package_note:pkg1",
      "a_in_invoice": "invoice:sales_1",
      "owned_by": "groups:sales",
      "owners": ["groups:sales", "org:acme_customer"],
      "c_vw_sl": "v_sl_pkg:['package_note:pkg1']",
      "f_out": {
        "pkg_delivered_qty": 2,
        "invoice": "invoice:sales_1"
      },
      "created_at": "2026-01-05T12:00:00Z",
      "updated_at": "2026-01-05T12:00:02Z",
      "created_by": "user:sales1",
      "updated_by": "user:sales1",
      "system_ping": "2026-01-05T12:00:02Z"
    }
  ],

  "sl": [
    {
      "id": "sl:inbound_purchase",
      "a_in_from": "invoice_line:pur_laptop",
      "a_in_to": "warehouse:main",
      "a_in_pkg": null,
      "a_in_qty": 10,
      "a_in_item": "item:laptop",
      "owned_by": "groups:ops",
      "owners": ["groups:ops", "org:tech_supplier", "invoice_line:pur_laptop", "warehouse:main"],
      "b_ctx_from_item": "item:laptop",
      "b_ctx_to_item": null,
      "b_ctx_pkg_inv": null,
      "b_ctx_from_inv": "invoice:purchase_1",
      "b_ctx_to_inv": null,
      "b_ctx_from_org": "org:tech_supplier",
      "b_ctx_to_org": null,
      "b_ctx_from_cogs": 1000,
      "b_ctx_to_cogs": null,
      "b_ctx_from_fx": 1.0,
      "b_ctx_to_fx": null,
      "c_vw_adj": "v_asl_sl:['sl:inbound_purchase']",
      "d_c1_item": "item:laptop",
      "d_c2_unit_cogs": 1000,
      "d_c3_net_qty": 10,
      "d_c4_wh_impact_qty": 10,
      "d_c5_fx": 1.0,
      "d_c6_from_type": "invoice_line",
      "d_c7_to_type": "warehouse",
      "e_guard_dag": true,
      "e_guard_has_item": true,
      "e_guard_wh_presence": true,
      "e_guard_invl_limit": true,
      "e_guard_item_match": true,
      "e_guard_stock_outbound": true,
      "e_guard_stock_inbound": true,
      "f_out": {
        "sl_inbound_qty": 10,
        "sl_outbound_qty": 0,
        "sl_delivered_qty": 10,
        "item": "item:laptop",
        "invl_org": "org:tech_supplier"
      },
      "created_at": "2026-01-01T10:00:01Z",
      "updated_at": "2026-05-20T08:00:07Z",
      "created_by": "user:ops_mgr",
      "updated_by": "user:ops_mgr",
      "system_ping": "2026-05-20T08:00:07Z"
    },
    {
      "id": "sl:outbound_sales",
      "a_in_from": "warehouse:main",
      "a_in_to": "invoice_line:sale_laptop",
      "a_in_pkg": "package_note:pkg1",
      "a_in_qty": 2,
      "a_in_item": "item:laptop",
      "owned_by": "groups:sales",
      "owners": ["groups:sales", "org:acme_customer", "warehouse:main", "invoice_line:sale_laptop", "package_note:pkg1"],
      "b_ctx_from_item": null,
      "b_ctx_to_item": "item:laptop",
      "b_ctx_pkg_inv": "invoice:sales_1",
      "b_ctx_from_inv": null,
      "b_ctx_to_inv": "invoice:sales_1",
      "b_ctx_from_org": null,
      "b_ctx_to_org": "org:acme_customer",
      "b_ctx_from_cogs": null,
      "b_ctx_to_cogs": 1000,
      "b_ctx_from_fx": null,
      "b_ctx_to_fx": 1.0,
      "c_vw_adj": "v_asl_sl:['sl:outbound_sales']",
      "d_c1_item": "item:laptop",
      "d_c2_unit_cogs": 1000,
      "d_c3_net_qty": 2,
      "d_c4_wh_impact_qty": 2,
      "d_c5_fx": 1.0,
      "d_c6_from_type": "warehouse",
      "d_c7_to_type": "invoice_line",
      "e_guard_dag": true,
      "e_guard_has_item": true,
      "e_guard_wh_presence": true,
      "e_guard_invl_limit": true,
      "e_guard_item_match": true,
      "e_guard_stock_outbound": true,
      "e_guard_stock_inbound": true,
      "f_out": {
        "sl_inbound_qty": 0,
        "sl_outbound_qty": 2,
        "sl_delivered_qty": 2,
        "item": "item:laptop",
        "invl_org": "org:acme_customer"
      },
      "created_at": "2026-01-05T12:00:01Z",
      "updated_at": "2026-01-05T12:00:03Z",
      "created_by": "user:sales1",
      "updated_by": "user:sales1",
      "system_ping": "2026-01-05T12:00:03Z"
    },
    {
      "id": "sl:outbound_sales_2",
      "a_in_from": "warehouse:main",
      "a_in_to": "invoice_line:il3",
      "a_in_pkg": null,
      "a_in_qty": 2,
      "a_in_item": "item:laptop",
      "owned_by": "groups:sales",
      "owners": ["groups:sales", "org:globex", "warehouse:main", "invoice_line:il3"],
      "b_ctx_from_item": null,
      "b_ctx_to_item": "item:laptop",
      "b_ctx_pkg_inv": null,
      "b_ctx_from_inv": null,
      "b_ctx_to_inv": "invoice:sales_2",
      "b_ctx_from_org": null,
      "b_ctx_to_org": "org:globex",
      "b_ctx_from_cogs": null,
      "b_ctx_to_cogs": 1000,
      "b_ctx_from_fx": null,
      "b_ctx_to_fx": 1.0,
      "c_vw_adj": "v_asl_sl:['sl:outbound_sales_2']",
      "d_c1_item": "item:laptop",
      "d_c2_unit_cogs": 1000,
      "d_c3_net_qty": 2,
      "d_c4_wh_impact_qty": 2,
      "d_c5_fx": 1.0,
      "d_c6_from_type": "warehouse",
      "d_c7_to_type": "invoice_line",
      "e_guard_dag": true,
      "e_guard_has_item": true,
      "e_guard_wh_presence": true,
      "e_guard_invl_limit": true,
      "e_guard_item_match": true,
      "e_guard_stock_outbound": true,
      "e_guard_stock_inbound": true,
      "f_out": {
        "sl_inbound_qty": 0,
        "sl_outbound_qty": 2,
        "sl_delivered_qty": 2,
        "item": "item:laptop",
        "invl_org": "org:globex"
      },
      "created_at": "2026-05-15T12:00:00Z",
      "updated_at": "2026-05-15T12:00:03Z",
      "created_by": "user:sales2",
      "updated_by": "user:sales2",
      "system_ping": "2026-05-15T12:00:03Z"
    }
  ],

  "tax_line": [
    {
      "id": "tax_line:tl1",
      "a_in_invoice_line": "invoice_line:sale_laptop",
      "a_in_tax_account": "tax:sales_tax",
      "a_in_rate": 10,
      "owned_by": "groups:sales",
      "owners": ["groups:sales", "org:acme_customer", "invoice_line:sale_laptop", "tax:sales_tax"],
      "b_ctx_invl_type": "sales",
      "b_ctx_invl_fx": 1.0,
      "b_ctx_invl_raw_base_val": 4000,
      "b_ctx_invl_adjusted_base_val": 4000,
      "b_ctx_invl_org": "org:acme_customer",
      "c_vw_adj": "v_atl_tl:['tax_line:tl1']",
      "d_c1_raw_tax_curr": 400,
      "d_c2_adjusted_tax_curr": 400,
      "d_c3_adjusted_tax_acc": 400,
      "f_out": {
        "tl_raw_tax": 400,
        "tl_adjusted_tax": 400,
        "tl_sales_adjusted_tax": 400,
        "tl_purchase_adjusted_tax": 0,
        "invl_org": "org:acme_customer"
      },
      "created_at": "2026-01-05T10:00:02Z",
      "updated_at": "2026-01-05T10:00:05Z",
      "created_by": "user:sales1",
      "updated_by": "user:sales1",
      "system_ping": "2026-01-05T10:00:05Z"
    }
  ],

  "adjustment_line": [
    {
      "id": "adjustment_line:adjl01_1",
      "a_in_note": "adjustment_note:adjn01",
      "a_in_invl": "invoice_line:pur_laptop",
      "a_in_delta_price": -2000,
      "owned_by": "groups:ops",
      "owners": ["groups:ops", "org:tech_supplier", "invoice_line:pur_laptop", "adjustment_note:adjn01"],
      "b_ctx_note_org": "org:tech_supplier",
      "b_ctx_invl_org": "org:tech_supplier",
      "e_guard_dag": true,
      "f_out": {
        "al_delta_price": -2000
      },
      "created_at": "2026-05-20T08:00:01Z",
      "updated_at": "2026-05-20T08:00:08Z",
      "created_by": "user:ops_mgr",
      "updated_by": "user:ops_mgr",
      "system_ping": "2026-05-20T08:00:08Z"
    }
  ],

  "adjustment_tax_line": [],
  "adjustment_stock_line": [],

  "v_pay_node_to": [
    {"node": "treasury:main", "pay_inbound_val": 4900},
    {"node": "acc:income_a", "pay_inbound_val": 0}
  ],
  "v_pay_node_from": [
    {"node": "org:acme_customer", "pay_outbound_val": 4900}
  ],
  "v_inv_org": [
    {"org": "org:tech_supplier", "inv_purchase_adjusted_total": 8000, "inv_sales_adjusted_total": 0},
    {"org": "org:acme_customer", "inv_purchase_adjusted_total": 0, "inv_sales_adjusted_total": 4900},
    {"org": "org:globex", "inv_purchase_adjusted_total": 0, "inv_sales_adjusted_total": 400}
  ],
  "v_pa_pay": [{"payment": "payment:pay_1", "pa_alloc_pay_amount": 4900}],
  "v_pa_inv": [{"invoice": "invoice:sales_1", "pa_alloc_inv_amount": 4900}],
  "v_invl_inv": [
    {"invoice": "invoice:purchase_1", "invl_raw_gross_val": 10000, "invl_adjusted_gross_val": 8000},
    {"invoice": "invoice:sales_1", "invl_raw_gross_val": 4500, "invl_adjusted_gross_val": 4900},
    {"invoice": "invoice:sales_2", "invl_raw_gross_val": 400, "invl_adjusted_gross_val": 400}
  ],
  "v_invl_item": [
    {"item": "item:laptop", "invl_purchase_qty": 10, "invl_purchase_adjusted_val": 8000, "invl_sales_qty": 4},
    {"item": "item:setup_service", "invl_purchase_qty": 0, "invl_purchase_adjusted_val": 0, "invl_sales_qty": 1}
  ],
  "v_sl_pkg": [{"pkg": "package_note:pkg1", "sl_delivered_qty": 2}],
  "v_sl_invl_from": [
    {"inv_line": "invoice_line:pur_laptop", "qty": 10}
  ],
  "v_sl_invl_to": [
    {"inv_line": "invoice_line:sale_laptop", "qty": 2},
    {"inv_line": "invoice_line:il3", "qty": 2}
  ],
  "v_sl_node_in": [
    {"node": "warehouse:main", "sl_inbound_qty": 10}
  ],
  "v_sl_node_out": [
    {"node": "warehouse:main", "sl_outbound_qty": 4}
  ],
  "v_tl_invl": [
    {"invoice_line": "invoice_line:sale_laptop", "tl_raw_tax": 400, "tl_adjusted_tax": 400}
  ],
  "v_tl_acc": [
    {"tax_account": "tax:sales_tax", "tl_sales_adjusted_tax": 400, "tl_purchase_adjusted_tax": 0}
  ],
  "v_al_invl": [
    {"invoice_line": "invoice_line:pur_laptop", "al_delta_price": -2000}
  ],
  "v_atl_tl": [],
  "v_asl_sl": [],

  "company": [
    {
      "id": "company:settings",
      "default_currency": "USD",
      "updated_at": "2025-12-01T00:00:00Z"
    }
  ]
}