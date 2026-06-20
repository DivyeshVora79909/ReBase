// ==============================================================================
// REBASE GRAPH ENGINE: DEFINITIVE CONSTITUTIONAL DATASET
// 7-Tier Lexicographical Standard | Maximum Entropy | Vector Physics
// ==============================================================================

const dataset = {
  // ---------- AUTH & RBAC ----------
  users: {
    "user:root": {
      id: "user:root",
      name: "Super Admin",
      email: "root@acme.com",
    },
    "user:alice": {
      id: "user:alice",
      name: "Alice Manager",
      email: "alice@acme.com",
    },
  },
  groups: {
    "groups:root": { id: "groups:root", name: "System Admins" },
    "groups:acme_admins": { id: "groups:acme_admins", name: "Acme Admins" },
  },
  link: [
    { in: "groups:root", out: "user:root" },
    { in: "groups:acme_admins", out: "user:alice" },
  ],

  // ---------- LEVEL 0: INDEPENDENT ANCHORS (Stateless / Parents) ----------
  org: {
    "org:tech_supplier": {
      name: "Tech Distro Inc.",
      currency: "USD",
      zb_child: {
        v_inv_org: {
          purchase_base_value: 10000,
          sales_base_value: 0,
          purchase_tax_value: 0,
          sales_tax_value: 0,
        },
        v_pay_to: { active_amount: 0 },
        v_pay_from: { active_amount: 0 },
      },
      zz: { net_financial_position: -10000 },
    },
    "org:acme_customer": {
      name: "Acme Corp",
      currency: "EUR",
      zb_child: {
        v_inv_org: {
          purchase_base_value: 0,
          sales_base_value: 4500,
          purchase_tax_value: 0,
          sales_tax_value: 400,
        },
        v_pay_to: { active_amount: 0 },
        v_pay_from: { active_amount: 4900 },
      },
      zz: { net_financial_position: 0 },
    },
    "org:globex": {
      id: "org:globex",
      name: "Globex Inc.",
      currency: "USD",
      zb_child: {
        v_inv_org: {
          purchase_base_value: 0,
          sales_base_value: 400,
          purchase_tax_value: 0,
          sales_tax_value: 0,
        },
        v_pay_to: { active_amount: 0 },
        v_pay_from: { active_amount: 0 },
      },
      zz: { net_financial_position: 400 }, // FIXED: Aggregates restored inv2
    },
  },

  treasury: {
    "treasury:main": {
      name: "Central Bank",
      currency: "USD",
      zb_child: {
        v_pay_to: { active_amount: 4900 },
        v_pay_from: { active_amount: 0 },
      },
      zz: { balance: 4900 },
    },
  },

  item: {
    "item:laptop": {
      name: "Pro Laptop",
      is_service: false,
      zb_child: {
        v_invl_item: {
          purchase_financial_qty: 10,
          purchase_base_value: 10000,
          sales_financial_qty: 4,
          sales_base_value: 4400, // FIXED: 2 (il1) + 2 (il3)
        },
        v_sl_matrix: { inbound_physical_qty: 10, outbound_physical_qty: 4 }, // FIXED: 2 (sl1) + 2 (sl2)
      },
      zz: { physical_stock: 6, avg_cogs: 1000 }, // FIXED: 10 - 4 = 6
    },
    "item:setup_service": {
      name: "Installation Service",
      is_service: true,
      zb_child: {
        v_invl_item: {
          purchase_financial_qty: 0,
          sales_financial_qty: 1,
          sales_base_value: 500,
        },
        v_sl_matrix: { inbound_physical_qty: 0, outbound_physical_qty: 0 },
      },
      zz: { physical_stock: 0, turnover: 1, avg_cogs: 0 },
    },
  },

  warehouse: {
    "warehouse:main": {
      name: "Central Fulfillment",
      zb_child: {
        v_sl_matrix: { inbound_physical_qty: 10, outbound_physical_qty: 4 },
      }, // FIXED: 10 - 4
      zz: { global_matrix_stock: 6 },
    },
  },

  acc: {
    "acc:cogs": {
      name: "Cost of Goods Sold",
      type: "expense",
      zb_child: { v_sl_cogs: { actual_cogs_value: 4000 } }, // FIXED: 2000 (sl1) + 2000 (sl2)
      zz: { balance: 4000 },
    },
  },

  tax_account: {
    "tax:sales_tax": {
      name: "Sales Tax Payable",
      zb_child: { v_tl: { sales_tax_value: 400, purchase_tax_value: 0 } },
      zz: { liability: 400 },
    },
  },

  // ---------- LEVEL 1: INTENTS ----------
  invoice: {
    "invoice:purchase_1": {
      org: "org:tech_supplier",
      raw_type: "purchase",
      is_suspended: false,
      is_locked: true,
      system_ping: "2026-01-01T10:00:00Z",

      A_guard: { state_check: true },
      za_parent: { currency: "USD" },
      zb_child: {
        v_invl_inv: {
          purchase_base_value: 10000,
          inbound_physical_qty: 10,
          outbound_physical_qty: 0,
        },
        v_tl_inv: { purchase_tax_value: 0, sales_tax_value: 0 },
        v_pa_inv: { allocated_amount: 0 },
      },
      zz: { grand_total: 10000 },
      zzz: { allocation_shield: 10000, vector_shield: true },
      zzzzz_out: {
        purchase_base_value: 10000,
        sales_base_value: 0,
        purchase_tax_value: 0,
        sales_tax_value: 0,
        is_locked: true,
      },
    },

    "invoice:sales_1": {
      org: "org:acme_customer",
      raw_type: "sales",
      is_suspended: false,
      is_locked: true,
      system_ping: "2026-01-05T10:00:00Z",

      A_guard: { state_check: true },
      za_parent: { currency: "EUR" },
      zb_child: {
        v_invl_inv: {
          sales_base_value: 4500,
          inbound_physical_qty: 0,
          outbound_physical_qty: 2,
        },
        v_tl_inv: { sales_tax_value: 400, purchase_tax_value: 0 },
        v_pa_inv: { allocated_amount: 4900 },
      },
      zz: { grand_total: 4900 },
      zzz: { allocation_shield: 0, vector_shield: true },
      zzzzz_out: {
        sales_base_value: 4500,
        purchase_base_value: 0,
        sales_tax_value: 400,
        purchase_tax_value: 0,
        is_locked: true,
      },
    },

    "invoice:inv2": {
      // FIXED: Restored ghost data
      org: "org:globex",
      raw_type: "sales",
      is_suspended: false,
      is_locked: false,
      system_ping: "2026-05-15T09:00:00Z",

      A_guard: { state_check: true },
      za_parent: { currency: "USD" },
      zb_child: {
        v_invl_inv: {
          sales_base_value: 400,
          inbound_physical_qty: 0,
          outbound_physical_qty: 2,
        },
        v_tl_inv: { sales_tax_value: 0, purchase_tax_value: 0 },
        v_pa_inv: { allocated_amount: 0 },
      },
      zz: { grand_total: 400 },
      zzz: { allocation_shield: 400, vector_shield: true },
      zzzzz_out: {
        sales_base_value: 400,
        purchase_base_value: 0,
        sales_tax_value: 0,
        purchase_tax_value: 0,
        is_locked: false,
      },
    },
  },

  payment: {
    "payment:pay_1": {
      from: "org:acme_customer",
      to: "treasury:main",
      raw_amount: 4900,
      fx_rate: 1.0,
      is_suspended: false,
      is_locked: true,
      system_ping: "2026-01-06T10:00:00Z",

      A_guard: { state_check: true },
      za_parent: { base_currency: "EUR" },
      zb_child: { v_pa_pay: { allocated_amount: 4900 } },
      zz: { active_amount: 4900 },
      zzz: { allocation_shield: 0 },
      zzzzz_out: { active_amount: 4900 },
    },
  },

  adjustment_note: {
    "an:note1": {
      org: "org:tech_supplier",
      A_guard: { state_check: true },
      za_parent: {},
      zb_child: {},
      zz: { total_delta_qty: -2, total_delta_cogs: 0 },
      zzzzz_out: { is_active: true },
    },
  },

  // ---------- LEVEL 2: BRANCHES ----------
  invoice_line: [
    {
      id: "invoice_line:pur_laptop",
      invoice: "invoice:purchase_1",
      item: "item:laptop",
      raw_qty: 12,
      raw_unit_price: 1000,
      system_ping: "2026-01-01T10:00:00Z",
      // FIXED: Purged is_suspended & is_locked

      A_guard: { state_check: true },
      za_parent: { inv_type: "purchase", inv_locked: true },
      zb_child: {
        v_sl_invl: { inbound_physical_qty: 10, outbound_physical_qty: 0 },
        v_al_invl: { delta_qty: -2, delta_price: 0 },
      },
      zz: {
        net_qty: 10,
        base_value: 10000,
        inventory_qty: 10,
        actual_unit_cogs: 1000,
      },
      zzz: { qty_shield: 0, vector_shield: true },
      zzzzz_out: {
        purchase_base_value: 10000,
        sales_base_value: 0,
        purchase_financial_qty: 10,
        sales_financial_qty: 0,
        inbound_physical_qty: 10,
        outbound_physical_qty: 0,
        unit_price: 1000,
        actual_unit_cogs: 1000,
        is_locked: true,
      },
    },
    {
      id: "invoice_line:sale_laptop",
      invoice: "invoice:sales_1",
      item: "item:laptop",
      raw_qty: 2,
      raw_unit_price: 2000,
      system_ping: "2026-01-05T10:00:00Z",

      A_guard: { state_check: true },
      za_parent: { inv_type: "sales", inv_locked: true, item_avg_cogs: 1000 },
      zb_child: {
        v_sl_invl: { inbound_physical_qty: 0, outbound_physical_qty: 2 },
        v_al_invl: { delta_qty: 0, delta_price: 0 },
      },
      zz: {
        net_qty: 2,
        base_value: 4000,
        inventory_qty: 2,
        actual_unit_cogs: 1000,
      },
      zzz: { qty_shield: 0, vector_shield: true },
      zzzzz_out: {
        sales_base_value: 4000,
        purchase_base_value: 0,
        sales_financial_qty: 2,
        purchase_financial_qty: 0,
        inbound_physical_qty: 0,
        outbound_physical_qty: 2,
        unit_price: 2000,
        actual_unit_cogs: 1000,
        is_locked: true,
      },
    },
    {
      id: "invoice_line:sale_service",
      invoice: "invoice:sales_1",
      item: "item:setup_service",
      raw_qty: 1,
      raw_unit_price: 500,
      system_ping: "2026-01-05T10:00:00Z",

      A_guard: { state_check: true },
      za_parent: { inv_type: "sales", inv_locked: true, item_avg_cogs: 0 },
      zb_child: {
        v_sl_invl: { inbound_physical_qty: 0, outbound_physical_qty: 0 },
        v_al_invl: { delta_qty: 0, delta_price: 0 },
      },
      zz: {
        net_qty: 1,
        base_value: 500,
        inventory_qty: 0,
        actual_unit_cogs: 0,
      },
      zzz: { qty_shield: 0, vector_shield: true },
      zzzzz_out: {
        sales_base_value: 500,
        purchase_base_value: 0,
        sales_financial_qty: 1,
        purchase_financial_qty: 0,
        inbound_physical_qty: 0,
        outbound_physical_qty: 0,
        unit_price: 500,
        actual_unit_cogs: 0,
        is_locked: true,
      },
    },
    {
      id: "invoice_line:il3", // FIXED: Restored ghost data
      invoice: "invoice:inv2",
      item: "item:laptop",
      raw_qty: 2,
      raw_unit_price: 200,
      system_ping: "2026-05-15T09:30:00Z",

      A_guard: { state_check: true },
      za_parent: { inv_type: "sales", inv_locked: false, item_avg_cogs: 1000 },
      zb_child: {
        v_sl_invl: { inbound_physical_qty: 0, outbound_physical_qty: 2 },
        v_al_invl: { delta_qty: 0, delta_price: 0 },
      },
      zz: {
        net_qty: 2,
        base_value: 400,
        inventory_qty: 2,
        actual_unit_cogs: 1000,
      },
      zzz: { qty_shield: 0, vector_shield: true },
      zzzzz_out: {
        sales_base_value: 400,
        purchase_base_value: 0,
        sales_financial_qty: 2,
        purchase_financial_qty: 0,
        inbound_physical_qty: 0,
        outbound_physical_qty: 2,
        unit_price: 200,
        actual_unit_cogs: 1000,
        is_locked: false,
      },
    },
  ],

  payment_allocation: [
    {
      id: "payment_allocation:pa1",
      payment: "payment:pay_1",
      invoice: "invoice:sales_1",
      raw_amount: 4900,
      system_ping: "2026-01-06T10:00:00Z",
      // FIXED: Purged state flags

      A_guard: { dag_check: true },
      za_parent: {
        pay_org: "org:acme_customer",
        inv_org: "org:acme_customer",
        pay_fx_rate: 1.0,
      },
      zb_child: {},
      zz: { amount_pay_curr: 4900, amount_inv_curr: 4900 },
      zzz: {},
      zzzzz_out: { allocated_amount: 4900 },
    },
  ],

  package_note: [
    {
      id: "package_note:pkg1",
      invoice: "invoice:sales_1",
      tracking: "TRACK-001",
      system_ping: "2026-01-05T12:00:00Z",
      // FIXED: Purged state flags

      A_guard: {},
      za_parent: { inv_locked: true },
      zb_child: { v_sl_pkg: { outbound_physical_qty: 2 } },
      zz: {},
      zzz: {},
      zzzzz_out: { outbound_physical_qty: 2, is_locked: true },
    },
  ],

  // ---------- LEVEL 3: LEAVES ----------
  sl: [
    {
      id: "sl:inbound_purchase",
      from: "invoice_line:pur_laptop",
      to: "warehouse:main",
      pkg: null,
      raw_qty: 10,
      is_suspended: false,
      is_locked: true,
      system_ping: "2026-01-01T10:00:00Z",

      A_guard: { state_check: true },
      za_parent: { item: "item:laptop", unit_cogs: 1000 },
      zb_child: { v_asl_sl: { delta_qty: 0 } },
      zz: { vector: 1, active_qty: 10, actual_cogs_value: 10000 },
      zzz: { matrix_shield: true },
      zzzzz_out: {
        inbound_physical_qty: 10,
        outbound_physical_qty: 0,
        actual_cogs_value: 10000,
      },
    },
    {
      id: "sl:outbound_sales",
      from: "warehouse:main",
      to: "invoice_line:sale_laptop",
      pkg: "package_note:pkg1",
      raw_qty: 2,
      is_suspended: false,
      is_locked: true,
      system_ping: "2026-01-05T12:00:00Z",

      A_guard: { state_check: true },
      za_parent: { item: "item:laptop", unit_cogs: 1000 },
      zb_child: { v_asl_sl: { delta_qty: 0 } },
      zz: { vector: -1, active_qty: 2, actual_cogs_value: 2000 },
      zzz: { matrix_shield: true },
      zzzzz_out: {
        inbound_physical_qty: 0,
        outbound_physical_qty: 2,
        actual_cogs_value: 2000,
      },
    },
    {
      id: "sl:outbound_sales_2", // FIXED: Restored ghost data
      from: "warehouse:main",
      to: "invoice_line:il3",
      pkg: null,
      raw_qty: 2,
      is_suspended: false,
      is_locked: false,
      system_ping: "2026-05-15T12:00:00Z",

      A_guard: { state_check: true },
      za_parent: { item: "item:laptop", unit_cogs: 1000 },
      zb_child: { v_asl_sl: { delta_qty: 0 } },
      zz: { vector: -1, active_qty: 2, actual_cogs_value: 2000 },
      zzz: { matrix_shield: true },
      zzzzz_out: {
        inbound_physical_qty: 0,
        outbound_physical_qty: 2,
        actual_cogs_value: 2000,
      },
    },
  ],

  tax_line: [
    {
      id: "tax_line:tl1",
      invoice_line: "invoice_line:sale_laptop",
      tax_account: "tax:sales_tax",
      raw_rate: 10,
      system_ping: "2026-01-05T10:00:00Z",
      // FIXED: Purged state flags

      A_guard: {},
      za_parent: { invl_base_value: 4000, inv_type: "sales" },
      zb_child: { v_atl_tl: { delta_amount: 0 } },
      zz: { tax_amount: 400 },
      zzz: { shield: true },
      zzzzz_out: { sales_tax_value: 400, purchase_tax_value: 0 },
    },
  ],

  // ---------- LEVEL 4: DELTAS ----------
  adjustment_line: [
    {
      id: "adjustment_line:al1",
      adjustment_note: "an:note1",
      invoice_line: "invoice_line:pur_laptop",
      delta_qty: -2,
      delta_cogs: 0,
      system_ping: "2026-05-20T08:00:00Z",
      // FIXED: Purged state flags

      A_guard: { dag_check: true },
      za_parent: {
        note_org: "org:tech_supplier",
        line_org: "org:tech_supplier",
      },
      zb_child: {},
      zz: {},
      zzzzz_out: { delta_qty: -2, delta_cogs: 0 },
    },
  ],
};
