const fs = require("fs");
const readline = require("readline");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const askQuestion = (query) =>
  new Promise((resolve) => rl.question(query, resolve));

async function runCompiler() {
  console.log("\n🚀 INITIALIZING REBASE META-COMPILER (V23.0 - INTERACTIVE)");
  console.log("============================================================\n");

  const file06 = fs.existsSync("06_table_fields.surql")
    ? fs.readFileSync("06_table_fields.surql", "utf8")
    : "";
  const file07 = fs.existsSync("07_views.surql")
    ? fs.readFileSync("07_views.surql", "utf8")
    : "";

  if (!file06 || !file07) {
    console.error(
      "❌ ERROR: Missing 06_table_fields.surql or 07_views.surql in directory.",
    );
    process.exit(1);
  }

  // ==============================================================================
  // 🔍 PHASE 1: RAW MATERIAL EXTRACTION (PARSING)
  // ==============================================================================

  // 1. EXTRACT TABLES
  const tablesList = [
    ...new Set(
      [...file06.matchAll(/DEFINE TABLE ([a-zA-Z0-9_]+)/g)].map((m) => m[1]),
    ),
  ].sort();

  // 2. EXTRACT RECORD LINKS (FOREIGN KEYS)
  const fieldTypeMap = {};
  const typeRegex =
    /DEFINE FIELD ([a-zA-Z0-9_]+) ON ([a-zA-Z0-9_]+) TYPE (?:option<)?record<([a-zA-Z0-9_| ]+)>/g;
  let match;
  while ((match = typeRegex.exec(file06)) !== null) {
    const fieldName = match[1];
    const tableName = match[2];
    const allowedTypesRaw = match[3];
    if (!fieldTypeMap[tableName]) fieldTypeMap[tableName] = {};
    fieldTypeMap[tableName][fieldName] = allowedTypesRaw
      .split("|")
      .map((t) => t.trim());
  }

  // 3. EXTRACT VIEWS
  const viewsList = [];
  const viewRegex =
    /DEFINE TABLE (?:OVERWRITE )?(v_[a-zA-Z0-9_]+) AS SELECT\s+(.+?)\s+FROM\s+([a-zA-Z0-9_]+).*?GROUP BY\s+([a-zA-Z0-9_,\s.]+);/gs;
  let matchView;
  while ((matchView = viewRegex.exec(file07)) !== null) {
    const fullMatch = matchView[0];
    const viewName = matchView[1];
    const selectBody = matchView[2];
    const sourceTable = matchView[3];
    const groupKeys = matchView[4]
      .split(",")
      .map((k) => k.trim())
      .filter((k) => k);

    const aliases = {};
    const aliasRegex = /([a-zA-Z0-9_.]+)\s+AS\s+([a-zA-Z0-9_]+)/gi;
    let aliasMatch;
    while ((aliasMatch = aliasRegex.exec(selectBody)) !== null) {
      aliases[aliasMatch[2]] = aliasMatch[1];
    }

    viewsList.push({
      name: viewName,
      sourceTable: sourceTable,
      groupKeys: groupKeys,
      aliases: aliases,
      rawQuery: fullMatch,
    });
  }

  // 4. EXTRACT DOWNWARD CASCADE DEPENDENCIES (DEEP GRAPH PATHS)
  const downwardCascades = {};

  function getPaths(table, parts, index) {
    if (index === parts.length - 1) return [[{ table }]];
    const prop = parts[index];
    const validPaths = [];
    if (fieldTypeMap[table] && fieldTypeMap[table][prop]) {
      for (const parent of fieldTypeMap[table][prop]) {
        const parentPaths = getPaths(parent, parts, index + 1);
        for (const p of parentPaths) {
          validPaths.push([{ table, field: prop }, ...p]);
        }
      }
    }
    return validPaths;
  }

  const blockRegex = /DEFINE TABLE ([a-zA-Z0-9_]+).*?(?=DEFINE TABLE|$)/gs;
  let blockMatch;
  while ((blockMatch = blockRegex.exec(file06)) !== null) {
    const childTable = blockMatch[1];
    const blockContent = blockMatch[0];
    const pathRegex = /\$this\.([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)/g;
    let pathMatch;

    while ((pathMatch = pathRegex.exec(blockContent)) !== null) {
      const parts = pathMatch[1].split(".");
      const paths = getPaths(childTable, parts, 0);

      paths.forEach((path) => {
        const rootTable = path[path.length - 1].table;
        const triggerField = parts[parts.length - 1];

        let reversePathStr = "$after";
        for (let j = path.length - 2; j >= 0; j--) {
          reversePathStr += `<~${path[j].table}`;
        }

        if (!downwardCascades[rootTable]) downwardCascades[rootTable] = {};
        if (!downwardCascades[rootTable][triggerField])
          downwardCascades[rootTable][triggerField] = new Set();

        downwardCascades[rootTable][triggerField].add(
          `LET $tgt = array::flatten([${reversePathStr}]).filter(|$v| $v != NONE);\n            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };`,
        );
      });
    }
  }

  // ==============================================================================
  // 👁️ PHASE 2: DISPLAY DISCOVERED DATA (INTERACTIVE)
  // ==============================================================================

  console.log("📦 DISCOVERED TABLES (" + tablesList.length + "):");
  console.log("   " + tablesList.join(", "));

  console.log("\n🔗 DISCOVERED RECORD LINKS (FOREIGN KEYS):");
  Object.entries(fieldTypeMap).forEach(([table, fields]) => {
    const links = Object.entries(fields).map(
      ([field, types]) => `${field} -> [${types.join("|")}]`,
    );
    console.log(`   ${table}: ${links.join(", ")}`);
  });

  console.log("\n📊 DISCOVERED BI VIEWS (" + viewsList.length + "):");
  viewsList.forEach((v) => {
    console.log(
      `   View: ${v.name} | Source: ${v.sourceTable} | Groups: [${v.groupKeys.join(", ")}]`,
    );
  });

  console.log("\n⚡ DISCOVERED DOWNWARD CASCADES (GRAPH DEPENDENCIES):");
  Object.entries(downwardCascades).forEach(([rootTable, triggers]) => {
    console.log(`   Trigger Table: ${rootTable}`);
    Object.entries(triggers).forEach(([field, queries]) => {
      console.log(
        `      └─ On Field Change: [${field}] -> Pings ${queries.size} reverse graph(s)`,
      );
    });
  });

  console.log("\n============================================================");

  const answer = await askQuestion(
    "Press ENTER to generate all SurrealQL files, or type 'cancel' to abort: ",
  );
  if (answer.toLowerCase() === "cancel") {
    console.log("❌ Compilation aborted by user.");
    process.exit(0);
  }

  console.log("\n⚙️ GENERATING FILES...");

  // ==============================================================================
  // 🏭 PHASE 3: ALGORITHMS & FILE GENERATION
  // ==============================================================================

  let file02 = `USE NS main DB main;\n\n`;
  let file03 = `USE NS main DB main;\n\n`;
  let file04 = `USE NS main DB main;\n\n`;
  let file05 = `USE NS main DB main;\n\n`;
  let file11 = `USE NS main DB main;\n\n`;
  let file08 = `USE NS main DB main;\n\n`;
  let file12 = `USE NS main DB main;\n\n`;
  let file09 = `USE NS main DB main;\n\n`;
  let viewsCompiledContent = file07;

  // --- ALGORITHM A: Base Security & Auditing ---
  tablesList.forEach((tb) => {
    file02 += `DEFINE TABLE OVERWRITE ${tb} SCHEMAFULL PERMISSIONS\n    FOR select WHERE '${tb}_select' IN $auth.permissions AND (owners CONTAINSANY $auth.parents OR owners CONTAINSANY $auth.dominates)\n    FOR create WHERE '${tb}_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)\n    FOR update WHERE '${tb}_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)\n    FOR delete WHERE '${tb}_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);\n\n`;
    file04 += `DEFINE FIELD OVERWRITE created_at ON TABLE ${tb} TYPE datetime VALUE $before OR time::now() READONLY;\nDEFINE FIELD OVERWRITE updated_at ON TABLE ${tb} TYPE datetime VALUE time::now();\nDEFINE FIELD OVERWRITE created_by ON TABLE ${tb} TYPE option<record<user>> VALUE $before OR $auth READONLY;\nDEFINE FIELD OVERWRITE updated_by ON TABLE ${tb} TYPE option<record<user>> VALUE $auth;\n\n`;
    file05 += `DEFINE FIELD OVERWRITE system_ping ON TABLE ${tb} TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;\n\n`;

    const parentsConfig = fieldTypeMap[tb];
    if (!parentsConfig || tb === "adjustment_note") {
      file03 += `DEFINE FIELD OVERWRITE owned_by ON TABLE ${tb} TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;\n`;
      file03 += `DEFINE FIELD OVERWRITE owners ON TABLE ${tb} TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));\n\n`;
    } else {
      file03 += `DEFINE FIELD OVERWRITE owned_by ON TABLE ${tb} TYPE option<record<groups>> VALUE `;
      if (tb === "sl") {
        file03 += `$this.a_from.owned_by ?? $this.a_to.owned_by ?? $this.a_pkg.owned_by;\n`;
      } else if (tb === "adjustment_line") {
        file03 += `$this.a_note.owned_by;\n`;
      } else {
        file03 += `$this.${Object.keys(parentsConfig)[0]}.owned_by;\n`;
      }
      const parentPaths = Object.keys(parentsConfig).map(
        (pField) => `$this.${pField}.owners`,
      );
      file03 += `DEFINE FIELD OVERWRITE owners ON TABLE ${tb} TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, ${parentPaths.join(", ")}]))).filter(|$v| $v != NONE);\n\n`;
    }
  });

  // --- ALGORITHM B: Base B-Tree Indexes ---
  Object.entries(fieldTypeMap).forEach(([tableName, fields]) => {
    Object.keys(fields).forEach((fieldName) => {
      file11 += `DEFINE INDEX idx_${tableName}_${fieldName} ON ${tableName} COLUMNS ${fieldName};\n`;
    });
  });

  // --- ALGORITHM C: Views, View Indexes, Pings, and Computeds ---
  viewsList.forEach((view) => {
    let viewOwnerChecks = [];

    view.groupKeys.forEach((groupKey) => {
      // Index the view
      file11 += `DEFINE INDEX idx_${view.name}_${groupKey} ON ${view.name} COLUMNS ${groupKey};\n`;

      const rawPath = view.aliases[groupKey] || groupKey;
      const parts = rawPath.split(".");
      let currentTables = [view.sourceTable];
      let isRecord = true;

      for (let i = 0; i < parts.length; i++) {
        const prop = parts[i];
        let nextTables = new Set();
        currentTables.forEach((t) => {
          if (fieldTypeMap[t] && fieldTypeMap[t][prop]) {
            fieldTypeMap[t][prop].forEach((pt) => nextTables.add(pt));
          }
        });
        if (nextTables.size === 0) {
          isRecord = false;
          break;
        }
        currentTables = Array.from(nextTables);
      }

      if (isRecord && currentTables.length > 0) {
        // Determine RBAC for View
        let permCheck = `'${view.sourceTable}_select' IN $auth.permissions`;
        let dagCheck = `(${groupKey}.owners CONTAINSANY $auth.parents OR ${groupKey}.owners CONTAINSANY $auth.dominates)`;
        viewOwnerChecks.push(`(${permCheck} AND ${dagCheck})`);

        // Generate Upward Ping (Elevator Up)
        file08 += `DEFINE EVENT ping_${view.name}_${groupKey} ON TABLE ${view.name} WHEN $event != 'NONE' THEN {\n`;
        file08 += `    IF $__rebase_halt_cascade != true {\n`;
        file08 += `        LET $tgt = array::flatten([$after.${groupKey} ?? $before.${groupKey}]).filter(|$v| $v != NONE);\n`;
        file08 += `        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };\n`;
        file08 += `    };\n};\n\n`;

        // Generate Computed BI Field on parent tables
        currentTables.forEach((targetTable) => {
          file12 += `DEFINE FIELD c_${view.name} ON ${targetTable} COMPUTED (SELECT * FROM ${view.name} WHERE ${groupKey} = $parent.id);\n`;
        });
      }
    });

    // Inject Permissions back into the raw query text
    let permissionCondition =
      viewOwnerChecks.length > 0
        ? viewOwnerChecks.join(" OR ")
        : `'${view.sourceTable}_select' IN $auth.permissions`;
    const permissionString = `\n    PERMISSIONS FOR select WHERE ${permissionCondition}\n    FOR create, update, delete NONE;`;
    viewsCompiledContent = viewsCompiledContent.replace(
      view.rawQuery,
      view.rawQuery.replace(/;$/, "") + permissionString,
    );
  });

  // --- ALGORITHM D: Downward Cascades ---
  Object.entries(downwardCascades).forEach(([rootTable, fieldsMap]) => {
    file09 += `DEFINE EVENT aot_cascade_downward ON TABLE ${rootTable} WHEN $event = 'UPDATE' THEN {\n`;
    file09 += `    IF $__rebase_halt_cascade != true {\n`;
    Object.entries(fieldsMap).forEach(([field, queriesSet]) => {
      file09 += `        IF $before.${field} != $after.${field} {\n`;
      queriesSet.forEach((query) => {
        file09 += `            ${query}\n`;
      });
      file09 += `        };\n`;
    });
    file09 += `    };\n};\n\n`;
  });

  // --- ALGORITHM E: RBAC File Injection (01_auth_rbac.surql) ---
  const authFile = "01_auth_rbac.surql";
  if (fs.existsSync(authFile)) {
    let authContent = fs.readFileSync(authFile, "utf8");
    let roleArrayStr = `[\n    'node_create', 'node_select', 'node_update', 'node_delete',\n    'link_create', 'link_select', 'link_delete',\n`;

    tablesList.forEach((tb, index) => {
      roleArrayStr += `    '${tb}_select', '${tb}_create', '${tb}_update', '${tb}_delete'`;
      if (index < tablesList.length - 1) roleArrayStr += `,`;
      roleArrayStr += `\n`;
    });
    roleArrayStr += `]`;

    const roleRegex =
      /CREATE groups:root SET name = 'System Admins', role = \[[^\]]*\];/g;
    if (roleRegex.test(authContent)) {
      authContent = authContent.replace(
        roleRegex,
        `CREATE groups:root SET name = 'System Admins', role = ${roleArrayStr};`,
      );
      fs.writeFileSync(authFile, authContent);
      console.log("✅ 01_auth_rbac.surql synced.");
    }
  }

  // --- FINISH: Write all files to disk ---
  fs.writeFileSync("02_table_permissions.surql", file02);
  fs.writeFileSync("03_owners.surql", file03);
  fs.writeFileSync("04_audit_meta_fields.surql", file04);
  fs.writeFileSync("05_system_flags.surql", file05);
  fs.writeFileSync("07_views_compiled.surql", viewsCompiledContent);
  fs.writeFileSync("08_events_upward.surql", file08);
  fs.writeFileSync("09_events_downward.surql", file09);
  fs.writeFileSync("11_indexes.surql", file11);
  fs.writeFileSync("12_computed_views.surql", file12);

  console.log("🏆 Compilation completed successfully. All files generated.");
  process.exit(0);
}

runCompiler();
