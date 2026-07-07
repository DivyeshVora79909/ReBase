const fs = require("fs");
const readline = require("readline");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const askQuestion = (query) =>
  new Promise((resolve) => rl.question(query, resolve));

async function runCompiler() {
  console.log(
    "\n🚀 INITIALIZING REBASE META-COMPILER (V24.1 - TRUTHINESS OPTIMIZED)",
  );
  console.log(
    "========================================================================\n",
  );

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
  // 🧠 PHASE 1: RAW MATERIAL EXTRACTION (NORMALIZED MAPS)
  // ==============================================================================

  const RAW = {
    tables: new Set(),
    fields: {}, // table -> field -> { isRecord, targets, isReference }
    views: {}, // viewName -> { sourceTable, groupKeys, aliases }
    usages: {}, // tableName -> Set of viewNames used
    downward: {}, // rootTable -> reversePath -> Set of triggering fields
  };

  // 1. EXTRACT TABLES & BLOCKS
  const tableBlocks = {};
  const tableRegex =
    /DEFINE TABLE (?:OVERWRITE )?([a-zA-Z0-9_]+)(.*?)(?=(?:DEFINE TABLE|$))/gs;
  let tMatch;
  while ((tMatch = tableRegex.exec(file06)) !== null) {
    const tb = tMatch[1];
    RAW.tables.add(tb);
    tableBlocks[tb] = tMatch[0];
    RAW.fields[tb] = {};
    RAW.usages[tb] = new Set();
  }

  // 2. EXTRACT RECORD FIELDS, REFERENCES, & DOMAINS
  const fieldRegex =
    /DEFINE FIELD (?:OVERWRITE )?([a-zA-Z0-9_]+) ON (?:TABLE )?([a-zA-Z0-9_]+)(.*?);/gs;
  let fMatch;
  while ((fMatch = fieldRegex.exec(file06)) !== null) {
    const fieldName = fMatch[1];
    const tableName = fMatch[2];
    const fieldDef = fMatch[3];

    const isRecord = /TYPE (?:option<)?record<([a-zA-Z0-9_| ]+)>/g.exec(
      fieldDef,
    );
    const isReference = fieldDef.includes("REFERENCE");

    if (isRecord && RAW.fields[tableName]) {
      RAW.fields[tableName][fieldName] = {
        isRecord: true,
        targets: isRecord[1].split("|").map((t) => t.trim()),
        isReference: isReference,
      };
    }
  }

  // 3. EXTRACT VIEWS
  const viewRegex =
    /DEFINE TABLE (?:OVERWRITE )?(v_[a-zA-Z0-9_]+) AS SELECT\s+(.+?)\s+FROM\s+([a-zA-Z0-9_]+).*?GROUP BY\s+([a-zA-Z0-9_,\s.]+);/gs;
  let vMatch;
  while ((vMatch = viewRegex.exec(file07)) !== null) {
    const vName = vMatch[1];
    const aliases = {};
    const aliasRegex = /([a-zA-Z0-9_.]+)\s+AS\s+([a-zA-Z0-9_]+)/gi;
    let aMatch;
    while ((aMatch = aliasRegex.exec(vMatch[2])) !== null) {
      aliases[aMatch[2]] = aMatch[1];
    }

    RAW.views[vName] = {
      sourceTable: vMatch[3],
      groupKeys: vMatch[4]
        .split(",")
        .map((k) => k.trim())
        .filter((k) => k),
      aliases: aliases,
      rawQuery: vMatch[0],
    };
  }

  // 4. EXTRACT VIEW USAGES (VALIDATION VS BI-ONLY)
  Object.keys(tableBlocks).forEach((tb) => {
    Object.keys(RAW.views).forEach((vName) => {
      if (
        tableBlocks[tb].includes(`'${vName}'`) ||
        tableBlocks[tb].includes(`"${vName}"`)
      ) {
        RAW.usages[tb].add(vName);
      }
    });
  });

  // 5. EXTRACT DOWNWARD CASCADE DEPENDENCIES
  function getPaths(table, parts, index) {
    if (index === parts.length - 1) return [[{ table }]];
    const prop = parts[index];
    const validPaths = [];
    if (RAW.fields[table] && RAW.fields[table][prop]) {
      for (const parent of RAW.fields[table][prop].targets) {
        const parentPaths = getPaths(parent, parts, index + 1);
        for (const p of parentPaths) {
          validPaths.push([{ table, field: prop }, ...p]);
        }
      }
    }
    return validPaths;
  }

  Object.keys(tableBlocks).forEach((childTable) => {
    const blockContent = tableBlocks[childTable];
    const pathRegex = /\$this\.([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)/g;
    let pMatch;
    const allPaths = [];

    while ((pMatch = pathRegex.exec(blockContent)) !== null) {
      allPaths.push(pMatch[1]);
    }

    if (childTable === "sl") {
      allPaths.push("a_from.owned_by", "a_to.owned_by", "a_pkg.owned_by");
    } else if (childTable === "adjustment_line") {
      allPaths.push("a_note.owned_by");
    } else {
      const firstRecordField = Object.keys(RAW.fields[childTable] || {})[0];
      if (firstRecordField) allPaths.push(`${firstRecordField}.owned_by`);
    }

    [...new Set(allPaths)].forEach((fullPath) => {
      const parts = fullPath.split(".");
      const paths = getPaths(childTable, parts, 0);

      paths.forEach((path) => {
        const rootTable = path[path.length - 1].table;
        const triggerField = parts[parts.length - 1];

        let reversePathStr = "$after";
        for (let j = path.length - 2; j >= 0; j--) {
          reversePathStr += `<~${path[j].table}`;
        }

        if (!RAW.downward[rootTable]) RAW.downward[rootTable] = {};
        if (!RAW.downward[rootTable][reversePathStr])
          RAW.downward[rootTable][reversePathStr] = new Set();

        RAW.downward[rootTable][reversePathStr].add(triggerField);
      });
    });
  });

  // ==============================================================================
  // 👁️ PHASE 2: DISPLAY DIAGNOSTICS & WARNINGS
  // ==============================================================================

  console.log("📦 NORMALIZED TABLES & DOMAINS:");
  Object.entries(RAW.fields).forEach(([table, fields]) => {
    const links = Object.entries(fields).map(([field, data]) => {
      const refStatus = data.isReference ? "(REF)" : "(SOFT)";
      return `${field} -> [${data.targets.join("|")}] ${refStatus}`;
    });
    if (links.length > 0) console.log(`   ${table}: ${links.join(", ")}`);
  });

  console.log("\n⚡ OPTIMIZED DOWNWARD CASCADES:");
  Object.entries(RAW.downward).forEach(([rootTable, paths]) => {
    console.log(`   [${rootTable}] triggers downward updates on:`);
    Object.entries(paths).forEach(([revPath, fields]) => {
      console.log(
        `      └─ Fields: {${Array.from(fields).join(", ")}} -> Updates: ${revPath}`,
      );
    });
  });

  console.log("\n📊 VIEW USAGE ANALYZER (UPWARD PINGS):");
  let warnings = 0;
  Object.keys(RAW.views).forEach((vName) => {
    let isUsedForValidation = false;
    Object.entries(RAW.usages).forEach(([tb, usedViews]) => {
      if (usedViews.has(vName)) {
        isUsedForValidation = true;
        const groups = RAW.views[vName].groupKeys;
        const targets = groups.map((k) => RAW.views[vName].aliases[k] || k);
        let isValid = false;
        targets.forEach((t) => {
          const parts = t.split(".");
          if (
            RAW.fields[RAW.views[vName].sourceTable] &&
            RAW.fields[RAW.views[vName].sourceTable][parts[0]]
          ) {
            if (
              RAW.fields[RAW.views[vName].sourceTable][
                parts[0]
              ].targets.includes(tb)
            )
              isValid = true;
          }
        });

        if (!isValid && tb !== RAW.views[vName].sourceTable) {
          console.log(
            `   ⚠️  WARNING: Table '${tb}' uses view '${vName}', but the view doesn't explicitly GROUP BY '${tb}'.`,
          );
          warnings++;
        }
      }
    });

    if (isUsedForValidation) {
      console.log(
        `   ✅ ${vName} is actively used for Validation (Upward Ping ENABLED).`,
      );
    } else {
      console.log(
        `   ☁️  ${vName} is used for BI only (Upward Ping DISABLED).`,
      );
    }
  });

  console.log("\n============================================================");
  if (warnings > 0)
    console.log(
      `⚠️  Found ${warnings} warnings. Compilation will proceed, but check your logic.`,
    );
  const answer = await askQuestion(
    "Press ENTER to generate optimized SurrealQL files, or 'cancel' to abort: ",
  );
  if (answer.toLowerCase() === "cancel") {
    console.log("❌ Compilation aborted.");
    process.exit(0);
  }

  console.log("\n⚙️ GENERATING FILES...");

  // ==============================================================================
  // 🏭 PHASE 3: FILE GENERATION
  // ==============================================================================

  let file02 = `USE NS main DB main;\n\n`;
  let file03 = `USE NS main DB main;\n\n`;
  let file04 = `USE NS main DB main;\n\n`;
  let file05 = `USE NS main DB main;\n\n`;
  let file08 = `USE NS main DB main;\n\n`;
  let file09 = `USE NS main DB main;\n\n`;
  let file11 = `USE NS main DB main;\n\n`;
  let file12 = `USE NS main DB main;\n\n`;
  let viewsCompiledContent = file07;

  // --- A. Base Security & Auditing ---
  Array.from(RAW.tables).forEach((tb) => {
    file02 += `DEFINE TABLE OVERWRITE ${tb} SCHEMAFULL PERMISSIONS\n    FOR select WHERE '${tb}_select' IN $auth.permissions AND (readers CONTAINSANY $auth.parents OR readers CONTAINSANY $auth.dominates)\n    FOR create WHERE '${tb}_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)\n    FOR update WHERE '${tb}_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)\n    FOR delete WHERE '${tb}_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);\n\n`;
    file04 += `DEFINE FIELD OVERWRITE created_at ON TABLE ${tb} TYPE datetime VALUE $before OR time::now() READONLY;\nDEFINE FIELD OVERWRITE updated_at ON TABLE ${tb} TYPE datetime VALUE time::now();\nDEFINE FIELD OVERWRITE created_by ON TABLE ${tb} TYPE option<record<user>> VALUE $before OR $auth READONLY;\nDEFINE FIELD OVERWRITE updated_by ON TABLE ${tb} TYPE option<record<user>> VALUE $auth;\n\n`;
    file05 += `DEFINE FIELD OVERWRITE system_ping ON TABLE ${tb} TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;\n\n`;

    const baseOwnedBy = `TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates`;

    if (
      Object.keys(RAW.fields[tb] || {}).length === 0 ||
      tb === "adjustment_note"
    ) {
      file03 += `DEFINE FIELD OVERWRITE owned_by ON TABLE ${tb} ${baseOwnedBy};\n`;
      file03 += `DEFINE FIELD OVERWRITE readers ON TABLE ${tb} TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));\n\n`;
    } else {
      let valStr = `$this.${Object.keys(RAW.fields[tb])[0]}.owned_by`;
      if (tb === "sl")
        valStr = `$this.a_from.owned_by ?? $this.a_to.owned_by ?? $this.a_pkg.owned_by`;
      if (tb === "adjustment_line") valStr = `$this.a_note.owned_by`;

      file03 += `DEFINE FIELD OVERWRITE owned_by ON TABLE ${tb} ${baseOwnedBy} VALUE ${valStr};\n`;
      const parentPaths = Object.keys(RAW.fields[tb]).map(
        (f) => `$this.${f}.readers`,
      );
      file03 += `DEFINE FIELD OVERWRITE readers ON TABLE ${tb} TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, ${parentPaths.join(", ")}]))).filter(|$v| $v != NONE);\n\n`;
    }
  });

  // --- B. Indexes ---
  Object.entries(RAW.fields).forEach(([tb, fields]) => {
    Object.keys(fields).forEach(
      (f) => (file11 += `DEFINE INDEX idx_${tb}_${f} ON ${tb} COLUMNS ${f};\n`),
    );
  });

  // --- C. Views (Pings, Computeds, RBAC) ---
  Object.entries(RAW.views).forEach(([vName, v]) => {
    let viewOwnerChecks = [];
    let isViewUsedForValidation = false;

    Object.values(RAW.usages).forEach((usedSet) => {
      if (usedSet.has(vName)) isViewUsedForValidation = true;
    });

    v.groupKeys.forEach((groupKey) => {
      file11 += `DEFINE INDEX idx_${vName}_${groupKey} ON ${vName} COLUMNS ${groupKey};\n`;

      const rawPath = v.aliases[groupKey] || groupKey;
      const parts = rawPath.split(".");
      let currentTables = [v.sourceTable];
      let isRecord = true;

      for (let i = 0; i < parts.length; i++) {
        const prop = parts[i];
        let nextTables = new Set();
        currentTables.forEach((t) => {
          if (RAW.fields[t] && RAW.fields[t][prop])
            RAW.fields[t][prop].targets.forEach((pt) => nextTables.add(pt));
        });
        if (nextTables.size === 0) {
          isRecord = false;
          break;
        }
        currentTables = Array.from(nextTables);
      }

      if (isRecord && currentTables.length > 0) {
        viewOwnerChecks.push(
          `('${v.sourceTable}_select' IN $auth.permissions AND (${groupKey}.readers CONTAINSANY $auth.parents OR ${groupKey}.readers CONTAINSANY $auth.dominates))`,
        );

        if (isViewUsedForValidation) {
          file08 += `DEFINE EVENT ping_${vName}_${groupKey} ON TABLE ${vName} WHEN $event != 'NONE' THEN {\n`;
          file08 += `    IF $__rebase_halt_cascade != true {\n`;
          // 🎯 TRUTHINESS OPTIMIZATION:
          file08 += `        LET $tgt = $after.${groupKey} ?? $before.${groupKey};\n`;
          file08 += `        IF $tgt { UPDATE $tgt SET system_ping = time::now(); };\n`;
          file08 += `    };\n};\n\n`;
        }

        currentTables.forEach((targetTable) => {
          file12 += `DEFINE FIELD c_${vName} ON ${targetTable} COMPUTED (SELECT * FROM ${vName} WHERE ${groupKey} = $parent.id);\n`;
        });
      }
    });

    let permissionCondition =
      viewOwnerChecks.length > 0
        ? viewOwnerChecks.join(" OR ")
        : `'${v.sourceTable}_select' IN $auth.permissions`;
    viewsCompiledContent = viewsCompiledContent.replace(
      v.rawQuery,
      v.rawQuery.replace(/;$/, "") +
        `\n    PERMISSIONS FOR select WHERE ${permissionCondition}\n    FOR create, update, delete NONE;`,
    );
  });

  // --- D. Downward Cascades (Dynamic OR Combiner) ---
  Object.entries(RAW.downward).forEach(([rootTable, paths]) => {
    file09 += `DEFINE EVENT aot_cascade_downward ON TABLE ${rootTable} WHEN $event = 'UPDATE' THEN {\n`;
    file09 += `    IF $__rebase_halt_cascade != true {\n`;
    Object.entries(paths).forEach(([revPath, fieldsSet]) => {
      const conditions = Array.from(fieldsSet)
        .map((f) => `$before.${f} != $after.${f}`)
        .join(" OR ");
      file09 += `        IF ${conditions} {\n`;
      // 🎯 TRUTHINESS OPTIMIZATION: Handles NONE and Empty Arrays natively!
      file09 += `            LET $tgt = ${revPath};\n`;
      file09 += `            IF $tgt { UPDATE $tgt SET system_ping = time::now(); };\n`;
      file09 += `        };\n`;
    });
    file09 += `    };\n};\n\n`;
  });

  // --- E. RBAC File Injection (01_auth_rbac.surql) ---
  const authFile = "01_auth_rbac.surql";
  if (fs.existsSync(authFile)) {
    let authContent = fs.readFileSync(authFile, "utf8");
    let roleArrayStr = `[\n    'node_create', 'node_select', 'node_update', 'node_delete',\n    'link_create', 'link_select', 'link_delete',\n`;

    Array.from(RAW.tables).forEach((tb, index) => {
      roleArrayStr += `    '${tb}_select', '${tb}_create', '${tb}_update', '${tb}_delete'`;
      if (index < RAW.tables.size - 1) roleArrayStr += `,`;
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

  fs.writeFileSync("02_table_permissions.surql", file02);
  fs.writeFileSync("03_owners.surql", file03);
  fs.writeFileSync("04_audit_meta_fields.surql", file04);
  fs.writeFileSync("05_system_flags.surql", file05);
  fs.writeFileSync("07_views_compiled.surql", viewsCompiledContent);
  fs.writeFileSync("08_events_upward.surql", file08);
  fs.writeFileSync("09_events_downward.surql", file09);
  fs.writeFileSync("11_indexes.surql", file11);
  fs.writeFileSync("12_computed_views.surql", file12);

  console.log(
    "🏆 Compilation completed successfully. All Truthiness Optimizations applied.",
  );
  process.exit(0);
}

runCompiler();
