const fs = require("fs");
const readline = require("readline");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

// ============================================================================
// ⚙️ CONFIGURATION
// ============================================================================
const EXCLUDED_TABLES = new Set(["user", "groups"]);
const INCLUDE_ARRAY_RECORDS_IN_READERS = false;

const PROJECT_DIR = "designs/test/";
const FILE_06_PATH = PROJECT_DIR + "06_table_fields.surql";
const FILE_07_PATH = PROJECT_DIR + "07_views.surql";
const AUTH_FILE_PATH = "01_auth_rbac.surql";

const askQuestion = (query) =>
  new Promise((resolve) => rl.question(query, resolve));

// ============================================================================
// 🧠 PHASE 1: THE PARSER
// ============================================================================
function parseSchema() {
  const file06 = fs.existsSync(FILE_06_PATH)
    ? fs.readFileSync(FILE_06_PATH, "utf8")
    : "";
  const file07 = fs.existsSync(FILE_07_PATH)
    ? fs.readFileSync(FILE_07_PATH, "utf8")
    : "";

  if (!file06 || !file07) {
    console.error(`❌ ERROR: Missing ${FILE_06_PATH} or ${FILE_07_PATH}`);
    process.exit(1);
  }

  const raw = { tables: {}, views: [], rawFile07: file07 };

  const tableRegex = /DEFINE TABLE (?:OVERWRITE )?([a-zA-Z0-9_]+)/g;
  let tMatch;
  while ((tMatch = tableRegex.exec(file06)) !== null) {
    raw.tables[tMatch[1]] = { name: tMatch[1], fields: [] };
  }

  const fieldRegex =
    /DEFINE FIELD (?:OVERWRITE )?([a-zA-Z0-9_]+) ON (?:TABLE )?([a-zA-Z0-9_]+)(.*?);/gs;
  let fMatch;
  while ((fMatch = fieldRegex.exec(file06)) !== null) {
    const [_, fieldName, tableName, fieldDef] = fMatch;
    const recordMatch =
      /TYPE (?:option<)?(?:array<)?record<([a-zA-Z0-9_| ]+)>/i.exec(fieldDef);

    if (raw.tables[tableName]) {
      raw.tables[tableName].fields.push({
        name: fieldName,
        isRelation: !!recordMatch,
        isArray: /array<record</i.test(fieldDef),
        targets: recordMatch
          ? recordMatch[1].split("|").map((t) => t.trim())
          : [],
      });
    }
  }

  const viewRegex =
    /DEFINE TABLE (?:OVERWRITE )?(v_[a-zA-Z0-9_]+) AS SELECT\s+(.+?)\s+FROM\s+([a-zA-Z0-9_]+).*?GROUP BY\s+([a-zA-Z0-9_,\s.]+);/gs;
  let vMatch;
  while ((vMatch = viewRegex.exec(file07)) !== null) {
    const [rawQuery, viewName, selectBlock, sourceTable, groupByBlock] = vMatch;
    raw.views.push({
      name: viewName,
      sourceTable: sourceTable,
      groupKeys: groupByBlock
        .split(",")
        .map((k) => k.trim())
        .filter(Boolean),
      rawQuery: rawQuery,
    });
  }

  return raw;
}

// ============================================================================
// 🕵️ PHASE 2: THE GRAPH ANALYZER
// ============================================================================
function buildSchemaGraph(raw) {
  const graph = {
    tables: [],
    views: raw.views,
    downwardCascades: {},
    rawViewsFile: raw.rawFile07,
  };

  for (const [tableName, tableData] of Object.entries(raw.tables)) {
    const processedFields = tableData.fields.map((field) => {
      const pointsToExcludedOnly =
        field.isRelation && field.targets.every((t) => EXCLUDED_TABLES.has(t));
      const pointsToAnyExcluded =
        field.isRelation && field.targets.some((t) => EXCLUDED_TABLES.has(t));
      return { ...field, pointsToExcludedOnly, pointsToAnyExcluded };
    });

    graph.tables.push({
      name: tableName,
      isExcluded: EXCLUDED_TABLES.has(tableName),
      fields: processedFields,
    });
  }

  // Map Downward Cascades
  graph.tables.forEach((sourceTable) => {
    sourceTable.fields.forEach((field) => {
      if (field.isRelation) {
        field.targets.forEach((targetTable) => {
          if (!graph.downwardCascades[targetTable])
            graph.downwardCascades[targetTable] = [];
          graph.downwardCascades[targetTable].push({
            sourceTable: sourceTable.name,
            sourceField: field.name,
          });
        });
      }
    });
  });

  return graph;
}

// ============================================================================
// 🏭 PHASE 3: THE GENERATORS (PURE FUNCTIONS)
// ============================================================================

function generatePermissions(graph) {
  let out = `USE NS main DB main;\n\n`;
  graph.tables.forEach((t) => {
    if (t.isExcluded) return;
    out += `DEFINE TABLE OVERWRITE ${t.name} SCHEMAFULL PERMISSIONS\n    FOR select WHERE '${t.name}_select' IN $auth.permissions AND (readers CONTAINSANY $auth.parents OR readers CONTAINSANY $auth.dominates)\n    FOR create WHERE '${t.name}_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)\n    FOR update WHERE '${t.name}_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)\n    FOR delete WHERE '${t.name}_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);\n\n`;
  });
  return out;
}

function generateAuditAndFlags(graph) {
  let auditOut = `USE NS main DB main;\n\n`;
  let flagsOut = `USE NS main DB main;\n\n`;
  graph.tables.forEach((t) => {
    if (t.isExcluded) return;
    auditOut += `DEFINE FIELD OVERWRITE created_at ON TABLE ${t.name} TYPE datetime VALUE $before OR time::now() READONLY;\nDEFINE FIELD OVERWRITE updated_at ON TABLE ${t.name} TYPE datetime VALUE time::now();\nDEFINE FIELD OVERWRITE created_by ON TABLE ${t.name} TYPE option<record<user>> VALUE $before OR $auth READONLY;\nDEFINE FIELD OVERWRITE updated_by ON TABLE ${t.name} TYPE option<record<user>> VALUE $auth;\n\n`;
    flagsOut += `DEFINE FIELD OVERWRITE system_ping ON TABLE ${t.name} TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;\n\n`;
  });
  return { file04: auditOut, file05: flagsOut };
}

function generateOwners(graph) {
  let out = `USE NS main DB main;\n\n`;
  const baseOwnedBy = `TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates`;

  graph.tables.forEach((t) => {
    if (t.isExcluded) return;

    // RULE 1: STRICT OWNED_BY. NO VALUE INHERITANCE ALLOWED.
    out += `DEFINE FIELD OVERWRITE owned_by ON TABLE ${t.name} ${baseOwnedBy};\n`;

    // RULE 2: CALCULATE READERS
    const parentPaths = [];
    let needsDoubleFlatten = false;

    t.fields.forEach((f) => {
      if (!f.isRelation) return;
      if (f.pointsToAnyExcluded) return; // Strict Exclusion

      if (f.isArray) {
        if (INCLUDE_ARRAY_RECORDS_IN_READERS) {
          parentPaths.push(`$this.${f.name}.readers`);
          needsDoubleFlatten = true;
        }
      } else {
        parentPaths.push(`$this.${f.name}.readers`);
      }
    });

    let flattenExpr = `array::flatten([$this.owned_by${parentPaths.length > 0 ? ", " + parentPaths.join(", ") : ""}])`;
    if (needsDoubleFlatten) {
      flattenExpr = `array::flatten(${flattenExpr})`;
    }

    out += `DEFINE FIELD OVERWRITE readers ON TABLE ${t.name} TYPE array<record<groups>> VALUE (array::distinct(${flattenExpr})).filter(|$v| $v != NONE);\n\n`;
  });
  return out;
}

function generateDownwardEvents(graph) {
  let out = `USE NS main DB main;\n\n`;
  for (const [rootTable, cascadeSources] of Object.entries(
    graph.downwardCascades,
  )) {
    out += `DEFINE EVENT aot_cascade_downward ON TABLE ${rootTable} WHEN $event = 'UPDATE' THEN {\n`;
    out += `    IF $__rebase_halt_cascade != true {\n`;

    // Group fields by source table to optimize conditions
    const grouped = {};
    cascadeSources.forEach((src) => {
      if (!grouped[src.sourceTable]) grouped[src.sourceTable] = new Set();
      grouped[src.sourceTable].add(src.sourceField);
    });

    for (const [sourceTable, fields] of Object.entries(grouped)) {
      const conditions = Array.from(fields)
        .map((f) => `$before.${f} != $after.${f}`)
        .join(" OR ");
      out += `        IF ${conditions} {\n`;
      out += `            LET $tgt = $after<~${sourceTable};\n`;
      out += `            IF $tgt { UPDATE $tgt SET system_ping = time::now(); };\n`;
      out += `        };\n`;
    }
    out += `    };\n};\n\n`;
  }
  return out;
}

function generateViewsAndIndexes(graph) {
  let file11 = `USE NS main DB main;\n\n`; // Indexes
  let file08 = `USE NS main DB main;\n\n`; // Upward Events
  let file12 = `USE NS main DB main;\n\n`; // Computed Views
  let file07 = graph.rawViewsFile; // Compiled Views

  // Index normal fields
  graph.tables.forEach((t) => {
    t.fields.forEach(
      (f) =>
        (file11 += `DEFINE INDEX idx_${t.name}_${f.name} ON ${t.name} COLUMNS ${f.name};\n`),
    );
  });

  // Process Views
  graph.views.forEach((v) => {
    v.groupKeys.forEach((groupKey) => {
      file11 += `DEFINE INDEX idx_${v.name}_${groupKey} ON ${v.name} COLUMNS ${groupKey};\n`;

      // Simplified upward ping logic (Assumes groupKey exists directly on sourceTable)
      file08 += `DEFINE EVENT ping_${v.name}_${groupKey} ON TABLE ${v.name} WHEN $event != 'NONE' THEN {\n`;
      file08 += `    IF $__rebase_halt_cascade != true {\n`;
      file08 += `        LET $tgt = $after.${groupKey} ?? $before.${groupKey};\n`;
      file08 += `        IF $tgt { UPDATE $tgt SET system_ping = time::now(); };\n`;
      file08 += `    };\n};\n\n`;

      file12 += `DEFINE FIELD c_${v.name} ON ${v.sourceTable} COMPUTED (SELECT * FROM ${v.name} WHERE ${groupKey} = $parent.id);\n`;
    });

    // Update permissions in compiled views file
    const permission = `('${v.sourceTable}_select' IN $auth.permissions)`;
    file07 = file07.replace(
      v.rawQuery,
      v.rawQuery.replace(/;$/, "") +
        `\n    PERMISSIONS FOR select WHERE ${permission}\n    FOR create, update, delete NONE;`,
    );
  });

  return { file07, file08, file11, file12 };
}

function updateAuthRbac(graph) {
  if (!fs.existsSync(AUTH_FILE_PATH)) return;

  let authContent = fs.readFileSync(AUTH_FILE_PATH, "utf8");
  let roleArrayStr = `[\n    'node_create', 'node_select', 'node_update', 'node_delete',\n    'link_create', 'link_select', 'link_delete',\n`;

  const tablesList = graph.tables.map((t) => t.name);
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
    fs.writeFileSync(AUTH_FILE_PATH, authContent);
    console.log("✅ 01_auth_rbac.surql synced.");
  }
}

// ============================================================================
// 🚀 PHASE 4: THE MAIN EXECUTION ENGINE
// ============================================================================

async function main() {
  console.log(
    "\n🚀 INITIALIZING REBASE META-COMPILER (V25 - PIPELINE ARCHITECTURE)",
  );
  console.log(
    "========================================================================\n",
  );

  const raw = parseSchema();
  const graph = buildSchemaGraph(raw);

  console.log("✅ AST Parsed & Schema Graph Built.");
  console.log(`   - Tables detected: ${graph.tables.length}`);
  console.log(`   - Views detected: ${graph.views.length}`);

  const answer = await askQuestion(
    "\nPress ENTER to generate optimized SurrealQL files, or 'cancel' to abort: ",
  );
  if (answer.toLowerCase() === "cancel") {
    console.log("❌ Compilation aborted.");
    process.exit(0);
  }

  console.log("\n⚙️ GENERATING FILES...");

  const file02 = generatePermissions(graph);
  const file03 = generateOwners(graph);
  const { file04, file05 } = generateAuditAndFlags(graph);
  const file09 = generateDownwardEvents(graph);
  const { file07, file08, file11, file12 } = generateViewsAndIndexes(graph);

  fs.writeFileSync("02_table_permissions.surql", file02);
  fs.writeFileSync("03_owners.surql", file03);
  fs.writeFileSync("04_audit_meta_fields.surql", file04);
  fs.writeFileSync("05_system_flags.surql", file05);
  fs.writeFileSync("07_views_compiled.surql", file07);
  fs.writeFileSync("08_events_upward.surql", file08);
  fs.writeFileSync("09_events_downward.surql", file09);
  fs.writeFileSync("11_indexes.surql", file11);
  fs.writeFileSync("12_computed_views.surql", file12);

  updateAuthRbac(graph);

  console.log(
    "🏆 Compilation completed successfully. Enterprise architecture applied.",
  );
  process.exit(0);
}

main();
