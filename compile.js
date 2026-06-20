// ==============================================================================
// REBASE META-COMPILER (UDS COMPLIANT)
// Parses 06_table_fields & 07_views to auto-generate the database ecosystem.
// ==============================================================================

const fs = require("fs");
const path = require("path");

console.log("🚀 Initializing ReBase Compiler Pipeline...");

// Read the Manual Sources of Truth
const file06 = fs.readFileSync("06_table_fields.surql", "utf8");
const file07 = fs.readFileSync("07_views.surql", "utf8");

// ==============================================================================
// 1. THE EXTRACTOR (Parsing the Physics)
// ==============================================================================

// Harvest every unique table name in the schema
const rawTables = [
  ...file06.matchAll(
    /DEFINE FIELD [a-zA-Z0-9_.]+\s+ON\s+(?:TABLE\s+)?([a-zA-Z0-9_]+)/g,
  ),
].map((m) => m[1]);
const allTables = [...new Set(rawTables)].sort();

// Dynamically identify the State Tables (only tables defining suspended/locked)
const rawStateTables = [
  ...file06.matchAll(/DEFINE FIELD (?:suspended|locked) ON\s+([a-zA-Z0-9_]+)/g),
].map((m) => m[1]);
const stateTables = [...new Set(rawStateTables)].sort();

// Map the Parent-Child DAG Relationships
const parentMap = {};
const relRegex =
  /DEFINE FIELD ([a-zA-Z0-9_]+) ON ([a-zA-Z0-9_]+) TYPE (?:option<)?record<([a-zA-Z0-9_| ]+)>/g;
let match;
while ((match = relRegex.exec(file06)) !== null) {
  const [_, parentField, childTable, parentTableRaw] = match;
  // Exclude independent self-pointers or system links
  if (
    parentField === "owned_by" ||
    parentField === "created_by" ||
    parentField === "updated_by"
  )
    continue;

  if (!parentMap[childTable]) parentMap[childTable] = [];
  const allowedParents = parentTableRaw.split("|").map((p) => p.trim());
  parentMap[childTable].push({ field: parentField, targets: allowedParents });
}

console.log(
  `🔍 Extracted ${allTables.length} tables. State tables identified: [${stateTables.join(", ")}]`,
);

// ==============================================================================
// 2. THE RBAC & BOOTSTRAP COMPILER (Generates File 01 Roles & File 02)
// ==============================================================================

// Compile File 02 (Permissions)
let file02 = `-- ==============================================================================
-- FILE 02: AUTO-GENERATED ROW-LEVEL SECURITY (RLS) GATES
-- ==============================================================================
USE NS main DB main;\n\n`;

allTables.forEach((tb) => {
  file02 += `DEFINE TABLE OVERWRITE ${tb} SCHEMAFULL PERMISSIONS
    FOR select WHERE '${tb}_select' IN $auth.permissions AND (owners CONTAINS $auth.parents OR owners CONTAINS $auth.dominates)
    FOR create WHERE '${tb}_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE '${tb}_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE '${tb}_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);\n\n`;
});
fs.writeFileSync("02_table_permissions.surql", file02);

// Dynamically update the groups:root bootstrap definition inside File 01
let file01 = fs.readFileSync("01_auth_rbac.surql", "utf8");
const rolesArray = allTables
  .map((tb) => {
    return `\n    '${tb}_select', '${tb}_create', '${tb}_update', '${tb}_delete'`;
  })
  .join(",");

const bootstrapRegex =
  /CREATE groups:root SET name = 'System Admins', role = \[\s*[\s\S]*?\s*\];/g;
const newBootstrap = `CREATE groups:root SET name = 'System Admins', role = [
    'node_create', 'node_select', 'node_update', 'node_delete',
    'link_create', 'link_select', 'link_delete',${rolesArray}
];`;

file01 = file01.replace(bootstrapRegex, newBootstrap);
fs.writeFileSync("01_auth_rbac.surql", file01);
console.log("⚡ Auto-injected compiled permissions into 01_auth_rbac.surql");

// ==============================================================================
// 3. THE OWNERS COMPILER (Generates File 03 - Write-Time Flattening)
// ==============================================================================
let file03 = `-- ==========================================
-- FILE 03: OWNERSHIP INHERITANCE (RBAC PERIMETERS)
-- ==========================================
USE NS main DB main;\n\n`;

allTables.forEach((tb) => {
  const parentsConfig = parentMap[tb];

  if (!parentsConfig) {
    // Independent Anchor (Level 0) or Intent (Level 1) Root
    file03 += `DEFINE FIELD OVERWRITE owned_by ON TABLE ${tb} TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS
    FOR select WHERE TRUE
    FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates
    FOR update WHERE $value = $before OR $value IN $auth.dominates;\n\n`;
    file03 += `DEFINE FIELD OVERWRITE owners ON TABLE ${tb} TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));\n\n`;
  } else {
    // Dependent Branch/Leaf (Level 2+)
    file03 += `DEFINE FIELD OVERWRITE owned_by ON TABLE ${tb} TYPE option<record<groups>> VALUE `;
    if (tb === "sl") {
      file03 += `$this.inv_line.owned_by ?? $this.pkg.owned_by ?? $this.from.owned_by;\n\n`;
    } else {
      file03 += `$this.${parentsConfig[0].field}.owned_by;\n\n`;
    }

    const parentPaths = parentsConfig.map((p) => {
      // Handle polymorphic targets
      if (p.targets.includes("polymorphic")) {
        return `$this.${p.field}.owners`;
      }
      return `$this.${p.field}.owners`;
    });

    file03 += `DEFINE FIELD OVERWRITE owners ON TABLE ${tb} TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by, ${parentPaths.join(", ")}]));\n\n`;
  }
});
fs.writeFileSync("03_owners.surql", file03);

// ==============================================================================
// 4. THE METADATA & FLAGS COMPILER (Generates Files 04 & 05)
// ==============================================================================
let file04 = `USE NS main DB main;\n\n`;
let file05 = `USE NS main DB main;\n\n`;

allTables.forEach((tb) => {
  file04 += `DEFINE FIELD OVERWRITE created_at ON TABLE ${tb} TYPE datetime VALUE $before OR time::now() READONLY;
DEFINE FIELD OVERWRITE updated_at ON TABLE ${tb} TYPE datetime VALUE time::now();
DEFINE FIELD OVERWRITE created_by ON TABLE ${tb} TYPE option<record<user>> VALUE $before OR $auth READONLY;
DEFINE FIELD OVERWRITE updated_by ON TABLE ${tb} TYPE option<record<user>> VALUE $auth;\n\n`;

  file05 += `DEFINE FIELD OVERWRITE system_ping ON TABLE ${tb} TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;\n\n`;
});

stateTables.forEach((tb) => {
  file05 += `DEFINE FIELD OVERWRITE suspended ON TABLE ${tb} TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE locked ON TABLE ${tb} TYPE bool DEFAULT false;\n\n`;
});

fs.writeFileSync("04_audit_meta_fields.surql", file04);
fs.writeFileSync("05_system_flags.surql", file05);

// ==============================================================================
// 5. THE REACTIVE EVENT COMPILER (Generates Files 08 & 09)
// ==============================================================================

// Compile File 08 (Upward View Pings - Stateless Signals)
let file08 = `-- ==============================================================================
-- FILE 08: UPWARD PROPAGATION (VIEW TO PARENT SIGNALS)
-- ==============================================================================
USE NS main DB main;\n\n`;

const viewRegex =
  /DEFINE TABLE OVERWRITE (v_[a-zA-Z0-9_]+) AS SELECT ([a-zA-Z0-9_.]+)(?:.node)? AS ([a-zA-Z0-9_]+)/g;
while ((match = viewRegex.exec(file07)) !== null) {
  const [_, viewName, selectCol, parentId] = match;
  file08 += `DEFINE EVENT ping_${viewName} ON TABLE ${viewName} WHEN $event != 'NONE' THEN {
    LET $t = $after.${parentId} ?? $before.${parentId};
    IF ($t.zzzzz_out.is_locked ?? false) = true { THROW "LOCKED"; };
    UPDATE $t SET system_ping = time::now();
  };\n\n`;
}
fs.writeFileSync("08_events_upward.surql", file08);

// Compile File 09 (Downward Pings - DAG Dependency Triggers)
let file09 = `-- ==============================================================================
-- FILE 09: DOWNWARD PROPAGATION (TOPOLOGY & CONTEXT PINGS)
-- ==============================================================================
USE NS main DB main;\n\n`;

const dependMap = {};
const fieldRegex =
  /DEFINE FIELD za_parent\.([a-zA-Z0-9_]+) ON ([a-zA-Z0-9_]+)[^;]+VALUE \$this\.([a-zA-Z0-9_]+)\.([a-zA-Z0-9_.]+)/g;
while ((match = fieldRegex.exec(file06)) !== null) {
  const [_, childField, childTable, parentTable, parentField] = match;
  if (!dependMap[parentTable]) dependMap[parentTable] = {};
  if (!dependMap[parentTable][childTable])
    dependMap[parentTable][childTable] = [];
  dependMap[parentTable][childTable].push(parentField);
}

Object.entries(dependMap).forEach(([parent, children]) => {
  Object.entries(children).forEach(([child, fields]) => {
    const uniqueFields = [...new Set(fields)];
    const triggers = uniqueFields
      .map((f) => `$before.${f} != $after.${f}`)
      .join(" OR ");

    file09 += `DEFINE EVENT push_${parent}_to_${child} ON TABLE ${parent}
WHEN $event = 'UPDATE' AND (${triggers}) THEN {
    UPDATE ${child} SET system_ping = time::now() WHERE ${parent} = $after.id;
};\n\n`;
  });
});
fs.writeFileSync("09_events_downward.surql", file09);

console.log(
  "🏆 compilation complete! Files 02, 03, 04, 05, 08, and 09 have been compiled and generated.",
);
