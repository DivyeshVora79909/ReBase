// ==============================================================================
// REBASE META-COMPILER (PROTOCOL V5.1 - DAG TOPOLOGY SUPPORT)
// ==============================================================================
const fs = require("fs");

console.log("🚀 Initializing ReBase Compiler Pipeline...");

const file06 = fs.readFileSync("06_table_fields.surql", "utf8");
const file07 = fs.readFileSync("07_views.surql", "utf8");

const allTables = [
  ...new Set(
    [...file06.matchAll(/DEFINE TABLE ([a-zA-Z0-9_]+)/g)].map((m) => m[1]),
  ),
].sort();

const fieldTypeMap = {};
const typeRegex =
  /DEFINE FIELD (a_in_[a-zA-Z0-9_]+) ON ([a-zA-Z0-9_]+) TYPE (?:option<)?record<([a-zA-Z0-9_| ]+)>/g;
let match;
while ((match = typeRegex.exec(file06)) !== null) {
  const [_, fieldName, tableName, allowedTypesRaw] = match;
  if (!fieldTypeMap[tableName]) fieldTypeMap[tableName] = {};
  fieldTypeMap[tableName][fieldName] = allowedTypesRaw
    .split("|")
    .map((t) => t.trim());
}

let file02 = `-- FILE 02: RLS PERMISSIONS\nUSE NS main DB main;\n\n`;
let file03 = `-- FILE 03: DAG OWNERSHIP INHERITANCE\nUSE NS main DB main;\n\n`;
let file04 = `-- FILE 04: AUDIT FIELDS\nUSE NS main DB main;\n\n`;
let file05 = `-- FILE 05: SYSTEM FLAGS\nUSE NS main DB main;\n\n`;

allTables.forEach((tb) => {
  file02 += `DEFINE TABLE OVERWRITE ${tb} SCHEMAFULL PERMISSIONS
    FOR select WHERE '${tb}_select' IN $auth.permissions AND (owners CONTAINS $auth.parents OR owners CONTAINS $auth.dominates)
    FOR create WHERE '${tb}_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR update WHERE '${tb}_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)
    FOR delete WHERE '${tb}_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);\n\n`;

  file04 += `DEFINE FIELD OVERWRITE created_at ON TABLE ${tb} TYPE datetime VALUE $before OR time::now() READONLY;\nDEFINE FIELD OVERWRITE updated_at ON TABLE ${tb} TYPE datetime VALUE time::now();\nDEFINE FIELD OVERWRITE created_by ON TABLE ${tb} TYPE option<record<user>> VALUE $before OR $auth READONLY;\nDEFINE FIELD OVERWRITE updated_by ON TABLE ${tb} TYPE option<record<user>> VALUE $auth;\n\n`;
  file05 += `DEFINE FIELD OVERWRITE system_ping ON TABLE ${tb} TYPE datetime DEFAULT time::now() PERMISSIONS FOR update NONE;\n\n`;

  const parentsConfig = fieldTypeMap[tb];
  if (!parentsConfig || tb === "adjustment_note") {
    file03 += `DEFINE FIELD OVERWRITE owned_by ON TABLE ${tb} TYPE record<groups> REFERENCE ON DELETE REJECT PERMISSIONS FOR select WHERE TRUE FOR create WHERE $value IN $auth.parents OR $value IN $auth.dominates FOR update WHERE $value = $before OR $value IN $auth.dominates;\n`;
    file03 += `DEFINE FIELD OVERWRITE owners ON TABLE ${tb} TYPE array<record<groups>> VALUE array::distinct(array::flatten([$this.owned_by]));\n\n`;
  } else {
    file03 += `DEFINE FIELD OVERWRITE owned_by ON TABLE ${tb} TYPE option<record<groups>> VALUE `;
    if (tb === "sl")
      file03 += `$this.a_in_from.owned_by ?? $this.a_in_to.owned_by ?? $this.a_in_pkg.owned_by;\n`;
    else file03 += `$this.${Object.keys(parentsConfig)[0]}.owned_by;\n`;

    const parentPaths = Object.keys(parentsConfig).map(
      (pField) => `$this.${pField}.owners`,
    );
    file03 += `DEFINE FIELD OVERWRITE owners ON TABLE ${tb} TYPE array<record<groups>> VALUE (array::distinct(array::flatten([$this.owned_by, ${parentPaths.join(", ")}]))).filter(|$v| $v != NONE);\n\n`;
  }
});
fs.writeFileSync("02_table_permissions.surql", file02);
fs.writeFileSync("03_owners.surql", file03);
fs.writeFileSync("04_audit_meta_fields.surql", file04);
fs.writeFileSync("05_system_flags.surql", file05);

let file08 = `-- FILE 08: UPWARD PROPAGATION (O(1) VIEWS TO PARENT SIGNAL)\nUSE NS main DB main;\n\n`;
const viewRegex =
  /DEFINE TABLE (?:OVERWRITE )?(v_[a-zA-Z0-9_]+) AS SELECT .*? GROUP BY ([a-zA-Z0-9_, ]+);/g;
while ((match = viewRegex.exec(file07)) !== null) {
  const viewName = match[1];
  const keys = match[2].split(",").map((k) => k.trim());
  if (keys.length === 1) {
    const parentKey = keys[0];
    file08 += `DEFINE EVENT ping_${viewName} ON TABLE ${viewName} WHEN $event != 'NONE' THEN {\n    LET $t = $after.${parentKey} ?? $before.${parentKey};\n    IF ($t.f_out.is_locked ?? false) = true { THROW "LOCKED"; };\n    UPDATE $t SET system_ping = time::now();\n};\n\n`;
  }
}
fs.writeFileSync("08_events_upward.surql", file08);

let file09 = `-- FILE 09: DOWNWARD PROPAGATION (DAG ALERTS)\nUSE NS main DB main;\n\n`;
const dependMap = {};
const blockRegex = /DEFINE TABLE ([a-zA-Z0-9_]+).*?(?=DEFINE TABLE|$)/gs;
while ((match = blockRegex.exec(file06)) !== null) {
  const childTable = match[1];
  const blockContent = match[0];
  const ctxRegex = /\$this\.(a_in_[a-zA-Z0-9_]+)\.f_out\.([a-zA-Z0-9_]+)/g;
  let ctxMatch;
  while ((ctxMatch = ctxRegex.exec(blockContent)) !== null) {
    const parentFieldRef = ctxMatch[1];
    const targetOutput = ctxMatch[2];
    const parentTables =
      fieldTypeMap[childTable] && fieldTypeMap[childTable][parentFieldRef];
    if (parentTables) {
      parentTables.forEach((pTable) => {
        if (!dependMap[pTable]) dependMap[pTable] = {};
        if (!dependMap[pTable][childTable]) dependMap[pTable][childTable] = {};
        if (!dependMap[pTable][childTable][parentFieldRef])
          dependMap[pTable][childTable][parentFieldRef] = new Set();
        dependMap[pTable][childTable][parentFieldRef].add(targetOutput);
      });
    }
  }
}
Object.entries(dependMap).forEach(([parent, children]) => {
  Object.entries(children).forEach(([child, fkMap]) => {
    Object.entries(fkMap).forEach(([fkField, fieldsSet]) => {
      const triggers = [...fieldsSet]
        .map((f) => `$before.f_out.${f} != $after.f_out.${f}`)
        .join(" OR ");
      file09 += `DEFINE EVENT push_${parent}_to_${child}_via_${fkField} ON TABLE ${parent}\nWHEN $event = 'UPDATE' AND (${triggers}) THEN {\n    UPDATE ${child} SET system_ping = time::now() WHERE ${fkField} = $after.id;\n};\n\n`;
    });
  });
});
fs.writeFileSync("09_events_downward.surql", file09);

console.log("🏆 DB Physics Restored! Compilation complete.");
