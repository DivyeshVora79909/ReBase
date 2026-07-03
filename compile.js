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
  /DEFINE FIELD ([a-zA-Z0-9_]+) ON ([a-zA-Z0-9_]+) TYPE (?:option<)?record<([a-zA-Z0-9_| ]+)>/g;
let match;
while ((match = typeRegex.exec(file06)) !== null) {
  const [_, fieldName, tableName, allowedTypesRaw] = match;
  if (!fieldTypeMap[tableName]) fieldTypeMap[tableName] = {};
  fieldTypeMap[tableName][fieldName] = allowedTypesRaw
    .split("|")
    .map((t) => t.trim());
}

let file02 = `USE NS main DB main;\n\n`;
let file03 = `USE NS main DB main;\n\n`;
let file04 = `USE NS main DB main;\n\n`;
let file05 = `USE NS main DB main;\n\n`;
let file11 = `USE NS main DB main;\n\n`;

allTables.forEach((tb) => {
  file02 += `DEFINE TABLE OVERWRITE ${tb} SCHEMAFULL PERMISSIONS\n    FOR select WHERE '${tb}_select' IN $auth.permissions AND (owners CONTAINS $auth.parents OR owners CONTAINS $auth.dominates)\n    FOR create WHERE '${tb}_create' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)\n    FOR update WHERE '${tb}_update' IN $auth.permissions AND (owned_by IN $auth.parents OR owned_by IN $auth.dominates)\n    FOR delete WHERE '${tb}_delete' IN $auth.permissions AND (owned_by IN $auth.dominates);\n\n`;

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

Object.entries(fieldTypeMap).forEach(([tableName, fields]) => {
  Object.keys(fields).forEach((fieldName) => {
    file11 += `DEFINE INDEX idx_${tableName}_${fieldName} ON ${tableName} COLUMNS ${fieldName};\n`;
  });
});

let file08 = `USE NS main DB main;\n\n`;
let file12 = `USE NS main DB main;\n\n`;

const viewRegex =
  /DEFINE TABLE (?:OVERWRITE )?(v_[a-zA-Z0-9_]+) AS SELECT\s+(.+?)\s+FROM\s+([a-zA-Z0-9_]+).*?GROUP BY\s+([a-zA-Z0-9_,\s]+);/gs;
let matchView;

while ((matchView = viewRegex.exec(file07)) !== null) {
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

  groupKeys.forEach((groupKey) => {
    file11 += `DEFINE INDEX idx_${viewName}_${groupKey} ON ${viewName} COLUMNS ${groupKey};\n`;

    const rawPath = aliases[groupKey] || groupKey;
    const parts = rawPath.split(".");
    let currentTables = [sourceTable];
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
      file08 += `DEFINE EVENT ping_${viewName}_${groupKey} ON TABLE ${viewName} WHEN $event != 'NONE' THEN {\n`;
      file08 += `    IF $__rebase_halt_cascade != true {\n`;
      file08 += `        LET $tgt = array::flatten([$after.${groupKey} ?? $before.${groupKey}]).filter(|$v| $v != NONE);\n`;
      file08 += `        IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };\n`;
      file08 += `    };\n`;
      file08 += `};\n\n`;

      currentTables.forEach((targetTable) => {
        file12 += `DEFINE FIELD c_${viewName} ON ${targetTable} COMPUTED (SELECT * FROM ${viewName} WHERE ${groupKey} = $parent.id);\n`;
      });
    }
  });
}

let file09 = `USE NS main DB main;\n\n`;
const masterEvents = {};

function getPaths(table, parts, index) {
  if (index === parts.length - 1) return [[table]];
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
while ((match = blockRegex.exec(file06)) !== null) {
  const childTable = match[1];
  const blockContent = match[0];

  const pathRegex = /\$this\.([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+)/g;
  let pathMatch;

  while ((pathMatch = pathRegex.exec(blockContent)) !== null) {
    const fullPath = pathMatch[1];
    const parts = fullPath.split(".");
    const paths = getPaths(childTable, parts, 0);

    paths.forEach((path) => {
      const rootTable = path[path.length - 1];
      const triggerField = parts[parts.length - 1];

      let reversePathStr = "$after";
      for (let j = path.length - 2; j >= 0; j--) {
        reversePathStr += `<~${path[j].table}`;
      }

      if (!masterEvents[rootTable]) masterEvents[rootTable] = {};
      if (!masterEvents[rootTable][triggerField])
        masterEvents[rootTable][triggerField] = new Set();

      masterEvents[rootTable][triggerField].add(
        `LET $tgt = array::flatten([${reversePathStr}]).filter(|$v| $v != NONE);\n            IF array::len($tgt) > 0 { UPDATE $tgt SET system_ping = time::now(); };`,
      );
    });
  }
}

Object.entries(masterEvents).forEach(([rootTable, fieldsMap]) => {
  file09 += `DEFINE EVENT aot_cascade_downward ON TABLE ${rootTable} WHEN $event = 'UPDATE' THEN {\n`;
  file09 += `    IF $__rebase_halt_cascade != true {\n`;
  Object.entries(fieldsMap).forEach(([field, queriesSet]) => {
    file09 += `        IF $before.${field} != $after.${field} {\n`;
    queriesSet.forEach((query) => {
      file09 += `            ${query}\n`;
    });
    file09 += `        };\n`;
  });
  file09 += `    };\n`;
  file09 += `};\n\n`;
});

const authFile = "01_auth_rbac.surql";
if (fs.existsSync(authFile)) {
  let authContent = fs.readFileSync(authFile, "utf8");

  // Construct the dynamic role array formatting
  let roleArrayStr = `[\n    'node_create', 'node_select', 'node_update', 'node_delete',\n    'link_create', 'link_select', 'link_delete',\n`;
  allTables.forEach((tb, index) => {
    roleArrayStr += `    '${tb}_select', '${tb}_create', '${tb}_update', '${tb}_delete'`;
    if (index < allTables.length - 1) roleArrayStr += `,`;
    roleArrayStr += `\n`;
  });
  roleArrayStr += `]`;

  // Regex to find and replace the existing array payload inside CREATE groups:root
  const roleRegex =
    /CREATE groups:root SET name = 'System Admins', role = \[[^\]]*\];/g;
  const replacement = `CREATE groups:root SET name = 'System Admins', role = ${roleArrayStr};`;

  if (roleRegex.test(authContent)) {
    authContent = authContent.replace(roleRegex, replacement);
    fs.writeFileSync(authFile, authContent);
    console.log(
      "✅ 01_auth_rbac.surql updated dynamically with all table permissions.",
    );
  } else {
    console.log(
      "⚠️ 01_auth_rbac.surql was found, but the 'CREATE groups:root ...' block couldn't be matched.",
    );
  }
} else {
  console.log(
    `⚠️ Note: ${authFile} not found. Skipping dynamic role injection.`,
  );
}

fs.writeFileSync("02_table_permissions.surql", file02);
fs.writeFileSync("03_owners.surql", file03);
fs.writeFileSync("04_audit_meta_fields.surql", file04);
fs.writeFileSync("05_system_flags.surql", file05);
fs.writeFileSync("08_events_upward.surql", file08);
fs.writeFileSync("09_events_downward.surql", file09);
fs.writeFileSync("11_indexes.surql", file11);
fs.writeFileSync("12_computed_views.surql", file12);

console.log(
  "🏆 V21.2 Compiler Complete! RBAC Sync, Deep Traversals, and BI Views are Live.",
);
