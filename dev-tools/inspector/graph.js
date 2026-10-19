"use strict";

const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const ACCESS = new Set(["owned_by", "read_by", "tenant", "parents", "parent_groups", "created_by", "updated_by"]);
const PRINCIPALS = ["rebase_tenant", "rebase_group", "rebase_user"];
const strings = value => Array.isArray(value) && value.every(item => typeof item === "string");

function validateCatalog(value) {
  if (value?.format !== "rebase-devtools" || value.version !== 1
    || typeof value.project !== "string" || !Array.isArray(value.tables)
    || !Array.isArray(value.roots) || !Array.isArray(value.memberships) || !Array.isArray(value.functions)) {
    throw new Error("Open a current build's devtools.json file.");
  }
  const names = new Set();
  for (const table of value.tables) {
    if (!table || typeof table.name !== "string" || !table.name || names.has(table.name)
      || typeof table.group !== "string" || typeof table.kind !== "string" || !Array.isArray(table.fields)
      || !Array.isArray(table.indexes) || table.indexes.some(index => typeof index?.definition !== "string")
      || table.view && (typeof table.view.source !== "string" || typeof table.view.definition !== "string")) {
      throw new Error("The catalog contains an invalid or repeated table.");
    }
    names.add(table.name);
    const fields = new Set();
    for (const field of table.fields) {
      if (!field || typeof field.name !== "string" || fields.has(field.name) || typeof field.type !== "string"
        || field.expression != null && typeof field.expression !== "string"
        || field.reference && !strings(field.reference.targets)) {
        throw new Error("Invalid field metadata in " + table.name);
      }
      fields.add(field.name);
    }
    const dependencies = table.dependencies;
    if (dependencies && (
      !Array.isArray(dependencies.calculations) || dependencies.calculations.some(item =>
        typeof item?.field !== "string" || !strings(item.inputs))
      || !Array.isArray(dependencies.references) || dependencies.references.some(item =>
        typeof item?.table !== "string" || typeof item.reference !== "string" || !strings(item.fields) || !strings(item.consumers))
      || !Array.isArray(dependencies.queries) || dependencies.queries.some(item =>
        typeof item?.field !== "string" || !Array.isArray(item.sources) || item.sources.some(source =>
          typeof source?.table !== "string" || typeof source.root !== "string"))
    )) throw new Error("Invalid dependency metadata in " + table.name);
  }
  const slots = new Set();
  for (const entry of [...value.roots, ...value.memberships]) {
    if (!entry || typeof entry.id !== "string" || slots.has(entry.id) || !names.has(entry.table)
      || typeof entry.field !== "string" || !strings(entry.key)
      || !strings(value.roots.includes(entry) ? entry.members : entry.roots)) {
      throw new Error("Invalid tree metadata.");
    }
    slots.add(entry.id);
  }
  for (const entry of value.roots) if (entry.members.some(id => !value.memberships.some(member => member.id === id))) throw new Error("Unknown tree member.");
  for (const entry of value.memberships) if (entry.roots.some(id => !value.roots.some(root => root.id === id))) throw new Error("Unknown tree root.");
  for (const fn of value.functions) if (typeof fn?.name !== "string" || typeof fn.body !== "string" || fn.calls != null && !strings(fn.calls)) {
    throw new Error("Invalid function metadata.");
  }
  return value;
}

function hash(value) {
  let result = 2166136261;
  for (const character of String(value)) result = Math.imul(result ^ character.charCodeAt(0), 16777619);
  return result >>> 0;
}

// Evenly spaced hues, assigned in a seeded order of the COMPLETE catalog.
// Filtering never reallocates colors. Changing the catalog may reallocate them.
function palette(names, seed = "rebase") {
  const order = [...new Set(names)].sort((a, b) => hash(seed + ":" + a) - hash(seed + ":" + b) || compare(a, b));
  const offset = hash(seed) / 2 ** 32;
  return new Map(order.map((name, index) => {
    const hue = Math.round(((offset + index / order.length) % 1) * 360000) / 1000;
    return [name, { color: "hsl(" + hue + ", 64%, 42%)", tint: "hsl(" + hue + ", 55%, 96%)", hue }];
  }));
}

function schemaElements(catalog, { layer = "references", technical = false } = {}) {
  const colors = palette(catalog.tables.map(table => table.name), catalog.project);
  const nodes = new Map(catalog.tables.map(table => [table.name, { data: {
    id: table.name, label: table.name, table: table.name, kind: table.kind, group: table.group,
    ...colors.get(table.name),
  } }]));
  const edges = new Map();
  function edge(kind, source, target, field, sourceField, label, sourceFields = [sourceField]) {
    for (const name of [source, target]) if (!nodes.has(name)) nodes.set(name, { data: {
      id: name, label: name === "*" ? "Any table" : name, table: name,
      kind: "external", group: "external", color: "#64748b", tint: "#f1f5f9",
    } });
    const id = JSON.stringify([kind, source, target, field, sourceField, label]);
    edges.set(id, { data: {
      id: "edge:" + id, source, target, kind, field, sourceField, sourceFields, label,
      color: nodes.get(kind === "membership" ? target : source).data.color,
    } });
  }
  const enabled = kind => layer === kind || layer === "all";
  for (const table of catalog.tables) {
    for (const field of table.fields) {
      if (!field.reference) continue;
      const access = ACCESS.has(field.name) || table.name === "rebase_access";
      if (!enabled(access ? "access" : "references")) continue;
      if (!access && !technical && (field.generated || field.kind !== "input")) continue;
      for (const target of field.reference.targets) {
        edge(access ? "access" : "reference", target, table.name, field.name, "", field.name);
      }
      if (field.reference.unrestricted) edge("reference", "*", table.name, field.name, "", field.name);
    }
    if (enabled("calculations")) {
      for (const route of table.dependencies?.references || []) {
        for (const consumer of route.consumers) {
          edge("scalar", route.table, table.name, consumer, "",
            route.reference + "." + route.fields.join(", ") + " → " + consumer, route.fields);
        }
      }
      for (const query of table.dependencies?.queries || []) {
        for (const source of query.sources) {
          edge("query", source.table, table.name, query.field, source.root, query.operation + " → " + query.field);
        }
      }
    }
    if (enabled("views") && table.view?.source) edge("view", table.view.source, table.name, "", "", "view");
  }
  if (enabled("memberships")) {
    const roots = new Map(catalog.roots.map(root => [root.id, root]));
    for (const member of catalog.memberships) {
      if (!technical && member.generated) continue;
      for (const id of member.roots) {
        const root = roots.get(id);
        if (root) edge("membership", member.table, root.table, root.field, member.field, member.field + " → " + root.field);
      }
    }
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()] };
}

function validateAccess(value) {
  if (value?.format !== "rebase-access" || value.version !== 1 || typeof value.tenant !== "string"
    || !Array.isArray(value.records) || !value.records.length) throw new Error("Open an access snapshot exported by the inspector.");
  const ids = new Set();
  for (const row of value.records) {
    if (!row || typeof row.id !== "string" || !PRINCIPALS.includes(row.table) || ids.has(row.id)
      || !Array.isArray(row.parents) || row.parents.some(parent => typeof parent !== "string")
      || row.tenant !== value.tenant || row.table === "rebase_tenant" && row.id !== value.tenant) {
      throw new Error("Access snapshot contains invalid, repeated or cross-tenant records.");
    }
    ids.add(row.id);
  }
  return value;
}

function accessElements(snapshot, colors = palette(PRINCIPALS)) {
  const defaults = palette(PRINCIPALS);
  const nodes = new Map(snapshot.records.map(row => [row.id, { data: {
    id: row.id, label: (row.name || row.id) + "\n" + row.table.replace("rebase_", ""),
    table: row.table, kind: row.table, group: "access", ...(colors.get(row.table) || defaults.get(row.table)), record: row,
  } }]));
  const edges = new Map();
  for (const row of snapshot.records) {
    for (const parent of new Set(row.parents)) {
      if (!nodes.has(parent)) {
        const table = parent.slice(0, parent.indexOf(":"));
        nodes.set(parent, { data: {
          id: parent, label: parent + "\nnot loaded", table, kind: "external", group: "access",
          color: colors.get(table)?.color || "#64748b", tint: "#f1f5f9",
        } });
      }
      const id = "parent:" + JSON.stringify([parent, row.id]);
      edges.set(id, { data: {
        id, source: parent, target: row.id, kind: "access", field: "parents",
        label: "direct parent", color: nodes.get(parent).data.color,
      } });
    }
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()] };
}

module.exports = { validateCatalog, validateAccess, palette, schemaElements, accessElements, PRINCIPALS };
