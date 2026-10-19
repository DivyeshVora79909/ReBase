"use strict";

const cytoscape = require("cytoscape");
const layouts = require("./layouts");
const { validateCatalog, validateAccess, palette, schemaElements, accessElements, PRINCIPALS } = require("./graph");
const { connectAccess, readAccess, readRecordState } = require("./access");

const $ = id => document.getElementById(id);
const escape = value => String(value ?? "").replace(/[&<>"']/g, character => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
})[character]);
const state = {
  catalog: null, access: null, mode: "schema", selection: null, field: null, tab: "fields",
  focus: "all", activeFunction: null, db: null, settings: null, epoch: 0, request: 0, read: 0,
};
let colors = palette(PRINCIPALS);
const cy = cytoscape({
  container: $("cy"), elements: [], minZoom: .04, maxZoom: 2.5, layout: { name: "preset" },
  style: [
    { selector: "node", style: {
      shape: "round-rectangle", width: 186, height: 46, label: "data(label)",
      "font-family": "system-ui, sans-serif", "font-size": 11, color: "#263b55",
      "text-wrap": "wrap", "text-max-width": 178, "text-valign": "center",
      "background-color": "data(tint)", "border-color": "data(color)", "border-width": 2,
    } },
    { selector: "edge", style: {
      width: 1.4, "curve-style": "bezier", "line-color": "data(color)", "line-opacity": .4,
      "target-arrow-color": "data(color)", "target-arrow-shape": "triangle",
      "arrow-scale": .7, label: "data(label)", "font-size": 9, "text-opacity": 0,
      "text-background-color": "#fff", "text-background-opacity": .95, "text-background-padding": 3,
      "text-rotation": "autorotate",
    } },
    { selector: 'edge[kind = "query"]', style: { "line-style": "dashed" } },
    { selector: 'edge[kind = "membership"]', style: { "target-arrow-shape": "diamond" } },
    { selector: 'node[kind = "view"]', style: { shape: "cut-rectangle" } },
    { selector: 'node[kind = "relation"]', style: { shape: "hexagon" } },
    { selector: 'node[kind = "external"]', style: { "border-style": "dashed", color: "#75869b" } },
    { selector: "node.cycle", style: { "border-style": "dashed" } },
    { selector: ".muted", style: { opacity: .14 } },
    { selector: "node.highlighted", style: { "border-width": 3 } },
    { selector: "node.active", style: { "border-width": 4, "underlay-color": "#a8c6f8", "underlay-opacity": .2, "underlay-padding": 8 } },
    { selector: "edge.highlighted", style: { width: 2.4, "line-opacity": .9, "text-opacity": 1 } },
    { selector: ".hidden", style: { display: "none" } },
  ],
});

function notice(message = "", kind = "") {
  $("notice").textContent = message;
  $("notice").className = "notice " + kind;
  $("notice").hidden = !message;
}
function code(value) { return "<pre><code>" + escape(value) + "</code></pre>"; }
function json(value) { return code(JSON.stringify(value, null, 2)); }
function source(value) {
  return value ? '<div class="source-location">' + escape(value.group + ":" + value.file + ":" + value.line) + "</div>" : "";
}
function badge(value, kind = "") { return '<span class="badge ' + kind + '">' + escape(value) + "</span>"; }
function tableLink(table, field = "", label = table + (field ? "." + field : "")) {
  return '<button class="reference-link" data-table="' + escape(table) + '" data-target-field="' + escape(field) + '">' +
    '<span class="dot" style="--swatch:' + escape(colors.get(table)?.color || "#94a3b8") + '"></span><span>' + escape(label) + "</span></button>";
}
function fieldLink(name) { return tableLink(state.selection, name, name); }
function functionLink(name) { return name ? '<button class="reference-link" data-function="' + escape(name) + '">' + escape(name) + "</button>" : ""; }
function swatch(targets) {
  const stops = targets.flatMap((target, index) => {
    const color = colors.get(target)?.color || "#94a3b8";
    return [color + " " + 100 * index / targets.length + "%", color + " " + 100 * (index + 1) / targets.length + "%"];
  });
  return '<span class="swatch" title="' + escape(targets.join(" or ")) + '" style="background:' +
    escape(stops.length ? "linear-gradient(90deg," + stops.join(",") + ")" : "#e2e8f0") + '"></span>';
}
function download(name, value, type = "application/json") {
  const url = URL.createObjectURL(new Blob([value], { type }));
  const link = document.createElement("a");
  link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderNavigation() {
  const query = $("search").value.trim().toLowerCase(), group = $("group-filter").value;
  const items = state.mode === "schema" ? (state.catalog?.tables || []).map(table => ({
    id: table.name, name: table.name, table: table.name, kind: table.kind,
    visible: group === "all" || group === table.group || group === table.kind,
    match: table.name.toLowerCase().includes(query) || table.fields.some(field => field.name.toLowerCase().includes(query)),
  })) : (state.access?.records || []).map(row => ({
    id: row.id, name: row.name || row.id, table: row.table, kind: row.table.replace("rebase_", ""),
    visible: true, match: (row.id + " " + row.name).toLowerCase().includes(query),
  }));
  const visible = items.filter(item => item.visible && item.match);
  $("list-count").textContent = visible.length + (state.mode === "schema" ? " tables" : " records");
  $("table-list").innerHTML = visible.map(item =>
    '<button data-select="' + escape(item.id) + '" class="' + (item.id === state.selection ? "active" : "") + '">' +
    '<span class="dot" style="--swatch:' + escape(colors.get(item.table)?.color || "#64748b") + '"></span>' +
    '<span class="table-name">' + escape(item.name) + "</span>" +
    (item.kind !== "table" ? "<small>" + escape(item.kind) + "</small>" : "") + "</button>"
  ).join("") || '<p class="empty-copy">No matches.</p>';
}

function renderDiagram() {
  const schema = state.mode === "schema";
  const data = schema ? state.catalog && schemaElements(state.catalog, {
    layer: $("layer").value, technical: $("technical").checked,
  }) : state.access && accessElements(state.access, colors);
  cy.batch(() => { cy.elements().remove(); if (data) cy.add(data); });
  $("empty-graph").hidden = Boolean(data?.nodes.length);
  $("empty-title").textContent = schema ? "Open a design" : "Explore tenant access";
  $("empty-description").textContent = schema ? "Drop devtools.json here or use Open file."
    : "Connect to a tenant or open an access snapshot.";
  $("project-name").textContent = state.catalog?.project || "Explore a design";
  $("schema-controls").hidden = !schema; $("access-controls").hidden = schema;
  $("group-filter").hidden = !schema;
  $("search").placeholder = schema ? "Find a table or field…" : "Find a person or group…";
  $("schema-mode").setAttribute("aria-pressed", String(schema));
  $("access-mode").setAttribute("aria-pressed", String(!schema));
  $("disconnect").hidden = !state.db;
  $("connect").textContent = state.db ? "Change connection" : "Connect";
  $("connection-state").textContent = state.db ? "Connected" : "Offline";
  $("access-scope").textContent = state.access?.tenant || "";
  $("refresh-access").disabled = !state.db;
  let cycles = 0;
  if (data?.nodes.length) {
    for (const component of cy.elements().tarjanStronglyConnected().components) {
      if (component.nodes().length > 1 || component.edges().some(edge => edge.source().id() === edge.target().id())) {
        component.nodes().addClass("cycle"); cycles++;
      }
    }
  }
  $("graph-count").textContent = cy.nodes().length + " nodes · " + cy.edges().length + " connections";
  $("legend").textContent = !schema
    ? "Arrows follow direct parents → children. Unloaded parents have hollow cards. Roles are read from the database."
    : $("layer").value === "memberships"
      ? "Contributors → tree roots. Diamonds mark membership; the provider decides which memberships are active."
      : "Sources → dependents. Dashed lines are ordered queries; diamonds are tree contributions.";
  if (cycles) $("legend").textContent += " Dashed node borders mark " + cycles + " cyclic component" + (cycles === 1 ? "." : "s.");
  renderNavigation(); renderSelection(); applyFocus(); layoutVisible();
}

function layoutVisible() {
  // Class membership is immediate; rendered visibility can lag a style update.
  const elements = cy.elements().not(".hidden");
  if (!elements.nodes().length) return;
  layouts[$("layout").value].arrange(elements);
  cy.fit(elements, 35);
}

function applyFocus() {
  cy.elements().removeClass("hidden muted highlighted active");
  let visible = cy.elements();
  if (state.mode === "schema" && $("group-filter").value !== "all") {
    const group = $("group-filter").value;
    const nodes = cy.nodes().filter(node => node.data("group") === group || node.data("kind") === group);
    visible = nodes.union(nodes.edgesWith(nodes));
  }
  const node = state.selection && cy.getElementById(state.selection);
  if (node?.length && state.focus !== "all") {
    const local = state.focus === "upstream" ? node.predecessors().union(node)
      : state.focus === "downstream" ? node.successors().union(node) : node.closedNeighborhood();
    visible = visible.intersection(local);
  }
  cy.elements().difference(visible).addClass("hidden");
  if (node?.length) {
    let highlighted = node.closedNeighborhood();
    if (state.field) {
      const edges = cy.edges().filter(edge =>
        edge.target().id() === node.id() && edge.data("field") === state.field
        || edge.source().id() === node.id() && edge.data("sourceFields")?.includes(state.field));
      highlighted = edges.union(edges.connectedNodes()).union(node);
    }
    visible.difference(highlighted).addClass("muted");
    highlighted.addClass("highlighted"); node.addClass("active");
  }
  for (const button of document.querySelectorAll("[data-focus]")) button.setAttribute("aria-pressed", String(button.dataset.focus === state.focus));
}

function select(id, field = null, center = false) {
  const changed = state.selection !== id;
  state.selection = id; state.field = field; state.activeFunction = null; state.read++;
  if (!id) state.focus = "all";
  else if (center) state.focus = "neighbors";
  if (field) {
    const metadata = state.catalog?.tables.find(table => table.name === id)?.fields.find(item => item.name === field);
    state.tab = ["root", "member"].includes(metadata?.kind) ? "trees" : metadata?.kind === "query" ? "dependencies" : "fields";
  } else if (changed) state.tab = "fields";
  renderNavigation(); renderSelection(); applyFocus();
  if (center || !id) layoutVisible();
}

function fieldDetails(table, field) {
  const targets = field.reference?.targets || [];
  let body = '<div class="field-detail"><strong>' + escape(field.name) + "</strong><p><code>" + escape(field.type) + "</code></p>" +
    badge(field.kind, "blue") + (field.required ? badge("required") : "") +
    (field.readonly ? badge("readonly") : "") + (field.generated ? badge("generated") : "") +
    targets.map(target => tableLink(target)).join("") +
    (field.reference?.unrestricted ? "<p>May reference any table.</p>" : "") +
    (field.reference?.many ? "<p>A collection of references. Each value selects an allowed target.</p>" : "") +
    source(field.source);
  if (field.expression) body += "<h4>Calculation / normalization</h4>" + code(field.expression) + helperLinks(field.expression);
  if (field.assertion) body += "<details><summary>Database assertion</summary>" + code(field.assertion) + "</details>";
  if (field.permissions) body += "<details><summary>Field permissions</summary>" + code(field.permissions) + "</details>";
  if (table.schema?.properties?.[field.name]) body += "<details><summary>Input validation</summary>" + json(table.schema.properties[field.name]) + "</details>";
  return body + "</div>";
}

function fieldsPanel(table) {
  const selected = table.fields.find(field => field.name === state.field);
  const visible = visibleFields(table);
  return (selected ? fieldDetails(table, selected) : "") +
    '<p class="list-caption">Inputs and calculations · tree slots have their own tab</p>' +
    visible.map(field => '<button class="field-row ' + (field.name === state.field ? "active" : "") +
      '" data-field="' + escape(field.name) + '"><span class="field-heading">' +
      (field.reference ? swatch(field.reference.targets) : "") + escape(field.name) +
      "<small>" + escape(field.publicInput ? "input" : field.kind) + (field.required ? " · required" : "") +
      "</small></span><code>" + escape(field.type) + "</code></button>").join("");
}

function visibleFields(table) {
  return table.fields.filter(field => $("technical").checked || field.publicInput
    || !field.generated && ["input", "derived", "computed", "output"].includes(field.kind));
}

function dependenciesPanel(table) {
  const dependencies = table.dependencies;
  const calculations = dependencies?.calculations || [];
  let body = "<h3>Evaluation order</h3>" + (calculations.length ? calculations.map((calculation, index) =>
    '<div class="info-card"><strong>' + (index + 1) + ". " + fieldLink(calculation.field) + "</strong>" +
    (calculation.inputs.length ? "<p>Uses " + calculation.inputs.map(fieldLink).join(" ") + "</p>" : "<p>No local field inputs.</p>") + "</div>"
  ).join("") : '<p class="empty-copy">No declared reactive calculations.</p>');
  body += "<h3>Direct parent fields</h3>" + (dependencies?.references?.map(route =>
    '<div class="info-card">' + tableLink(route.table) + "<p>Through " + fieldLink(route.reference) + "</p>" +
    code(route.fields.join("\n")) + "<p>Used by " + route.consumers.map(fieldLink).join(" ") + "</p></div>"
  ).join("") || "<p>No declared scalar routes.</p>");
  body += "<h3>Ordered queries</h3>" + (dependencies?.queries?.map(query => {
    const field = table.fields.find(field => field.name === query.field);
    return '<div class="info-card">' + badge(query.operation, "blue") + badge(query.phase === "validate" ? "validation" : "calculation") +
      "<strong>" + fieldLink(query.field) + "</strong>" + query.sources.map(item => tableLink(item.table, item.root)).join("") +
      "<p>Descriptor specifies the source, bounds, projection and fallback.</p>" +
      (field?.expression ? code(field.expression) + helperLinks(field.expression) : "") + "</div>";
  }).join("") || "<p>No declared ordered queries.</p>");
  const downstream = state.catalog.tables.flatMap(consumer => (consumer.dependencies?.references || [])
    .filter(route => route.table === table.name)
    .map(route => '<div class="info-card">' + tableLink(consumer.name) + "<p>Reads " + escape(route.fields.join(", ")) +
      " through " + escape(route.reference) + "</p>" + route.consumers.map(field => tableLink(consumer.name, field, field)).join("") + "</div>"));
  body += "<details><summary>Downstream scalar consumers (" + downstream.length + ")</summary>" + downstream.join("") + "</details>";
  return body + recordForm(table);
}

function treesPanel(table) {
  const roots = state.catalog.roots.filter(root => root.table === table.name && ($("technical").checked || !root.generated));
  const memberships = state.catalog.memberships.filter(member => member.table === table.name && ($("technical").checked || !member.generated));
  let body = "<h3>Roots owned by this table</h3>" + (roots.map(root => {
    const reads = state.catalog.tables.flatMap(consumer => (consumer.dependencies?.queries || [])
      .filter(query => query.sources.some(item => item.table === table.name && item.root === root.field))
      .map(query => tableLink(consumer.name, query.field)));
    return '<div class="info-card">' + badge(root.unique ? "unique keys" : "duplicate keys") +
      "<strong>" + escape(root.field) + "</strong><p>Key: " + escape(root.key.join(", ")) + "</p>" +
      "<details" + (state.field === root.field ? " open" : "") + "><summary>Participants (" + root.members.length + " slots)</summary>" +
      root.members.map(id => { const member = state.catalog.memberships.find(member => member.id === id); return member ? tableLink(member.table, member.field) : ""; }).join("") +
      "</details><details><summary>Ordered consumers (" + reads.length + ")</summary>" + reads.join("") + "</details></div>";
  }).join("") || "<p>This table owns no declared roots.</p>");
  body += "<h3>Trees this table can participate in</h3><p>These are declared possibilities. The membership function chooses active roots and contributions for each record.</p>" +
    (memberships.map(member => '<div class="info-card"><strong>' + escape(member.field) + "</strong>" +
      member.roots.map(id => { const root = state.catalog.roots.find(root => root.id === id); return root ? tableLink(root.table, root.field) : ""; }).join("") +
      "<p>" + (member.reader ? "Nominates an immediate owner for read access." : "Index membership does not grant read access.") + "</p>" +
      functionLink(member.provider) + "</div>").join("") || "<p>No declared membership slots.</p>");
  body += "<details><summary>Shared aggregation functions</summary><p>The identity, leaf summary and ordered combination are shared by these trees.</p>" +
    Object.entries(state.catalog.monoid || {}).map(([role, name]) => "<p>" + escape(role) + ": " + functionLink(name) + "</p>").join("") + "</details>";
  return body + recordForm(table);
}

function helperLinks(expression) {
  return [...new Set(String(expression).match(/\bfn::[A-Za-z_][\w:]*(?=\s*\()/g) || [])].map(functionLink).join("");
}
function functionDetails(name, open = false) {
  const fn = state.catalog.functions.find(fn => fn.name === name);
  if (!fn) return '<p class="source-location">' + escape(name) + " is a generated or external helper.</p>";
  return "<details" + (open ? " open" : "") + "><summary>" + escape(fn.name) + "</summary>" + source(fn.source) +
    code(fn.name + "(" + fn.parameters + ") {\n" + fn.body + "\n}") + (fn.calls || []).map(functionLink).join("") + "</details>";
}
function sourcePanel(table) {
  const names = new Set([table.dependencies?.memberships, table.dependencies?.invariant, table.dependencies?.requiredOutputs].filter(Boolean));
  for (const field of table.fields) for (const name of field.expression?.match(/\bfn::[A-Za-z_][\w:]*(?=\s*\()/g) || []) names.add(name);
  return source(table.source) +
    (table.dependencies?.invariant ? "<h3>Invariant</h3>" + functionLink(table.dependencies.invariant) : "") +
    (table.effect ? "<h3>Effect contract</h3>" + json(table.effect) : "") +
    (state.activeFunction ? "<h3>Selected function</h3>" + functionDetails(state.activeFunction, true) : "") +
    "<h3>Declared helpers</h3>" + [...names].map(name => functionDetails(name)).join("") +
    (table.view ? "<h3>View definition</h3>" + code(table.view.definition) : "") +
    "<details><summary>Native indexes (" + table.indexes.length + ")</summary>" + table.indexes.map(index => code(index.definition)).join("") + "</details>" +
    (table.schema ? "<details><summary>Public input JSON Schema</summary>" + json(table.schema) + "</details>" : "<p>No public input JSON Schema is published for this table.</p>") +
    (table.comment ? "<details><summary>Table annotations</summary>" + code(table.comment) + "</details>" : "");
}
function recordForm(table) {
  return "<h3>Inspect a record's calculated state</h3><p>" +
    (state.db ? "Read the actual queries and tree slots within " + escape(state.settings.tenant) + "." : "Connect to inspect actual query values and tree memberships.") +
    "</p>" + (state.db ? '<form id="record-form" class="record-form"><input id="record-id" aria-label="Record ID" placeholder="' +
      escape(table.name + ":…") + '" required><button>Read</button></form><div id="record-result"></div>' : "");
}

function renderSelection() {
  $("detail-tabs").hidden = state.mode !== "schema" || !state.selection;
  if (!state.selection) {
    $("selection-title").innerHTML = "<h2>See how it connects</h2><p>Select a table, field or connection.</p>";
    $("detail-body").innerHTML = state.mode === "schema" && state.catalog ?
      '<div class="info-card"><strong>' + state.catalog.tables.length + " tables and views</strong><p>" +
      state.catalog.roots.filter(root => !root.generated).length + " declared tree roots · " +
      state.catalog.tables.reduce((sum, table) => sum + (table.dependencies?.queries.length || 0), 0) + " ordered query slots</p></div>" +
      "<p>Use References for structure, Calculations for inputs and consumers, and Tree memberships for contributions.</p>" +
      "<p>Colors identify tables. A split swatch lists the alternatives of a polymorphic reference.</p>" :
      "<p>Access follows direct parents from a tenant through groups and users. A snapshot contains only the records visible to its login and within its stated limit.</p>";
    return;
  }
  if (state.mode === "access") {
    const row = state.access?.records.find(row => row.id === state.selection);
    $("selection-title").innerHTML = "<h2>" + escape(row?.name || state.selection) + "</h2><p>" + escape(state.selection) + "</p>";
    $("detail-body").innerHTML = row ? badge(row.table.replace("rebase_", ""), "blue") +
      (row.login_access === false ? badge("login disabled", "amber") : "") +
      "<h3>Direct parents</h3>" + (row.parents.map(id => '<button class="reference-link" data-select="' + escape(id) + '">' + escape(id) + "</button>").join("") || "<p>Tenant root.</p>") +
      "<h3>" + (row.table === "rebase_user" ? "Effective permissions" : "Role") + "</h3>" +
      "<p>Read from the database; graph reachability alone does not grant these permissions.</p>" +
      json(row.permissions || row.role || []) + "<details><summary>Snapshot fields</summary>" + json(row) + "</details>" :
      "<p>This parent was not loaded. It may be outside the read limit, unavailable, or not visible to the login.</p>";
    return;
  }
  const table = state.catalog.tables.find(table => table.name === state.selection);
  if (!table) {
    $("detail-tabs").hidden = true;
    $("selection-title").innerHTML = "<h2>" + escape(state.selection) + "</h2>";
    $("detail-body").innerHTML = "<p>This reference target is not declared in the current catalog.</p>";
    return;
  }
  $("selection-title").innerHTML = "<h2>" + escape(table.name) + "</h2>" + badge(table.group) + badge(table.kind) +
    badge(visibleFields(table).length + " visible fields");
  for (const button of document.querySelectorAll("[data-tab]")) button.setAttribute("aria-pressed", String(button.dataset.tab === state.tab));
  $("detail-body").innerHTML = state.tab === "fields" ? fieldsPanel(table)
    : state.tab === "dependencies" ? dependenciesPanel(table)
    : state.tab === "trees" ? treesPanel(table) : sourcePanel(table);
  const form = $("record-form");
  if (form) form.onsubmit = async event => {
    event.preventDefault();
    const id = $("record-id").value, epoch = state.epoch, request = ++state.read;
    const result = $("record-result"), db = state.db;
    result.textContent = "Reading…";
    try {
      const record = await readRecordState(db, table, id, state.settings.tenant);
      if (epoch === state.epoch && request === state.read && result.isConnected) result.innerHTML = json(record);
    } catch (error) {
      if (epoch === state.epoch && request === state.read && result.isConnected) result.textContent = error.message;
    }
  };
}

function setMode(mode) {
  state.mode = mode; state.selection = null; state.field = null; state.focus = "all"; state.read++;
  $("search").value = "";
  renderDiagram();
}
function loadCatalog(value) {
  state.catalog = validateCatalog(value);
  colors = palette(state.catalog.tables.map(table => table.name), state.catalog.project);
  $("group-filter").value = "all";
  setMode("schema"); notice();
}
async function disconnect() {
  state.epoch++; state.request++; state.read++;
  const previous = state.db; state.db = null; state.settings = null; state.access = null;
  if (state.mode === "access") state.selection = null;
  renderDiagram();
  if (previous) await previous.close();
}
async function openFile(file) {
  if (!file) return;
  try {
    const value = JSON.parse(await file.text());
    if (value.format === "rebase-access") {
      validateAccess(value);
      await disconnect();
      state.access = value; setMode("access");
      notice(value.truncated ? "This saved snapshot reached its read limit; some records are not loaded." : "Opened a saved access snapshot.", value.truncated ? "warning" : "");
    } else { validateCatalog(value); await disconnect(); loadCatalog(value); }
  } catch (error) { notice(error.message, "error"); }
}

cy.on("tap", "node", event => select(event.target.id()));
cy.on("tap", "edge", event => select(event.target.target().id(), event.target.data("field") || null));
cy.on("tap", event => { if (event.target === cy) select(null); });
$("search").oninput = renderNavigation;
$("group-filter").onchange = () => { renderNavigation(); applyFocus(); layoutVisible(); };
$("layer").onchange = renderDiagram;
$("technical").onchange = renderDiagram;
for (const [name, layout] of Object.entries(layouts)) $("layout").add(new Option(layout.label, name));
$("layout").onchange = layoutVisible;
$("fit").onclick = layoutVisible;
$("schema-mode").onclick = () => setMode("schema");
$("access-mode").onclick = () => setMode("access");
$("clear-selection").onclick = () => select(null);
$("open-file").onclick = () => $("file-input").click();
$("file-input").onchange = event => { openFile(event.target.files[0]); event.target.value = ""; };
$("export-file").onclick = () => {
  const value = state.mode === "schema" ? state.catalog : state.access;
  if (value) download((state.mode === "schema" ? state.catalog.project : "access") + ".json", JSON.stringify(value, null, 2));
  else notice("Load a catalog or access snapshot first.");
};
$("export-image").onclick = () => {
  if (!cy.nodes().length) return;
  const link = document.createElement("a");
  link.href = cy.png({ bg: "#f8fafc", scale: 2 }); link.download = "rebase-graph.png"; link.click();
};
document.addEventListener("click", event => {
  const button = event.target.closest("button");
  if (!button) return;
  if (button.dataset.select) select(button.dataset.select, null, true);
  if (button.dataset.table) {
    $("group-filter").value = "all";
    select(button.dataset.table, button.dataset.targetField || null, true);
  }
  if (button.dataset.field) select(state.selection, button.dataset.field);
  if (button.dataset.function) { state.tab = "source"; state.activeFunction = button.dataset.function; state.read++; renderSelection(); }
  if (button.dataset.tab) { state.tab = button.dataset.tab; state.read++; renderSelection(); }
  if (button.dataset.focus) {
    state.focus = button.dataset.focus; applyFocus(); layoutVisible();
  }
});
document.addEventListener("keydown", event => {
  if (event.key === "Escape" && !$("connection-dialog").open && !["INPUT", "SELECT", "TEXTAREA"].includes(event.target.tagName)) select(null);
});
$("connect").onclick = () => { $("connection-error").textContent = ""; $("connection-dialog").showModal(); };
function closeConnectionDialog() {
  // A cancelled login must not replace a newer connection when it finishes.
  if (!state.db) state.epoch++;
  $("connection-form").elements.password.value = "";
  $("connection-form").elements.token.value = "";
  $("connect-submit").disabled = false;
  $("connection-dialog").close();
}
$("close-dialog").onclick = closeConnectionDialog;
$("connection-dialog").addEventListener("cancel", event => { event.preventDefault(); closeConnectionDialog(); });
$("authentication").onchange = event => {
  $("server-auth").hidden = event.target.value === "token";
  $("token-auth").hidden = event.target.value !== "token";
};
$("disconnect").onclick = () => disconnect().then(() => notice("Disconnected.")).catch(error => notice(error.message, "error"));
$("connection-form").onsubmit = async event => {
  event.preventDefault();
  if ($("connect-submit").disabled) return;
  const options = Object.fromEntries(new FormData(event.target));
  options.limit = Number(options.limit);
  if (options.authentication === "server") delete options.token;
  else { delete options.username; delete options.password; }
  $("connect-submit").disabled = true; $("connection-error").textContent = "Connecting…";
  const closing = disconnect();
  const epoch = state.epoch;
  try {
    await closing;
    if (epoch !== state.epoch) return;
    const { db, snapshot } = await connectAccess(options);
    if (epoch !== state.epoch) { await db.close(); return; }
    state.db = db; state.access = snapshot;
    state.settings = { tenant: snapshot.tenant, limit: options.limit };
    closeConnectionDialog();
    setMode("access");
    notice(snapshot.truncated ? "Read limit reached. Some users or groups are not loaded; increase the limit to include more."
      : "Loaded records visible to this login. The inspector performs no writes.", snapshot.truncated ? "warning" : "");
  } catch (error) {
    if (epoch === state.epoch) $("connection-error").textContent = error.message;
  } finally {
    if (epoch === state.epoch) {
      $("connection-form").elements.password.value = "";
      $("connection-form").elements.token.value = "";
      $("connect-submit").disabled = false;
    }
  }
};
$("refresh-access").onclick = async () => {
  const epoch = state.epoch, request = ++state.request;
  const db = state.db, settings = state.settings;
  if (!db) return;
  $("refresh-access").disabled = true;
  try {
    const snapshot = await readAccess(db, settings.tenant, settings.limit);
    if (epoch !== state.epoch || request !== state.request) return;
    state.access = snapshot; renderDiagram();
    notice(snapshot.truncated ? "Read limit reached; some records are not loaded." : "Access snapshot refreshed.", snapshot.truncated ? "warning" : "");
  } catch (error) {
    if (epoch === state.epoch && request === state.request) notice(error.message, "error");
  } finally {
    if (epoch === state.epoch && request === state.request) $("refresh-access").disabled = !state.db;
  }
};
document.addEventListener("dragover", event => {
  if (event.dataTransfer.types.includes("Files")) { event.preventDefault(); $("drop-target").hidden = false; }
});
document.addEventListener("dragleave", event => { if (!event.relatedTarget) $("drop-target").hidden = true; });
document.addEventListener("drop", event => {
  event.preventDefault(); $("drop-target").hidden = true; openFile(event.dataTransfer.files[0]);
});
window.addEventListener("beforeunload", () => { state.epoch++; if (state.db) state.db.close(); });
let resizeFrame;
new ResizeObserver(() => {
  cy.resize(); cancelAnimationFrame(resizeFrame);
  resizeFrame = requestAnimationFrame(layoutVisible);
}).observe($("cy"));
try {
  const embedded = JSON.parse($("rebase-catalog").textContent);
  if (embedded) loadCatalog(embedded); else renderDiagram();
} catch (error) { renderDiagram(); notice(error.message, "error"); }
