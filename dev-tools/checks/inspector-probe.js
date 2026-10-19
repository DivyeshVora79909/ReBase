#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { parseArgs } = require("node:util");
const { chromium } = require("playwright");
const { Surreal, RecordId } = require("surrealdb");
const { build, prepare } = require("../index");
const { buildInspector } = require("../inspector/build");
const { readAccess, readRecordState } = require("../inspector/access");
const { start } = require("../temporal-tree/harness");
const { resolveConfiguration } = require("../../config/environment");

async function main() {
  const { values } = parseArgs({ options: { screenshots: { type: "string" } } });
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-inspector-"));
  const configuration = resolveConfiguration({ NODE_ENV: "test" });
  let browser, server, db;
  const report = { offline: [], native: [], browser: [] };
  try {
    const accounting = build({ project: "all-in-accounting", explain: "*", configuration });
    const accountingFile = path.join(temporary, "accounting.html");
    fs.writeFileSync(accountingFile, buildInspector(accounting.catalog));
    const compiled = build({ project: "index-analytics", outputDir: path.join(temporary, "analytics"), configuration });
    browser = await chromium.launch({ headless: true,
      ...(process.env.REBASE_BROWSER_EXECUTABLE ? { executablePath: process.env.REBASE_BROWSER_EXECUTABLE } : {}),
    });
    const page = await browser.newPage({ viewport: { width: 1500, height: 950 } });
    const errors = [], external = [];
    page.on("pageerror", error => errors.push(error.message));
    page.on("request", request => { if (/^https?:/.test(request.url())) external.push(request.url()); });
    await page.goto(pathToFileURL(accountingFile).href);
    await page.locator('#table-list [data-select="sales_issue"]').waitFor();
    assert.equal(await page.locator("#table-list button").count(), 65);
    assert.deepEqual(external, [], "standalone page makes no CDN or HTTP requests");
    await page.locator('#table-list [data-select="sales_issue"]').click();
    const neighborhood = await page.evaluate(() => {
      const graph = document.getElementById("cy")._cyreg.cy;
      return { count: graph.nodes(":visible").length, width: graph.getElementById("sales_issue").renderedWidth(),
        parent: graph.getElementById("stock_account").position("y"), child: graph.getElementById("sales_issue").position("y") };
    });
    assert.equal(neighborhood.count, 8);
    assert(neighborhood.width > 100, "selecting a table lays out a readable neighborhood");
    assert(neighborhood.parent < neighborhood.child, "parents appear above their dependents");
    await page.locator('[data-field="stock_account"]').click();
    assert.match(await page.locator(".field-detail").innerText(), /misc_stock_account/);
    assert.match(await page.locator(".field-detail").innerText(), /stock_account/);
    const gradient = await page.locator('[data-field="stock_account"] .swatch').evaluate(node => node.style.background);
    assert.match(gradient, /linear-gradient/);
    await page.locator('[data-tab="dependencies"]').click();
    assert.match(await page.locator("#detail-body").innerText(), /q_stock_reporting/);
    assert.match(await page.locator("#detail-body").innerText(), /latest/);
    await page.locator('[data-tab="trees"]').click();
    assert.match(await page.locator("#detail-body").innerText(), /z_invoice/);
    await page.locator('[data-function="fn::accounting::issue_members"]').first().click();
    assert.match(await page.locator("#detail-body").innerText(), /fn::accounting::commercial/);
    report.offline.push("all 65 tables", "polymorphic colors", "queries and memberships", "function source");
    for (const layer of ["calculations", "memberships", "access", "views", "all", "references"]) {
      await page.locator("#layer").selectOption(layer);
      assert.match(await page.locator("#graph-count").textContent(), /nodes/);
    }
    await page.locator("#technical").check();
    await page.locator("#technical").uncheck();
    await page.locator("#search").fill("rebase_group");
    await page.locator('#table-list [data-select="rebase_group"]').focus();
    await page.keyboard.press("Enter");
    assert.match(await page.locator("#selection-title").textContent(), /rebase_group/);
    await page.locator("#search").fill("");
    const [saved] = await Promise.all([
      page.waitForEvent("download"), page.locator("#export-file").click(),
    ]);
    const exported = JSON.parse(fs.readFileSync(await saved.path(), "utf8"));
    assert.equal(exported.format, "rebase-devtools");
    assert.equal(exported.tables.length, 65);
    await page.locator("#file-input").setInputFiles({ name: "bad.json", mimeType: "application/json", buffer: Buffer.from('{"version":0}') });
    await page.locator("#notice.error").waitFor();
    assert.equal(await page.locator("#table-list button").count(), 65, "bad input preserves the current graph");
    if (values.screenshots) {
      fs.mkdirSync(values.screenshots, { recursive: true });
      await page.locator("#file-input").setInputFiles({ name: "catalog.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(accounting.catalog)) });
      await page.locator('#table-list [data-select="sales_issue"]').click();
      await page.locator('[data-field="stock_account"]').click();
      await page.screenshot({ path: path.join(values.screenshots, "schema-desktop.png") });
    }
    await page.setViewportSize({ width: 430, height: 860 });
    await page.waitForFunction(() => document.documentElement.scrollWidth <= innerWidth);
    if (values.screenshots) await page.screenshot({ path: path.join(values.screenshots, "schema-mobile.png") });
    await page.setViewportSize({ width: 1500, height: 950 });
    report.browser.push("layers", "keyboard navigation", "snapshot export", "malformed import", "mobile layout");
    assert.deepEqual(errors, []);

    const payload = '</script><script>globalThis.inspectorUntrusted = true</script><img src=x onerror="globalThis.inspectorUntrusted = true">';
    const cyclic = { format: "rebase-devtools", version: 1, project: "cycles", roots: [], memberships: [], monoid: {},
      functions: [{ name: "fn::example", body: payload, parameters: "", calls: [] }],
      tables: ["cycle_a", "cycle_b", "isolated"].map((name, index) => ({
        name, kind: "table", group: "project", indexes: [], comment: payload,
        fields: index < 2 ? [{ name: "parent", type: "record", kind: "input", expression: "fn::example()",
          reference: { targets: [index ? "cycle_a" : "cycle_b"] } }] : [],
      })),
    };
    const cyclicFile = path.join(temporary, "cycles.html");
    fs.writeFileSync(cyclicFile, buildInspector(cyclic));
    await page.goto(pathToFileURL(cyclicFile).href);
    await page.locator('[data-select="cycle_a"]').click();
    assert.match(await page.locator("#legend").textContent(), /1 cyclic component/);
    assert.equal(await page.locator("#table-list button").count(), 3);
    await page.locator('[data-tab="source"]').click();
    await page.locator("#detail-body details").first().locator("summary").click();
    assert.match(await page.locator("#detail-body").textContent(), /globalThis.inspectorUntrusted/);
    assert.equal(await page.evaluate(() => globalThis.inspectorUntrusted), undefined);
    assert.deepEqual(external, [], "displaying imported source never executes it");
    report.browser.push("cycles and isolated tables", "inert imported source");

    console.log("PASS standalone schema browsing and browser interactions");
    server = await start({ engine: "memory" });
    db = new Surreal();
    await db.connect(server.url.replace(/^http/, "ws") + "/rpc");
    await db.signin({ username: "root", password: "root" });
    await db.query("DEFINE NAMESPACE inspector; USE NS inspector; DEFINE DATABASE inspector;");
    await db.use({ namespace: "inspector", database: "inspector" });
    await prepare(db, { schema: compiled.bundle });
    await db.query([
      "CREATE rebase_tenant:one SET name = 'Tenant One';",
      "CREATE rebase_tenant:two SET name = 'Tenant Two';",
      "CREATE rebase_group:a SET name = 'Finance', parents = [rebase_tenant:one], role = ['node_select'];",
      "CREATE rebase_group:b SET name = 'Operations', parents = [rebase_tenant:one], role = ['node_select'];",
      "CREATE rebase_user:alice SET name = 'Alice', parents = [rebase_group:a, rebase_group:b], login_access = false;",
      "CREATE rebase_user:bob SET name = 'Bob', parents = [rebase_group:a], login_access = false;",
      "CREATE rebase_user:other SET name = 'Other tenant', parents = [rebase_tenant:two], login_access = false;",
    ].join("\n"));
    await db.query("CREATE $id SET name = 'Numeric identity', parents = [rebase_group:a], login_access = false;", { id: new RecordId("rebase_user", 42) });
    const snapshot = await readAccess(db, "rebase_tenant:one", 100);
    assert.equal(snapshot.records.length, 6);
    assert(!snapshot.records.some(row => row.name === "Other tenant"));
    assert(snapshot.records.some(row => row.id === "rebase_user:42"));
    assert.deepEqual(snapshot.records.find(row => row.id === "rebase_user:alice").parents, ["rebase_group:a", "rebase_group:b"]);
    assert.deepEqual(snapshot.records.find(row => row.id === "rebase_user:alice").permissions, ["node_select"]);
    const limited = await readAccess(db, "rebase_tenant:one", 1);
    assert.equal(limited.truncated, true);
    assert.equal(limited.records.length, 3);
    await assert.rejects(readAccess(db, "rebase_user:alice"), /rebase_tenant/);
    await assert.rejects(readAccess(db, "rebase_tenant:missing"), /not found/);
    const compound = new RecordId("rebase_tenant", ["compound", "tenant"]);
    await db.query("CREATE $id SET name = 'Compound key';", { id: compound });
    assert.equal((await readAccess(db, String(compound))).records.length, 1);
    const table = compiled.catalog.tables.find(table => table.name === "rebase_tenant");
    const actual = await readRecordState(db, table, "rebase_tenant:one", "rebase_tenant:one");
    assert(actual.z_auth_identifiers);
    await assert.rejects(readRecordState(db, table, "rebase_tenant:two", "rebase_tenant:one"), /outside this tenant/);
    await assert.rejects(readRecordState(db, table, "rebase_user:alice", "rebase_tenant:one"), /different table/);
    report.native.push("tenant isolation", "native numeric and compound keys", "multiple parents", "effective permissions", "explicit truncation", "record tree state");

    await page.goto(pathToFileURL(compiled.artifacts.inspectorPath).href);
    await page.locator("#connect").click();
    const form = page.locator("#connection-form");
    await form.locator('[name="endpoint"]').fill(server.url.replace(/^http/, "ws") + "/rpc");
    await form.locator('[name="namespace"]').fill("inspector");
    await form.locator('[name="database"]').fill("inspector");
    await form.locator('[name="tenant"]').fill("rebase_tenant:one");
    await form.locator('[name="username"]').fill("root");
    await form.locator('[name="password"]').fill("wrong");
    await form.locator('button[type="submit"]').click();
    await page.waitForFunction(() => !document.getElementById("connect-submit").disabled);
    assert.match(await page.locator("#connection-error").textContent(), /auth|credentials|signin|sign in/i);
    await form.locator('[name="password"]').fill("root");
    await form.locator('button[type="submit"]').click();
    await page.waitForFunction(() => document.getElementById("connection-state").textContent === "Connected");
    assert.equal(await form.locator('[name="password"]').inputValue(), "");
    assert.equal(await page.locator("#table-list button").count(), 6);
    await page.locator('[data-select="rebase_user:alice"]').click();
    assert.match(await page.locator("#detail-body").textContent(), /node_select/);
    const [accessFile] = await Promise.all([page.waitForEvent("download"), page.locator("#export-file").click()]);
    const access = JSON.parse(fs.readFileSync(await accessFile.path(), "utf8"));
    assert.equal(access.format, "rebase-access");
    assert(!JSON.stringify(access).includes("password"));
    if (values.screenshots) await page.screenshot({ path: path.join(values.screenshots, "access-desktop.png") });
    await page.locator("#schema-mode").click();
    await page.locator('[data-select="rebase_tenant"]').click();
    await page.locator('[data-tab="trees"]').click();
    await page.locator("#record-id").fill("rebase_tenant:one");
    await page.locator("#record-form button").click();
    await page.locator("#record-result pre").waitFor();
    assert.match(await page.locator("#record-result").textContent(), /z_auth_identifiers/);
    await page.locator("#disconnect").click();
    await page.waitForFunction(() => document.getElementById("connection-state").textContent === "Offline");
    await page.locator("#file-input").setInputFiles({ name: "access.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(access)) });
    await page.locator('[data-select="rebase_user:alice"]').waitFor();
    assert.equal(await page.locator("#connection-state").textContent(), "Offline");
    report.browser.push("native login and failure", "access graph", "credentials cleared", "record state", "offline access import");

    // Hold a real server response, cancel that login, then deliver its late result.
    // A newly opened dialog must retain its input and the cancelled client closes.
    const held = Promise.withResolvers(), closed = Promise.withResolvers();
    let release;
    await page.routeWebSocket("**/rpc", route => {
      const upstream = route.connectToServer(), messages = [];
      let paused = true;
      upstream.onMessage(message => {
        if (paused) { messages.push(message); held.resolve(); }
        else route.send(message);
      });
      release = () => { paused = false; for (const message of messages) route.send(message); };
      route.onClose(async (code, reason) => { await upstream.close({ code, reason }); closed.resolve(); });
    });
    await page.locator("#connect").click();
    await form.locator('[name="password"]').fill("root");
    await form.locator('button[type="submit"]').click();
    await held.promise;
    await page.locator("#close-dialog").click();
    await page.locator("#connect").click();
    await form.locator('[name="password"]').fill("new dialog input");
    release();
    await closed.promise;
    assert.equal(await page.locator("#connection-state").textContent(), "Offline");
    assert.equal(await form.locator('[name="password"]').inputValue(), "new dialog input");
    await page.locator("#close-dialog").click();
    report.browser.push("cancelled login cannot restore stale state or clear newer input");
    assert.deepEqual(errors, []);
    console.log("PASS native access and connected/offline inspector flows");
    console.log(JSON.stringify(report, null, 2));
  } finally {
    if (browser) await browser.close();
    if (db) await db.close();
    if (server) await server.close();
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { main };
