"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { Decimal, RecordId, Uuid } = require("surrealdb");
const { resolveConfiguration } = require("../../config/environment");
const { buildProject } = require("../compiler/project");
const {
  assertClientInput,
  loadClientSchemas,
  writeClientSchemas,
} = require("../client-schemas");
const { writeArtifacts } = require("../compiler/pipeline");
const { prepareDocument, recordId } = require("../populate");
const { fixture, prepareFixture } = require("../accounting/fixture-example");

const repositoryRoot = path.resolve(__dirname, "../..");
const accountingSchemas = path.resolve(__dirname, "../../designs/all-in-accounting/schemas");
const accountingSchemaFiles = [
  "account_claim.schema.json",
  "account_entry.schema.json",
  "claim_settlement.schema.json",
  "currency.schema.json",
  "direct_tax_account.schema.json",
  "exchange_pair.schema.json",
  "exchange_rate.schema.json",
  "indirect_tax_account.schema.json",
  "invoice_settlement.schema.json",
  "issue_adjustment.schema.json",
  "issue_adjustment_net_tax.schema.json",
  "issue_adjustment_tax.schema.json",
  "issue_net_tax.schema.json",
  "issue_tax.schema.json",
  "item.schema.json",
  "measure_unit.schema.json",
  "misc_currency_account.schema.json",
  "misc_stock_account.schema.json",
  "net_tax_adjustment.schema.json",
  "operating_unit.schema.json",
  "organization.schema.json",
  "organization_currency_account.schema.json",
  "organization_resource_account.schema.json",
  "payment_adjustment.schema.json",
  "payment_withholding.schema.json",
  "production.schema.json",
  "production_capacity.schema.json",
  "production_cost.schema.json",
  "production_input.schema.json",
  "production_output.schema.json",
  "purchase_adjustment_note.schema.json",
  "purchase_invoice.schema.json",
  "purchase_issue.schema.json",
  "resource_exchange.schema.json",
  "sales_adjustment_note.schema.json",
  "sales_invoice.schema.json",
  "sales_issue.schema.json",
  "service.schema.json",
  "stock_account.schema.json",
  "stock_entry.schema.json",
  "subsidiary.schema.json",
  "tax_adjustment.schema.json",
  "tax_adjustment_net_tax.schema.json",
  "tax_deposit.schema.json",
  "tax_offset.schema.json",
  "tax_refund.schema.json",
  "tax_settlement.schema.json",
  "treasury.schema.json"
];

function temporaryDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "rebase-client-schemas-"));
}

function snapshotTree(directory) {
  const entries = [];
  function visit(file, relative = ".") {
    const stat = fs.lstatSync(file);
    const entry = { path: relative, mode: stat.mode };
    if (stat.isSymbolicLink()) entry.target = fs.readlinkSync(file);
    else if (stat.isDirectory()) {
      entry.type = "directory";
      entries.push(entry);
      for (const name of fs.readdirSync(file).sort()) {
        visit(path.join(file, name), path.join(relative, name));
      }
      return;
    } else {
      entry.type = "file";
      entry.contents = fs.readFileSync(file).toString("base64");
    }
    entries.push(entry);
  }
  visit(directory);
  return entries;
}

function validCreateExample(schema) {
  const required = new Set(schema.required || []);
  const properties = { ...(schema.properties || {}) };
  for (const [keyword, pick] of [["oneOf", clauses => clauses[0]], ["anyOf", clauses => clauses[0]]]) {
    const clause = pick(schema[keyword] || []);
    for (const key of clause?.required || []) required.add(key);
    Object.assign(properties, clause?.properties || {});
  }
  const example = {};
  for (const key of required) {
    const property = properties[key] || schema.properties?.[key];
    assert(property, `public contract has a schema for required property ${key}`);
    if (property.enum) example[key] = property.enum[0];
    else if (property.type === "string" && property.format === "date-time") example[key] = "2026-10-05T00:00:00Z";
    else if (property.type === "string" && property.pattern?.includes(":.+$")) {
      const table = property.pattern.match(/^\^\(\?:([^|)]+)/)?.[1];
      assert(table, `record pattern is a supported table union: ${property.pattern}`);
      example[key] = `${table}:example`;
    } else if (property.type === "string" && property.pattern?.includes("[0-9]")) {
      example[key] = "0.5";
    } else if (property.type === "string") example[key] = "example";
    else if (property.type === "integer" || property.type === "number") example[key] = property.minimum ?? 0;
    else if (property.type === "boolean") example[key] = false;
    else assert.fail(`Add a small fixture value for ${key} (${property.type})`);
  }
  return example;
}

test("accounting exports and validates exactly its public create schemas", (t) => {
  const root = temporaryDirectory();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directCatalog = loadClientSchemas(accountingSchemas);
  assert.deepEqual([...directCatalog.schemas.keys()].map(name => `${name}.schema.json`), accountingSchemaFiles);

  for (const [name, entry] of directCatalog.schemas) {
    const valid = validCreateExample(entry.schema);
    assert.doesNotThrow(() => assertClientInput(directCatalog, name, valid), `${name} representative input`);
    assert.equal(Object.keys(entry.schema.properties).some(field => field.startsWith("z_")), false,
      `${name} does not expose internal tree fields`);
    const missingRequired = { ...valid };
    delete missingRequired[entry.schema.required[0]];
    assert.equal(entry.validate(missingRequired), false, `${name} requires ${entry.schema.required[0]}`);
    assert.equal(entry.validate({ ...valid, _unexpected_client_field: true }), false, `${name} rejects unknown inputs`);
  }

  const issue = directCatalog.schemas.get("sales_issue");
  const issueExample = validCreateExample(issue.schema);
  issueExample.price = "0.335";
  assert.doesNotThrow(() => assertClientInput(directCatalog, "sales_issue", issueExample));
  assert.equal(issue.validate({ ...issueExample, owned_by: "untrusted:example" }), false,
    "public create inputs reject unrecognized record table prefixes");
  assert.equal(issue.validate({ ...issueExample, exchange_rate: "exchange_rate:another" }), false,
    "an issue prices directly in its invoice currency; dated rates are derived elsewhere");
  const missingInvoice = { ...issueExample }; delete missingInvoice.invoice;
  assert.equal(issue.validate(missingInvoice), false, "an issue requires its invoice parent");
  const accountEntry = validCreateExample(directCatalog.schemas.get("account_entry").schema);
  accountEntry.account = "organization_currency_account:customer";
  accountEntry.real = "0";
  accountEntry.receivable = "1";
  assert.doesNotThrow(() => assertClientInput(directCatalog, "account_entry", accountEntry),
    "explicit zero is a valid client value when selected");
  const changed = validCreateExample(directCatalog.schemas.get("issue_adjustment").schema);
  Object.assign(changed, { quantity_delta: "-1", price_delta: "0.66" });
  assert.doesNotThrow(() => assertClientInput(directCatalog, "issue_adjustment", changed));
  assert.equal(directCatalog.schemas.get("issue_adjustment").validate({ ...changed, amount_delta: "-0.66" }), false);
  assert.equal(directCatalog.schemas.get("issue_adjustment").validate({ ...changed, quantity_delta: "0", price_delta: "0.00" }), false);
  assert.equal(issue.validate({ ...issueExample, quantity: "-1" }), false);
  assert.equal(issue.validate({ ...issueExample, quantity: "0" }), false);
  assert.equal(issue.validate({ ...issueExample, price: "0" }), true, "zero-priced issues remain valid inputs");

  const payment = validCreateExample(directCatalog.schemas.get("invoice_settlement").schema);
  Object.assign(payment, { fee_account: "misc_currency_account:fees", fee_rate: "0.4",
    fee_tax_rate: "18", fee_tax_creditable: true, fee_tax_account: "indirect_tax_account:input",
    exchange_pair: "exchange_pair:fx" });
  assert.doesNotThrow(() => assertClientInput(directCatalog, "invoice_settlement", payment));
  for (const field of ["fee_amount", "fee_credit_amount", "read_by", "z_payment_currency"]) {
    assert.equal(directCatalog.schemas.get("invoice_settlement").validate({ ...payment, [field]: "1" }), false);
  }
  const adjustment = validCreateExample(directCatalog.schemas.get("issue_adjustment_tax").schema);
  assert.equal(directCatalog.schemas.get("issue_adjustment_tax").validate({ ...adjustment, adjustment_note: "sales_adjustment_note:note" }), false,
    "a rule-linked tax inherits the adjustment note rather than accepting a second grouping input");
  assert.equal(directCatalog.schemas.get("issue_adjustment_tax").validate({ ...adjustment, source_tax: "issue_net_tax:net" }), false,
    "base-tax and net-tax adjustments have distinct typed source references");

  const outputDir = path.join(root, "build", "accounting", "client", "schemas");
  const exported = writeClientSchemas({ sourceDir: accountingSchemas, outputDir });
  assert.deepEqual(exported.schemas, accountingSchemaFiles);
  assert.deepEqual(fs.readdirSync(outputDir).sort(), accountingSchemaFiles);
  for (const file of accountingSchemaFiles) {
    assert.deepEqual(fs.readFileSync(path.join(outputDir, file)), fs.readFileSync(path.join(accountingSchemas, file)));
  }
  assert.deepEqual(writeClientSchemas({ sourceDir: accountingSchemas, outputDir, check: true }).schemas,
    accountingSchemaFiles);

  const buildOutput = path.join(root, "direct-profile-build");
  const result = buildProject({
    projectDir: path.resolve(repositoryRoot, "designs/all-in-accounting"),
    frameworkDir: path.resolve(repositoryRoot, "framework"),
    outputDir: buildOutput,
    configuration: resolveConfiguration({ NODE_ENV: "test" }),
  }, repositoryRoot);
  assert.deepEqual(result.clientSchemas.schemas, accountingSchemaFiles);
  const builtClientDir = path.join(buildOutput, "client", "schemas");
  assert.deepEqual(fs.readdirSync(builtClientDir).sort(), accountingSchemaFiles);
  assert.equal(fs.existsSync(path.join(builtClientDir, "rebase_user.schema.json")), false);
  assert.equal(fs.existsSync(path.join(builtClientDir, "issue_return.surql")), false);
});

test("exports only authored schemas as byte-identical client artifacts", (t) => {
  const root = temporaryDirectory();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const outputDir = path.join(root, "build", "client", "schemas");

  const result = writeClientSchemas({ sourceDir: accountingSchemas, outputDir });
  assert.equal(result.schemas.length, accountingSchemaFiles.length);
  for (const file of result.schemas) {
    assert.deepEqual(
      fs.readFileSync(path.join(outputDir, file)),
      fs.readFileSync(path.join(accountingSchemas, file)),
    );
  }
  assert.deepEqual(writeClientSchemas({ sourceDir: accountingSchemas, outputDir, check: true }).schemas, result.schemas);
});

test("buildProject exports only public schemas into each independent build directory", (t) => {
  const root = temporaryDirectory();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const outputs = [path.join(root, "build-a"), path.join(root, "build-b")];
  const expected = accountingSchemaFiles;
  const build = (outputDir, check = false) => buildProject({
    projectDir: path.join(repositoryRoot, "designs/all-in-accounting"),
    frameworkDir: path.join(repositoryRoot, "framework"),
    outputDir,
    check,
    configuration: resolveConfiguration({ NODE_ENV: "test" }),
  }, repositoryRoot);

  for (const outputDir of outputs) {
    const result = build(outputDir);
    const exportedDir = path.join(outputDir, "client", "schemas");
    assert.equal(result.clientSchemas.schemas.length, expected.length);
    assert.deepEqual(fs.readdirSync(exportedDir).sort(), expected);
    assert.equal(fs.existsSync(path.join(exportedDir, "rebase_user.schema.json")), false);
  }
  assert.notEqual(
    path.join(outputs[0], "client", "schemas"),
    path.join(outputs[1], "client", "schemas"),
  );
  assert.doesNotThrow(() => build(outputs[0], true));

  const privateDataOutput = path.join(root, "private-data-profile");
  const privateDataBuild = buildProject({
    projectDir: path.join(repositoryRoot, "designs/test"),
    frameworkDir: path.join(repositoryRoot, "framework"),
    outputDir: privateDataOutput,
    configuration: resolveConfiguration({ NODE_ENV: "test" }),
  }, repositoryRoot);
  assert.equal(privateDataBuild.clientSchemas.schemas.length, 0);
  assert.equal(fs.existsSync(path.join(repositoryRoot, "designs/test/data/rebase_user.schema.json")), true);
  assert.equal(fs.existsSync(path.join(privateDataOutput, "client", "schemas")), false);
});

test("refuses overlapping or symlink-aliased source and output trees before clearing them", (t) => {
  const root = temporaryDirectory();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const sourceDir = path.join(root, "schemas");
  fs.mkdirSync(sourceDir);
  const schemaPath = path.join(sourceDir, "public.schema.json");
  const source = '{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}\n';
  fs.writeFileSync(schemaPath, source);
  const alias = path.join(root, "schema-alias");
  fs.symlinkSync(sourceDir, alias, "dir");

  for (const outputDir of [sourceDir, root, alias]) {
    assert.throws(
      () => writeClientSchemas({ sourceDir, outputDir }),
      /must not overlap/,
    );
    assert.equal(fs.readFileSync(schemaPath, "utf8"), source);
  }
});

test("buildProject rejects overlapping project or framework outputs without changing either tree", (t) => {
  const root = temporaryDirectory();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const projectDir = path.join(root, "project");
  const frameworkDir = path.join(root, "inputs", "framework");
  fs.mkdirSync(path.join(projectDir, "table-handlers"), { recursive: true });
  fs.mkdirSync(path.join(projectDir, "schemas"), { recursive: true });
  fs.mkdirSync(frameworkDir, { recursive: true });
  fs.writeFileSync(path.join(projectDir, "core.surql"), "DEFINE TABLE example SCHEMAFULL;\n");
  fs.writeFileSync(path.join(projectDir, "schemas", "example.schema.json"), "{}\n");
  fs.writeFileSync(path.join(projectDir, "table-handlers", "example.js"), "module.exports = {};\n");
  fs.writeFileSync(path.join(frameworkDir, "schema.surql"), "DEFINE TABLE framework_item SCHEMAFULL;\n");
  const projectAlias = path.join(root, "project-alias");
  const frameworkAlias = path.join(root, "framework-alias");
  fs.symlinkSync(projectDir, projectAlias, "dir");
  fs.symlinkSync(frameworkDir, frameworkAlias, "dir");

  const projectBefore = snapshotTree(projectDir);
  const frameworkBefore = snapshotTree(frameworkDir);
  const configuration = resolveConfiguration({ NODE_ENV: "test" });
  const outputs = [
    projectDir,
    path.join(projectDir, "nested-output"),
    root,
    path.join(root, "inputs"),
    frameworkDir,
    path.join(frameworkDir, "nested-output"),
    projectAlias,
    frameworkAlias,
  ];

  for (const outputDir of outputs) {
    assert.throws(() => buildProject({
      projectDir,
      frameworkDir,
      outputDir,
      configuration,
    }, root), /must not overlap/);
    assert.deepEqual(snapshotTree(projectDir), projectBefore);
    assert.deepEqual(snapshotTree(frameworkDir), frameworkBefore);
  }
});

test("writeArtifacts preflights every copy destination before it writes or prunes", (t) => {
  const root = temporaryDirectory();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, "project", "table-handlers");
  const secondSource = path.join(root, "project", "webhook-handlers");
  const outputDir = path.join(root, "build");
  fs.mkdirSync(source, { recursive: true });
  fs.mkdirSync(secondSource, { recursive: true });
  fs.writeFileSync(path.join(source, "table.js"), "table source\n");
  fs.writeFileSync(path.join(secondSource, "webhook.js"), "webhook source\n");
  const before = [snapshotTree(source), snapshotTree(secondSource)];

  assert.throws(() => writeArtifacts({
    outputDir,
    bundle: "DEFINE TABLE generated SCHEMAFULL;\n",
    contracts: { tables: {} },
    copies: [
      { sourceDir: source, outputDir: secondSource },
      { sourceDir: secondSource, outputDir: path.join(outputDir, "webhook-handlers") },
    ],
  }), /must not overlap/);
  assert.deepEqual([snapshotTree(source), snapshotTree(secondSource)], before);
  assert.equal(fs.existsSync(outputDir), false);
});

test("rejects generated-file symlinks before changing source or existing output", (t) => {
  const root = temporaryDirectory();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const projectDir = path.join(root, "project");
  const outputDir = path.join(root, "build");
  fs.cpSync(path.join(repositoryRoot, "designs/test"), projectDir, { recursive: true });
  const protectedFile = path.join(projectDir, "authoring-notes.txt");
  fs.writeFileSync(protectedFile, "Keep this authoring input.\n");
  const publicOutput = path.join(outputDir, "client", "schemas");
  fs.mkdirSync(publicOutput, { recursive: true });
  fs.writeFileSync(path.join(publicOutput, "stale.schema.json"), "{}\n");

  for (const name of [
    "schema.surql",
    "runtime-contracts.json",
    "migrate-one-shot-backfill.surql",
    "migrate-one-shot-finalize.surql",
  ]) {
    const target = path.join(outputDir, name);
    fs.symlinkSync(protectedFile, target);
    const before = snapshotTree(root);
    for (const check of [false, true]) {
      assert.throws(() => writeArtifacts({ outputDir, bundle: "generated output" }, { check }), /must not be a symbolic link/);
      assert.deepEqual(snapshotTree(root), before);
      assert.throws(() => buildProject({
        projectDir,
        frameworkDir: path.join(repositoryRoot, "framework"),
        outputDir,
        check,
        configuration: resolveConfiguration({ NODE_ENV: "test" }),
      }, root), /must not be a symbolic link/);
      assert.deepEqual(snapshotTree(root), before);
    }
    fs.unlinkSync(target);
  }
});

test("replaces hard-linked generated artifacts without changing authoring input", (t) => {
  const root = temporaryDirectory();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const projectDir = path.join(root, "project");
  const outputDir = path.join(root, "build");
  fs.cpSync(path.join(repositoryRoot, "designs/test"), projectDir, { recursive: true });
  const protectedFile = path.join(projectDir, "authoring-notes.txt");
  fs.writeFileSync(protectedFile, "Keep this authoring input.\n");
  fs.chmodSync(protectedFile, 0o666);
  const protectedMode = fs.statSync(protectedFile).mode & 0o7777;
  const publicOutput = path.join(outputDir, "client", "schemas");
  fs.mkdirSync(publicOutput, { recursive: true });
  fs.writeFileSync(path.join(publicOutput, "stale.schema.json"), "{}\n");
  fs.linkSync(protectedFile, path.join(outputDir, "schema.surql"));
  assert.equal(fs.statSync(protectedFile).nlink, 2);

  const result = buildProject({
    projectDir,
    frameworkDir: path.join(repositoryRoot, "framework"),
    outputDir,
    configuration: resolveConfiguration({ NODE_ENV: "test" }),
  }, root);
  assert.equal(result.schema.tables.size > 0, true);
  assert.equal(fs.readFileSync(protectedFile, "utf8"), "Keep this authoring input.\n");
  assert.equal(fs.statSync(protectedFile).nlink, 1);
  const generatedSchema = path.join(outputDir, "schema.surql");
  assert.match(fs.readFileSync(generatedSchema, "utf8"), /-- REBASE:/);
  assert.equal(fs.statSync(protectedFile).mode & 0o7777, protectedMode);
  assert.equal(fs.statSync(generatedSchema).mode & 0o7777, protectedMode);
  assert.equal(fs.existsSync(publicOutput), false);
  assert.equal(fs.readdirSync(outputDir).some((name) => name.startsWith(".rebase-artifact-")), false);
});

test("buildProject preflights handler aliases before pruning existing public output", (t) => {
  const root = temporaryDirectory();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const projectDir = path.join(root, "project");
  const outputDir = path.join(root, "build");
  fs.cpSync(path.join(repositoryRoot, "designs/test"), projectDir, { recursive: true });
  const schemasOutput = path.join(outputDir, "client", "schemas");
  fs.mkdirSync(schemasOutput, { recursive: true });
  fs.writeFileSync(path.join(schemasOutput, "stale.schema.json"), "{}\n");
  fs.symlinkSync(path.join(projectDir, "table-handlers"), path.join(outputDir, "table-handlers"), "dir");
  const projectBefore = snapshotTree(projectDir);
  const outputBefore = snapshotTree(outputDir);

  assert.throws(() => buildProject({
    projectDir,
    frameworkDir: path.join(repositoryRoot, "framework"),
    outputDir,
    configuration: resolveConfiguration({ NODE_ENV: "test" }),
  }, root), /must not overlap/);
  assert.deepEqual(snapshotTree(projectDir), projectBefore);
  assert.deepEqual(snapshotTree(outputDir), outputBefore);
});

test("rejects unknown source files and unresolved external references without loading them", (t) => {
  const root = temporaryDirectory();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const schemasDir = path.join(root, "schemas");
  fs.mkdirSync(schemasDir);
  fs.writeFileSync(path.join(schemasDir, "notes.md"), "private note");
  assert.throws(() => loadClientSchemas(schemasDir), /only \*\.schema\.json files/);

  fs.rmSync(path.join(schemasDir, "notes.md"));
  fs.writeFileSync(path.join(schemasDir, "example.schema.json"), JSON.stringify({
    $schema: "http://json-schema.org/draft-07/schema#",
    $ref: "https://example.invalid/schema.json",
  }));
  assert.throws(() => loadClientSchemas(schemasDir), /can't resolve reference|resolve ref/i);
});

test("check detects stale public schemas even if the source directory is gone", (t) => {
  const root = temporaryDirectory();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const sourceDir = path.join(root, "missing-source");
  const outputDir = path.join(root, "build", "client", "schemas");
  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(path.join(outputDir, "old.schema.json"), "{}\n");

  assert.throws(() => writeClientSchemas({ sourceDir, outputDir, check: true }), /stale/);
  writeClientSchemas({ sourceDir, outputDir });
  assert.equal(fs.existsSync(outputDir), false);
  assert.deepEqual(writeClientSchemas({ sourceDir, outputDir, check: true }).schemas, []);
});

test("accounting fixture validates native SDK values and explicit temporal sources", () => {
  const rows = prepareFixture();
  assert.equal(rows.length, 17);
  assert(rows[0].id instanceof RecordId);
  assert.equal(String(rows[0].id), "currency:demo_usd");
  const invoice = rows.find(row => row.table === "sales_invoice");
  const issue = rows.find(row => row.table === "sales_issue");
  const payment = rows.find(row => row.table === "invoice_settlement");
  assert(invoice.content.account instanceof RecordId);
  assert(issue.content.counterparty_stock instanceof RecordId);
  assert(issue.content.price instanceof Decimal);
  assert(payment.content.amount instanceof Decimal);
  assert(payment.content.effective_at instanceof Date);
  assert(payment.content.effective_at < issue.content.effective_at, "covered advance uses its real earlier date");
  assert(issue.content.effective_at < invoice.content.invoice_date);
  const invalid = structuredClone(fixture.find(row => row.table === "invoice_settlement"));
  invalid.content.amount = "not-a-decimal";
  assert.throws(() => prepareFixture([invalid]), /Invalid invoice_settlement input/);
});

test("populate transform defaults to identity, supports overrides, then rejects invalid rows", async () => {
  const catalog = loadClientSchemas(accountingSchemas), schema = catalog.schemas.get("invoice_settlement");
  const input = { owned_by: "rebase_tenant:default", invoice: "sales_invoice:demo", treasury: "treasury:demo_cash",
    amount: "42.50", effective_at: "2027-01-02T00:00:00Z" };
  assert.strictEqual(await prepareDocument(input, {table:"invoice_settlement",index:0,seed:"repeatable",validate:schema.validate}),input);
  let context;
  const adjusted = await prepareDocument(input, {table:"invoice_settlement",index:7,seed:"repeatable",validate:schema.validate,
    transform:async(document, options)=>{context=options;return {...document,amount:"100.25"};}});
  assert.deepEqual(context,{table:"invoice_settlement",index:7,seed:"repeatable"});assert.equal(adjusted.amount,"100.25");
  await assert.rejects(()=>prepareDocument(input,{table:"invoice_settlement",index:0,seed:"repeatable",validate:schema.validate,
    transform:document=>({...document,amount:"not-a-decimal"})}),/Generated invalid invoice_settlement/);
});

test("public accounting schemas expose inputs and preserve native record identities", () => {
  const catalog = loadClientSchemas(accountingSchemas);
  const input = {owned_by:"rebase_tenant:default",account:"organization_currency_account:demo_customer",invoice_date:"2027-01-10T00:00:00Z"};
  assert.strictEqual(assertClientInput(catalog,"sales_invoice",input),input);
  const sdkId = new RecordId("organization_currency_account",Uuid.v7()), canonical = String(sdkId);
  assert.match(canonical,/^organization_currency_account:u"[0-9a-f-]{36}"$/i);assert(recordId(canonical).equals(sdkId));
  const canonicalV4 = 'organization_currency_account:u"550e8400-e29b-41d4-a716-446655440000"';
  assert.equal(String(recordId(canonicalV4)),canonicalV4);
  for (const customKey of ["fixture-prefix-0198f92c-8a8a-7abc-8def-0123456789ab-suffix","0198f92c-8a8a-7abc-8def-0123456789ab"]) {
    const original = new RecordId("organization_currency_account",customKey);
    assert(recordId(String(original)).equals(original));assert(recordId(`organization_currency_account:${customKey}`).equals(original));
    assertClientInput(catalog,"sales_invoice",{...input,account:String(original)});
  }
  assertClientInput(catalog,"sales_invoice",{...input,owned_by:String(new RecordId("rebase_group",Uuid.v7())),account:canonicalV4});
  assert.throws(()=>assertClientInput(catalog,"sales_invoice",{...input,z_history:{}}),/Invalid sales_invoice input/);
  for (const entry of catalog.schemas.values()) {
    assert.equal(Object.keys(entry.schema.properties).some(field=>field.startsWith("z_")),false);
    assert.equal(Object.keys(entry.schema.properties).some(field=>field.startsWith("x-rebase-")),false);
  }
});

test("populate recordId converts the actual database string-cast spellings without changing key identity", () => {
  const uuid4 = "550e8400-e29b-41d4-a716-446655440000";
  const uuidRecord = new RecordId("organization", new Uuid(uuid4));
  assert(recordId(`organization:u'${uuid4}'`).equals(uuidRecord));

  const customKey = "fixture-prefix-0198f92c-8a8a-7abc-8def-0123456789ab-suffix";
  const customRecord = new RecordId("treasury", customKey);
  assert(recordId(`treasury:\`${customKey}\``).equals(customRecord));
  assert(recordId(String(customRecord)).equals(customRecord));

  const simpleRecord = new RecordId("organization", "demo_owner");
  assert(recordId("organization:demo_owner").equals(simpleRecord));
});
