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

test("exports only authored schemas as byte-identical client artifacts", (t) => {
  const root = temporaryDirectory();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const outputDir = path.join(root, "build", "client", "schemas");

  const result = writeClientSchemas({ sourceDir: accountingSchemas, outputDir });
  assert.equal(result.schemas.length, 5);
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
  const expected = [
    "cash_in.schema.json",
    "currency.schema.json",
    "organization.schema.json",
    "treasury.schema.json",
    "treasury_account.schema.json",
  ];
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

test("accounting fixture validates the same input schemas and binds native SDK values", () => {
  const rows = prepareFixture();
  assert.equal(rows.length, 6);
  assert(rows[0].id instanceof RecordId);
  assert.equal(String(rows[0].id), "organization:demo_owner");
  assert(rows[4].content.economic_entity instanceof RecordId);
  assert.equal(String(rows[4].content.economic_entity), "organization:demo_owner");
  assert(rows[5].content.to_account instanceof RecordId);
  assert.equal(String(rows[5].content.to_account), "treasury_account:demo_cash");
  assert(rows[4].content.minimum_balance instanceof Decimal);
  assert(rows[5].content.amount instanceof Decimal);
  assert(rows[5].content.effective_at instanceof Date);
  assert.equal(rows[5].content.effective_at.toISOString(), "2026-10-01T00:00:00.000Z");

  const invalid = structuredClone(fixture[5]);
  invalid.content.amount = "0.00";
  assert.throws(() => prepareFixture([invalid]), /Invalid cash_in input/);
});

test("populate transform defaults to identity, supports overrides, then rejects invalid rows", async () => {
  const catalog = loadClientSchemas(accountingSchemas);
  const schema = catalog.schemas.get("cash_in");
  const input = {
    owned_by: "rebase_group:root",
    from_party: "organization:demo_customer",
    to_account: "treasury_account:demo_cash",
    amount: "42.50",
    effective_at: "2026-10-01T00:00:00Z",
  };

  assert.strictEqual(await prepareDocument(input, {
    table: "cash_in", index: 0, seed: "repeatable", validate: schema.validate,
  }), input);

  let context;
  const adjusted = await prepareDocument(input, {
    table: "cash_in",
    index: 7,
    seed: "repeatable",
    validate: schema.validate,
    transform: async (document, options) => {
      context = options;
      return { ...document, amount: "100.25" };
    },
  });
  assert.deepEqual(context, { table: "cash_in", index: 7, seed: "repeatable" });
  assert.equal(adjusted.amount, "100.25");

  await assert.rejects(() => prepareDocument(input, {
    table: "cash_in",
    index: 0,
    seed: "repeatable",
    validate: schema.validate,
    transform: (document) => ({ ...document, amount: "not-a-decimal" }),
  }), /Generated invalid cash_in/);
});

test("public accounting schemas express client input shape without tree fields or fixture keywords", () => {
  const catalog = loadClientSchemas(accountingSchemas);
  const account = {
    owned_by: "rebase_group:root",
    economic_entity: "organization:demo_owner",
    treasury: "treasury:demo_bank",
    currency: "currency:demo_usd",
    minimum_balance: "0.00",
  };
  assert.strictEqual(assertClientInput(catalog, "treasury_account", account), account);

  const sdkId = new RecordId("organization", Uuid.v7());
  const canonical = String(sdkId);
  assert.match(canonical, /^organization:u"[0-9a-f-]{36}"$/i);
  assert(recordId(canonical).equals(sdkId));
  const canonicalV4 = 'organization:u"550e8400-e29b-41d4-a716-446655440000"';
  assert.equal(String(recordId(canonicalV4)), canonicalV4);
  for (const customKey of [
    "fixture-prefix-0198f92c-8a8a-7abc-8def-0123456789ab-suffix",
    "0198f92c-8a8a-7abc-8def-0123456789ab",
  ]) {
    const original = new RecordId("organization", customKey);
    assert(recordId(String(original)).equals(original));
    assert(recordId(`organization:${customKey}`).equals(original));
  }
  const sdkCustomId = new RecordId("organization", "fixture-prefix-0198f92c-8a8a-7abc-8def-0123456789ab-suffix");
  assertClientInput(catalog, "treasury_account", {
    ...account,
    economic_entity: String(sdkCustomId),
  });
  assertClientInput(catalog, "treasury_account", {
    ...account,
    owned_by: String(new RecordId("rebase_group", Uuid.v7())),
    economic_entity: canonicalV4,
  });

  assert.throws(() => assertClientInput(catalog, "treasury_account", { ...account, z_history: {} }), /Invalid treasury_account input/);
  for (const entry of catalog.schemas.values()) {
    assert.equal(Object.keys(entry.schema.properties).some((field) => field.startsWith("z_")), false);
    assert.equal(Object.keys(entry.schema.properties).some((field) => field.startsWith("x-rebase-")), false);
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
