const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { buildIndexedPermissionQuery } = require("../scripts/benchmark-permissions");
const { compileProject } = require("../src/compiler");
const { parseCliArgs } = require("../src/project");
const { parseSchema, resolveRecordTargets } = require("../src/schema");

function createProject(config = {}) {
  const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-project-"));
  fs.writeFileSync(path.join(projectDir, "rebase.config.js"), `module.exports = ${JSON.stringify(config)};\n`);
  fs.writeFileSync(path.join(projectDir, "schema.surql"), "DEFINE TABLE note SCHEMAFULL; DEFINE FIELD text ON note TYPE string;\n");
  fs.writeFileSync(path.join(projectDir, "views.surql"), "");
  return projectDir;
}

test("the CLI requires an explicit schema source", () => {
  assert.throws(() => parseCliArgs([]), /--project is required/);
  const args = parseCliArgs(["--project", "schema"]);
  assert.equal(args.projectDir, "schema");
});

test("multiline views resolve direct, nested, and polymorphic record targets", () => {
  const fields = `
    DEFINE TABLE organization SCHEMAFULL;
    DEFINE TABLE person SCHEMAFULL;
    DEFINE TABLE task SCHEMAFULL;
    DEFINE TABLE order SCHEMAFULL;
    DEFINE TABLE order_line SCHEMAFULL;
    DEFINE FIELD a_target ON task TYPE record<organization | person>;
    DEFINE FIELD a_organization ON order TYPE record<organization>;
    DEFINE FIELD a_order ON order_line TYPE record<order>;
  `;
  const views = `
    DEFINE TABLE v_task_target AS
      SELECT a_target AS target, count() AS total
      FROM task
      GROUP BY target;
    DEFINE TABLE v_order_org AS SELECT a_order.a_organization AS org, count() AS total FROM order_line GROUP BY org;
  `;
  const schema = parseSchema(fields, views);
  assert.equal(schema.views.length, 2);
  assert.deepEqual(resolveRecordTargets(schema, "task", "a_target"), ["organization", "person"]);
  assert.deepEqual(resolveRecordTargets(schema, "order_line", "a_order.a_organization"), ["organization"]);
});

test("compilation emits generic permission indexes and target-side computed views", () => {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-compiler-"));
  fs.writeFileSync(path.join(outputDir, "optimizer.json"), "legacy\n");
  fs.writeFileSync(path.join(outputDir, "manifest.json"), "legacy\n");
  const result = compileProject({
    projectDir: "designs/test",
    outputDir,
    includeArrayReaders: false,
    check: false,
  });

  assert.equal(result.viewCount, 8);
  const bundle = fs.readFileSync(path.join(outputDir, "schema.surql"), "utf8");

  assert.equal(result.tableCount, 7);
  assert.doesNotMatch(bundle, /idx_user_parents/);
  assert.doesNotMatch(bundle, /send_reset_email|password_management/);
  assert.match(bundle, /DEFINE TABLE setting SCHEMAFULL/);
  assert.match(bundle, /DEFINE FIELD scope ON setting TYPE record[\s\S]+REFERENCE ON DELETE CASCADE/);
  assert.match(bundle, /DEFINE FIELD values ON setting TYPE object FLEXIBLE/);
  assert.match(bundle, /DEFINE FIELD secrets ON setting TYPE object FLEXIBLE[\s\S]+FOR select NONE/);
  assert.match(bundle, /setting_scope_key ON setting FIELDS scope, key UNIQUE/);
  assert.match(bundle, /idx_setting_primary[^\n]+primary/);
  assert.match(bundle, /idx_setting_readers[^\n]+readers_index\.\*/);
  assert.match(bundle, /idx_test_primitive_readers[^\n]+readers_index\.\*/);
  assert.match(bundle, /idx_test_primitive_owned_by/);
  assert.match(bundle, /owned_by ON TABLE test_primitive TYPE record<user \| groups>/);
  assert.match(bundle, /readers ON TABLE test_primitive TYPE array<record<user \| groups>>/);
  assert.doesNotMatch(bundle, /readers_index ON TABLE test_primitive[^\n]+PERMISSIONS/);
  assert.match(bundle, /FOR create WHERE 'test_primitive_create' IN \$auth\.permissions AND \(owned_by = \$auth OR owned_by IN \$auth\.parents OR owned_by IN \$auth\.dominates\)/);
  assert.match(bundle, /FOR delete WHERE 'test_primitive_delete' IN \$auth\.permissions AND \(owned_by = \$auth OR owned_by IN \$auth\.dominates\)/);
  assert.match(bundle, /\[<string>\$this\.id\][\s\S]+\$this\.parents[\s\S]+\$this\.dominates/);
  assert.match(bundle, /c_v_test_prim_target ON TABLE test_primitive/);
  assert.match(bundle, /c_v_test_creator_user ON TABLE user/);
  assert.match(bundle, /ping_v_test_prim_target[\s\S]+LET \$__rebase_halt_cascade = true/);
  assert.match(bundle, /rebase_cascade_downward[\s\S]+LET \$__rebase_halt_cascade = true/);
  assert.match(bundle, /<~\(setting FIELD primary\)/);
  assert.ok(!fs.existsSync(path.join(outputDir, "manifest.json")));
  assert.ok(!fs.existsSync(path.join(outputDir, "optimizer.json")));
});

test("the public DX surface lists the supported environment and generic commands", () => {
  const envExample = fs.readFileSync(path.join(__dirname, "../.env.example"), "utf8");
  for (const name of [
    "SURREAL_ENDPOINT",
    "SURREAL_USER",
    "SURREAL_PASS",
    "SURREAL_NAMESPACE",
    "SURREAL_DATABASE",
    "REBASE_BUILD_DIR",
    "REBASE_BENCHMARK_SCALES",
    "REBASE_BENCHMARK_MEMBERSHIPS",
    "REBASE_BENCHMARK_SAMPLES",
    "REBASE_BENCHMARK_BATCH_SIZE",
    "REBASE_BENCHMARK_OUTPUT",
  ]) assert.match(envExample, new RegExp(`^${name}=`, "m"));

  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "../package.json"), "utf8"));
  assert.deepEqual(Object.keys(pkg.scripts).sort(), ["benchmark", "build", "check", "test", "verify"]);
  assert.ok(!fs.existsSync(path.join(__dirname, "../scripts/deploy.js")));
  assert.ok(!fs.existsSync(path.join(__dirname, "../scripts/bootstrap-admin.js")));
  assert.ok(!fs.existsSync(path.join(__dirname, "../framework/settings.surql")));
});

test("settings are ordinary project schema rather than a framework table", () => {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-no-settings-"));
  compileProject({ projectDir: createProject(), outputDir, check: false });
  const bundle = fs.readFileSync(path.join(outputDir, "schema.surql"), "utf8");
  assert.doesNotMatch(bundle, /DEFINE TABLE setting SCHEMAFULL/);
});

test("project-wide owner selection is validated and generated", () => {
  const ownerOutput = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-owner-mode-"));
  compileProject({
    projectDir: createProject({ authorization: { selectMode: "owner" } }),
    outputDir: ownerOutput,
    check: false,
  });
  const ownerBundle = fs.readFileSync(path.join(ownerOutput, "schema.surql"), "utf8");
  assert.match(ownerBundle, /FOR select WHERE 'note_select' IN \$auth\.permissions AND \(owned_by = \$auth OR owned_by IN \$auth\.parents OR owned_by IN \$auth\.dominates\)/);

  const readersOutput = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-readers-mode-"));
  compileProject({ projectDir: createProject(), outputDir: readersOutput, check: false });
  const readersBundle = fs.readFileSync(path.join(readersOutput, "schema.surql"), "utf8");
  assert.match(readersBundle, /FOR select WHERE 'note_select' IN \$auth\.permissions AND readers_index CONTAINSANY \$auth\.z_access_index/);

  assert.throws(() => compileProject({
    projectDir: createProject({ authorization: { selectMode: "invalid" } }),
    outputDir: fs.mkdtempSync(path.join(os.tmpdir(), "rebase-invalid-mode-")),
    check: false,
  }), /Invalid authorization\.selectMode/);
});

test("permission benchmark binds scalar ACL keys into one OR query", () => {
  const query = buildIndexedPermissionQuery(2, true);
  assert.match(query, /LET \$rebase_access_0 = \$auth\.z_access_index\[0\]/);
  assert.match(query, /LET \$rebase_access_1 = \$auth\.z_access_index\[1\]/);
  assert.match(query, /readers_index CONTAINS \$rebase_access_0 OR readers_index CONTAINS \$rebase_access_1/);
  assert.match(query, /LIMIT 50 EXPLAIN FULL;/);
});
