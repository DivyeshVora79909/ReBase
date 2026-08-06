const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { buildIndexedPermissionQuery } = require("../scripts/benchmark-permissions");
const { compileProject } = require("../src/compiler");
const { parseCliArgs } = require("../src/project");
const { parseSchema, resolveRecordTargets } = require("../src/schema");

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
  const result = compileProject({
    projectDir: "designs/test",
    outputDir,
    includeArrayReaders: false,
    check: false,
  });

  assert.equal(result.viewCount, 8);
  const bundle = fs.readFileSync(path.join(outputDir, "schema.surql"), "utf8");
  const optimizer = JSON.parse(fs.readFileSync(path.join(outputDir, "optimizer.json"), "utf8"));

  assert.equal(result.tableCount, 7);
  assert.doesNotMatch(bundle, /idx_user_parents/);
  assert.doesNotMatch(bundle, /send_reset_email|password_management/);
  assert.match(bundle, /DEFINE TABLE setting SCHEMAFULL/);
  assert.match(bundle, /DEFINE FIELD scope ON setting TYPE record[\s\S]+REFERENCE ON DELETE CASCADE/);
  assert.match(bundle, /DEFINE FIELD values ON setting TYPE object FLEXIBLE/);
  assert.match(bundle, /DEFINE FIELD secrets ON setting TYPE object FLEXIBLE[\s\S]+FOR select NONE/);
  assert.match(bundle, /setting_scope_key ON setting FIELDS scope, key UNIQUE/);
  assert.match(bundle, /idx_setting_readers[^\n]+readers_index\.\*/);
  assert.match(bundle, /idx_test_primitive_readers[^\n]+readers_index\.\*/);
  assert.match(bundle, /idx_test_primitive_owned_by/);
  assert.match(bundle, /c_v_test_prim_target ON TABLE test_primitive/);
  assert.match(bundle, /c_v_test_creator_user ON TABLE user/);
  assert.match(bundle, /ping_v_test_prim_target[\s\S]+LET \$__rebase_halt_cascade = true/);
  assert.match(bundle, /rebase_cascade_downward[\s\S]+LET \$__rebase_halt_cascade = true/);
  assert.ok(!fs.existsSync(path.join(outputDir, "manifest.json")));
  assert.match(optimizer.findings[0].observedPlan, /TableScan/);
});

test("permission benchmark binds scalar ACL keys into one OR query", () => {
  const query = buildIndexedPermissionQuery(2, true);
  assert.match(query, /LET \$rebase_access_0 = \$auth\.z_access_index\[0\]/);
  assert.match(query, /readers_index CONTAINS \$rebase_access_0 OR readers_index CONTAINS \$rebase_access_1/);
  assert.match(query, /LIMIT 50 EXPLAIN FULL;/);
});

test("deployment preserves schema events and field processing", () => {
  const deploy = fs.readFileSync(path.join(__dirname, "../scripts/deploy.js"), "utf8");
  assert.match(deploy, /surreal\("validate"/);
  assert.match(deploy, /surreal\("sql"/);
  assert.doesNotMatch(deploy, /surreal\("import"/);
});
