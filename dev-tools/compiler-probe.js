#!/usr/bin/env node

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { compileFromArgs, main: compilerMain } = require("./compiler/cli");
const { parseArgs: parseMigrationArgs, runLifecycleMigration } = require("./lifecycle-migration");
const { resolveConfiguration } = require("../config/environment");
const compilerApi = require("./compiler");
const { businessFields } = require('../src/fields');
const { parseSchema } = require('../src/schema');
const { generateSecurity } = require('../src/generators/security');
const { generateRuntimeContracts } = require('../src/generators/effects');
const { classifyMaterials, materialStatements } = require('./compiler/materials');

const ROOT = path.resolve(__dirname, "..");
const FRAMEWORK = path.join(ROOT, "framework");

function schema(effect = "") {
  return `
    DEFINE TABLE rebase_user SCHEMAFULL;
    DEFINE TABLE rebase_group SCHEMAFULL;
    ${effect}
  `;
}

function validEffect(extra = "") {
  return `
    DEFINE TABLE delivery SCHEMAFULL COMMENT '@rebase-effect async @rebase-adapter sendDelivery @rebase-timeout 2s';
    DEFINE FIELD payload ON delivery TYPE string READONLY COMMENT '@rebase-effect-input';
    DEFINE FIELD result ON delivery TYPE option<string> DEFAULT NONE
      PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-effect-output';
    ${extra}
  `;
}

function handler(table = "delivery", body = "return { outcome: 'success', patch: { result: record.payload } };") {
  return `module.exports = { table: '${table}', on: { async CREATE({ record }) { ${body} } } };\n`;
}

function project(root, source, handlers = [handler()]) {
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, "material.surql"), source);
  if (handlers !== null) {
    const directory = path.join(root, "table-handlers");
    fs.mkdirSync(directory, { recursive: true });
    handlers.forEach((sourceText, index) => fs.writeFileSync(path.join(directory, `${index}.js`), sourceText));
  }
}

function compile(projectDir, outputDir, overrides = {}) {
  const { runtimeUrl, runtimeSecret, ...compilerOptions } = overrides;
  const configuration = resolveConfiguration({
    ...(runtimeUrl ? { REBASE_RUNTIME_URL: runtimeUrl } : {}),
    ...(runtimeSecret ? { REBASE_RUNTIME_SECRET: runtimeSecret } : {}),
  });
  return compileFromArgs({
    projectDir,
    frameworkDir: FRAMEWORK,
    outputDir,
    ...compilerOptions,
    configuration,
  }, ROOT);
}

async function main() {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-compiler-probe-"));
  try {
    const fieldKinds = parseSchema(`
      DEFINE TABLE example SCHEMAFULL;
      DEFINE FIELD amount ON example TYPE decimal ASSERT $value > 0dec;
      DEFINE FIELD normalized ON example TYPE string VALUE string::trim($value);
      DEFINE FIELD quoted ON example TYPE string COMMENT 'VALUE is documentation';
      DEFINE FIELD z_amount ON example TYPE decimal VALUE $this.amount * 2dec COMMENT '@rebase-derived';
    `, '');
    assert.deepEqual(businessFields(fieldKinds.tables.get('example')), ['amount', 'normalized', 'quoted']);
    const nestedAudit = parseSchema(`
      DEFINE TABLE nested_example SCHEMAFULL;
      DEFINE FIELD profile ON nested_example TYPE object;
      DEFINE FIELD profile.email ON nested_example TYPE string COMMENT '@rebase-audit';
      DEFINE FIELD profile.private_note ON nested_example TYPE string;
    `, '');
    assert.deepEqual([...nestedAudit.tables.get('nested_example').nestedFields.keys()], ['profile.email', 'profile.private_note']);
    assert.throws(() => parseSchema(`DEFINE TABLE nested_example SCHEMAFULL;
      DEFINE FIELD profile ON nested_example TYPE object COMMENT '@rebase-audit';
      DEFINE FIELD profile.email ON nested_example TYPE string COMMENT '@rebase-audit';`, ''), /overlaps profile\.email/);
    assert.throws(() => parseSchema(`DEFINE TABLE nested_example SCHEMAFULL;
      DEFINE FIELD profile.* ON nested_example TYPE string COMMENT '@rebase-audit';`, ''), /wildcard.*concrete leaf/);
    assert.throws(() => parseSchema("DEFINE TABLE nested_example SCHEMAFULL COMMENT '@rebase-audit';", ''), /field-only/);
    assert.throws(() => parseSchema("DEFINE TABLE employee SCHEMAFULL COMMENT '@rebase-principal user';", ''), /retired annotation.*fixed rebase_user\/rebase_group/);
    assert.throws(() => parseSchema(`DEFINE TABLE audit_choice SCHEMAFULL;
      DEFINE FIELD secret ON audit_choice TYPE string COMMENT '@rebase-audit @rebase-change-log';`, ''), /choose either/);
    const operationSchema = parseSchema(`
      DEFINE TABLE storage_config SCHEMAFULL;
      DEFINE TABLE grant_storage SCHEMAFULL COMMENT '@rebase-operation grant CREATE UPDATE @rebase-adapter createS3UploadGrant @rebase-timeout 1500ms';
      DEFINE FIELD config ON grant_storage TYPE record<storage_config> READONLY COMMENT '@rebase-operation-input';
      DEFINE FIELD object_key ON grant_storage TYPE string COMMENT '@rebase-operation-input';
      DEFINE FIELD expires_in ON grant_storage TYPE option<int> DEFAULT NONE COMMENT '@rebase-operation-input';
      DEFINE FIELD access_url ON grant_storage TYPE option<string> DEFAULT NONE PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-operation-output';
      DEFINE TABLE create_payment SCHEMAFULL COMMENT '@rebase-operation inline CREATE @rebase-adapter createPayment';
      DEFINE FIELD amount ON create_payment TYPE int READONLY COMMENT '@rebase-operation-input';
      DEFINE FIELD provider_id ON create_payment TYPE option<string> DEFAULT NONE PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-operation-output';
      DEFINE TABLE send_receipt SCHEMAFULL COMMENT '@rebase-operation queued CREATE @rebase-adapter sendReceipt';
      DEFINE FIELD address ON send_receipt TYPE string READONLY COMMENT '@rebase-operation-input';
      DEFINE FIELD message_id ON send_receipt TYPE option<string> DEFAULT NONE PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-operation-output';
    `, '');
    const operationContracts = generateRuntimeContracts(operationSchema, {
      user: 'rebase_user', group: 'rebase_group',
    }).tables;
    assert.deepEqual(operationContracts.grant_storage, {
      mode: 'grant',
      events: ['CREATE', 'UPDATE'],
      timeoutMs: 1500,
      inputFields: ['config', 'expires_in', 'object_key'],
      optionalInputs: ['expires_in'],
      patchFields: ['access_url'],
      references: [{ field: 'config', array: false, optional: false, targets: ['storage_config'] }],
      adapters: ['createS3UploadGrant'],
    });
    assert.equal(operationContracts.create_payment.mode, 'inline');
    assert.deepEqual(operationContracts.create_payment.events, ['CREATE']);
    assert.equal(operationContracts.create_payment.timeoutMs, 60000);
    assert.equal(operationContracts.send_receipt.mode, 'queued');
    assert.equal(operationContracts.send_receipt.timeoutMs, 60000);
    for (const contract of Object.values(operationContracts)) {
      assert.equal('process' in contract, false);
      assert.equal('schedule' in contract, false);
      assert.equal('machineFields' in contract, false);
    }
    for (const [source, expected] of [
      ["DEFINE TABLE op SCHEMAFULL COMMENT '@rebase-operation grant';", /requires explicit CREATE or UPDATE/],
      ["DEFINE TABLE op SCHEMAFULL COMMENT '@rebase-operation sync CREATE';", /Invalid @rebase-operation mode/],
      ["DEFINE TABLE op SCHEMAFULL COMMENT '@rebase-operation grant DELETE';", /cannot handle DELETE/],
      ["DEFINE TABLE op SCHEMAFULL COMMENT '@rebase-operation inline CREATE UPDATE';", /supports CREATE only/],
      ["DEFINE TABLE op SCHEMAFULL COMMENT '@rebase-operation queued CREATE @rebase-operation queued CREATE';", /Duplicate @rebase-operation/],
      ["DEFINE TABLE op SCHEMAFULL COMMENT '@rebase-operation queued CREATE @rebase-effect async';", /cannot be combined with legacy effect declarations/],
      ["DEFINE TABLE op SCHEMAFULL; DEFINE FIELD value ON op TYPE string COMMENT '@rebase-operation-input';", /field markers require a table @rebase-operation/],
      ["DEFINE TABLE op SCHEMAFULL COMMENT '@rebase-operation queued CREATE'; DEFINE FIELD value ON op TYPE string COMMENT '@rebase-effect-input';", /legacy @rebase-effect field markers cannot be used/],
    ]) assert.throws(() => parseSchema(source, ''), expected);
    const readerSchema = parseSchema(`
      DEFINE TABLE reader_parent SCHEMAFULL;
      DEFINE TABLE reader_child SCHEMAFULL;
      DEFINE FIELD parent ON reader_child TYPE option<record<reader_parent>> COMMENT '@rebase-readers';
      DEFINE FIELD unmarked_parent ON reader_child TYPE option<record<reader_parent>>;
    `, '');
    const readerSystemTables = new Set(['rebase_user', 'rebase_group']);
    const readersSecurity = generateSecurity(readerSchema, {
      principalTables: ['rebase_user', 'rebase_group'], selectPolicy: 'readers',
    }, readerSystemTables);
    const ownerSecurity = generateSecurity(readerSchema, {
      principalTables: ['rebase_user', 'rebase_group'], selectPolicy: 'owner',
    }, readerSystemTables);
    const indexLine = security => security.match(/DEFINE FIELD OVERWRITE readers_index ON TABLE reader_child[^\n]+/)[0];
    assert.equal(indexLine(readersSecurity), indexLine(ownerSecurity), 'both select policies compute the same protected reader index');
    assert.match(indexLine(readersSecurity), /\[<string>\$this\.parent\.owned_by\].*PERMISSIONS NONE/);
    assert.doesNotMatch(indexLine(readersSecurity), /parent\.readers_index/);
    assert.match(readersSecurity, /readers_index CONTAINSANY \$auth\.z_access_index/,
      'reader grants intersect both user and group authorization principals');
    assert.doesNotMatch(ownerSecurity, /readers_index CONTAINSANY/,
      'owner policy does not apply reader grants');
    assert.match(ownerSecurity, /owned_by IN \$auth\.z_access_index/,
      'owner policy includes directly owned users and groups');
    const explicit = classifyMaterials([{
      group: 'project', path: 'explicit.surql', relative: 'explicit.surql',
      source: "-- fixture\n-- REBASE SECTION schema BEGIN\nDEFINE TABLE explicit_example SCHEMAFULL;\n-- REBASE SECTION schema END\n",
    }]);
    const explicitTable = materialStatements(explicit, 'project', 'schema')[0];
    assert.equal(explicitTable.location.line, 3, 'explicit section definitions retain source lines');
    const fixture = fs.readFileSync(path.join(ROOT, 'dev-tools/temporal-tree/compiler-fixture.surql'), 'utf8');
    const temporal = path.join(temp, 'temporal');
    project(temporal, fixture, null);
    const tree = compile(temporal, path.join(temp, 'temporal-build'));
    assert(tree.temporal.routes.some((r) => r.target === 'inherited_fact' && r.table === 'chained_fact'));
    const namedField = tree.schema.tables.get('principal_report').fields.get('z_name');
    assert.equal(namedField.location.relative, 'material.surql');
    assert.equal(namedField.location.line, fixture.split('\n').findIndex(line => line.includes('DEFINE FIELD OVERWRITE z_name')) + 1);
    const materialSet = compilerApi.loadMaterials({ groups: [
      { name: 'framework', roots: [FRAMEWORK] }, { name: 'project', roots: [temporal] },
    ] });
    assert.equal(materialSet.files.find(file => file.group === 'project').source, fixture, 'raw project SQL is preserved');
    const resolved = compilerApi.resolveModel(materialSet);
    assert.equal(compilerApi.emitModel(resolved).bundle, tree.bundle, 'public resolve and emit passes match the compatibility API');
    const explicitlyProfiled = compilerApi.compileProject({ groups: [
      { name: 'foundation', roots: [FRAMEWORK] }, { name: 'application', roots: [temporal] },
    ], profiles: { framework: 'foundation', project: 'application' } });
    assert.equal(explicitlyProfiled.bundle, tree.bundle, 'explicit profile composition keeps the emitted semantics');
    assert.equal(fs.existsSync(path.join(temp, 'public-api-build')), false, 'pure compile API writes no artifacts');
    for (const [name, alteration, error] of [
      ['untracked', (s) => s.replace('a_parent ON chained_fact TYPE record<inherited_fact> REFERENCE ON DELETE REJECT', 'a_parent ON chained_fact TYPE record<inherited_fact>'), /REFERENCE/],
      ['missing_value', (s) => s.replace('VALUE $this.a_user.name', ''), /requires VALUE/],
    ]) {
      const dir = path.join(temp, name);
      project(dir, alteration(fixture), null);
      assert.throws(() => compile(dir, path.join(dir, 'build')), error);
    }
    const badTreeDir = path.join(temp, 'bad-tree-source-location');
    project(badTreeDir, fixture.replace('@rebase-tree-root @rebase-tree-key datetime', '@rebase-tree-root'), null);
    assert.throws(() => compile(badTreeDir, path.join(badTreeDir, 'build')),
      /tree_owner\.z_book.*project:material\.surql:\d+:\d+/);
    const forwardSource = fixture.replace('VALUE $this.a_user.name', 'VALUE $this.z_zz')
      + "\nDEFINE FIELD z_zz ON principal_report TYPE string VALUE $this.a_user.name COMMENT '@rebase-derived';";
    const forwardDir = path.join(temp, 'forward');
    project(forwardDir, forwardSource, null);
    const forward = compile(forwardDir, path.join(forwardDir, 'build'));
    assert.match(forward.bundle, /LET \$r1 = object::extend\(\$r0, \{ z_zz:/);
    assert.match(forward.bundle, /LET \$r2 = object::extend\(\$r1, \{ z_name:/);
    const cyclicSource = fixture.replace('VALUE $this.a_user.name', 'VALUE $this.z_zz')
      + "\nDEFINE FIELD z_zz ON principal_report TYPE string VALUE $this.z_name COMMENT '@rebase-derived';";
    const cyclicDir = path.join(temp, 'cyclic');
    project(cyclicDir, cyclicSource, null);
    assert.throws(() => compile(cyclicDir, path.join(cyclicDir, 'build')), /principal_report: derived field cycle z_name -> z_zz -> z_name/);
    const valid = path.join(temp, "valid");
    const output = path.join(temp, "build");
    project(valid, schema(validEffect()));
    assert.throws(() => compileFromArgs({
      projectDir: valid,
      namespace: "flag_ns",
    }, ROOT), /is process-profile configuration/);
    const result = compile(valid, output, {
      runtimeUrl: "https://runtime.internal",
      runtimeSecret: "probe-secret",
    });
    const generatedBackfill = fs.readFileSync(path.join(output, "migrate-one-shot-backfill.surql"), "utf8");
    const generatedFinalizer = fs.readFileSync(path.join(output, "migrate-one-shot-finalize.surql"), "utf8");
    assert.equal(generatedBackfill, `${result.lifecycleMigration.backfill}\n`);
    assert.equal(generatedFinalizer, `${result.lifecycleMigration.finalize}\n`);
    assert.match(generatedBackfill, /LET \$rebase_migration_batch_delivery/);
    assert.match(generatedFinalizer, /REBASE_ONE_SHOT_BACKFILL_INCOMPLETE/);
    assert.throws(() => parseMigrationArgs(["--apply"]), /confirm-workers-stopped/);
    assert.throws(() => parseMigrationArgs(["--apply", "--confirm-workers-stopped"]), /confirm-backup-created/);
    assert.equal(parseMigrationArgs([
      "--apply", "--confirm-workers-stopped", "--confirm-backup-created",
    ]).apply, true);
    const migrationTableNames = [...result.lifecycleMigration.backfill.matchAll(/RETURN \{ table: '([A-Za-z_][A-Za-z0-9_]*)'/g)]
      .map((match) => match[1]);
    let migrationPass = 0;
    let finalized = false;
    const boundedMigration = await runLifecycleMigration({
      backfillSql: generatedBackfill,
      finalizeSql: generatedFinalizer,
      db: {
        async query(sql) {
          if (sql === generatedFinalizer) {
            finalized = true;
            return [{ status: "OK", result: null }];
          }
          migrationPass += 1;
          return migrationTableNames.map((table) => ({
              status: "OK",
              result: { table, processed: migrationPass === 1 ? 1 : 0 },
            }));
        },
      },
      maxPasses: 2,
    });
    assert.deepEqual(boundedMigration, {
      complete: true,
      passes: 2,
      reports: migrationTableNames.map((table) => ({ table, processed: 0 })),
    });
    assert.equal(finalized, true);
    let limitedFinalized = false;
    const incompleteMigration = await runLifecycleMigration({
      backfillSql: generatedBackfill,
      finalizeSql: generatedFinalizer,
      db: {
        async query(sql) {
          if (sql === generatedFinalizer) limitedFinalized = true;
          return migrationTableNames.map((table) => ({ status: "OK", result: { table, processed: 1 } }));
        },
      },
      maxPasses: 1,
    });
    assert.equal(incompleteMigration.complete, false);
    assert.equal(limitedFinalized, false, "the finalizer must not run when a bounded pass limit is reached");
    assert.equal(result.contracts.tables.delivery.process, "async");
    assert.deepEqual(result.contracts.principals, {
      user: "rebase_user",
      group: "rebase_group",
      root: "rebase_group:root",
    });
    assert.deepEqual(result.contracts.tables.delivery.events, ["CREATE"]);
    assert.deepEqual(result.contracts.tables.delivery.patchFields, ["result"]);
    assert.deepEqual(result.contracts.tables.delivery.adapters, ["sendDelivery"]);
    assert.match(result.bundle, /session::ns\(\)/);
    assert.match(result.bundle, /session::db\(\)/);
    const oauthAccess = result.bundle.match(/-- REBASE: oauth access\n([\s\S]*?)(?=\n-- REBASE:)/)?.[1] || "";
    assert.match(oauthAccess, /DEFINE ACCESS OVERWRITE oauth/);
    assert.match(oauthAccess, /internal\/oauth/);
    assert.match(oauthAccess, /token: \$oauth_token/);
    assert.doesNotMatch(oauthAccess, /provider_token/);
    assert.match(oauthAccess, /login_access = true/);
    assert.doesNotMatch(oauthAccess, /\b(?:SIGNUP|CREATE|UPDATE|UPSERT|INSERT)\b/);
    assert.match(result.bundle, /execute_at ON TABLE delivery TYPE datetime DEFAULT time::now\(\)/);
    assert.match(result.bundle, /priority ON TABLE delivery TYPE int DEFAULT 50/);
    assert.match(result.bundle, /rebase_attempt ON TABLE delivery TYPE int DEFAULT 0/);
    assert.match(result.bundle, /rebase_provider_started_at ON TABLE delivery TYPE option<datetime> DEFAULT NONE/);
    assert.match(result.bundle, /rebase_provider_started_at != NONE THEN 'ambiguous'/);
    assert.match(result.bundle, /DEFINE TABLE OVERWRITE rebase_reconciliation_cursor SCHEMAFULL PERMISSIONS NONE/);
    assert.doesNotMatch(result.bundle, /TYPE option<\{ cron: string/);
    assert.doesNotMatch(result.bundle, /rebase_schedule_(?:next_at|index|finished_at)/);
    assert.match(result.bundle, /rebase_lease_token[\s\S]*PERMISSIONS FOR select, create, update NONE/);
    assert.doesNotMatch(result.bundle, /USE NS source_only DB source_only/);
    assert.match(result.lifecycleMigration.backfill, /FROM delivery[\s\S]*ORDER BY id LIMIT 1000/);
    assert.match(result.lifecycleMigration.backfill, /schedule = NONE[\s\S]*rebase_schedule_next_at = NONE/);
    assert.match(result.lifecycleMigration.finalize, /REMOVE FIELD IF EXISTS schedule ON TABLE delivery/);
    assert(fs.existsSync(result.artifacts.backfillPath));
    assert(fs.existsSync(result.artifacts.finalizeMigrationPath));
    compile(valid, output, { runtimeUrl: "https://runtime.internal", runtimeSecret: "probe-secret", check: true });
    const first = fs.readFileSync(path.join(output, "schema.surql"), "utf8");
    compile(valid, output, { runtimeUrl: "https://runtime.internal", runtimeSecret: "probe-secret" });
    assert.equal(fs.readFileSync(path.join(output, "schema.surql"), "utf8"), first);

    const operationProject = path.join(temp, 'operation-project');
    project(operationProject, schema(`
      DEFINE TABLE grant_storage SCHEMAFULL COMMENT '@rebase-operation grant CREATE @rebase-adapter createS3UploadGrant';
      DEFINE FIELD key ON grant_storage TYPE string COMMENT '@rebase-operation-input';
      DEFINE FIELD access_url ON grant_storage TYPE option<string> DEFAULT NONE
        PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-operation-output';
      DEFINE TABLE create_payment SCHEMAFULL COMMENT '@rebase-operation inline CREATE @rebase-adapter createPayment';
      DEFINE FIELD amount ON create_payment TYPE int READONLY COMMENT '@rebase-operation-input';
      DEFINE FIELD provider_id ON create_payment TYPE option<string> DEFAULT NONE
        PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-operation-output';
      DEFINE TABLE send_receipt SCHEMAFULL COMMENT '@rebase-operation queued CREATE @rebase-adapter sendReceipt';
      DEFINE FIELD address ON send_receipt TYPE string READONLY COMMENT '@rebase-operation-input';
      DEFINE FIELD message_id ON send_receipt TYPE option<string> DEFAULT NONE
        PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-operation-output';
    `), [
      `module.exports = { table: 'grant_storage', grant: { async CREATE() { return { patch: { access_url: 'signed' } }; } } };`,
      `module.exports = { table: 'create_payment', async execute() { return { patch: { provider_id: 'pay_local' } }; } };`,
      `module.exports = { table: 'send_receipt', async execute() { return { patch: { message_id: 'msg_local' } }; } };`,
    ]);
    const operationBuild = path.join(temp, 'operation-build');
    const operations = compile(operationProject, operationBuild, {
      runtimeUrl: 'https://runtime.internal',
      runtimeSecret: 'probe-secret',
    });
    assert.equal(operations.contracts.tables.grant_storage.mode, 'grant');
    assert.equal(operations.contracts.tables.create_payment.mode, 'inline');
    assert.equal(operations.contracts.tables.send_receipt.mode, 'queued');
    assert.deepEqual(operations.contracts.tables.create_payment.identityFields, ['execution_id', 'revision']);
    assert.equal(Object.hasOwn(operations.contracts.tables.grant_storage, 'identityFields'), false);
    assert.match(operations.bundle, /\/internal\/grant/);
    assert.match(operations.bundle, /\/internal\/inline/);
    assert.match(operations.bundle, /\/internal\/wake\/task/);
    assert.match(operations.bundle, /ASYNC RETRY 0 MAXDEPTH 0/);
    assert.match(operations.bundle, /execution_id ON TABLE send_receipt TYPE uuid[\s\S]*VALUE IF \$before = NONE THEN rand::uuid::v7\(\)/);
    assert.match(operations.bundle, /revision ON TABLE send_receipt TYPE uuid[\s\S]*VALUE IF \$before = NONE THEN rand::uuid::v7\(\)/);
    assert.match(operations.bundle, /rebase_lease_token ON TABLE create_payment/);
    assert.doesNotMatch(operations.bundle, /rebase_schedule_next_at ON TABLE create_payment/);
    assert.doesNotThrow(() => compile(operationProject, operationBuild, {
      runtimeUrl: 'https://runtime.internal', runtimeSecret: 'probe-secret', check: true,
    }));

    const unsafeGrantProject = path.join(temp, 'unsafe-grant-project');
    project(unsafeGrantProject, schema(`
      DEFINE TABLE unsafe_grant SCHEMAFULL COMMENT '@rebase-operation grant CREATE @rebase-adapter sendBrevoEmail';
      DEFINE FIELD recipient ON unsafe_grant TYPE string READONLY COMMENT '@rebase-operation-input';
      DEFINE FIELD result ON unsafe_grant TYPE option<string> DEFAULT NONE
        PERMISSIONS FOR select WHERE true FOR create, update NONE COMMENT '@rebase-operation-output';
    `), [
      `module.exports = { table: 'unsafe_grant', grant: { async CREATE() { return { patch: { result: 'sent' } }; } } };`,
    ]);
    assert.throws(() => compile(unsafeGrantProject, path.join(temp, 'unsafe-grant-build')),
      /adapter sendBrevoEmail is not permitted for a grant operation/);

    const profiled = compilerMain([
      "--project", valid,
      "--framework", FRAMEWORK,
      "--output", path.join(temp, "profile-build"),
    ], {
      SURREAL_NAMESPACE: "profile_ns",
      SURREAL_DATABASE: "profile_db",
      REBASE_RUNTIME_URL: "https://profile-runtime.internal",
      REBASE_RUNTIME_SECRET: "profile-secret",
    });
    assert.match(profiled.bundle, /USE NS profile_ns DB profile_db/);
    assert.match(profiled.bundle, /profile-runtime\.internal/);
    assert.throws(() => compilerMain([
      "--project", valid,
      "--framework", FRAMEWORK,
      "--output", path.join(temp, "profile-build"),
      "--check",
    ], {
      SURREAL_NAMESPACE: "profile_two",
      SURREAL_DATABASE: "profile_db",
      REBASE_RUNTIME_URL: "https://profile-runtime.internal",
      REBASE_RUNTIME_SECRET: "profile-secret",
    }), /stale/i);
    const neutral = compilerMain([
      "--project", valid,
      "--framework", FRAMEWORK,
      "--output", path.join(temp, "neutral-build"),
    ], {});
    assert.doesNotMatch(neutral.bundle, /-- REBASE: context/);
    assert.doesNotMatch(neutral.bundle, /internal\/wake/);
    assert.doesNotMatch(neutral.bundle, /DEFINE ACCESS OVERWRITE oauth/);

    const cases = [
      ["missing handler", schema(validEffect()), null, /table-handlers|handler/i],
      ["duplicate handler", schema(validEffect()), [handler(), handler()], /duplicate table handler/i],
      ["undeclared handler", schema(validEffect()), [handler(), handler("unknown", "return { outcome: 'success' };")], /compiled runtime contract|no @rebase-effect/i],
      ["lifecycle collision", schema(validEffect("DEFINE FIELD rebase_outcome ON delivery TYPE option<string>;")), [handler()], /reserved lifecycle field/i],
      ["mutable async input", schema(validEffect().replace("TYPE string READONLY", "TYPE string")), [handler()], /inputs must be READONLY/i],
      ["client writable output", schema(validEffect().replace("PERMISSIONS FOR select WHERE true FOR create, update NONE", "PERMISSIONS FULL")), [handler()], /deny client create and update/i],
      ["create writable readonly output", schema(validEffect().replace("PERMISSIONS FOR select WHERE true FOR create, update NONE", "READONLY")), [handler()], /deny client create and update/i],
      ["async update event", schema(validEffect().replace("@rebase-effect async", "@rebase-effect async @rebase-events CREATE UPDATE")), [handler()], /support only CREATE/i],
      ["missing event handler", schema(validEffect().replace("@rebase-effect async", "@rebase-effect sync @rebase-events CREATE DELETE")), [handler()], /on\.DELETE/i],
      ["undeclared event handler", schema(validEffect()), [`module.exports = { table: 'delivery', on: { async CREATE() { return { outcome: 'success' }; }, async UPDATE() { return { outcome: 'success' }; } } };\n`], /not declared/i],
      ["invalid adapter marker", schema(validEffect().replace("sendDelivery", "send-delivery")), [handler()], /invalid @rebase-adapter/i],
      ["retired provider marker", schema(validEffect().replace("@rebase-adapter sendDelivery", "@rebase-provider sendDelivery")), [handler()], /retired.*rebase-provider|rebase-adapter/i],
    ];
    for (const [name, source, handlers, expected] of cases) {
      const directory = path.join(temp, name.replaceAll(" ", "-"));
      project(directory, source, handlers);
      assert.throws(() => compile(directory, path.join(directory, "build")), expected, name);
    }

    const mutableRegistry = require("../gateway/handlers").loadTableHandlers(path.join(valid, "table-handlers"), {
      contracts: new Map(Object.entries(result.contracts.tables)),
      mutable: true,
    });
    mutableRegistry.unregister("delivery");
    assert.equal(mutableRegistry.get("delivery"), null);
    mutableRegistry.register({ table: "delivery", on: { async CREATE() { return { outcome: "success", patch: {} }; } } });
    assert(mutableRegistry.get("delivery"));
    const frozenRegistry = require("../gateway/handlers").loadTableHandlers(path.join(valid, "table-handlers"), {
      contracts: new Map(Object.entries(result.contracts.tables)),
    });
    assert.throws(() => frozenRegistry.register({ table: "delivery", on: { async CREATE() {} } }), /frozen/i);
    console.log("compiler: lifecycle contracts, context neutrality, determinism, validation failures, and mutable test registry passed");
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

if (require.main === module) main().catch((error) => {
  console.error(`compiler: FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});

module.exports = { main };
