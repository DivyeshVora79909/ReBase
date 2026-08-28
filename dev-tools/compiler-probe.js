#!/usr/bin/env node

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { compileFromArgs, main: compilerMain } = require("./compiler/cli");

const ROOT = path.resolve(__dirname, "..");
const FRAMEWORK = path.join(ROOT, "framework");

function schema(effect = "") {
  return `
    DEFINE TABLE user SCHEMAFULL COMMENT '@rebase-principal user';
    DEFINE TABLE groups SCHEMAFULL COMMENT '@rebase-principal group';
    ${effect}
  `;
}

function validEffect(extra = "") {
  return `
    DEFINE TABLE delivery SCHEMAFULL COMMENT '@rebase-effect async @rebase-provider email @rebase-timeout 2s';
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
  return compileFromArgs({
    projectDir,
    frameworkDir: FRAMEWORK,
    outputDir,
    ...overrides,
  }, ROOT);
}

async function main() {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-compiler-probe-"));
  try {
    const valid = path.join(temp, "valid");
    const output = path.join(temp, "build");
    project(valid, schema(validEffect()));
    const result = compile(valid, output, {
      runtimeUrl: "https://runtime.internal",
      runtimeSecret: "probe-secret",
    });
    assert.equal(result.contracts.tables.delivery.process, "async");
    assert.deepEqual(result.contracts.tables.delivery.events, ["CREATE"]);
    assert.deepEqual(result.contracts.tables.delivery.patchFields, ["result"]);
    assert.match(result.bundle, /session::ns\(\)/);
    assert.match(result.bundle, /session::db\(\)/);
    assert.match(result.bundle, /TYPE option<\{ cron: string/);
    assert.match(result.bundle, /rebase_lease_token[\s\S]*PERMISSIONS FOR select, create, update NONE/);
    assert.doesNotMatch(result.bundle, /USE NS source_only DB source_only/);
    compile(valid, output, { runtimeUrl: "https://runtime.internal", runtimeSecret: "probe-secret", check: true });
    const first = fs.readFileSync(path.join(output, "schema.surql"), "utf8");
    compile(valid, output, { runtimeUrl: "https://runtime.internal", runtimeSecret: "probe-secret" });
    assert.equal(fs.readFileSync(path.join(output, "schema.surql"), "utf8"), first);

    const profile = path.join(temp, ".env.profile");
    fs.writeFileSync(profile, [
      "SURREAL_NAMESPACE=profile_ns",
      "SURREAL_DATABASE=profile_db",
      "REBASE_RUNTIME_URL=https://profile-runtime.internal",
      "REBASE_WAKE_SECRET=profile-secret",
    ].join("\n"));
    const profiled = compilerMain([
      "--env-file", profile,
      "--project", valid,
      "--framework", FRAMEWORK,
      "--output", path.join(temp, "profile-build"),
    ]);
    assert.match(profiled.bundle, /USE NS profile_ns DB profile_db/);
    assert.match(profiled.bundle, /profile-runtime\.internal/);
    const secondProfile = path.join(temp, ".env.second-profile");
    fs.writeFileSync(secondProfile, [
      "SURREAL_NAMESPACE=profile_two",
      "SURREAL_DATABASE=profile_db",
      "REBASE_RUNTIME_URL=https://profile-runtime.internal",
      "REBASE_WAKE_SECRET=profile-secret",
    ].join("\n"));
    assert.throws(() => compilerMain([
      "--env-file", secondProfile,
      "--project", valid,
      "--framework", FRAMEWORK,
      "--output", path.join(temp, "profile-build"),
      "--check",
    ]), /stale/i);
    const neutral = compilerMain([
      "--project", valid,
      "--framework", FRAMEWORK,
      "--output", path.join(temp, "neutral-build"),
    ]);
    assert.doesNotMatch(neutral.bundle, /-- REBASE: context/);
    assert.doesNotMatch(neutral.bundle, /internal\/wake/);

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
