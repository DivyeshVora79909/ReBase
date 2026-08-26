#!/usr/bin/env node

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  assertConnectionConfiguration,
  loadEnvironment,
  parseEnvFile,
  resolveConfiguration,
} = require("../config/environment");

function main() {
  assert.deepEqual(
    parseEnvFile(`
    # comment
    PLAIN=value # trailing comment
    QUOTED="value with spaces"
    QUOTED_COMMENT="value # retained" # trailing comment
    SINGLE='literal value'
  `),
    {
      PLAIN: "value",
      QUOTED: "value with spaces",
      QUOTED_COMMENT: "value # retained",
      SINGLE: "literal value",
    },
  );

  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "rebase-environment-probe-"),
  );
  try {
    const file = path.join(directory, ".env.local");
    fs.writeFileSync(
      file,
      [
        "SURREAL_ENDPOINT=ws://profile/rpc",
        "SURREAL_USER=profile-user",
        "SURREAL_PASS=profile-secret",
        "SURREAL_NAMESPACE=profile-ns",
        "SURREAL_DATABASE=profile-db",
        "REBASE_RUNTIME_URL=http://runtime",
        "REBASE_WAKE_SECRET=wake-secret",
      ].join("\n"),
    );
    const loaded = loadEnvironment(["--env-file", file, "--count", "2"], {
      baseEnv: { SURREAL_ENDPOINT: "ws://inherited/rpc" },
    });
    assert.deepEqual(loaded.args, ["--count", "2"]);
    assert.equal(loaded.values.SURREAL_ENDPOINT, "ws://profile/rpc");
    const equalsLoaded = loadEnvironment(
      [`--env-file=${file}`, "--count", "2"],
      {
        baseEnv: { SURREAL_ENDPOINT: "ws://inherited/rpc" },
      },
    );
    assert.deepEqual(equalsLoaded.args, ["--count", "2"]);
    assert.equal(equalsLoaded.file, file);
    const config = resolveConfiguration(loaded.values, {
      endpoint: "ws://override/rpc",
      namespace: "override-ns",
      database: "override-db",
    });
    assert.equal(config.surreal.endpoint, "ws://override/rpc");
    assert.deepEqual(config.surreal.defaultContext, {
      namespace: "override-ns",
      database: "override-db",
    });
    assert.equal(config.runtime.url, "http://runtime");
    assert.equal(config.runtime.wakeSecret, "wake-secret");
    assert.equal(config.webhooks.emailSecret, undefined);
    const flagConfig = resolveConfiguration(loaded.values, {
      namespace: "flag-ns",
      database: "flag-db",
      runtimeUrl: "http://flag-runtime",
      runtimeSecret: "flag-secret",
    });
    assert.deepEqual(flagConfig.surreal.defaultContext, {
      namespace: "flag-ns",
      database: "flag-db",
    });
    assert.equal(flagConfig.runtime.wakeSecret, "flag-secret");
    assertConnectionConfiguration(config);

    const neutral = resolveConfiguration({
      REBASE_RUNTIME_URL: "http://partial",
    });
    assert.equal(neutral.runtime.url, "http://partial");
    assert.equal(neutral.runtime.wakeSecret, undefined);
    assert.throws(
      () => assertConnectionConfiguration(neutral),
      /Missing configuration/,
    );
    const partialContext = resolveConfiguration({
      SURREAL_NAMESPACE: "only-ns",
    });
    assert.equal(partialContext.surreal.defaultContext, undefined);
    assert.equal(partialContext.surreal.namespace, "only-ns");
    const contextsOnly = resolveConfiguration({
      SURREAL_ENDPOINT: "ws://contexts/rpc",
      SURREAL_USER: "user",
      SURREAL_PASS: "pass",
      REBASE_CONTEXTS: '[{"namespace":"tenant","database":"app"}]',
    });
    assertConnectionConfiguration(contextsOnly);
    assert.throws(
      () => loadEnvironment(["--env-file", path.join(directory, "missing")]),
      /not found/i,
    );

    const visualizer = fs.readFileSync(
      path.join(__dirname, "visualizer.html"),
      "utf8",
    );
    assert.match(visualizer, /URLSearchParams/);
    assert.doesNotMatch(visualizer, /ws:\/\/127\.0\.0\.1:8000/);
    assert.doesNotMatch(visualizer, /pass:\s*"root"/);
    assert.doesNotMatch(visualizer, /rpc\("use", \["main", "main"\]\)/);
    console.log(
      "environment: profiles, precedence, missing files, canonical contexts, and visualizer configuration passed",
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(`environment: FAIL: ${error.stack || error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { main };
