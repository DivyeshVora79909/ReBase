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
        "SURREAL_USERNAME=profile-user",
        "SURREAL_PASSWORD=profile-secret",
        "SURREAL_NAMESPACE=profile-ns",
        "SURREAL_DATABASE=profile-db",
        "REBASE_RUNTIME_URL=http://runtime",
        "REBASE_RUNTIME_SECRET=runtime-secret",
        "REBASE_STORAGE_BUCKET=profile-bucket",
        "REBASE_PLATFORM_EMAIL_RESEND_API_KEY=profile-resend-key",
        "REBASE_PLATFORM_EMAIL_FROM=ReBase <onboarding@resend.dev>",
        "REBASE_RECOVERY_RATE_LIMIT_WINDOW_MS=60000",
        "REBASE_RECOVERY_RATE_LIMIT_IP=8",
        "REBASE_RECOVERY_RATE_LIMIT_IDENTIFIER=2",
        "REBASE_RECOVERY_INVITE_TTL_MS=3600000",
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
    assert.equal(config.runtime.secret, "runtime-secret");
    assert.equal(config.storage.bucket, "profile-bucket");
    assert.deepEqual(config.platformEmail, {
      resendApiKey: "profile-resend-key",
      from: "ReBase <onboarding@resend.dev>",
    });
    assert.deepEqual(config.accounts.recovery, {
      windowMs: 60000,
      ip: 8,
      identifier: 2,
      inviteTtlMs: 3600000,
    });
    assert.deepEqual(config.webhooks, {});
    const flagConfig = resolveConfiguration(loaded.values, {
      namespace: "flag-ns",
      database: "flag-db",
      runtimeUrl: "http://flag-runtime",
      runtimeSecret: "flag-secret",
      storageBucket: "flag-bucket",
    });
    assert.deepEqual(flagConfig.surreal.defaultContext, {
      namespace: "flag-ns",
      database: "flag-db",
    });
    assert.equal(flagConfig.runtime.secret, "flag-secret");
    assert.equal(flagConfig.storage.bucket, "flag-bucket");
    const nestedRecovery = resolveConfiguration({}, {
      accounts: { recovery: { windowMs: 2000, ip: 4, identifier: 1, inviteTtlMs: 120000 } },
    });
    assert.deepEqual(nestedRecovery.accounts.recovery, {
      windowMs: 2000,
      ip: 4,
      identifier: 1,
      inviteTtlMs: 120000,
    });
    assertConnectionConfiguration(config);

    const neutral = resolveConfiguration({
      REBASE_RUNTIME_URL: "http://partial",
    });
    assert.equal(neutral.runtime.url, "http://partial");
    assert.equal(neutral.runtime.secret, undefined);
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
      SURREAL_USERNAME: "user",
      SURREAL_PASSWORD: "pass",
      REBASE_ALLOWED_CONTEXTS: '[{"namespace":"tenant","database":"app"}]',
    });
    assertConnectionConfiguration(contextsOnly);
    const testRecordValues = resolveConfiguration({
      REBASE_TEST_RECORD__EMAIL_BREVO_CONFIG__API_KEY: "documentation-only-secret",
    });
    assert.equal(JSON.stringify(testRecordValues).includes("documentation-only-secret"), false);
    assert.throws(
      () => loadEnvironment(["--env-file", path.join(directory, "missing")]),
      /not found/i,
    );

    const visualizer = fs.readFileSync(
      path.join(__dirname, "visualizer.html"),
      "utf8",
    );
    assert.match(visualizer, /URLSearchParams/);
    assert.match(visualizer, /finalQueryResult/);
    assert.match(visualizer, /statements\.at\(-1\)/);
    assert.doesNotMatch(visualizer, /res\.result\[0\]/);
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
