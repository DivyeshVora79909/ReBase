#!/usr/bin/env node

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  assertConfiguredContext,
  assertConnectionConfiguration,
  resolveConfiguration,
} = require("../config/environment");
const { parseArgs: parseCompilerArgs } = require("./compiler/cli");
const { parseArgs: parsePopulateArgs } = require("./populate");
const { parseArgs: parseWorkbenchArgs } = require("./workbench");

function main() {
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
        "SURREAL_NAMESPACE=profile_ns",
        "SURREAL_DATABASE=profile_db",
        "REBASE_RUNTIME_URL=http://runtime",
        "REBASE_RUNTIME_SECRET=runtime-secret",
        "REBASE_AUTHENTICATION_PAYLOAD_SECRET=profile-authentication-payload-secret-32-bytes",
        "REBASE_STORAGE_BUCKET=profile-bucket",
        "REBASE_PLATFORM_EMAIL_RESEND_API_KEY=profile-resend-key",
        "REBASE_PLATFORM_EMAIL_FROM=ReBase <onboarding@resend.dev>",
        "REBASE_AUTHENTICATION_CHALLENGE_TTL_MS=600000",
        "REBASE_TERMINAL_TASK_RETENTION_DAYS=14",
        "REBASE_AUTHENTICATION_RATE_LIMIT_WINDOW_MS=60000",
        "REBASE_AUTHENTICATION_RATE_LIMIT_IP=8",
        "REBASE_AUTHENTICATION_RATE_LIMIT_IDENTIFIER=2",
        "REBASE_PLATFORM_SMS_TWILIO_ACCOUNT_SID=ACprofile",
        "REBASE_PLATFORM_SMS_TWILIO_API_KEY_SID=SKprofile",
        "REBASE_PLATFORM_SMS_TWILIO_API_KEY_SECRET=profile-twilio-secret",
        "REBASE_PLATFORM_SMS_TWILIO_FROM=+10000000000",
      ].join("\n"),
    );
    const loaded = spawnSync(process.execPath, [
      "--env-file", file,
      "-e",
      "const keys=['SURREAL_ENDPOINT','SURREAL_USERNAME','SURREAL_PASSWORD','SURREAL_NAMESPACE','SURREAL_DATABASE','REBASE_RUNTIME_URL','REBASE_RUNTIME_SECRET','REBASE_AUTHENTICATION_PAYLOAD_SECRET','REBASE_STORAGE_BUCKET','REBASE_PLATFORM_EMAIL_RESEND_API_KEY','REBASE_PLATFORM_EMAIL_FROM','REBASE_AUTHENTICATION_CHALLENGE_TTL_MS','REBASE_TERMINAL_TASK_RETENTION_DAYS','REBASE_AUTHENTICATION_RATE_LIMIT_WINDOW_MS','REBASE_AUTHENTICATION_RATE_LIMIT_IP','REBASE_AUTHENTICATION_RATE_LIMIT_IDENTIFIER','REBASE_PLATFORM_SMS_TWILIO_ACCOUNT_SID','REBASE_PLATFORM_SMS_TWILIO_API_KEY_SID','REBASE_PLATFORM_SMS_TWILIO_API_KEY_SECRET','REBASE_PLATFORM_SMS_TWILIO_FROM'];process.stdout.write(JSON.stringify(Object.fromEntries(keys.map(key=>[key,process.env[key]]))))",
    ], {
      encoding: "utf8",
      env: { ...process.env, SURREAL_ENDPOINT: "ws://inherited/rpc" },
    });
    assert.equal(loaded.status, 0, loaded.stderr);
    const values = JSON.parse(loaded.stdout);
    assert.equal(values.SURREAL_ENDPOINT, "ws://inherited/rpc");
    assert.equal(values.SURREAL_USERNAME, "profile-user");
    const config = resolveConfiguration(values);
    assert.equal(config.surreal.endpoint, "ws://inherited/rpc");
    assert.deepEqual(config.surreal.defaultContext, {
      namespace: "profile_ns",
      database: "profile_db",
    });
    assert.equal(config.runtime.url, "http://runtime");
    assert.equal(config.runtime.secret, "runtime-secret");
    assert.equal(config.authentication.payloadSecret, "profile-authentication-payload-secret-32-bytes");
    assert.equal(config.storage.bucket, "profile-bucket");
    assert.equal(Object.hasOwn(config, "platformEmail"), false);
    assert.equal(Object.hasOwn(config, "platformSms"), false);
    assert.equal(config.authentication.challengeTtlMs, 600000);
    assert.equal(config.server.terminalTaskRetentionDays, 14);
    assert.deepEqual(config.authentication.rateLimits, {
      windowMs: 60000,
      ip: 8,
      identifier: 2,
    });
    assert.deepEqual(config.webhooks, {});
    assert.equal(Object.isFrozen(config), true);
    assert.equal(Object.isFrozen(config.surreal.contexts), true);
    assert.equal(Object.isFrozen(config.authentication.rateLimits), true);
    assert.throws(() => resolveConfiguration(values, { endpoint: "ws://override/rpc" }), /overrides are unsupported/);
    assertConnectionConfiguration(config);
    assert.deepEqual(assertConfiguredContext(config, {
      namespace: "profile_ns",
      database: "profile_db",
    }), { namespace: "profile_ns", database: "profile_db" });
    assert.throws(() => assertConfiguredContext(config, {
      namespace: "outside",
      database: "profile_db",
    }), /not configured/);

    const contextsOnly = resolveConfiguration({
      SURREAL_ENDPOINT: "ws://contexts/rpc",
      SURREAL_USERNAME: "user",
      SURREAL_PASSWORD: "pass",
      REBASE_ALLOWED_CONTEXTS: '[{"namespace":"tenant","database":"app"}]',
    });
    assertConnectionConfiguration(contextsOnly);
    assert.throws(() => resolveConfiguration({ REBASE_RUNTIME_URL: "http://partial" }), /provided together/);
    assert.throws(() => resolveConfiguration({ SURREAL_NAMESPACE: "only_ns" }), /provided together/);
    assert.throws(() => resolveConfiguration({ REBASE_HTTP_PORT: "not-a-number" }), /must be an integer/);
    assert.throws(() => resolveConfiguration({ REBASE_HTTP_PORT: "65536" }), /between 0 and 65535/);
    assert.throws(() => resolveConfiguration({ REBASE_HTTP_DEBUG: "sometimes" }), /must be true or false/);
    assert.throws(() => resolveConfiguration({
      SURREAL_ENDPOINT: "ftp://localhost",
      SURREAL_USERNAME: "user",
      SURREAL_PASSWORD: "pass",
    }), /must use/);
    assert.throws(() => resolveConfiguration({ REBASE_AUTHENTICATION_CHALLENGE_TTL_MS: "59999" }), /between/);
    assert.throws(() => resolveConfiguration({ REBASE_TERMINAL_TASK_RETENTION_DAYS: "0" }), /between/);
    assert.throws(() => resolveConfiguration({ REBASE_TERMINAL_TASK_RETENTION_DAYS: "3651" }), /between/);
    assert.throws(() => resolveConfiguration({
      REBASE_ALLOWED_CONTEXTS: '[{"namespace":"tenant","database":"app"},{"namespace":"tenant","database":"app"}]',
    }), /duplicate contexts/);
    assert.throws(() => resolveConfiguration({ REBASE_QUEUE_DRIVER: "sqs" }), /SQS driver was removed/);
    assert.throws(() => parseCompilerArgs(["--namespace", "override"]), /Unknown argument/);
    assert.throws(() => parsePopulateArgs(["--database", "override"]), /Unknown option/);
    assert.throws(() => parseWorkbenchArgs(["--endpoint", "ws://override/rpc"]), /Unknown option/);
    const testRecordValues = resolveConfiguration({
      REBASE_TEST_RECORD__EMAIL_BREVO_CONFIG__API_KEY: "documentation-only-secret",
    });
    assert.equal(JSON.stringify(testRecordValues).includes("documentation-only-secret"), false);
    const missingProfile = spawnSync(process.execPath, [
      "--env-file", path.join(directory, "missing"), "-e", "process.exit(0)",
    ], { encoding: "utf8" });
    assert.notEqual(missingProfile.status, 0);

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
      "environment: native Node profiles, inherited-variable precedence, strict immutable configuration, allowlisted contexts, removed overrides, and visualizer configuration passed",
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
