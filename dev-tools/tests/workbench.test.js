"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { PassThrough } = require("node:stream");
const { once } = require("node:events");
const test = require("node:test");
const {
  ROOT,
  build,
  connect,
  prepare,
  fixtures,
  projectOptions,
} = require("../index");
const { resolveConfiguration } = require("../../config/environment");
const { startWorkbench } = require("../workbench");

function testConfiguration() {
  return resolveConfiguration({
    NODE_ENV: "test",
    SURREAL_ENDPOINT: "ws://example.test/rpc",
    SURREAL_USERNAME: "root",
    SURREAL_PASSWORD: "test-password",
    SURREAL_NAMESPACE: "test_ns",
    SURREAL_DATABASE: "test_db",
  });
}

test("public build API compiles offline into the requested directory", async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "rebase-dev-tools-build-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));

  const result = build({
    project: "test",
    outputDir: directory,
    root: ROOT,
    configuration: resolveConfiguration({ NODE_ENV: "test" }),
  });

  assert.equal(result.projectDir, path.join(ROOT, "designs", "test"));
  assert.equal(result.outputDir, directory);
  assert.match(await fs.readFile(path.join(directory, "schema.surql"), "utf8"), /DEFINE TABLE/);
  const checked = build({
    project: "test",
    outputDir: directory,
    root: ROOT,
    configuration: resolveConfiguration({ NODE_ENV: "test" }),
    check: true,
  });
  assert.equal(checked.outputDir, directory);
  const schemaPath = path.join(directory, "schema.surql");
  await fs.writeFile(schemaPath, "stale schema");
  assert.throws(() => build({
    project: "test",
    outputDir: directory,
    root: ROOT,
    configuration: resolveConfiguration({ NODE_ENV: "test" }),
    check: true,
  }), /Generated output is stale/);
  assert.equal(await fs.readFile(schemaPath, "utf8"), "stale schema");
  assert.equal(projectOptions({ project: "all-in-accounting" }).projectDir, "designs/all-in-accounting");
  assert.equal(projectOptions({ projectDir: "fixtures" }).projectDir, "fixtures");
  assert.throws(() => projectOptions({ project: "test", outputDir: "" }), /outputDir must be a non-empty path/);
  assert.throws(() => build({
    project: "test",
    root: ROOT,
    environment: {},
    configuration: resolveConfiguration({ NODE_ENV: "test" }),
  }), /process-profile configuration/);
  assert.throws(() => build({
    project: "test",
    root: ROOT,
    connectTimeoutMs: 1,
    configuration: resolveConfiguration({ NODE_ENV: "test" }),
  }), /connectTimeoutMs is process-profile configuration/);
});

test("connect checks configured contexts before opening a stubbed session", async () => {
  const configuration = testConfiguration();
  const opened = [];
  const handle = { db: { query: async () => [] }, close: async () => {} };
  const openConnection = async (options) => {
    opened.push(options);
    return handle;
  };

  assert.equal(await connect(undefined, { configuration, openConnection }), handle);
  assert.deepEqual(opened[0], {
    endpoint: "ws://example.test/rpc",
    username: "root",
    password: "test-password",
    connectTimeoutMs: configuration.surreal.connectTimeoutMs,
    namespace: "test_ns",
    database: "test_db",
  });
  await assert.rejects(
    connect(undefined, { configuration, connectTimeoutMs: 1, openConnection }),
    /connectTimeoutMs is process-profile configuration/,
  );
  await assert.rejects(
    connect({ namespace: "outside", database: "test_db" }, { configuration, openConnection }),
    /not configured in this process profile/,
  );
  assert.equal(opened.length, 1);
});

test("public API exposes fixtures without redundant check, deploy, or populate helpers", () => {
  const api = require("../index");
  assert.strictEqual(fixtures, require("../fixtures"));
  assert.strictEqual(prepare, require("../prepare").prepare);
  for (const removed of ["check", "deploy", "populate"]) {
    assert.equal(Object.hasOwn(api, removed), false);
  }
});

test("workbench exposes fixture helpers directly with explicit arguments", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const calls = [];
  const fixtureApi = {
    populate: async (...args) => { calls.push(args); return { populated: true }; },
  };
  const preparation = async (...args) => { calls.push(args); return { prepared: true }; };
  const workbench = startWorkbench({
    project: "test", environment: {}, input, output, api: { fixtures: fixtureApi, prepare: preparation },
  });
  const exited = once(workbench.server, "exit");
  try {
    assert.strictEqual(workbench.context.fixtures, fixtureApi);
    assert.strictEqual(workbench.context.prepare, preparation);
    for (const removed of ["check", "deploy", "populate"]) {
      assert.equal(Object.hasOwn(workbench.context, removed), false);
    }
    workbench.context.project = { project: "all-in-accounting", outputDir: "unused" };
    const connection = { db: { query: async () => [] } };
    const options = { count: 3 };
    assert.deepEqual(await workbench.context.fixtures.populate(connection, options), { populated: true });
    assert.strictEqual(calls[0][0], connection);
    assert.strictEqual(calls[0][1], options);
    assert.equal(calls[0].length, 2);
    assert.deepEqual(await workbench.context.prepare(connection.db, { clear: true }), { prepared: true });
    assert.strictEqual(calls[1][0], connection.db);
    assert.deepEqual(calls[1][1], { clear: true });
    input.write(".clear\n");
    await new Promise((resolve) => setImmediate(resolve));
    assert.strictEqual(workbench.context.fixtures, fixtureApi);
    assert.strictEqual(workbench.context.prepare, preparation);
  } finally {
    input.end(".exit\n");
    await exited;
    await workbench.closeConnections();
  }
});

test("native workbench evaluates JavaScript and await, then closes sessions", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  let text = "";
  output.on("data", (chunk) => { text += chunk.toString(); });
  const opened = [];
  let closed = 0;
  const api = {
    build: async () => ({ built: true }),
    connect: async (context) => {
      opened.push(context);
      return { db: { query: async () => [] }, close: async () => { closed += 1; } };
    },
  };
  const workbench = startWorkbench({ project: "test", environment: {}, input, output, api });
  const exited = once(workbench.server, "exit");
  input.end([
    "1 + 2",
    "await Promise.resolve(40 + 2)",
    "await connect({ namespace: 'test_ns', database: 'test_db' })",
    ".exit",
    "",
  ].join("\n"));
  await exited;
  await workbench.closeConnections();

  assert.match(text, /3/);
  assert.match(text, /42/);
  assert.equal(opened.length, 1);
  assert.equal(opened[0].namespace, "test_ns");
  assert.equal(opened[0].database, "test_db");
  assert.equal(closed, 1);
});

test("native workbench uses its live project options and allows explicit overrides", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const api = {
    build: async (options) => options,
    connect: async () => ({ close: async () => {} }),
  };
  const workbench = startWorkbench({ project: "test", environment: {}, input, output, api });
  const exited = once(workbench.server, "exit");

  assert.equal((await workbench.context.build()).project, "test");
  assert.equal((await workbench.context.build({ check: true })).check, true);
  workbench.context.project.project = "all-in-accounting";
  assert.equal((await workbench.context.build()).project, "all-in-accounting");
  const explicitDirectory = await workbench.context.build({ project: "./designs/test" });
  assert.equal(explicitDirectory.project, "./designs/test");
  assert.equal(Object.hasOwn(explicitDirectory, "projectDir"), false);

  input.end(".exit\n");
  await exited;
  await workbench.closeConnections();
});

test("workbench merges mutable project options, honors reassignment, and restores them after clear", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const builds = [];
  const api = {
    build: async (options) => { builds.push(options); return options; },
    connect: async () => ({ close: async () => {} }),
  };
  const workbench = startWorkbench({ project: "test", environment: {}, input, output, api });
  const exited = once(workbench.server, "exit");

  input.end([
    "project.outputDir = 'mutable-output'",
    "await build()",
    "await build({ outputDir: 'per-call-output' })",
    "project = { project: 'all-in-accounting', projectDir: 'stale-project-dir' }",
    "await build()",
    "await build({ project: 'all-in-one' })",
    ".clear",
    "await build()",
    ".exit",
    "",
  ].join("\n"));
  await exited;

  assert.equal(builds[0].project, "test");
  assert.equal(builds[0].outputDir, "mutable-output");
  assert.equal(builds[1].outputDir, "per-call-output");
  assert.equal(builds[2].projectDir, "stale-project-dir");
  assert.equal(builds[3].project, "all-in-one");
  assert.equal(Object.hasOwn(builds[3], "projectDir"), false);
  assert.equal(builds[4].project, "test");
  assert.equal(Object.hasOwn(builds[4], "outputDir"), false);
  assert.equal(workbench.context.project.project, "test");
  await workbench.closeConnections();
});

test("bare build inspection is compact while full compiler results remain accessible", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  let text = "";
  output.on("data", (chunk) => { text += chunk.toString(); });
  const secret = "private-repl-inspection-sentinel";
  const buildResult = {
    projectDir: "designs/test",
    outputDir: "build/test",
    configuration: { surreal: { password: secret }, runtime: { secret } },
    bundle: `DEFINE EVENT secret VALUE '${secret}';`,
    artifacts: { schemaPath: "schema.surql" },
    tableHandlerCount: 2,
  };
  const api = {
    build: () => buildResult,
    connect: async () => ({ close: async () => {} }),
  };
  const workbench = startWorkbench({ project: "test", environment: {}, input, output, api });
  const exited = once(workbench.server, "exit");
  input.end("await build()\nawait build({ check: true })\n.exit\n");
  await exited;

  assert.match(text, /operation: 'build'/);
  assert.equal((text.match(/operation: 'build'/g) || []).length, 2);
  assert.doesNotMatch(text, /artifactCount/);
  assert.doesNotMatch(text, new RegExp(secret));
  const result = await workbench.context.build();
  assert.equal(result.configuration.surreal.password, secret);
  assert.match(result.bundle, new RegExp(secret));
  await workbench.closeConnections();
});

test("managed SDK connections preserve the raw client and share pending close failures", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  let text = "";
  output.on("data", (chunk) => { text += chunk.toString(); });
  let beginClose;
  let rejectClose;
  let closeCalls = 0;
  const closeStarted = new Promise((resolve) => { beginClose = resolve; });
  const closeFailure = new Error("stub close failed");
  const sdk = { query: async (query) => [query] };
  const api = {
    build: async () => ({}),
    connect: async () => ({
      db: sdk,
      close: () => {
        closeCalls += 1;
        beginClose();
        return new Promise((_resolve, reject) => { rejectClose = reject; });
      },
    }),
  };
  const workbench = startWorkbench({ project: "test", environment: {}, input, output, api });
  const exited = once(workbench.server, "exit");
  const connection = await workbench.context.connect();
  assert.strictEqual(connection.db, sdk);
  assert.deepEqual(await connection.db.query("SELECT 1"), ["SELECT 1"]);

  const firstClose = connection.close();
  const secondClose = connection.close();
  assert.strictEqual(secondClose, firstClose);
  await closeStarted;
  let shutdownSettled = false;
  const shutdown = workbench.closeConnections();
  shutdown.finally(() => { shutdownSettled = true; }).catch(() => {});
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(shutdownSettled, false);
  assert.equal(closeCalls, 1);
  rejectClose(closeFailure);
  await assert.rejects(firstClose, /stub close failed/);
  await assert.rejects(secondClose, /stub close failed/);
  await assert.rejects(shutdown, /Workbench connection cleanup failed/);
  assert.equal(shutdownSettled, true);
  input.end(".exit\n");
  await exited;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal((text.match(/ReBase workbench connection cleanup failed\./g) || []).length, 1);
  assert.doesNotMatch(text, /stub close failed/);
});

test("cleanup retains a manual close failure while another connection is still opening", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  let finishOpening;
  let rejectClosing;
  let opens = 0;
  const failure = new Error("manual close failed while waiting for open");
  const api = {
    connect: () => ++opens === 1
      ? { close: () => new Promise((_resolve, reject) => { rejectClosing = reject; }) }
      : new Promise((resolve) => { finishOpening = resolve; }),
  };
  const workbench = startWorkbench({ project: "test", environment: {}, input, output, api });
  const managed = await workbench.context.connect();
  const manualClose = managed.close();
  const pending = workbench.context.connect();
  const pendingRejection = assert.rejects(pending, /connections are closing/);
  const cleanup = workbench.closeConnections();
  const cleanupRejection = assert.rejects(cleanup, (error) => (
    error instanceof AggregateError && error.errors.length === 1 && error.errors[0] === failure
  ));
  await new Promise((resolve) => setImmediate(resolve));
  rejectClosing(failure);
  await assert.rejects(manualClose, (error) => error === failure);
  finishOpening({ close: async () => {} });
  await pendingRejection;
  const exited = once(workbench.server, "exit");
  input.end(".exit\n");
  await exited;
  await cleanupRejection;
});

test("REPL clear restores workbench helpers without losing connection ownership", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  let closed = 0;
  const api = {
    build: async () => ({}),
    connect: async () => ({ close: async () => { closed += 1; } }),
  };
  const workbench = startWorkbench({ project: "test", environment: {}, input, output, api });
  const exited = once(workbench.server, "exit");
  await workbench.context.connect();
  input.write(".clear\n");
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(typeof workbench.context.build, "function");
  assert.equal(typeof workbench.context.closeConnections, "function");
  await workbench.context.closeConnections();
  assert.equal(closed, 1);
  input.end(".exit\n");
  await exited;
});

test("workbench shutdown waits for late SDK close and rejects later connects", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  let finishOpening;
  let finishClosing;
  let startClosing;
  let closed = 0;
  const closingStarted = new Promise((resolve) => { startClosing = resolve; });
  const api = {
    build: async () => ({}),
    connect: () => new Promise((resolve) => { finishOpening = resolve; }),
  };
  const history = process.env.NODE_REPL_HISTORY;
  const workbench = startWorkbench({ project: "test", environment: {}, input, output, api });
  const exited = once(workbench.server, "exit");
  assert.equal(process.env.NODE_REPL_HISTORY, history);
  const pending = workbench.context.connect();
  await new Promise((resolve) => setImmediate(resolve));
  input.end(".exit\n");
  await exited;
  finishOpening({
    db: { query: async () => [] },
    close: () => {
      closed += 1;
      startClosing();
      return new Promise((resolve) => { finishClosing = resolve; });
    },
  });
  let shutdownSettled = false;
  const shutdown = workbench.closeConnections().then(() => { shutdownSettled = true; });
  await closingStarted;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(shutdownSettled, false);
  await assert.rejects(workbench.context.connect(), /connections are closing/);
  finishClosing();
  await shutdown;
  await assert.rejects(pending, /connections are closing/);
  assert.equal(shutdownSettled, true);
  assert.equal(closed, 1);
});

test("workbench reports a late-open close failure after all cleanup attempts settle", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  let text = "";
  output.on("data", (chunk) => { text += chunk.toString(); });
  let finishOpening;
  let rejectClosing;
  let startClosing;
  const closingStarted = new Promise((resolve) => { startClosing = resolve; });
  const closeFailure = new Error("late-close-private-sentinel");
  const api = {
    build: async () => ({}),
    connect: () => new Promise((resolve) => { finishOpening = resolve; }),
  };
  const workbench = startWorkbench({ project: "test", environment: {}, input, output, api });
  const exited = once(workbench.server, "exit");
  const pending = workbench.context.connect();
  await new Promise((resolve) => setImmediate(resolve));
  input.end(".exit\n");
  await exited;
  finishOpening({
    db: { query: async () => [] },
    close: () => {
      startClosing();
      return new Promise((_resolve, reject) => { rejectClosing = reject; });
    },
  });

  let shutdownSettled = false;
  const shutdown = workbench.closeConnections();
  shutdown.finally(() => { shutdownSettled = true; }).catch(() => {});
  await closingStarted;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(shutdownSettled, false);
  rejectClosing(closeFailure);
  await assert.rejects(pending, /late-close-private-sentinel/);
  await assert.rejects(shutdown, /Workbench connection cleanup failed/);
  assert.equal(shutdownSettled, true);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal((text.match(/ReBase workbench connection cleanup failed\./g) || []).length, 1);
  assert.doesNotMatch(text, /late-close-private-sentinel/);
});
