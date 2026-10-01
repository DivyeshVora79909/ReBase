#!/usr/bin/env node

const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { Surreal } = require("surrealdb");
const { createTableStore } = require("../gateway/store");
const { createRuntime } = require("../gateway/runtime");
const { loadTableHandlers } = require("../gateway/handlers");
const { queryResult } = require("../gateway/utils");

const namespace = "credential_probe";
const database = "checks";
const result = (rows) => queryResult(rows);
const firstRecord = (rows) => {
  const value = result(rows);
  return Array.isArray(value) ? value[0] : value;
};

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function startDatabase() {
  const port = await freePort();
  const child = spawn("surreal", [
    "start", "memory", "--user", "root", "--pass", "root",
    "--bind", `127.0.0.1:${port}`, "--no-banner", "--log", "error",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Disposable SurrealDB exited: ${stderr}`);
    try {
      const socket = net.createConnection(port, "127.0.0.1");
      await new Promise((resolve, reject) => {
        socket.once("connect", resolve);
        socket.once("error", reject);
      });
      socket.destroy();
      return { child, endpoint: `ws://127.0.0.1:${port}/rpc` };
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 30));
    }
  }
  child.kill("SIGTERM");
  throw new Error(`Disposable SurrealDB did not start: ${stderr}`);
}

async function signIn(endpoint, email) {
  const db = new Surreal();
  await db.connect(endpoint);
  await db.signin({
    namespace, database, access: "account_password",
    variables: { identifier: email, password: "probe-password" },
  });
  return db;
}

async function assertNoRecord(client, root, id, query) {
  await client.query(query).catch(() => null);
  const rows = result(await root.query(`SELECT VALUE id FROM ${id};`));
  assert.equal(rows.length, 0, `unauthorized create wrote ${id}`);
}

async function main() {
  const started = Date.now();
  const disposable = await startDatabase();
  const clients = [];
  let root;
  try {
    root = new Surreal();
    await root.connect(disposable.endpoint);
    await root.signin({ username: "root", password: "root" });
    await root.query(`DEFINE NAMESPACE ${namespace}; USE NS ${namespace}; DEFINE DATABASE ${database}; USE DB ${database};`);
    await root.use({ namespace, database });
    await root.query(fs.readFileSync(path.resolve("build/test/schema.surql"), "utf8"));
    await root.query(`
      CREATE rebase_group:tenant SET name = 'Tenant', parents = [rebase_group:root],
        role = ['send_brevo_email_create', 'send_brevo_email_select', 'send_twilio_sms_create', 'send_twilio_sms_select'];
      CREATE rebase_group:unrelated SET name = 'Unrelated', parents = [rebase_group:root],
        role = ['send_brevo_email_create', 'send_brevo_email_select', 'send_twilio_sms_create', 'send_twilio_sms_select'];
      CREATE rebase_group:unauthorized SET name = 'Unauthorized', parents = [rebase_group:root], role = [];
      CREATE rebase_user:alice SET name = 'Alice', parents = [rebase_group:tenant],
        password = crypto::argon2::generate('probe-password');
      CREATE rebase_user:delegate SET name = 'Delegate', parents = [rebase_group:tenant],
        password = crypto::argon2::generate('probe-password');
      CREATE rebase_user:bob SET name = 'Bob', parents = [rebase_group:unrelated],
        password = crypto::argon2::generate('probe-password');
      CREATE rebase_user:charlie SET name = 'Charlie', parents = [rebase_group:unauthorized],
        password = crypto::argon2::generate('probe-password');
      CREATE authentication_email:alice SET principal = rebase_user:alice, address = 'alice@example.test';
      CREATE authentication_email:delegate SET principal = rebase_user:delegate, address = 'delegate@example.test';
      CREATE authentication_email:bob SET principal = rebase_user:bob, address = 'bob@example.test';
      CREATE authentication_email:charlie SET principal = rebase_user:charlie, address = 'charlie@example.test';
      UPDATE authentication_email:alice SET verified_revision = revision, verified_at = time::now();
      UPDATE authentication_email:delegate SET verified_revision = revision, verified_at = time::now();
      UPDATE authentication_email:bob SET verified_revision = revision, verified_at = time::now();
      UPDATE authentication_email:charlie SET verified_revision = revision, verified_at = time::now();
      CREATE rebase_email_delivery_config:platform SET owned_by = rebase_group:root,
        api_key = 'platform-email-secret', from_email = 'platform@example.test', from_name = 'Platform';
      CREATE rebase_sms_delivery_config:platform SET owned_by = rebase_group:root,
        account_sid = 'ACplatform', auth_token = 'platform-sms-secret', from_number = '+10000000001';
    `);
    const alice = await signIn(disposable.endpoint, "alice@example.test");
    const delegate = await signIn(disposable.endpoint, "delegate@example.test");
    const bob = await signIn(disposable.endpoint, "bob@example.test");
    const charlie = await signIn(disposable.endpoint, "charlie@example.test");
    const anonymous = new Surreal();
    await anonymous.connect(disposable.endpoint);
    clients.push(alice, delegate, bob, charlie, anonymous);

    await anonymous.use({ namespace, database }).catch(() => {});
    await anonymous.query("SELECT * FROM rebase_email_delivery_config:platform;").catch(() => {});
    await anonymous.query(`CREATE rebase_email_delivery_config:anonymous SET owned_by = rebase_user:alice,
      api_key = 'anonymous-secret', from_email = 'anonymous@example.test', from_name = 'Anonymous';`).catch(() => {});
    assert.equal(result(await root.query("SELECT VALUE id FROM rebase_email_delivery_config:anonymous;" )).length, 0);

    assert.equal(result(await alice.query("SELECT id FROM rebase_email_delivery_config:platform;" )).length, 0);
    assert.equal(result(await bob.query("SELECT id FROM rebase_sms_delivery_config:platform;" )).length, 0);
    await alice.query("UPDATE rebase_email_delivery_config:platform SET api_key = 'client-tamper';").catch(() => {});
    await alice.query("DELETE rebase_email_delivery_config:platform;").catch(() => {});
    await bob.query("UPDATE rebase_sms_delivery_config:platform SET auth_token = 'client-tamper';").catch(() => {});
    await bob.query("DELETE rebase_sms_delivery_config:platform;").catch(() => {});
    assert.equal(result(await root.query("RETURN rebase_email_delivery_config:platform.api_key;")), "platform-email-secret");
    assert.equal(result(await root.query("RETURN rebase_sms_delivery_config:platform.auth_token;")), "platform-sms-secret");
    await assertNoRecord(alice, root, "rebase_email_delivery_config:forged", `CREATE rebase_email_delivery_config:forged SET
      owned_by = rebase_group:root, api_key = 'forged', from_email = 'a@example.test', from_name = 'A';`);
    await assertNoRecord(alice, root, "rebase_sms_delivery_config:forged", `CREATE rebase_sms_delivery_config:forged SET
      owned_by = rebase_group:root, account_sid = 'ACforged', auth_token = 'forged', from_number = '+10000000002';`);

    const emailCreated = firstRecord(await alice.query(`CREATE rebase_email_delivery_config:alice SET
      owned_by = rebase_user:alice, api_key = 'alice-email-secret',
      from_email = 'alice@example.test', from_name = 'Alice', reply_to = 'reply@example.test' RETURN AFTER;`));
    assert.equal(emailCreated.api_key, undefined);
    assert.equal(result(await alice.query("RETURN type::is_none(rebase_email_delivery_config:alice.api_key);")), true);
    assert.equal(result(await alice.query("SELECT VALUE id FROM rebase_email_delivery_config:alice WHERE api_key = 'alice-email-secret';")).length, 0);
    const smsCreated = firstRecord(await alice.query(`CREATE rebase_sms_delivery_config:tenant SET
      owned_by = rebase_group:tenant, account_sid = 'ACtenant', auth_token = 'tenant-sms-secret',
      api_key_sid = 'tenant-sid', api_key_secret = 'tenant-key-secret', from_number = '+10000000003' RETURN AFTER;`));
    assert.equal(smsCreated.auth_token, undefined);
    assert.equal(smsCreated.api_key_sid, undefined);
    assert.equal(smsCreated.api_key_secret, undefined);
    assert.equal(result(await bob.query("SELECT * FROM rebase_email_delivery_config:alice;" )).length, 0);
    await anonymous.query("UPDATE rebase_email_delivery_config:alice SET api_key = 'anonymous-tamper';").catch(() => {});
    await anonymous.query("DELETE rebase_email_delivery_config:alice;").catch(() => {});
    assert.equal(result(await root.query("RETURN rebase_email_delivery_config:alice.api_key;")), "alice-email-secret");
    assert.equal(result(await delegate.query("SELECT * FROM rebase_sms_delivery_config:tenant;" ))[0].auth_token, undefined);
    assert.equal(result(await bob.query("UPDATE rebase_email_delivery_config:alice SET from_name = 'Other' RETURN AFTER;" )).length, 0);
    assert.equal(result(await root.query("RETURN rebase_email_delivery_config:alice.from_name;")), "Alice");
    await assert.rejects(alice.query("UPDATE rebase_email_delivery_config:alice SET owned_by = rebase_user:bob;"));

    const emailAfter = firstRecord(await alice.query(`UPDATE rebase_email_delivery_config:alice SET
      from_name = api_key ?? 'blocked',
      from_email = api_key ?? 'safe@example.test',
      reply_to = api_key ?? 'safe@example.test' RETURN AFTER;`));
    assert.equal(emailAfter.from_name, "blocked", JSON.stringify(emailAfter));
    assert.equal(emailAfter.from_email, "safe@example.test");
    assert.equal(emailAfter.reply_to, "safe@example.test");
    assert.equal(emailAfter.api_key, undefined);
    for (const secret of ["auth_token", "api_key_sid", "api_key_secret"]) {
      const updated = firstRecord(await delegate.query(`UPDATE rebase_sms_delivery_config:tenant
        SET account_sid = ${secret} ?? 'blocked', from_number = ${secret} ?? '+10000000004' RETURN AFTER;`));
      assert.equal(updated.account_sid, "blocked");
      assert.equal(updated.from_number, "+10000000004");
      assert.equal(updated[secret], undefined);
    }
    assert.equal(result(await root.query("RETURN rebase_email_delivery_config:alice.api_key;")), "alice-email-secret");
    assert.equal(result(await root.query("RETURN rebase_sms_delivery_config:tenant.auth_token;")), "tenant-sms-secret");
    assert.equal(result(await root.query("RETURN rebase_sms_delivery_config:tenant.api_key_secret;")), "tenant-key-secret");
    const rotated = firstRecord(await delegate.query(`UPDATE rebase_sms_delivery_config:tenant
      SET auth_token = 'rotated-sms-secret' RETURN AFTER;`));
    assert.equal(rotated.auth_token, undefined);
    assert.equal(result(await root.query("RETURN rebase_sms_delivery_config:tenant.auth_token;")), "rotated-sms-secret");
    const rotatedEmail = firstRecord(await alice.query(`UPDATE rebase_email_delivery_config:alice
      SET api_key = 'rotated-email-secret' RETURN AFTER;`));
    assert.equal(rotatedEmail.api_key, undefined);
    assert.equal(result(await root.query("RETURN rebase_email_delivery_config:alice.api_key;")), "rotated-email-secret");

    await assertNoRecord(bob, root, "send_brevo_email:cross_owner", `CREATE send_brevo_email:cross_owner SET owned_by = rebase_user:bob,
      config = rebase_email_delivery_config:alice, to = ['recipient@example.test'], subject = 'denied';`);
    await assertNoRecord(alice, root, "send_brevo_email:root_reference", `CREATE send_brevo_email:root_reference SET owned_by = rebase_user:alice,
      config = rebase_email_delivery_config:platform, to = ['recipient@example.test'], subject = 'denied';`);
    await assertNoRecord(charlie, root, "send_brevo_email:unauthorized", `CREATE send_brevo_email:unauthorized SET owned_by = rebase_user:charlie,
      to = ['recipient@example.test'], subject = 'No permission';`);
    const byocEmail = firstRecord(await alice.query(`CREATE send_brevo_email:byoc SET owned_by = rebase_user:alice,
      config = rebase_email_delivery_config:alice, to = ['recipient@example.test'], subject = 'BYOC';`));
    const platformEmail = firstRecord(await alice.query(`CREATE send_brevo_email:platform SET owned_by = rebase_user:alice,
      to = ['recipient@example.test'], subject = 'Platform';`));
    const byocSms = firstRecord(await delegate.query(`CREATE send_twilio_sms:byoc SET owned_by = rebase_user:delegate,
      config = rebase_sms_delivery_config:tenant, to = '+10000000005', body = 'BYOC';`));
    const platformSms = firstRecord(await alice.query(`CREATE send_twilio_sms:platform SET owned_by = rebase_user:alice,
      to = '+10000000005', body = 'Platform';`));
    const roleRevoked = firstRecord(await alice.query(`CREATE send_brevo_email:role_revoked SET owned_by = rebase_user:alice,
      config = rebase_email_delivery_config:alice, to = ['recipient@example.test'], subject = 'Role revoked';`));
    const denied = firstRecord(await alice.query(`CREATE send_brevo_email:revoked SET owned_by = rebase_user:alice,
      config = rebase_email_delivery_config:alice, to = ['recipient@example.test'], subject = 'Owner revoked';`));
    assert(denied?.id);
    const missingCreator = firstRecord(await root.query(`CREATE send_brevo_email:missing_creator SET owned_by = rebase_group:tenant,
      to = ['recipient@example.test'], subject = 'Missing creator';`));
    assert(missingCreator?.id);
    assert(missingCreator.created_by == null, "system-created operation fixture should have no user creator");
    assert.equal(String(byocEmail.created_by), "rebase_user:alice");
    assert.equal(String(platformEmail.created_by), "rebase_user:alice");
    assert.equal(String(byocSms.created_by), "rebase_user:delegate");
    assert.equal(String(platformSms.created_by), "rebase_user:alice");

    const contracts = new Map(Object.entries(JSON.parse(fs.readFileSync(path.resolve("build/test/runtime-contracts.json"), "utf8")).tables));
    const handlers = loadTableHandlers("designs/test/table-handlers", { contracts });
    const databaseStore = createTableStore(root);
    let secretLoads = 0;
    const store = { ...databaseStore, async load(id) {
      if (String(id).startsWith("rebase_email_delivery_config:") || String(id).startsWith("rebase_sms_delivery_config:")) secretLoads += 1;
      return databaseStore.load(id);
    } };
    const sends = [];
    const runtime = createRuntime({
      stores: { async forContext() { return store; } }, handlers, contracts,
      adapters: {
        async sendBrevoEmail(input) { sends.push({ channel: "email", credential: input.apiKey }); return { messageId: "mock-email", provider: "mock", accepted: input.to }; },
        async getBrevoEmailEvents() { return []; },
        async sendTwilioSms(input) { sends.push({ channel: "phone", credential: input.configuration.auth_token }); return { messageId: "mock-sms" }; },
      },
    });
    const execute = (id) => runtime.execute({ namespace, database, id });
    assert.equal((await execute("send_brevo_email:byoc")).state, "succeeded");
    assert.equal((await execute("send_brevo_email:platform")).state, "succeeded");
    assert.equal((await execute("send_twilio_sms:byoc")).state, "succeeded");
    assert.equal((await execute("send_twilio_sms:platform")).state, "succeeded");
    assert.deepEqual(sends, [
      { channel: "email", credential: "rotated-email-secret" },
      { channel: "email", credential: "platform-email-secret" },
      { channel: "phone", credential: "rotated-sms-secret" },
      { channel: "phone", credential: "platform-sms-secret" },
    ]);
    const persistedEmailOperation = JSON.stringify(result(await root.query("SELECT * FROM send_brevo_email:byoc;")));
    const persistedSmsOperation = JSON.stringify(result(await root.query("SELECT * FROM send_twilio_sms:byoc;")));
    for (const secret of ["rotated-email-secret", "platform-email-secret", "rotated-sms-secret", "platform-sms-secret"]) {
      assert.equal(persistedEmailOperation.includes(secret), false);
      assert.equal(persistedSmsOperation.includes(secret), false);
    }
    await root.query("UPDATE rebase_email_delivery_config:alice SET owned_by = rebase_user:bob;");
    const loadsBefore = secretLoads;
    const sendsBefore = sends.length;
    const blocked = await execute("send_brevo_email:revoked");
    assert.equal(blocked.action, "dead-letter");
    assert.equal(result(await root.query("RETURN send_brevo_email:revoked.rebase_outcome;")), "failed");
    assert.equal(secretLoads, loadsBefore, "worker must deny before loading a secret");
    assert.equal(sends.length, sendsBefore);
    await root.query("UPDATE rebase_email_delivery_config:alice SET owned_by = rebase_user:alice;");
    await root.query("UPDATE rebase_group:tenant SET role = [];");
    const loadsBeforeRoleRevocation = secretLoads;
    const sendsBeforeRoleRevocation = sends.length;
    const roleRevokedResult = await execute("send_brevo_email:role_revoked");
    assert.equal(roleRevokedResult.action, "dead-letter");
    assert.equal(secretLoads, loadsBeforeRoleRevocation, "worker must recheck the operation permission before loading BYOC secrets");
    assert.equal(sends.length, sendsBeforeRoleRevocation);
    const noCreatorLoads = secretLoads;
    const noCreatorSends = sends.length;
    const noCreator = await execute("send_brevo_email:missing_creator");
    assert.equal(noCreator.action, "dead-letter");
    assert.equal(secretLoads, noCreatorLoads, "worker must reject a task without a creator before loading a secret");
    assert.equal(sends.length, noCreatorSends);
    console.log(`credentials: owner, delegation, redaction, platform binding, BYOC, unauthorized operation, and pre-load guards passed (${Date.now() - started}ms)`);
  } finally {
    await Promise.all(clients.map((client) => client.close().catch(() => {})));
    await root?.close().catch(() => {});
    disposable.child.kill("SIGTERM");
  }
}

main().catch((error) => {
  console.error(`credentials: FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});
