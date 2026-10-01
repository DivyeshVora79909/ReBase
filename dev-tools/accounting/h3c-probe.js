#!/usr/bin/env node

const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { Surreal } = require('surrealdb');
const { queryResult } = require('../../gateway/utils');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');

const root = path.resolve(__dirname, '../..');
const fixtureDirectory = path.join(__dirname, 'h3c-fixture');

function numeric(value) { return Number(String(value).replace(/dec$/i, '')); }
async function rejects(action, label) { await assert.rejects(action, undefined, label); }

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', (error) => error ? reject(error) : resolve()));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForPort(port, child) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`SurrealDB exited with ${child.exitCode}`);
    const ready = await new Promise((resolve) => {
      const socket = net.connect(port, '127.0.0.1');
      const finish = (value) => { socket.destroy(); resolve(value); };
      socket.setTimeout(100, () => finish(false));
      socket.once('connect', () => finish(true));
      socket.once('error', () => finish(false));
    });
    if (ready) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('H3c SurrealDB did not become ready');
}

function compileAndValidate() {
  const materials = loadMaterials({ groups: [
    { name: 'framework', roots: [path.join(root, 'framework')] },
    { name: 'project', roots: [path.join(root, 'designs/all-in-accounting'), fixtureDirectory] },
  ] });
  const compiled = generateBundle(materials);
  const accountingMaterials = loadMaterials({ groups: [
    { name: 'framework', roots: [path.join(root, 'framework')] },
    { name: 'project', roots: [path.join(root, 'designs/all-in-accounting')] },
  ] });
  const accountingTableCount = generateBundle(accountingMaterials).schema.tables.size;
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-h3c-'));
  try {
    const schemaPath = path.join(temporary, 'schema.surql');
    fs.writeFileSync(schemaPath, compiled.bundle);
    const validated = spawnSync('surreal', ['validate', schemaPath], { encoding: 'utf8' });
    assert.equal(validated.status, 0, validated.stderr || validated.stdout || 'H3c native validation failed');
  } finally { fs.rmSync(temporary, { recursive: true, force: true }); }
  assert.equal(compiled.schema.tables.size, accountingTableCount + 3,
    'accounting profile plus exactly three disposable H3c tables');
  return { bundle: compiled.bundle, materialCount: materials.files.length, tableCount: compiled.schema.tables.size };
}

async function graph(db) {
  return queryResult(await db.query(`RETURN {
    headers: (SELECT * FROM h3c_header ORDER BY id),
    packages: (SELECT * FROM h3c_package ORDER BY id),
    deliveries: (SELECT * FROM h3c_delivery ORDER BY id),
    issues: (SELECT * FROM sales_invoice_issue ORDER BY id),
    lines: (SELECT * FROM sales_invoice_line ORDER BY id),
    dispatches: (SELECT * FROM stock_out ORDER BY id),
    stock: (SELECT * FROM ONLY stock_account:h3c_stock),
    invoices: (SELECT * FROM sales_invoice ORDER BY id),
    claim: (SELECT * FROM ONLY claim_account:h3c_customer)
  };`));
}

function lineFor(data, id) {
  const line = data.lines.find((row) => String(row.id) === id);
  assert(line, `missing authoritative sales invoice line ${id}`);
  return line;
}

async function assertOracle(db) {
  const data = await graph(db);
  const byId = new Map([...data.headers, ...data.packages].map((row) => [String(row.id), row]));
  const totals = new Map(data.headers.map((row) => [String(row.id), { count: 0, quantity: 0 }]));
  for (const leaf of data.deliveries) {
    const levels = [leaf];
    let cursor = leaf;
    while (cursor.parent) {
      cursor = byId.get(String(cursor.parent));
      assert(cursor, `missing typed H3c ancestor of ${leaf.id}`);
      levels.push(cursor);
      assert(levels.length <= 10, 'ancestry must terminate at the header in ten record levels');
    }
    assert.equal(levels.length, 10, 'header + eight packages + delivery are ten actual records');
    const header = levels[9];
    assert.equal(String(header.id).startsWith('h3c_header:'), true);
    for (let index = 0; index < 9; index += 1) {
      const child = levels[index], parent = levels[index + 1];
      for (const field of ['line', 'invoice', 'claim_account', 'customer', 'economic_entity',
        'currency', 'direction', 'dispatch_at', 'recognition_at', 'source_quantity',
        'available_quantity', 'root']) {
        assert.equal(String(child[field]), String(parent[field]), `${child.id}.${field} follows one typed parent hop`);
      }
      assert.equal(numeric(child.depth), numeric(parent.depth) + 1, 'depth follows exactly one parent record');
    }
    assert.equal(String(leaf.declared_invoice), String(header.invoice), 'leaf document agrees with header');
    assert.equal(leaf.declared_direction, header.direction, 'leaf direction agrees with header');
    assert(numeric(leaf.quantity) > 0 && numeric(leaf.quantity) <= numeric(leaf.available_quantity),
      'leaf contributes a bounded entered quantity');
    const tally = totals.get(String(header.id));
    tally.count += 1;
    tally.quantity += numeric(leaf.quantity);
  }
  for (const header of data.headers) {
    const tally = totals.get(String(header.id));
    const summary = header.z_deliveries.summary;
    const line = lineFor(data, String(header.line));
    const dispatch = data.dispatches.find((row) => String(row.id) === String(line.source));
    const issue = data.issues.find((row) => String(row.id) === line.rebase_managed_source);
    assert(dispatch && issue, 'header traces to an actual dispatch and issued invoice source');
    assert.equal(numeric(header.source_quantity), numeric(line.billed_quantity), 'header source quantity follows real billed line');
    assert.equal(String(header.invoice), String(line.invoice), 'header document follows real billed line');
    assert.equal(String(header.invoice), String(issue.invoice), 'header document follows issued invoice source');
    assert.equal(String(header.claim_account), String(data.claim.id), 'header claim follows canonical line claim');
    assert.equal(String(header.customer), String(data.claim.opponent), 'header customer follows canonical claim');
    assert.equal(String(header.customer), String(dispatch.to_party), 'header customer agrees with physical dispatch');
    assert.equal(String(header.economic_entity), String(data.claim.economic_entity), 'header entity follows claim');
    assert.equal(String(header.economic_entity), String(data.stock.economic_entity), 'header entity agrees with stock');
    assert.equal(String(header.currency), String(data.claim.currency), 'header currency follows claim');
    assert.equal(header.direction, 'sales', 'existing sales invoice line fixes ancestry direction');
    assert.equal(String(header.dispatch_at), String(dispatch.effective_at), 'header dispatch date follows physical movement');
    assert.equal(String(header.recognition_at), String(issue.issued_at), 'header recognition follows invoice issue');
    assert.equal(numeric(summary.measures?.quantity?.sum ?? 0), tally.quantity,
      `${header.id} leaf-only quantity sum`);
    assert.equal(summary.count ?? 0, tally.count, `${header.id} leaf-only active positions`);
    if (tally.count) {
      for (const field of ['invoice', 'customer', 'economic_entity', 'currency',
        'direction', 'available_quantity']) {
        assert.equal(summary.tags[field].uniform, true, `${header.id} ${field} tag uniform`);
        assert.equal(String(summary.tags[field].value), String(header[field]), `${header.id} ${field} tag`);
      }
    }
  }
  const physical = data.dispatches.reduce((sum, row) => sum - numeric(row.quantity), 8);
  assert.equal(numeric(data.stock.z_history.summary.measures.quantity.sum), physical,
    'fixture delivery leaves never duplicate physical stock effects');
  return data;
}

async function setup(db) {
  await db.query(`
    CREATE ONLY organization:h3c_owner SET owned_by = rebase_group:root, name = 'H3c owner';
    CREATE ONLY organization:h3c_customer SET owned_by = rebase_group:root, name = 'H3c customer';
    CREATE ONLY currency:h3c_usd SET owned_by = rebase_group:root, code = 'USD', name = 'H3c dollar', precision = 2;
    CREATE ONLY measure_unit:h3c_kg SET owned_by = rebase_group:root, code = 'kg', name = 'H3c kilogram', dimension = 'mass';
    CREATE ONLY item:h3c_item SET owned_by = rebase_group:root, name = 'H3c item', unit = measure_unit:h3c_kg;
    CREATE ONLY operating_unit:h3c_unit SET owned_by = rebase_group:root,
      economic_entity = organization:h3c_owner, name = 'H3c warehouse';
    CREATE ONLY stock_account:h3c_stock SET owned_by = rebase_group:root,
      economic_entity = organization:h3c_owner, operating_unit = operating_unit:h3c_unit, resource = item:h3c_item;
    CREATE ONLY claim_account:h3c_customer SET owned_by = rebase_group:root,
      economic_entity = organization:h3c_owner, opponent = organization:h3c_customer, currency = currency:h3c_usd;
    CREATE ONLY sales_invoice:h3c_invoice_a SET owned_by = rebase_group:root,
      claim_account = claim_account:h3c_customer, number = 'H3C-A';
    CREATE ONLY sales_invoice:h3c_invoice_c SET owned_by = rebase_group:root,
      claim_account = claim_account:h3c_customer, number = 'H3C-C';
    CREATE ONLY stock_in:h3c_opening SET owned_by = rebase_group:root,
      from_party = organization:h3c_customer, to_account = stock_account:h3c_stock,
      quantity = 8dec, effective_at = d'2026-06-29T00:00:00Z';
    CREATE ONLY stock_out:h3c_dispatch_a SET owned_by = rebase_group:root,
      from_account = stock_account:h3c_stock, to_party = organization:h3c_customer,
      quantity = 4dec, effective_at = d'2026-07-01T00:00:00Z';
    CREATE ONLY stock_out:h3c_dispatch_c SET owned_by = rebase_group:root,
      from_account = stock_account:h3c_stock, to_party = organization:h3c_customer,
      quantity = 4dec, effective_at = d'2026-07-01T00:00:00Z';
    CREATE ONLY sales_invoice_issue:h3c_issue_a SET owned_by = rebase_group:root,
      invoice = sales_invoice:h3c_invoice_a, issued_at = d'2026-07-02T00:00:00Z',
      lines = [{ line_key: 'main', source: stock_out:h3c_dispatch_a, billed_quantity: 4dec, unit_price: 1dec }];
    CREATE ONLY sales_invoice_issue:h3c_issue_c SET owned_by = rebase_group:root,
      invoice = sales_invoice:h3c_invoice_c, issued_at = d'2026-07-02T00:00:00Z',
      lines = [{ line_key: 'main', source: stock_out:h3c_dispatch_c, billed_quantity: 4dec, unit_price: 1dec }];
  `);
  const data = await graph(db);
  const lineA = data.lines.find((row) => String(row.invoice) === 'sales_invoice:h3c_invoice_a');
  const lineC = data.lines.find((row) => String(row.invoice) === 'sales_invoice:h3c_invoice_c');
  assert(lineA && lineC, 'real managed sales invoice lines exist before H3c ancestry');
  await db.query(`
    CREATE ONLY h3c_header:a SET owned_by = rebase_group:root, line = ${lineA.id}, available_quantity = 4dec;
    CREATE ONLY h3c_header:b SET owned_by = rebase_group:root, line = ${lineA.id}, available_quantity = 4dec;
    CREATE ONLY h3c_header:c SET owned_by = rebase_group:root, line = ${lineC.id}, available_quantity = 4dec;
  `);
  for (const [prefix, header, count] of [
    ['a', 'h3c_header:a', 8], ['b', 'h3c_header:b', 3], ['c', 'h3c_header:c', 3],
  ]) {
    for (let depth = 1; depth <= count; depth += 1) {
      const parent = depth === 1 ? header : `h3c_package:${prefix}${depth - 1}`;
      const declared = prefix === 'a' && depth === 4 ? ', declared_invoice = sales_invoice:h3c_invoice_a' : '';
      await db.query(`CREATE ONLY h3c_package:${prefix}${depth} SET owned_by = rebase_group:root,
        parent = ${parent}${declared};`);
    }
  }
  for (let depth = 6; depth <= 8; depth += 1) {
    const parent = depth === 6 ? 'h3c_package:a5' : `h3c_package:s${depth - 1}`;
    await db.query(`CREATE ONLY h3c_package:s${depth} SET owned_by = rebase_group:root,
      parent = ${parent};`);
  }
  for (let depth = 4; depth <= 8; depth += 1) {
    const parent = depth === 4 ? 'h3c_package:c3' : `h3c_package:c${depth - 1}`;
    await db.query(`CREATE ONLY h3c_package:c${depth} SET owned_by = rebase_group:root,
      parent = ${parent};`);
  }
  await db.query(`
    CREATE ONLY h3c_delivery:main SET owned_by = rebase_group:root, parent = h3c_package:a8,
      declared_invoice = sales_invoice:h3c_invoice_a, declared_direction = 'sales', quantity = 1.5dec;
    CREATE ONLY h3c_delivery:sibling SET owned_by = rebase_group:root, parent = h3c_package:s8,
      declared_invoice = sales_invoice:h3c_invoice_a, declared_direction = 'sales', quantity = 1.5dec;
  `);
}

async function probe(db) {
  await setup(db);
  let data = await assertOracle(db);
  assert.equal(data.headers.find((row) => String(row.id) === 'h3c_header:a').z_deliveries.summary.count, 2);
  assert.equal(numeric(data.headers.find((row) => String(row.id) === 'h3c_header:a')
    .z_deliveries.summary.measures.quantity.sum), 3, 'two bounded partial leaves contribute 1.5 each');
  assert.equal(data.headers.find((row) => String(row.id) === 'h3c_header:b').z_deliveries.summary.count, 0);
  let before = await graph(db);
  await rejects(() => db.query(`CREATE ONLY h3c_delivery:short SET owned_by = rebase_group:root,
    parent = h3c_package:a3, declared_invoice = sales_invoice:h3c_invoice_a,
    declared_direction = 'sales', quantity = 1dec;`), 'a delivery cannot skip required package ancestors');
  await rejects(() => db.query(`CREATE ONLY h3c_package:missing SET owned_by = rebase_group:root,
    parent = h3c_package:absent;`), 'a package cannot omit a typed parent');
  await rejects(() => db.query(`CREATE ONLY h3c_delivery:wrong_document SET owned_by = rebase_group:root,
    parent = h3c_package:a8, declared_invoice = sales_invoice:h3c_invoice_c,
    declared_direction = 'sales', quantity = 0.25dec;`), 'mixed invoice tags cannot enter the populated root');
  await rejects(() => db.query(`CREATE ONLY h3c_delivery:mixed_direction SET owned_by = rebase_group:root,
    parent = h3c_package:a8, declared_invoice = sales_invoice:h3c_invoice_a,
    declared_direction = 'purchase', quantity = 0.25dec;`), 'mixed sales/purchase direction cannot enter the populated root');
  await rejects(() => db.query(`CREATE ONLY h3c_delivery:uniform_wrong_document SET owned_by = rebase_group:root,
    parent = h3c_package:c8, declared_invoice = sales_invoice:h3c_invoice_a,
    declared_direction = 'sales', quantity = 0.25dec;`),
  'uniform invoice tag still must match its otherwise empty header root');
  await rejects(() => db.query(`CREATE ONLY h3c_delivery:uniform_wrong_direction SET owned_by = rebase_group:root,
    parent = h3c_package:c8, declared_invoice = sales_invoice:h3c_invoice_c,
    declared_direction = 'purchase', quantity = 0.25dec;`),
  'uniform direction tag still must match its otherwise empty header root');
  assert.deepEqual(await graph(db), before, 'invalid depth, document and direction leave all sources and roots intact');

  await db.query('UPDATE h3c_package:a4 SET parent = h3c_package:b3;');
  data = await assertOracle(db);
  assert.equal(data.headers.find((row) => String(row.id) === 'h3c_header:a').z_deliveries.summary.count, 0,
    'compatible middle-level reparent clears old header root');
  assert.equal(data.headers.find((row) => String(row.id) === 'h3c_header:b').z_deliveries.summary.count, 2,
    'compatible middle-level reparent moves both descendant leaves');
  assert.equal(numeric(data.headers.find((row) => String(row.id) === 'h3c_header:a')
    .z_deliveries.summary.measures?.quantity?.sum ?? 0), 0, 'old root loses both quantities');
  assert.equal(numeric(data.headers.find((row) => String(row.id) === 'h3c_header:b')
    .z_deliveries.summary.measures.quantity.sum), 3, 'new root gains both quantities');
  before = await graph(db);
  await rejects(() => db.query('UPDATE h3c_package:a4 SET parent = h3c_package:c3;'),
    'uniform descendant document A cannot move below document C');
  assert.deepEqual(await graph(db), before, 'incompatible middle-level reparent restores old and new roots');

  await db.query('UPDATE h3c_delivery:main SET quantity = 1.25dec;');
  data = await assertOracle(db);
  assert.equal(numeric(data.headers.find((row) => String(row.id) === 'h3c_header:b')
    .z_deliveries.summary.measures.quantity.sum), 2.75,
  'entered partial leaf quantity updates exactly one root position');
  await db.query('UPDATE h3c_header:b SET available_quantity = 2.75dec;');
  data = await assertOracle(db);
  assert.equal(data.deliveries.every((row) => numeric(row.available_quantity) === 2.75), true,
    'ancestor capacity edit refreshes every descendant shadow and root tag');
  await db.query("UPDATE sales_invoice_issue:h3c_issue_a SET issued_at = d'2026-07-03T00:00:00Z';");
  data = await assertOracle(db);
  assert.equal(numeric(queryResult(await db.query(`RETURN fn::tree::read(h3c_header:b,
    'z_deliveries', 'before', [d'2026-07-03T00:00:00Z']).measures.quantity.sum ?? 0dec;`))), 0,
  'recognition edit moves both leaf positions away from the old date');
  await db.query("UPDATE stock_out:h3c_dispatch_a SET effective_at = d'2026-07-02T00:00:00Z';");
  data = await assertOracle(db);
  assert.equal(data.deliveries.every((row) => String(row.dispatch_at).startsWith('2026-07-02')), true,
    'dispatch date refreshes every descendant shadow after recognition');

  await db.query('DELETE h3c_delivery:sibling;');
  data = await assertOracle(db);
  assert.equal(data.headers.find((row) => String(row.id) === 'h3c_header:b').z_deliveries.summary.count, 1,
    'leaf deletion removes exactly one root position');
  await db.query(`CREATE ONLY h3c_delivery:sibling SET owned_by = rebase_group:root,
    parent = h3c_package:s8, declared_invoice = sales_invoice:h3c_invoice_a,
    declared_direction = 'sales', quantity = 1.5dec;`);
  await assertOracle(db);
  before = await graph(db);
  await rejects(() => db.query('DELETE sales_invoice_issue:h3c_issue_a;'),
    'an issued source cannot be deleted while typed ancestry references its managed line');
  assert.deepEqual(await graph(db), before, 'failed source deletion keeps the complete ancestry and all roots');
  await rejects(() => db.query(`UPDATE sales_invoice_issue:h3c_issue_a SET lines = [
    { line_key: 'main', source: stock_out:h3c_dispatch_a,
      billed_quantity: 2.5dec, unit_price: 1dec }
  ];`), 'final header guard rejects billed capacity below two descendant leaf positions');
  assert.deepEqual(await graph(db), before,
    'final guard rejection restores issue, managed line, dispatch, every ancestor, leaves and old/new roots');
}

async function main() {
  const compiled = compileAndValidate();
  if (process.argv.includes('--validate-only')) {
    process.stdout.write(`H3c isolated fixture compiled and natively validated: ${compiled.tableCount} tables, ${compiled.materialCount} materials\n`);
    return;
  }
  const port = await freePort();
  const child = spawn('surreal', [
    'start', 'memory', '--user', 'root', '--pass', 'root',
    '--bind', `127.0.0.1:${port}`, '--no-banner', '--log', 'error',
  ], { cwd: root, stdio: ['ignore', 'ignore', 'ignore'] });
  const db = new Surreal();
  try {
    await waitForPort(port, child);
    await db.connect(`ws://127.0.0.1:${port}/rpc`);
    await db.signin({ username: 'root', password: 'root' });
    const namespace = `h3c_${Date.now().toString(36)}`;
    await db.query(`DEFINE NAMESPACE ${namespace};`);
    await db.use({ namespace });
    await db.query('DEFINE DATABASE probe;');
    await db.use({ namespace, database: 'probe' });
    await db.query(compiled.bundle);
    await probe(db);
    process.stdout.write('H3c fixture: ten typed levels, bounded branch, reactive reparent and rollback passed\n');
  } finally {
    await db.close().catch(() => {});
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolve) => child.once('exit', resolve));
    }
  }
}

if (require.main === module) main().catch((error) => {
  console.error(`H3c fixture: FAIL: ${error.stack || error}`);
  process.exitCode = 1;
});
