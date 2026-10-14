'use strict';
// Compile the real tree model and runtime against a small explicit fixture.
// Framework tenant/record-user authorization has its own integration probe.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Surreal } = require('surrealdb');
const { parseSchema } = require('../compiler/schema');
const { generateTemporal } = require('../compiler/generators/temporal');
const { start, client, applySchema } = require('./harness');
const oracle = require('./oracle');

const literal = value => JSON.stringify(value);
const at = n => `2026-10-04T12:00:${String(n).padStart(2, '0')}Z`;
const tuple = (slot, key) => `[${key.map((value, i) => {
  if (i === 0 && slot === 'z_price') return `${value}dec`;
  if (i === 0 && ['z_partition', 'z_nominal'].includes(slot)) return value;
  if (i === 0 && slot === 'z_uuid') return `u'${value}'`;
  if (i === 0 && slot === 'z_record') return value;
  if (i === 2 && slot === 'z_partition') return `d'${value}'`;
  return literal(value);
}).join(', ')}]`;
const read = (owner, operation, argument) => `fn::tree::read(${owner.rid}, '${owner.slot}', '${operation}', ${argument})`;

async function recordClient(url, access) {
  const response = await fetch(`${url}/signin`, { method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ ns: 'temporal_probe', db: 'fixture', ac: access }) });
  const { token } = await response.json();
  assert(token, `record access ${access} returned no token`);
  return client(url, 'fixture', token);
}

function decimalParts(value) {
  const [whole, fraction = ''] = String(value).split('.');
  return { value: BigInt(whole + fraction), scale: fraction.length };
}
function compareDecimal(a, b) {
  const left = decimalParts(a), right = decimalParts(b);
  const x = left.value * 10n ** BigInt(right.scale), y = right.value * 10n ** BigInt(left.scale);
  return x < y ? -1 : x > y ? 1 : 0;
}
function compare(a, b, slot = a.at(-1)) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const difference = i === 0 && ['z_price', 'z_second_price'].includes(slot)
      ? compareDecimal(a[i], b[i]) : a[i] < b[i] ? -1 : a[i] > b[i] ? 1 : 0;
    if (difference) return difference;
  }
  return a.length - b.length;
}

const snapshot = q => q(`RETURN {
  catalogs: (SELECT * FROM ordered_catalog ORDER BY id),
  facts: array::concat((SELECT * FROM ordered_a ORDER BY id), (SELECT * FROM ordered_b ORDER BY id))
};`);
function verify(data) {
  const entries = [];
  const add = (row, slot, root, business, measures = {}, tags = {}) => entries.push({
    link: { rid: row.id, slot }, owner: { rid: row.catalog, slot: root },
    key: [...business, row.id, slot], measures, tags, dependent: false,
  });
  for (const row of data.facts) {
    if (row.identifier !== undefined) {
      add(row, 'z_identifier', 'z_identifier', [row.identifier]);
      add(row, 'z_nominal', 'z_nominal', [row.tenant, row.identifier]);
    }
    if (row.boolean_key != null) add(row, 'z_boolean', 'z_boolean', [row.boolean_key]);
    if (row.uuid_key != null) add(row, 'z_uuid', 'z_uuid', [row.uuid_key]);
    if (row.record_key != null) add(row, 'z_record', 'z_record', [row.record_key]);
    if (row.price !== undefined) add(row, 'z_price', 'z_price', [row.price], {
      weight: Number(row.weight) * (row.second_price !== undefined && compareDecimal(row.price, row.second_price) === 0 ? 2 : 1),
    }, { currency: row.currency });
    if (row.second_price !== undefined && (row.price === undefined || compareDecimal(row.price, row.second_price) !== 0)) {
      add(row, 'z_second_price', 'z_price', [row.second_price], { weight: Number(row.weight) }, { currency: row.currency });
    }
    add(row, 'z_partition', 'z_partition', [row.tenant, row.category, row.at], { weight: Number(row.weight) });
  }
  return oracle.verify(data.catalogs, data.facts, entries, compare);
}

async function verifyReads(q, groups) {
  let count = 0;
  for (const { owner, entries } of groups.values()) {
    for (const reverse of [false, true]) {
      const wanted = reverse ? entries.toReversed() : entries;
      const collected = [];
      let after;
      do {
        const page = await q(`RETURN ${read(owner, 'page', `[3, ${after ? tuple(owner.slot, after) : 'NONE'}, ${reverse}]`)};`);
        assert(page.items.length <= 3);
        assert(Number.isInteger(page.revision));
        collected.push(...page.items.map(item => item.link));
        after = page.next;
        count++;
      } while (after);
      assert.deepEqual(collected, wanted.map(entry => entry.link), `bounded ${reverse ? 'reverse' : 'forward'} pages ${owner.rid}/${owner.slot}`);
    }
    for (const entry of entries) {
      const key = tuple(owner.slot, entry.key), business = tuple(owner.slot, entry.key.slice(0, -2));
      const first = entries.find(candidate => compare(candidate.key.slice(0, -2), entry.key.slice(0, -2), owner.slot) === 0);
      assert.deepEqual(await q(`RETURN ${read(owner, 'find', business)};`), first.link);
      for (const reverse of [false, true]) for (const inclusive of [false, true]) {
        const ordered = reverse ? entries.toReversed() : entries;
        const expected = ordered.find(candidate => {
          const order = compare(candidate.key, entry.key, owner.slot);
          return (reverse ? order < 0 : order > 0) || inclusive && order === 0;
        });
        const request = read(owner, 'seek', `[${key}, ${reverse}, ${inclusive}]`);
        assert.deepEqual(await q(`RETURN ${request};`), expected?.link ?? null, request);
        count++;
      }
      count++;
    }
  }
  return count;
}

async function main() {
  require('./contract-probe').main();
  const source = fs.readFileSync(path.join(__dirname, 'ordered-fixture.surql'), 'utf8');
  const support = fs.readFileSync(path.resolve(__dirname, '../../framework/reads.surql'), 'utf8');
  const compiled = generateTemporal(parseSchema(source + '\n' + support, ''), { selectPolicy: 'readers' },
    new Set(['rebase_read', 'rebase_read_frame', 'rebase_read_group', 'rebase_read_lock'])).sql;
  const server = await start({ engine: 'surrealkv' }), q = client(server.url);
  let reader;
  let mutations = 0, rejected = 0, reads = 0;
  const mutate = async sql => { await q(sql); mutations++; const data = await snapshot(q); verify(data); return data; };
  const reject = async (sql, pattern) => {
    const before = await snapshot(q);
    await assert.rejects(q(sql), pattern, sql);
    assert.deepEqual(await snapshot(q), before, 'rejected write rolls back sources, roots, links and revision');
    verify(before); rejected++;
  };
  const create = (table, id, identifier, price, second = '', extra = '') => mutate(`CREATE ${table}:${id} SET
    tenant=ordered_tenant:a, owned_by=person:source, catalog=ordered_catalog:a,
    identifier=${literal(identifier)}, price=${price}dec, at=d'${at(1)}'${second}${extra};`);
  try {
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(q, source + '\n' + support + '\n' + compiled);
    await q(`CREATE rebase_user:tree_reader SET name='Tree reader', parents=[rebase_tenant:default];
      DEFINE ACCESS ordered_tree_reader ON DATABASE TYPE RECORD SIGNIN rebase_user:tree_reader;`);
    reader = await recordClient(server.url, 'ordered_tree_reader');
    await q(`CREATE ordered_tenant:a; CREATE ordered_tenant:b;
      CREATE ordered_catalog:a SET tenant=ordered_tenant:a, owned_by=person:root;
      CREATE ordered_catalog:a2 SET tenant=ordered_tenant:a, owned_by=person:another;
      CREATE ordered_catalog:b SET tenant=ordered_tenant:b, owned_by=person:root;
      CREATE ordered_catalog:key_a SET tenant=ordered_tenant:a, owned_by=person:keys;
      CREATE ordered_catalog:key_b SET tenant=ordered_tenant:a, owned_by=person:keys;
      CREATE ordered_catalog:key_c SET tenant=ordered_tenant:a, owned_by=person:keys;`);
    const values = ['4', '2', '6', '1', '3', '5', '7', '-1.25', '9007199254740993.123456788', '9007199254740993.123456789'];
    const typedKeys = new Map([
      ['n0', ", boolean_key=true, uuid_key=u'0198c6c4-bd70-7d6d-8a7a-87bb773590db', record_key=ordered_catalog:key_a"],
      ['n1', ", boolean_key=false, uuid_key=u'0198c6c5-bd70-7d6d-8a7a-87bb773590db', record_key=ordered_catalog:key_b"],
    ]);
    for (const [index, value] of values.entries()) {
      const id = `n${index}`;
      await create(index % 2 ? 'ordered_b' : 'ordered_a', id, `key${index}`, value, '', typedKeys.get(id) || '');
    }
    await create('ordered_b', 'tie', 'tie', '3');
    await create('ordered_a', 'two', 'two', '8', ', second_price=9dec');
    await mutate('UPDATE ordered_a:two SET second_price=8dec;');
    await mutate('UPDATE ordered_a:two SET second_price=10dec;');
    await mutate("UPDATE ordered_a:n0 SET category='b', at=d'2026-10-04T12:00:02Z';");
    await mutate("UPDATE ordered_b:n1 SET identifier='rekeyed', price=-4.5dec;");
    await mutate("UPDATE ordered_a:n2 SET catalog=ordered_catalog:a2;");
    await mutate('UPDATE ordered_a:n4 SET identifier=NONE, price=NONE;');
    await mutate('DELETE ordered_a:n6;');
    let data = await snapshot(q);
    reads += await verifyReads(reader, verify(data));
    await mutate('UPDATE ordered_b:n1 SET boolean_key=NONE;');
    await mutate(`UPDATE ordered_a:n0 SET boolean_key=false,
      uuid_key=u'0198c6c6-bd70-7d6d-8a7a-87bb773590db', record_key=ordered_catalog:key_c;`);
    data = await snapshot(q);
    const boolOwner = { rid: 'ordered_catalog:a', slot: 'z_boolean' };
    const uuidOwner = { rid: 'ordered_catalog:a', slot: 'z_uuid' };
    const recordOwner = { rid: 'ordered_catalog:a', slot: 'z_record' };
    assert.equal(await reader(`RETURN ${read(boolOwner, 'find', '[true]')};`), null, 'bool rekey removes the prior key');
    assert.deepEqual(await reader(`RETURN ${read(boolOwner, 'find', '[false]')};`), { rid: 'ordered_a:n0', slot: 'z_boolean' });
    assert.equal(await reader(`RETURN ${read(uuidOwner, 'find', "[u'0198c6c4-bd70-7d6d-8a7a-87bb773590db']")};`), null,
      'UUID rekey removes the prior key');
    assert.deepEqual(await reader(`RETURN ${read(uuidOwner, 'find', "[u'0198c6c6-bd70-7d6d-8a7a-87bb773590db']")};`),
      { rid: 'ordered_a:n0', slot: 'z_uuid' });
    assert.equal(await reader(`RETURN ${read(recordOwner, 'find', '[ordered_catalog:key_a]')};`), null,
      'record rekey removes the prior key');
    assert.deepEqual(await reader(`RETURN ${read(recordOwner, 'find', '[ordered_catalog:key_c]')};`),
      { rid: 'ordered_a:n0', slot: 'z_record' });
    verify(data);
    reads += await verifyReads(reader, verify(data));
    const roots = await q('RETURN fn::rebase::tree_roots((SELECT * FROM ONLY ordered_a:n0));');
    assert.deepEqual(roots, ['ordered_catalog:a']);
    assert.equal(data.facts.find(row => row.id === 'ordered_a:n0').owned_by, 'person:source');

    await reject(`CREATE ordered_b:duplicate SET tenant=ordered_tenant:a, owned_by=person:source,
      catalog=ordered_catalog:a, identifier='key0', at=d'${at(2)}';`, /TREE_DUPLICATE_VALUE/);
    await reject("UPDATE ordered_b:n3 SET identifier='key0';", /TREE_DUPLICATE_VALUE/);
    await reject('UPDATE ordered_a:n0 SET duplicate_identifier=true;', /TREE_DUPLICATE_VALUE/);
    await reject('UPDATE ordered_a:n0 SET catalog=ordered_catalog:b;', /TREE_TENANT_MISMATCH/);
    await reject("UPDATE ordered_a:n0 SET currency='INR';", /ORDERED_CURRENCY/);
    await reject('UPDATE ordered_catalog:a SET budget=0dec;', /ORDERED_BUDGET/);
    await reject('UPDATE ordered_a:n0 SET price=1;', /TREE_ORDERED_KEY/);
    await reject('UPDATE ordered_a:n0 SET price=1.25f;', /TREE_ORDERED_KEY/);
    await reject('DELETE ordered_catalog:a;', /TREE_OWNER_NOT_EMPTY|referenc/i);
    for (const expression of [
      "fn::tree::read(ordered_catalog:a,'z_price','find',[1])",
      "fn::tree::read(ordered_catalog:a,'z_partition','find',[ordered_tenant:a])",
      "fn::tree::read(ordered_catalog:a,'z_identifier','page',[0])",
      "fn::tree::read(ordered_catalog:a,'z_identifier','page',[201])",
      "fn::tree::read(ordered_catalog:a,'z_identifier','page',[2,123])",
    ]) await assert.rejects(reader(`RETURN ${expression};`), /TREE_READ_KEY|TREE_PAGE_LIMIT/);
    assert.deepEqual(await q(`RETURN [
      fn::tree::valid_key([true,'fact:a','s'],'bool',true),
      fn::tree::valid_key([rand::uuid::v7(),'fact:a','s'],'uuid',true),
      fn::tree::valid_key([person:a,'fact:a','s'],'record',true),
      fn::tree::valid_key([1.5f,'fact:a','s'],'decimal',true),
      fn::tree::valid_key([NaN,'fact:a','s'],'decimal',true),
      fn::tree::valid_key([1dec,'fact:a','s'],'int',true)
    ];`), [true, true, true, false, false, false]);

    // Root revision serializes two concurrent writers before the uniqueness
    // decision, so both cannot commit even when they start from an empty key.
    const raceClients = [new Surreal(), new Surreal()];
    let competing;
    try {
      await Promise.all(raceClients.map(async db => {
        await db.connect(`${server.url.replace('http:', 'ws:')}/rpc`);
        await db.signin({ username: 'root', password: 'root' });
        await db.use({ namespace: 'temporal_probe', database: 'fixture' });
      }));
      competing = await Promise.allSettled(raceClients.map((db, index) => db.query(`CREATE ordered_${index ? 'b' : 'a'}:race_${index} SET
        tenant=ordered_tenant:a, owned_by=person:source, catalog=ordered_catalog:a,
        identifier='racing', at=d'${at(3)}';`)));
    } finally { await Promise.all(raceClients.map(db => db.close().catch(() => {}))); }
    assert.equal(competing.filter(result => result.status === 'fulfilled').length, 1);
    assert.match(String(competing.find(result => result.status === 'rejected').reason), /DUPLICATE|conflict|transaction/i);
    verify(await snapshot(q));
    const before = await snapshot(q);
    await applySchema(q, compiled);
    assert.deepEqual(await snapshot(q), before, 'compiler reapplication preserves populated typed trees');
    await reject('DELETE ordered_a;', /AVL_PARENT_MISMATCH|AVL_MISSING_SLOT/);
    await mutate(`BEGIN TRANSACTION; ${before.facts.map(row => `DELETE ONLY ${row.id};`).join('\n')} COMMIT TRANSACTION;`);
    assert((await snapshot(q)).catalogs.every(row => row.z_identifier.summary.count === 0 && row.z_partition.summary.count === 0));
    console.log(`PASS ordered trees: ${mutations} mutations, ${reads} typed reads/pages, ${rejected} rollback cases, exact decimals, composite, nominal, bool, UUID and record keys, cross-table uniqueness and independent-session concurrent serialization`);
  } finally { await server.close(); }
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { main };
