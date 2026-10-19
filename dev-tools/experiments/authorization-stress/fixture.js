'use strict';

// Large authorization fixtures are intentionally created with native INSERTs.
// This keeps work bounded by the batch size while still letting SurrealDB run
// ordinary field VALUE and REFERENCE bookkeeping for every fact.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const { RecordId, Decimal } = require('surrealdb');
const { loadMaterials } = require('../../compiler/materials');
const { generateBundle } = require('../../compiler/pipeline');
const oracle = require('../../temporal-tree/oracle');

const ROOT = path.resolve(__dirname, '../../..');
const rootSlot = (table, slot) => `z_${table}_${slot}`;
const recordId = (table, key) => new RecordId(table, key);
const qid = value => String(value);

function normalize(configs) {
  assert(Array.isArray(configs) && configs.length, 'fixture configs required');
  return configs.map(({ table, slots, measures }) => {
    assert.match(table, /^[a-z][a-z0-9_]*$/);
    assert(Number.isSafeInteger(slots) && slots >= 0 && slots <= 32);
    assert(Number.isSafeInteger(measures) && measures >= 0 && measures <= 32);
    return { table, slots, measures };
  });
}

function schema(configs) {
  const tables = normalize(configs);
  const statements = [];
  for (const { table, slots, measures } of tables) {
    statements.push(`DEFINE TABLE OVERWRITE ${table} SCHEMAFULL${slots ? ` COMMENT '@rebase-members fn::stress::${table}_members'` : ''};`);
    statements.push(`DEFINE FIELD OVERWRITE tenant ON ${table} TYPE record<rebase_tenant>;`);
    statements.push(`DEFINE FIELD OVERWRITE owned_by ON ${table} TYPE record<rebase_user | rebase_group>;`);
    statements.push(`DEFINE FIELD OVERWRITE read_by ON ${table} TYPE record<rebase_user | rebase_group> VALUE $this.owned_by PERMISSIONS FOR select, create WHERE true FOR update NONE;`);
    statements.push(`DEFINE FIELD OVERWRITE seq ON ${table} TYPE int;`);
    statements.push(`DEFINE FIELD OVERWRITE rank ON ${table} TYPE int;`);
    statements.push(`DEFINE FIELD OVERWRITE amount ON ${table} TYPE int;`);
    statements.push(`DEFINE FIELD OVERWRITE status ON ${table} TYPE string;`);
    statements.push(`DEFINE FIELD OVERWRITE payload ON ${table} TYPE string;`);
    for (let i = 0; i < slots; i++) {
      const slot = `z${i}`, root = rootSlot(table, slot);
      statements.push(`DEFINE FIELD OVERWRITE ${root} ON rebase_user TYPE object PERMISSIONS FOR select WHERE $auth != NONE AND fn::rebase::can_access($auth, id) COMMENT '@rebase-tree-root @rebase-tree-key int @rebase-tree-duplicates';`);
      statements.push(`DEFINE FIELD OVERWRITE ${root} ON rebase_group TYPE object PERMISSIONS FOR select WHERE $auth != NONE AND fn::rebase::can_access($auth, id) COMMENT '@rebase-tree-root @rebase-tree-key int @rebase-tree-duplicates';`);
      statements.push(`DEFINE FIELD OVERWRITE ${slot} ON ${table} TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner rebase_user.${root} @rebase-tree-owner rebase_group.${root} @rebase-tree-no-reader';`);
    }
    if (slots) statements.push(`DEFINE FUNCTION OVERWRITE fn::stress::${table}_members($row: object) { RETURN [${Array.from({ length: slots }, (_, i) => `fn::tree::ordered_member($row.id, 'z${i}', $row.owned_by, '${rootSlot(table, `z${i}`)}', [$row.rank], {${Array.from({ length: measures }, (_, j) => `m${j}: <decimal>$row.amount * ${j + 1}`).join(',')}}, {})`).join(',')}]; } PERMISSIONS NONE;`);
  }
  statements.push("DEFINE TABLE OVERWRITE auth_anchor SCHEMAFULL;");
  statements.push("DEFINE FIELD OVERWRITE title ON auth_anchor TYPE string;");
  statements.push("DEFINE TABLE OVERWRITE auth_report SCHEMAFULL;");
  statements.push("DEFINE FIELD OVERWRITE title ON auth_report TYPE string;");
  statements.push("DEFINE FIELD OVERWRITE anchors ON auth_report TYPE array<record<auth_anchor>> DEFAULT [] REFERENCE ON DELETE REJECT COMMENT '@rebase-readers';");
  return statements.join('\n');
}

function compileFixture(configs) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-authorization-stress-'));
  fs.writeFileSync(path.join(directory, 'stress.surql'), schema(configs));
  const materials = loadMaterials({ groups: [
    { name: 'framework', roots: [path.join(ROOT, 'framework')] },
    { name: 'project', roots: [directory] },
  ] });
  const compiled = generateBundle(materials);
  return { ...compiled, directory, cleanup: () => fs.rmSync(directory, { recursive: true, force: true }) };
}

// Height for a contiguous midpoint-built interval, without retaining a tree.
function balanceHeight(size) { return size <= 0 ? 0 : Math.floor(Math.log2(size)) + 1; }
function summarize(count, first, last, measures) {
  const output = { count, first, last, measures: {}, tags: {}, spans: {} };
  for (let j = 0; j < measures; j++) {
    const amount = new Decimal(j + 1), sum = new Decimal(count * (j + 1));
    output.measures[`m${j}`] = { sum, min: amount, max: amount, min_prefix: new Decimal(0), max_prefix: sum,
      instant_min: new Decimal(0), instant_max: sum };
  }
  return output;
}
function setBoundaries(summary, start, end, ownerIndex, ownerCount, measures) {
  const firstRank = Math.floor((ownerIndex + start * ownerCount) / 3);
  const lastRank = Math.floor((ownerIndex + (end - 1) * ownerCount) / 3);
  if (firstRank === lastRank) return summary;
  const firstEnd = Math.min(end, Math.ceil(((firstRank + 1) * 3 - ownerIndex) / ownerCount));
  const lastStart = Math.max(start, Math.ceil((lastRank * 3 - ownerIndex) / ownerCount));
  const firstCount = firstEnd - start, lastCount = end - lastStart, count = end - start;
  for (let j = 0; j < measures; j++) {
    const metric = summary.measures[`m${j}`], factor = j + 1;
    metric.boundary_min = new Decimal(firstCount * factor);
    metric.boundary_max = new Decimal((count - lastCount) * factor);
  }
  return summary;
}
function link(id, slot) { return { rid: id, slot }; }
function oracleValue(value) {
  if (value instanceof RecordId) return String(value);
  // Synthetic measures are bounded exact integers (n<=100M, factor<=32).
  // Compare their values, not SDK Decimal encoding/scale internals.
  if (value instanceof Decimal) return Number(value);
  if (Array.isArray(value)) return value.map(oracleValue);
  if (value && typeof value === 'object' && !(value instanceof Decimal)) {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, oracleValue(item)]));
  }
  return value;
}
function compareStressKey(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const x = i === 0 ? Number(a[i]) : String(a[i]), y = i === 0 ? Number(b[i]) : String(b[i]);
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return a.length - b.length;
}

function resultValue(result) {
  if (Array.isArray(result)) {
    const last = result.at(-1);
    return last && !Array.isArray(last) && Object.hasOwn(last, 'result') ? last.result : last;
  }
  return result;
}
async function query(db, sql, vars) { return resultValue(await db.query(sql, vars)); }
function nodeFor(table, owner, ownerIndex, ordinal, count, ownerCount, slots, measures) {
  const seq = ownerIndex + ordinal * ownerCount;
  const id = recordId(table, `r${String(seq).padStart(10, '0')}`);
  const slotNodes = {};
  for (let s = 0; s < slots; s++) {
    const slot = `z${s}`, root = rootSlot(table, slot);
    let lo = 0, hi = count, parent = link(owner, root), mid = 0;
    while (lo < hi) {
      mid = lo + Math.floor((hi - lo) / 2);
      if (ordinal === mid) break;
      parent = link(recordId(table, `r${String(ownerIndex + mid * ownerCount).padStart(10, '0')}`), slot);
      if (ordinal < mid) hi = mid; else lo = mid + 1;
    }
    const start = { a: lo, b: hi, m: mid };
    const leftCount = start.m - start.a, rightCount = start.b - start.m - 1;
    const median = (a, b) => a >= b ? null : a + Math.floor((b - a) / 2);
    const leftOrd = median(start.a, start.m), rightOrd = median(start.m + 1, start.b);
    const left = leftOrd == null ? null : link(recordId(table, `r${String(ownerIndex + leftOrd * ownerCount).padStart(10, '0')}`), slot);
    const right = rightOrd == null ? null : link(recordId(table, `r${String(ownerIndex + rightOrd * ownerCount).padStart(10, '0')}`), slot);
    const loSeq = ownerIndex + start.a * ownerCount, hiSeq = ownerIndex + (start.b - 1) * ownerCount;
    const key = [Math.floor(seq / 3), String(id), slot];
    const linkSeq = ord => ord < 0 || ord >= count ? null : link(recordId(table, `r${String(ownerIndex + ord * ownerCount).padStart(10, '0')}`), slot);
    const parentLink = ordinal === Math.floor(count / 2) ? link(owner, root) : parent;
    slotNodes[slot] = { owner: link(owner, root), key,
      parent: parentLink, ...(left ? { left } : {}), ...(right ? { right } : {}),
      ...(linkSeq(ordinal - 1) ? { prev: linkSeq(ordinal - 1) } : {}), ...(linkSeq(ordinal + 1) ? { next: linkSeq(ordinal + 1) } : {}),
      height: Math.max(balanceHeight(leftCount), balanceHeight(rightCount)) + 1,
      value: summarize(1, key, key, measures),
      summary: setBoundaries(summarize(start.b - start.a, [Math.floor(loSeq / 3), `${table}:r${String(loSeq).padStart(10, '0')}`, slot], [Math.floor(hiSeq / 3), `${table}:r${String(hiSeq).padStart(10, '0')}`, slot], measures), start.a, start.b, ownerIndex, ownerCount, measures) };
  }
  return { id, seq, rank: Math.floor(seq / 3), owner, slotNodes };
}

async function loadFactsNative(db, { table, n, owners, slots, measures, batchRows = 500, onProgress = () => {} }) {
  ({ slots, measures } = normalize([{ table, slots, measures }])[0]);
  assert(Number.isSafeInteger(n) && n >= 0);
  assert(owners?.length, 'at least one owner is required');
  assert(Number.isSafeInteger(batchRows) && batchRows > 0);
  const ownerIds = owners.map((owner, i) => typeof owner === 'string' ? recordId(...owner.split(':', 2)) : owner);
  const ownerRows = await query(db, 'SELECT id, tenant FROM $owners;', { owners: ownerIds });
  const ownerTenants = new Map((ownerRows || []).map(row => [String(row.id), row.tenant]));
  const ownedCounts = ownerIds.map((_, i) => Math.max(0, Math.floor((n - 1 - i) / ownerIds.length) + 1));
  // Remove maintained event hooks while loading. Their exact definitions are
  // restored in finally; field VALUE and REFERENCES remain active.
  const info = await query(db, `INFO FOR TABLE ${table}`);
  const events = info?.events || {};
  const restore = [];
  try {
    for (const [name, event] of Object.entries(events)) {
      if (typeof event === 'string') restore.push(event);
      else if (event?.definition) restore.push(event.definition);
      await query(db, `REMOVE EVENT ${name} ON ${table}`);
    }
    await query(db, `DELETE ${table} RETURN NONE;`);
    for (const owner of ownerIds) for (let s = 0; s < slots; s++) {
      const field = rootSlot(table, `z${s}`);
      const emptyHead = { height: 0, revision: 0, summary: { count: 0, measures: {}, tags: {}, spans: {} } };
      await query(db, `OPTION IMPORT; UPDATE $owner SET ${field} = $head;`, { owner, head: emptyHead });
    }
    for (let start = 0; start < n; start += batchRows) {
      const batch = [];
      const end = Math.min(n, start + batchRows);
      for (let seq = start; seq < end; seq++) {
        const ownerIndex = seq % ownerIds.length, owner = ownerIds[ownerIndex];
        const tenant = ownerTenants.get(String(owner));
        assert(tenant, `Could not resolve tenant for ${owner}`);
        const row = { id: recordId(table, `r${String(seq).padStart(10, '0')}`), tenant,
          owned_by: owner, seq, rank: Math.floor(seq / 3), amount: 1,
          status: seq % 100 === 0 ? 'hot' : 'cold', payload: 'authorization-stress-fixture' };
        if (slots) {
          const treeNodes = nodeFor(table, owner, ownerIndex, Math.floor(seq / ownerIds.length), ownedCounts[ownerIndex], ownerIds.length, slots, measures).slotNodes;
          for (let s = 0; s < slots; s++) row[`z${s}`] = treeNodes[`z${s}`];
        }
        batch.push(row);
      }
      await query(db, `INSERT INTO ${table} $rows RETURN NONE;`, { rows: batch });
      await onProgress({ table, loaded: end, total: n });
    }
    // VALUE fields replace root headers on ordinary writes. Under OPTION IMPORT
    // only these precomputed headers are patched; no records are imported.
    for (let oi = 0; oi < ownerIds.length; oi++) {
      const count = ownedCounts[oi];
      if (!count) continue;
      const rootOrdinal = Math.floor(count / 2);
      const rootId = recordId(table, `r${String(oi + rootOrdinal * ownerIds.length).padStart(10, '0')}`);
      for (let s = 0; s < slots; s++) {
        const slot = `z${s}`, field = rootSlot(table, slot);
        const treeHeight = balanceHeight(count);
        const firstSeq = oi, lastSeq = oi + (count - 1) * ownerIds.length;
        const head = { root: link(rootId, slot), height: treeHeight, revision: count,
          summary: setBoundaries(summarize(count, [Math.floor(firstSeq / 3), `${table}:r${String(firstSeq).padStart(10, '0')}`, slot],
            [Math.floor(lastSeq / 3), `${table}:r${String(lastSeq).padStart(10, '0')}`, slot], measures), 0, count, oi, ownerIds.length, measures) };
        await query(db, `OPTION IMPORT; UPDATE $owner SET ${field} = $head;`, { owner: ownerIds[oi], head });
      }
    }
  } finally {
    for (const definition of restore) await query(db, `${definition};`);
    const after = await query(db, `INFO FOR TABLE ${table}`);
    assert.deepEqual(after?.events || {}, events, `${table}: restored events exactly`);
  }
  return { table, records: n, nodes: n * slots, owners: ownerIds.length };
}

function compareDefinitionOrder(a, b) {
  return a.split('.').length - b.split('.').length || a.localeCompare(b);
}
function emptyHead() { return { height: 0, revision: 0, summary: { count: 0, measures: {}, tags: {}, spans: {} } }; }
function requireEmptyReferenceValue(row, field) {
  const value = row[field];
  assert(value == null || Array.isArray(value) && value.length === 0,
    `image seed requires ${field} to be NONE or empty; found a nonempty native reference`);
}

async function loadFactsImage(db, { table, n, owners, slots, measures, batchRows = 500, onProgress = () => {} }) {
  assert.match(table, /^stress_[a-z0-9_]+$/, 'image seed is restricted to disposable stress tables');
  ({ slots, measures } = normalize([{ table, slots, measures }])[0]);
  assert(Number.isSafeInteger(n) && n >= 0);
  assert(owners?.length, 'at least one owner is required');
  assert(Number.isSafeInteger(batchRows) && batchRows > 0);
  const ownerIds = owners.map(owner => typeof owner === 'string' ? recordId(...owner.split(':', 2)) : owner);
  const originalInfo = await query(db, `INFO FOR TABLE ${table}`);
  const originalDb = await query(db, 'INFO FOR DB');
  const tableDefinition = originalDb?.tables?.[table];
  assert(tableDefinition, `Missing original table definition for ${table}`);
  const fields = originalInfo.fields || {}, events = originalInfo.events || {};
  const ownedByDefinition = fields.owned_by;
  assert(ownedByDefinition?.includes('REFERENCE'), `${table}.owned_by must retain native REFERENCE semantics`);
  const nativeReferences = Object.entries(fields).filter(([name, definition]) => name !== 'owned_by' && /\bREFERENCE\b/.test(definition));
  const ownerRows = await query(db, 'SELECT id, tenant FROM $owners;', { owners: ownerIds });
  const ownerTenants = new Map(ownerRows.map(row => [String(row.id), row.tenant]));
  const ownedCounts = ownerIds.map((_, i) => Math.max(0, Math.floor((n - 1 - i) / ownerIds.length) + 1));
  const prototypeIds = ownerIds.map((_, i) => recordId(table, `fixture_prototype_${String(i).padStart(4, '0')}`));
  const prototypeByOwner = new Map();
  let restoreNeeded = false;
  try {
    restoreNeeded = true;
    for (const name of Object.keys(events)) await query(db, `REMOVE EVENT ${name} ON ${table}`);
    // Removal and prototype creation are normal writes while every original
    // field definition, especially owned_by REFERENCE, remains active.
    await query(db, `DELETE ${table} RETURN NONE;`);
    for (const owner of ownerIds) for (let s = 0; s < slots; s++) {
      await query(db, `OPTION IMPORT; UPDATE $owner SET ${rootSlot(table, `z${s}`)} = $head;`, { owner, head: emptyHead() });
    }
    const prototypes = ownerIds.map((owner, i) => ({ id: prototypeIds[i], owned_by: owner, seq: 0, rank: 0,
      amount: 1, status: 'cold', payload: 'authorization-stress-prototype' }));
    if (prototypes.length) await query(db, `INSERT INTO ${table} $rows RETURN NONE;`, { rows: prototypes });
    const prototypeRows = prototypes.length ? await query(db, 'SELECT * FROM $ids;', { ids: prototypeIds }) : [];
    assert.equal(prototypeRows.length, ownerIds.length, `${table}: native prototype rows`);
    for (let i = 0; i < prototypeRows.length; i++) {
      const prototype = prototypeRows[i];
      for (const [field] of nativeReferences) requireEmptyReferenceValue(prototype, field);
      prototypeByOwner.set(String(ownerIds[i]), prototype);
    }
    // This DELETE runs with the original owner reference definition active so
    // SurrealDB cleans the prototype backlinks natively.
    await query(db, `DELETE ${table} RETURN NONE;`);
    const fieldNames = Object.keys(fields).filter(name => name !== 'owned_by')
      .sort((a, b) => b.split('.').length - a.split('.').length || b.localeCompare(a));
    for (const field of fieldNames) await query(db, `REMOVE FIELD ${field} ON ${table}`);
    await query(db, `DEFINE TABLE OVERWRITE ${table} SCHEMALESS PERMISSIONS NONE;`);

    for (let start = 0; start < n; start += batchRows) {
      const batch = [];
      const end = Math.min(n, start + batchRows);
      for (let seq = start; seq < end; seq++) {
        const ownerIndex = seq % ownerIds.length, owner = ownerIds[ownerIndex];
        const prototype = prototypeByOwner.get(String(owner));
        assert(prototype, `No native prototype for ${owner}`);
        const row = { ...prototype, id: recordId(table, `r${String(seq).padStart(10, '0')}`),
          owned_by: owner, seq, rank: Math.floor(seq / 3), amount: 1,
          status: seq % 100 === 0 ? 'hot' : 'cold', payload: 'authorization-stress-fixture' };
        if (slots) {
          const treeNodes = nodeFor(table, owner, ownerIndex, Math.floor(seq / ownerIds.length),
            ownedCounts[ownerIndex], ownerIds.length, slots, measures).slotNodes;
          for (let s = 0; s < slots; s++) row[`z${s}`] = treeNodes[`z${s}`];
        }
        batch.push(row);
      }
      if (batch.length) await query(db, `INSERT INTO ${table} $rows RETURN NONE;`, { rows: batch });
      await onProgress({ table, loaded: end, total: n });
    }
    for (let oi = 0; oi < ownerIds.length; oi++) {
      const owner = ownerIds[oi], count = ownedCounts[oi];
      for (let s = 0; s < slots; s++) {
        let head = emptyHead();
        if (count) {
          const slot = `z${s}`, rootOrdinal = Math.floor(count / 2);
          const rootId = recordId(table, `r${String(oi + rootOrdinal * ownerIds.length).padStart(10, '0')}`);
          const firstSeq = oi, lastSeq = oi + (count - 1) * ownerIds.length;
          head = { root: link(rootId, slot), height: balanceHeight(count), revision: count,
            summary: setBoundaries(summarize(count, [Math.floor(firstSeq / 3), `${table}:r${String(firstSeq).padStart(10, '0')}`, slot],
              [Math.floor(lastSeq / 3), `${table}:r${String(lastSeq).padStart(10, '0')}`, slot], measures), 0, count, oi, ownerIds.length, measures) };
        }
        await query(db, `OPTION IMPORT; UPDATE $owner SET ${rootSlot(table, `z${s}`)} = $head;`, { owner, head });
      }
    }
  } finally {
    // Restore schema and events even if insertion or progress reporting fails.
    if (restoreNeeded) {
      await query(db, tableDefinition.replace(/^DEFINE TABLE\s+/, 'DEFINE TABLE OVERWRITE ') + ';');
      const fieldNames = Object.keys(fields).sort(compareDefinitionOrder);
      for (const field of fieldNames) {
        const definition = fields[field].replace(/^DEFINE FIELD\s+/, 'DEFINE FIELD OVERWRITE ');
        await query(db, `${definition};`);
      }
      for (const definition of Object.values(events)) await query(db, `${definition};`);
    }
  }
  const restoredInfo = await query(db, `INFO FOR TABLE ${table}`);
  const restoredDb = await query(db, 'INFO FOR DB');
  assert.deepEqual(restoredInfo, originalInfo, `${table}: complete table metadata restored`);
  assert.equal(restoredDb.tables[table], tableDefinition, `${table}: table permissions and schema restored`);
  return { table, records: n, nodes: n * slots, owners: ownerIds.length, seedMode: 'image', prototypeKeys: [...(prototypeByOwner.values().next().value ? Object.keys(prototypeByOwner.values().next().value) : [])] };
}

async function loadFacts(db, config) {
  const mode = config.seedMode || 'image';
  assert(['image', 'native'].includes(mode), `Unknown stress seed mode: ${mode}`);
  return mode === 'native' ? loadFactsNative(db, config) : loadFactsImage(db, config);
}

async function verifyFacts(db, { table, n, owners, slots, measures, batchRows = 500, onProgress = () => {} }) {
  ({ slots, measures } = normalize([{ table, slots, measures }])[0]);
  const ownerIds = owners.map(owner => typeof owner === 'string' ? recordId(...owner.split(':', 2)) : owner);
  const ownerRows = (await query(db, 'SELECT * FROM $owners;', { owners: ownerIds })).map(oracleValue);
  const tenantByOwner = new Map(ownerRows.map(row => [String(row.id), String(row.tenant)]));
  const checks = { records: 0, nodes: 0, rootHeads: 0 };
  const oracleRecords = n <= 1000 ? [] : null;
  for (let offset = 0; offset < n; offset += batchRows) {
    const ids = Array.from({ length: Math.min(batchRows, n - offset) }, (_, i) => recordId(table, `r${String(offset + i).padStart(10, '0')}`));
    const found = await query(db, 'SELECT * FROM $ids;', { ids });
    assert.equal(found.length, ids.length, `${table}: record count at ${offset}`);
    for (const raw of found) {
      const row = oracleValue(raw);
      if (oracleRecords) oracleRecords.push(row);
      const seq = Number(row.seq), ownerIndex = seq % ownerIds.length, owner = ownerIds[ownerIndex];
      assert.equal(String(row.id), `${table}:r${String(seq).padStart(10, '0')}`);
      assert.equal(Number(row.rank), Math.floor(seq / 3));
      assert.equal(String(row.owned_by), String(owner));
      assert.equal(String(row.read_by), String(owner));
      assert.equal(String(row.tenant), tenantByOwner.get(String(owner)));
      assert.equal(Number(row.amount), 1);
      assert.equal(row.status, seq % 100 === 0 ? 'hot' : 'cold');
      assert.equal(row.payload, 'authorization-stress-fixture');
      checks.records++;
      const expected = nodeFor(table, owner, ownerIndex, Math.floor(seq / ownerIds.length),
        Math.max(0, Math.floor((n - 1 - ownerIndex) / ownerIds.length) + 1), ownerIds.length, slots, measures).slotNodes;
      for (let s = 0; s < slots; s++) {
        const node = row[`z${s}`];
        assert(node && node.owner && node.key && node.summary, `${table}:${seq}/z${s} missing tree node`);
        assert.equal(String(node.owner.rid), String(owner));
        assert.deepEqual(node.key, [Math.floor(seq / 3), String(row.id), `z${s}`]);
        assert.deepEqual(oracleValue(node), oracleValue(expected[`z${s}`]), `${table}:${seq}/z${s} complete seeded node`);
        checks.nodes++;
      }
    }
    await onProgress({ table, phase: 'verify', loaded: Math.min(n, offset + batchRows), total: n });
  }
  for (let oi = 0; oi < ownerIds.length; oi++) {
    const count = Math.max(0, Math.floor((n - 1 - oi) / ownerIds.length) + 1);
    const owner = ownerIds[oi];
    for (let s = 0; s < slots; s++) {
      const field = rootSlot(table, `z${s}`);
      const result = await query(db, `RETURN $owner.${field};`, { owner });
      const expectedHead = count ? (() => {
        const rootOrdinal = Math.floor(count / 2), firstSeq = oi, lastSeq = oi + (count - 1) * ownerIds.length;
        return { root: link(recordId(table, `r${String(oi + rootOrdinal * ownerIds.length).padStart(10, '0')}`), `z${s}`),
          height: balanceHeight(count), revision: count,
          summary: setBoundaries(summarize(count, [Math.floor(firstSeq / 3), `${table}:r${String(firstSeq).padStart(10, '0')}`, `z${s}`],
            [Math.floor(lastSeq / 3), `${table}:r${String(lastSeq).padStart(10, '0')}`, `z${s}`], measures), 0, count, oi, ownerIds.length, measures) };
      })() : { height: 0, revision: 0, summary: { count: 0, measures: {}, tags: {}, spans: {} } };
      assert.deepEqual(oracleValue(result), oracleValue(expectedHead), `${table}:${field} complete seeded head`);
      checks.rootHeads++;
    }
  }
  if (oracleRecords) {
    const oracleOwners = ownerRows.map(owner => Object.fromEntries([
      ['id', owner.id],
      ...Array.from({ length: slots }, (_, s) => { const slot = `z${s}`; return [rootSlot(table, slot), owner[rootSlot(table, slot)]]; }),
    ]));
    const entries = oracleRecords.flatMap(row => Array.from({ length: slots }, (_, s) => {
      const slot = `z${s}`;
      return { link: { rid: String(row.id), slot }, owner: { rid: String(row.owned_by), slot: rootSlot(table, slot) },
        key: [Number(row.rank), String(row.id), slot],
        measures: Object.fromEntries(Array.from({ length: measures }, (_, j) => [`m${j}`, Number(row.amount) * (j + 1)])), tags: {} };
    }));
    oracle.verify(oracleOwners, oracleRecords, entries, compareStressKey);
  }
  return { table, ...checks };
}

module.exports = { schema, compileFixture, loadFacts, verifyFacts, rootSlot, recordId };

