#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const seedrandom = require('seedrandom');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, applySchema } = require('./harness');
const { snapshot, instrument, expectedReads, oracle } = require('./observed-probe');

const ROOT = path.resolve(__dirname, '../..');
const seeds = [20261014, 7, 1031];
const create = (id, fields) => `CREATE ${id} SET owned_by=rebase_tenant:default, ${fields};`;
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const count = (state, id) => state.stats.find(row => row.id === id)?.calls ?? 0;
const derivedCalls = state => state.calls.reduce((sum, row) => sum + Number(row.calls || 0), 0);
const int = (random, min, max) => min + Math.floor(random() * (max - min + 1));
const pick = (random, values) => values[int(random, 0, values.length - 1)];
const ordered = values => values.slice().sort((a, b) => a.id.localeCompare(b.id));
function semanticState(state) {
  return {
    points: ordered(state.points.map(({ id, curve, at, value, other }) => ({ id, curve, at, value, other }))),
    readers: ordered(state.readers.map(({ id, curve, at, until, operation, inclusive, disabled, quantity, z_rate, amount }) =>
      ({ id, curve, at, until, operation, inclusive, disabled, quantity, z_rate, amount }))),
    publications: ordered(state.publications.map(({ id, curve, published, current, mapped, ranges, selection }) =>
      ({ id, curve, published, current, mapped, ranges, selection }))),
    expectedReads: expectedReads(state).map(row => JSON.stringify(row)).sort(),
  };
}

async function main() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-observed-history-'));
  const fixturePath = path.join(__dirname, 'observed-fixture.surql');
  const fixtureSql = fs.readFileSync(fixturePath, 'utf8');
  fs.writeFileSync(path.join(directory, 'fixture.surql'), fixtureSql);
  const compiled = generateBundle(loadMaterials({ groups: [
    { name: 'framework', roots: [path.join(ROOT, 'framework')] },
    { name: 'project', roots: [directory] },
  ] }));
  const instrumented = instrument(compiled.bundle);
  const server = await start({ engine: 'surrealkv' });
  const q = client(server.url);
  const sourceHash = sha256(fixtureSql), bundleHash = sha256(compiled.bundle), executedBundleHash = sha256(instrumented);
  const revision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim();
  let current = { seed: null, index: -1, label: 'schema application', sql: null };
  let checkpoints = 0, candidateReads = 0, derivedRefreshes = 0;

  const write = async (seed, index, label, sql) => {
    current = { seed, index, label, sql };
    const before = await snapshot(q);
    try {
      await q(sql);
      const after = await snapshot(q);
      oracle(after);
      candidateReads += count(after, 'read_probe_stats:candidates') - count(before, 'read_probe_stats:candidates');
      derivedRefreshes += derivedCalls(after) - derivedCalls(before);
      checkpoints++;
      return { before, after };
    } catch (error) {
      const after = await snapshot(q).catch(() => null);
      const evidence = {
        revision, seed, operationIndex: index, label, sql, before, after,
        error: error.stack || error.message, sourceSha256: sourceHash,
        compiledBundleSha256: bundleHash, instrumentedBundleSha256: executedBundleHash,
        engine: server.engine, node: process.version,
      };
      fs.writeFileSync(process.env.REBASE_HISTORY_FAILURE || path.join(os.tmpdir(), 'rebase-observed-history-failure.json'),
        JSON.stringify(evidence, null, 2));
      throw error;
    }
  };

  try {
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(q, instrumented);

    for (const seed of seeds) {
      const random = seedrandom(String(seed));
      const suffix = String(seed);
      const curve = `read_curve:history_${suffix}`;
      const peer = `read_curve:history_peer_${suffix}`;
      const pointRows = new Map();
      const readerRows = new Map();
      let operationIndex = 0;
      const apply = async (label, sql) => write(seed, operationIndex++, label, sql);

      await apply('create main source', create(curve, 'initial=5dec'));
      await apply('create empty peer source', create(peer, 'initial=7dec'));
      for (const [name, at, value, other] of [
        ['four', 4, 3, 1], ['eight_a', 8, 5, 2], ['eight_b', 8, 2, 4],
      ]) {
        const id = `read_point:history_${suffix}_${name}`;
        await apply(`create source point ${name}`, create(id, `curve=${curve},at=${at},value=${value}dec,other=${other}dec`));
        pointRows.set(id, { curve, at, value, other });
      }
      const initialReaders = [
        ['latest_a', curve, 2, 'latest', 100, false],
        ['latest_b', curve, 2, 'latest', 100, false],
        ['next', curve, 3, 'next', 100, false],
        ['before', curve, 8, 'before', 100, false],
        ['range', curve, 4, 'range', 9, false],
        ['exact', curve, 8, 'exact', 100, false],
        ['summary', curve, 0, 'summary', 100, false],
        ['empty_fallback', peer, 2, 'latest', 100, false],
      ];
      for (const [name, owner, at, operation, until, inclusive] of initialReaders) {
        const id = `read_reader:history_${suffix}_${name}`;
        await apply(`create ${name} reader`, create(id,
          `curve=${owner},at=${at},operation='${operation}',until=${until},inclusive=${inclusive},quantity=2dec`));
        readerRows.set(id, { curve: owner, at, operation, until, inclusive, disabled: false, quantity: 2 });
      }
      const inclusiveReader = `read_reader:history_${suffix}_latest_b`;
      const inclusiveState = readerRows.get(inclusiveReader);
      inclusiveState.at = 8;
      inclusiveState.operation = 'latest';
      inclusiveState.inclusive = false;
      await apply('set full inclusive predecessor boundary',
        `UPDATE ONLY ${inclusiveReader} SET at=8,operation='latest',inclusive=false;`);
      inclusiveState.inclusive = true;
      await apply('include an exact latest boundary', `UPDATE ONLY ${inclusiveReader} SET inclusive=true;`);
      inclusiveState.operation = 'next';
      inclusiveState.inclusive = false;
      await apply('set full exclusive successor boundary', `UPDATE ONLY ${inclusiveReader} SET operation='next',inclusive=false;`);
      inclusiveState.inclusive = true;
      await apply('include an exact next boundary', `UPDATE ONLY ${inclusiveReader} SET inclusive=true;`);
      for (const [name, owner] of [['main', curve], ['peer', peer]])
        await apply(`create ${name} array/object/map publication`, create(`read_publication:history_${suffix}_${name}`, `curve=${owner}`));

      // A gap/fallback reader must follow insertion of a predecessor and return
      // to the source record when that predecessor is removed again.
      const early = `read_point:history_${suffix}_early`;
      await apply('insert before first point', create(early, `curve=${curve},at=1,value=9dec,other=0dec`));
      pointRows.set(early, { curve, at: 1, value: 9, other: 0 });
      await apply('delete predecessor and restore fallback', `DELETE ONLY ${early};`);
      pointRows.delete(early);

      const operations = [
        'insert', 'value', 'move-time', 'move-owner', 'delete',
        'reader-shape', 'branch', 'initial', 'unrelated-measure', 'reader-owner',
      ];
      for (let index = 0; index < 20; index++) {
        const operation = operations[index % operations.length];
        const ids = [...pointRows.keys()];
        const readerIds = [...readerRows.keys()];
        if (operation === 'insert') {
          const id = `read_point:history_${suffix}_random_${index}`;
          const row = { curve: pick(random, [curve, peer]), at: int(random, -2, 12),
            value: int(random, 1, 9), other: int(random, 0, 5) };
          await apply(`insert tied/partial-bound point ${index}`, create(id,
            `curve=${row.curve},at=${row.at},value=${row.value}dec,other=${row.other}dec`));
          pointRows.set(id, row);
        } else if (operation === 'value') {
          const id = pick(random, ids), row = pointRows.get(id);
          row.value = int(random, 1, 9);
          await apply(`change consumed measure ${index}`, `UPDATE ONLY ${id} SET value=${row.value}dec;`);
        } else if (operation === 'move-time') {
          const id = pick(random, ids), row = pointRows.get(id);
          row.at = int(random, -2, 12);
          await apply(`move source key across readers ${index}`, `UPDATE ONLY ${id} SET at=${row.at};`);
        } else if (operation === 'move-owner') {
          const id = pick(random, ids), row = pointRows.get(id);
          row.curve = row.curve === curve ? peer : curve;
          await apply(`move source owner ${index}`, `UPDATE ONLY ${id} SET curve=${row.curve};`);
        } else if (operation === 'delete') {
          const id = pick(random, ids.filter(id => id !== `read_point:history_${suffix}_four`));
          if (ids.length <= 3 || !id) continue;
          await apply(`delete source and restore affected gaps ${index}`, `DELETE ONLY ${id};`);
          pointRows.delete(id);
        } else if (operation === 'reader-shape') {
          const id = pick(random, readerIds), row = readerRows.get(id);
          row.operation = pick(random, ['latest', 'next', 'before', 'range', 'exact', 'summary']);
          row.at = int(random, -2, 12);
          row.until = row.at + int(random, 1, 8);
          row.inclusive = random() < 0.5;
          await apply(`change operation, bounds and inclusive flag ${index}`,
            `UPDATE ONLY ${id} SET operation='${row.operation}',at=${row.at},until=${row.until},inclusive=${row.inclusive};`);
        } else if (operation === 'branch') {
          const id = pick(random, readerIds), row = readerRows.get(id);
          row.disabled = !row.disabled;
          await apply(`turn read branch ${row.disabled ? 'off' : 'on'} ${index}`,
            `UPDATE ONLY ${id} SET disabled=${row.disabled};`);
        } else if (operation === 'initial') {
          const owner = pick(random, [curve, peer]), value = int(random, 1, 12);
          await apply(`change fallback source value ${index}`, `UPDATE ONLY ${owner} SET initial=${value}dec;`);
        } else if (operation === 'unrelated-measure') {
          const id = pick(random, ids), row = pointRows.get(id);
          row.other = int(random, 0, 9);
          await apply(`change unrelated or mapped measure ${index}`, `UPDATE ONLY ${id} SET other=${row.other}dec;`);
        } else {
          const id = pick(random, readerIds), row = readerRows.get(id);
          row.curve = row.curve === curve ? peer : curve;
          await apply(`move reader owner away/back ${index}`, `UPDATE ONLY ${id} SET curve=${row.curve};`);
        }

        if (index % 10 === 9) {
          const id = pick(random, [...pointRows.keys()]), row = pointRows.get(id);
          const oldOwner = row.curve, newOwner = oldOwner === curve ? peer : curve;
          row.curve = newOwner;
          await apply(`metamorphic point move away ${index}`, `UPDATE ONLY ${id} SET curve=${newOwner};`);
          row.curve = oldOwner;
          await apply(`metamorphic point move back ${index}`, `UPDATE ONLY ${id} SET curve=${oldOwner};`);
        }
      }

      // An unused quote is a metamorphic source change: it must update its own
      // tree without changing any read rooted in the independent point sources.
      const dates = `read_dates:history_unused_${suffix}`;
      const quote = `read_quote:history_unused_${suffix}`;
      await apply('create unused quote source', create(dates, 'initial=2dec'));
      await apply('insert unused dated quote', create(quote, `curve=${dates},at=d'2027-03-01T00:00:00.000000001Z',rate=3dec`));
      await apply('delete unused dated quote', `DELETE ONLY ${quote};`);
      await apply('delete unused quote source', `DELETE ONLY ${dates};`);

      const reorderA = `read_point:history_${suffix}_reorder_a`;
      const reorderB = `read_point:history_${suffix}_reorder_b`;
      await apply('insert independent fact A before B', create(reorderA, `curve=${curve},at=0,value=4dec,other=1dec`));
      pointRows.set(reorderA, { curve, at: 0, value: 4, other: 1 });
      await apply('insert independent fact B after A', create(reorderB, `curve=${peer},at=12,value=6dec,other=2dec`));
      pointRows.set(reorderB, { curve: peer, at: 12, value: 6, other: 2 });
      const orderedAB = semanticState(await snapshot(q));
      await apply('remove independent fact A', `DELETE ONLY ${reorderA};`);
      pointRows.delete(reorderA);
      await apply('remove independent fact B', `DELETE ONLY ${reorderB};`);
      pointRows.delete(reorderB);
      await apply('insert independent fact B before A', create(reorderB, `curve=${peer},at=12,value=6dec,other=2dec`));
      pointRows.set(reorderB, { curve: peer, at: 12, value: 6, other: 2 });
      await apply('insert independent fact A after B', create(reorderA, `curve=${curve},at=0,value=4dec,other=1dec`));
      pointRows.set(reorderA, { curve, at: 0, value: 4, other: 1 });
      const orderedBA = semanticState(await snapshot(q));
      try {
        assert.deepEqual(orderedBA, orderedAB, 'independent insertion order preserves semantic state and logical reads');
      } catch (error) {
        const evidence = {
          revision, seed, operationIndex, label: 'reorder independent insertions',
          sql: ['create fact A', 'create fact B', 'delete fact A', 'delete fact B', 'create fact B', 'create fact A'],
          before: orderedAB, after: orderedBA, error: error.stack || error.message,
          sourceSha256: sourceHash, compiledBundleSha256: bundleHash,
          instrumentedBundleSha256: executedBundleHash, engine: server.engine, node: process.version,
        };
        fs.writeFileSync(process.env.REBASE_HISTORY_FAILURE || path.join(os.tmpdir(), 'rebase-observed-history-failure.json'),
          JSON.stringify(evidence, null, 2));
        throw error;
      }

      console.log(`seed ${seed}: source-sorted history verified`);
    }

    for (const table of ['read_publication', 'read_reader', 'read_point', 'read_curve']) {
      for (const id of await q(`SELECT VALUE id FROM ${table} ORDER BY id;`))
        await write(null, checkpoints, `cleanup ${table}`, `DELETE ${id};`);
    }
    for (const table of ['read_quote', 'read_dates']) {
      for (const id of await q(`SELECT VALUE id FROM ${table} ORDER BY id;`))
        await write(null, checkpoints, `cleanup ${table}`, `DELETE ${id};`);
    }
    const end = await snapshot(q);
    assert.equal(end.reads.length, 0, 'all seeded subscriptions cleaned');
    assert.equal(end.groups.length, 0, 'all seeded groups cleaned');
    assert.equal(end.frames.length, 0, 'all seeded frames cleaned');
    assert(end.locks.every(row => !/\[read_(?:curve|point|reader|publication|quote|dates):/.test(row.id)),
      'no seeded source fences remain');
    console.log(JSON.stringify({ status: 'PASS', seeds, checkpoints, candidateReads, derivedRefreshes,
      sourceSha256: sourceHash, compiledBundleSha256: bundleHash, instrumentedBundleSha256: executedBundleHash,
      revision, engine: server.engine, node: process.version, cleanup: true }));
  } finally {
    await server.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

main().catch(error => {
  console.error('Observed history campaign failed at:', error.stack || error.message);
  process.exitCode = 1;
});
