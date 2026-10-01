#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { performance } = require('node:perf_hooks');
const { compileFromArgs } = require('./compiler/cli');
const { start, client, applySchema } = require('./temporal-tree/harness');
const { splitStatements } = require('../src/surql');

const ownerCount = 10;
const pathHeight = 20;
const factKinds = [
  'inbound_invoice', 'supplier_payment', 'input_tax', 'tax_remittance',
  'customer_refund', 'stock_receipt', 'vendor_adjustment', 'payroll_payment',
  'delivery_return', 'recovery_payment',
];

function parseOptions(argv) {
  const options = { n: 1000000, densities: [1, 0.5, 0.1], counts: [1, 10, 100], batchSizes: [1, 10, 100], storage: 'surrealkv', maxProjectedSeconds: 60, allowSlow: false };
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (key === '--allow-slow') {
      options.allowSlow = true;
      continue;
    }
    const value = argv[++index];
    if (value === undefined) throw new Error(`Missing value for ${key}`);
    if (key === '--n') options.n = Number(value);
    else if (key === '--densities') options.densities = value.split(',').map(Number);
    else if (key === '--counts') options.counts = value.split(',').map(Number);
    else if (key === '--batch-sizes') options.batchSizes = value.split(',').map(Number);
    else if (key === '--storage') options.storage = value;
    else if (key === '--max-projected-seconds') options.maxProjectedSeconds = Number(value);
    else throw new Error(`Unknown option: ${key}`);
  }
  if (!Number.isSafeInteger(options.n) || options.n < 1000)
    throw new Error('--n must be an integer >= 1000');
  if (!options.densities.length || options.densities.some((value) => ![1, 0.5, 0.1].includes(value)))
    throw new Error('--densities supports 1, 0.5, and 0.1');
  for (const key of ['counts', 'batchSizes']) {
    if (!options[key].length || options[key].some((value) => !Number.isSafeInteger(value) || value < 1))
      throw new Error(`--${key === 'counts' ? 'counts' : 'batch-sizes'} must contain positive integers`);
  }
  if (!['rocksdb', 'surrealkv'].includes(options.storage))
    throw new Error('--storage must be rocksdb or surrealkv');
  if (!Number.isFinite(options.maxProjectedSeconds) || options.maxProjectedSeconds < 0)
    throw new Error('--max-projected-seconds must be a nonnegative number');
  return options;
}

function idForPath(index) {
  return `path_${String(index).padStart(2, '0')}`;
}

function idForShard(index) {
  return `shard_${String(index).padStart(2, '0')}`;
}

function keyFor(id, slot, at) {
  return { id: `stress_fact:${id}`, slot, at };
}

function keySql(key) {
  return `[d'${key.at}', '${key.id}', '${key.slot}']`;
}

function refSql(table, id, slot) {
  return `{rid:${table}:${id},slot:'${slot}'}`;
}

function summarySql(count, first, last) {
  return `{count:${count},dependents:0,first:${keySql(first)},last:${keySql(last)},measures:{amount:{sum:0dec,min_prefix:0dec,max_prefix:0dec,min:0dec,max:0dec,instant_min:0dec,instant_max:0dec}},tags:{},spans:{}}`;
}

function valueSql(count, key) {
  return summarySql(count, key, key);
}

function createBackbone(n, density) {
  const activeRows = Math.floor(10 * density);
  const base = new Date('2026-01-01T00:00:00.000Z').getTime();
  const pathNodes = Array.from({ length: pathHeight }, (_, index) => ({
    id: idForPath(index),
    kind: index < 10 ? factKinds[index] : 'compressed_path',
    sequence: index < 10 ? index : 0,
    amount: index < 10 ? 100 : 0,
    rule: index < activeRows ? 'active' : 'steady',
    weight: 1,
    height: pathHeight - index,
    left: index < pathHeight - 1 ? idForShard(index) : null,
    right: index < pathHeight - 1 ? idForPath(index + 1) : null,
    parent: index === 0 ? null : idForPath(index - 1),
  }));
  const shardWeight = Math.floor((n - pathHeight) / (pathHeight - 1));
  const shardRemainder = (n - pathHeight) % (pathHeight - 1);
  const shardNodes = Array.from({ length: pathHeight - 1 }, (_, index) => ({
    id: idForShard(index),
    kind: 'compressed_aggregate',
    sequence: 0,
    amount: 0,
    rule: 'steady',
    weight: shardWeight + (index < shardRemainder ? 1 : 0),
    height: pathHeight - index - 1,
    left: null,
    right: null,
    parent: idForPath(index),
  }));
  const inorder = [];
  for (let index = 0; index < pathHeight - 1; index += 1)
    inorder.push(shardNodes[index], pathNodes[index]);
  inorder.push(pathNodes.at(-1));
  for (let index = 0; index < inorder.length; index += 1) {
    inorder[index].at = new Date(base + index * 1000).toISOString();
    inorder[index].previous = inorder[index - 1]?.id ?? null;
    inorder[index].next = inorder[index + 1]?.id ?? null;
  }

  const byId = new Map(inorder.map((node) => [node.id, node]));
  for (const node of inorder) {
    node.key = keyFor(node.id, 'z01_leg', node.at);
    node.summary = node.id.startsWith('shard_')
      ? { count: node.weight, first: node.key, last: node.key }
      : null;
  }
  for (let index = pathHeight - 1; index >= 0; index -= 1) {
    const node = pathNodes[index];
    const left = node.left ? byId.get(node.left).summary : null;
    const right = node.right ? byId.get(node.right).summary : null;
    node.summary = {
      count: (left?.count ?? 0) + node.weight + (right?.count ?? 0),
      first: left?.first ?? node.key,
      last: right?.last ?? node.key,
    };
  }
  assert.equal(pathNodes[0].summary.count, n);
  return { activeRows, pathNodes, shardNodes, inorder, byId, rootSummary: pathNodes[0].summary };
}

function nodeSql(node, slotIndex) {
  const slot = `z${String(slotIndex + 1).padStart(2, '0')}_leg`;
  const key = keyFor(node.id, slot, node.at);
  const summary = node.id.startsWith('shard_')
    ? { count: node.weight, first: key, last: key }
    : {
      count: node.summary.count,
      first: node.summary.first,
      last: node.summary.last,
    };
  const parent = node.parent
    ? refSql('stress_fact', node.parent, `z${String(slotIndex + 1).padStart(2, '0')}_leg`)
    : refSql('stress_owner', `owner_${String(slotIndex + 1).padStart(2, '0')}`, 'z_book');
  const fields = [
    `owner:${refSql('stress_owner', `owner_${String(slotIndex + 1).padStart(2, '0')}`, 'z_book')}`,
    `parent:${parent}`,
    ...(node.left ? [`left:${refSql('stress_fact', node.left, `z${String(slotIndex + 1).padStart(2, '0')}_leg`)}`] : []),
    ...(node.right ? [`right:${refSql('stress_fact', node.right, `z${String(slotIndex + 1).padStart(2, '0')}_leg`)}`] : []),
    ...(node.previous ? [`prev:${refSql('stress_fact', node.previous, `z${String(slotIndex + 1).padStart(2, '0')}_leg`)}`] : []),
    ...(node.next ? [`next:${refSql('stress_fact', node.next, `z${String(slotIndex + 1).padStart(2, '0')}_leg`)}`] : []),
    `key:${keySql(key)}`,
    `value:${valueSql(node.weight, key)}`,
    `height:${node.height}`,
    `summary:${summarySql(summary.count, { ...summary.first, slot }, { ...summary.last, slot })}`,
  ];
  return `{${fields.join(',')}}`;
}

function backboneStatements(backbone) {
  const statements = [];
  for (let index = 0; index < ownerCount; index += 1) {
    const owner = String(index + 1).padStart(2, '0');
    statements.push(`CREATE stress_owner:owner_${owner} SET owned_by=rebase_group:root;`);
  }
  statements.push("CREATE stress_rule:active SET owned_by=rebase_group:root,a_rate=0dec;");
  statements.push("CREATE stress_rule:steady SET owned_by=rebase_group:root,a_rate=0dec;");
  for (const node of backbone.inorder) {
    const facts = [
      `owned_by=rebase_group:root`,
      `a_kind='${node.kind}'`,
      `a_sequence=${node.sequence}`,
      `a_amount=${node.amount}dec`,
      `a_effective_at=d'${node.at}'`,
      `a_rule=stress_rule:${node.rule}`,
    ];
    for (let index = 0; index < ownerCount; index += 1) {
      const owner = String(index + 1).padStart(2, '0');
      facts.push(`a_owner_${owner}=stress_owner:owner_${owner}`);
      facts.push(`z${owner}_leg=${nodeSql(node, index)}`);
    }
    statements.push(`CREATE stress_fact:${node.id} SET ${facts.join(',')};`);
  }
  for (let index = 0; index < ownerCount; index += 1) {
    const owner = String(index + 1).padStart(2, '0');
    const rootSlot = `z${owner}_leg`;
    const rootSummary = summarySql(
      backbone.rootSummary.count,
      { ...backbone.rootSummary.first, slot: rootSlot },
      { ...backbone.rootSummary.last, slot: rootSlot },
    );
    statements.push(`UPDATE stress_owner:owner_${owner} SET z_book={root:${refSql('stress_fact', idForPath(0), rootSlot)},height:${pathHeight},revision:0,refreshing:false,dirty:NONE,cursor:NONE,summary:${rootSummary}};`);
  }
  return statements;
}

function expectedSums(activeRows) {
  return Array.from({ length: ownerCount }, (_, ownerIndex) => {
    let total = 0;
    for (let sequence = 0; sequence < activeRows; sequence += 1)
      total += (sequence + ownerIndex + 1) % 2 === 0 ? 100 : -100;
    return total;
  });
}

async function readRoots(q) {
  const owners = Array.from({ length: ownerCount }, (_, index) => `stress_owner:owner_${String(index + 1).padStart(2, '0')}`);
  const fields = (expression) => `[${owners.map((owner) => `${owner}.z_book.${expression}`).join(',')}]`;
  const result = await q(`RETURN {counts:${fields('summary.count')},heights:${fields('height')},revisions:${fields('revision')},sums:${fields('summary.measures.amount.sum')}};`);
  for (const key of ['counts', 'heights', 'revisions', 'sums']) result[key] = result[key].map(Number);
  return result;
}

function assertRoots(actual, n, sums, message) {
  assert.deepEqual(actual.counts, Array(ownerCount).fill(n), `${message}: logical row counts`);
  assert.deepEqual(actual.heights, Array(ownerCount).fill(pathHeight), `${message}: tree heights`);
  assert.deepEqual(actual.sums, sums, `${message}: amount aggregates`);
}

function ownerReferences() {
  return Array.from({ length: ownerCount }, (_, index) => {
    const owner = String(index + 1).padStart(2, '0');
    return `a_owner_${owner}=stress_owner:owner_${owner}`;
  });
}

function seededRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state += 0x6D2B79F5;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function modelCycles(count, seed) {
  const random = seededRandom(seed);
  const balances = Array(ownerCount).fill(0);
  const kinds = Object.fromEntries(factKinds.map((kind) => [kind, 0]));
  for (let sequence = 0; sequence < count; sequence += 1) {
    const amount = 80 + Math.floor(random() * 41);
    const kind = factKinds[sequence % factKinds.length];
    kinds[kind] += 1;
    for (let ownerIndex = 0; ownerIndex < ownerCount; ownerIndex += 1) {
      const sign = (sequence + ownerIndex + 1) % 2 === 0 ? 1 : -1;
      balances[ownerIndex] += sign * amount;
      balances[ownerIndex] += sign * 25;
      balances[ownerIndex] -= sign * (amount + 25);
    }
  }
  assert.deepEqual(balances, Array(ownerCount).fill(0), 'balanced modeled lifecycle');
  return { records: count, sourceEvents: count * 3, kinds, finalOwnerDeltas: balances };
}

function cycleSql(id, sequence, amount, at) {
  const kind = factKinds[sequence % factKinds.length];
  const common = [
    `owned_by=rebase_group:root`,
    `a_kind='${kind}'`,
    `a_sequence=${sequence}`,
    `a_amount=${amount}dec`,
    `a_effective_at=d'${at}'`,
    `a_rule=stress_rule:active`,
    ...ownerReferences(),
  ];
  return [
    `CREATE stress_fact:${id} SET ${common.join(',')};`,
    `UPDATE stress_fact:${id} SET a_amount=${amount + 25}dec;`,
    `DELETE stress_fact:${id};`,
  ];
}

async function exerciseCycles(q, n, expected, count, batchSize, density, ordinal) {
  const random = seededRandom(20260923 + Math.round(density * 1000) + count * 31 + batchSize);
  const latencies = [];
  for (let offset = 0; offset < count; offset += batchSize) {
    const statements = [];
    const end = Math.min(count, offset + batchSize);
    for (let index = offset; index < end; index += 1) {
      const id = `cycle_${String(ordinal).padStart(2, '0')}_${String(index).padStart(4, '0')}`;
      const amount = 80 + Math.floor(random() * 41);
      const at = new Date(Date.parse('2026-01-02T00:00:00.000Z') + index * 1000 + ordinal * 1000000).toISOString();
      statements.push(...cycleSql(id, index, amount, at));
    }
    const startedAt = performance.now();
    await q(`BEGIN TRANSACTION;\n${statements.join('\n')}\nCOMMIT TRANSACTION;`);
    latencies.push(performance.now() - startedAt);
    const roots = await readRoots(q);
    assertRoots(roots, n, expected, `CRUD cycle ${count}/${batchSize} after rows ${offset}-${end - 1}`);
  }
  const sorted = [...latencies].sort((left, right) => left - right);
  return {
    records: count,
    rowsPerTransaction: batchSize,
    transactions: latencies.length,
    sourceEvents: count * 3,
    elapsedMs: latencies.reduce((sum, latency) => sum + latency, 0),
    transactionMedianMs: sorted[Math.floor((sorted.length - 1) / 2)],
    transactionP95Ms: sorted[Math.ceil(sorted.length * 0.95) - 1],
  };
}

async function runScenario(compiled, options) {
  const server = await start({ engine: options.storage });
  const q = client(server.url);
  const backbone = createBackbone(options.n, 1);
  try {
    const statements = splitStatements(compiled.bundle);
    const events = statements.filter((statement) => {
      const match = /^DEFINE\s+EVENT\s+(?:OVERWRITE\s+)?([A-Za-z_][A-Za-z0-9_]*)\s+ON\s+(?:TABLE\s+)?([A-Za-z_][A-Za-z0-9_]*)/i.exec(statement.trim());
      return match && ['stress_owner', 'stress_rule', 'stress_fact'].includes(match[2]);
    });
    const schema = statements.filter((statement) => !/^DEFINE\s+EVENT\b/i.test(statement.trim())).join('\n');
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture;');
    await applySchema(q, schema);
    const seed = backboneStatements(backbone);
    for (let offset = 0; offset < seed.length; offset += 50)
      await q(seed.slice(offset, offset + 50).join('\n'));
    await q(events.join('\n'));

    let roots = await readRoots(q);
    assertRoots(roots, options.n, Array(ownerCount).fill(0), 'seeded backbone');
    assert.deepEqual(roots.revisions, Array(ownerCount).fill(0), 'seeded tree revisions');
    const membershipSlots = await q("RETURN [stress_fact:path_00.z01_leg,stress_fact:path_00.z02_leg,stress_fact:path_00.z03_leg,stress_fact:path_00.z04_leg,stress_fact:path_00.z05_leg,stress_fact:path_00.z06_leg,stress_fact:path_00.z07_leg,stress_fact:path_00.z08_leg,stress_fact:path_00.z09_leg,stress_fact:path_00.z10_leg];");
    assert.equal(membershipSlots.filter((slot) => slot !== null).length, ownerCount, 'each source row starts with ten active tree memberships');
    console.log(JSON.stringify({ phase: 'seeded', logicalN: options.n, m: ownerCount, treeHeight: pathHeight, physicalBackboneRows: backbone.inorder.length }));
    const crud = [];
    const densityResults = [];
    let previousActiveRows = 10;
    let oneCycleMs = null;
    let cycleOrdinal = 0;
    for (const density of options.densities) {
      const activeRows = Math.floor(10 * density);
      if (activeRows !== previousActiveRows) {
        const updates = [];
        for (let sequence = 0; sequence < 10; sequence += 1) {
          const shouldBeActive = sequence < activeRows;
          const wasActive = sequence < previousActiveRows;
          if (shouldBeActive !== wasActive) {
            const targetRule = shouldBeActive ? 'active' : 'steady';
            updates.push(`UPDATE stress_fact:${idForPath(sequence)} SET a_rule=stress_rule:${targetRule};`);
          }
        }
        if (updates.length) await q(`BEGIN TRANSACTION;\n${updates.join('\n')}\nCOMMIT TRANSACTION;`);
        roots = await readRoots(q);
        assertRoots(roots, options.n, Array(ownerCount).fill(0), `density ${density} references staged`);
        previousActiveRows = activeRows;
      }

      const beforeRule = roots.revisions;
      console.log(JSON.stringify({ phase: 'rule-refresh', density, r: activeRows, reactiveTreeMemberships: activeRows * ownerCount }));
      const updateStarted = performance.now();
      await q('BEGIN TRANSACTION; UPDATE stress_rule:active SET a_rate=1dec; COMMIT TRANSACTION;');
      const ruleUpdateMs = performance.now() - updateStarted;
      roots = await readRoots(q);
      const expected = expectedSums(activeRows);
      assertRoots(roots, options.n, expected, `density ${density} rule fanout`);
      assert.deepEqual(roots.revisions, beforeRule.map((revision) => revision + activeRows), 'one revision per refreshed record on each of ten trees');
      const refreshedAmounts = await q('RETURN [stress_fact:path_00.z12_amount,stress_fact:path_01.z12_amount,stress_fact:path_02.z12_amount,stress_fact:path_03.z12_amount,stress_fact:path_04.z12_amount,stress_fact:path_05.z12_amount,stress_fact:path_06.z12_amount,stress_fact:path_07.z12_amount,stress_fact:path_08.z12_amount,stress_fact:path_09.z12_amount];');
      assert.deepEqual(refreshedAmounts.map(Number), Array.from({ length: 10 }, (_, index) => index < activeRows ? 100 : 0));

      if (oneCycleMs === null) {
        const beforeCycle = roots.revisions;
        const result = await exerciseCycles(q, options.n, expected, 1, 1, density, cycleOrdinal++);
        roots = await readRoots(q);
        assert.deepEqual(roots.revisions, beforeCycle.map((revision) => revision + 3), 'create, update, and delete each revisit all ten trees');
        oneCycleMs = result.elapsedMs;
        crud.push(result);
      }

      const resetStarted = performance.now();
      await q('BEGIN TRANSACTION; UPDATE stress_rule:active SET a_rate=0dec; COMMIT TRANSACTION;');
      const ruleResetMs = performance.now() - resetStarted;
      roots = await readRoots(q);
      assertRoots(roots, options.n, Array(ownerCount).fill(0), `density ${density} rule reset`);
      densityResults.push({
        density,
        r: activeRows,
        ruleUpdateMs,
        ruleResetMs,
        refreshedTreeMemberships: activeRows * ownerCount,
        revisionDelta: activeRows,
      });
    }

    const crudWorkloads = [];
    const finalActiveRows = Math.floor(10 * options.densities.at(-1));
    const runLargerCycles = options.allowSlow
      || options.counts.some((count) => count > 1 && (oneCycleMs * count) / 1000 <= options.maxProjectedSeconds);
    let largerCycleBaseline = Array(ownerCount).fill(0);
    if (runLargerCycles) {
      await q('BEGIN TRANSACTION; UPDATE stress_rule:active SET a_rate=1dec; COMMIT TRANSACTION;');
      largerCycleBaseline = expectedSums(finalActiveRows);
      roots = await readRoots(q);
      assertRoots(roots, options.n, largerCycleBaseline, 'larger CRUD cycles armed');
    }
    for (const count of options.counts) {
      const model = modelCycles(count, 20260923 + count);
      for (const batchSize of options.batchSizes) {
        const projection = {
          records: count,
          rowsPerTransaction: batchSize,
          modeledSourceEvents: model.sourceEvents,
          modelVerifiedNetZero: true,
          projectedBackendMs: oneCycleMs * count,
          status: count === 1 ? 'covered by measured one-cycle smoke' : 'not run: projected runtime',
        };
        if (count > 1 && options.allowSlow) {
          const measured = await exerciseCycles(q, options.n, largerCycleBaseline, count, batchSize, 1, cycleOrdinal++);
          crudWorkloads.push({ ...projection, status: 'measured', ...measured });
        } else {
          const projectedSeconds = projection.projectedBackendMs / 1000;
          if (count > 1 && projectedSeconds <= options.maxProjectedSeconds) {
            const measured = await exerciseCycles(q, options.n, largerCycleBaseline, count, batchSize, 1, cycleOrdinal++);
            crudWorkloads.push({ ...projection, status: 'measured', ...measured });
          } else {
            crudWorkloads.push({
              ...projection,
              reason: count === 1 ? 'same one-record work as measured smoke' : `estimated ${projectedSeconds.toFixed(1)}s exceeds ${options.maxProjectedSeconds}s guard`,
              modeledKinds: model.kinds,
            });
          }
        }
      }
    }
    if (runLargerCycles) {
      await q('BEGIN TRANSACTION; UPDATE stress_rule:active SET a_rate=0dec; COMMIT TRANSACTION;');
      roots = await readRoots(q);
      assertRoots(roots, options.n, Array(ownerCount).fill(0), 'larger CRUD cycles reset');
    }

    await server.close();
    return {
      engine: server.engine,
      logicalN: options.n,
      physicalBackboneRows: backbone.inorder.length,
      treeHeight: pathHeight,
      m: ownerCount,
      densities: densityResults,
      measuredCrudCycle: crud[0],
      crudWorkloads,
    };
  } finally {
    await server.close();
  }
}

async function main(argv = process.argv.slice(2)) {
  const options = parseOptions(argv);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-synthetic-write-amplification-'));
  try {
    const compiled = compileFromArgs({
      projectDir: 'dev-tools/synthetic-write-amplification',
      frameworkDir: 'framework',
      outputDir: temp,
    });
    const surrealBinary = process.env.REBASE_TREE_SURREAL_BIN || 'surreal';
    const surrealVersion = execFileSync(surrealBinary, ['version'], { encoding: 'utf8' }).trim();
    console.log(JSON.stringify({
      surreal: surrealVersion,
      node: process.version,
      platform: process.platform,
      engine: options.storage,
      logicalN: options.n,
      m: ownerCount,
      backbone: 'weighted 20-level AVL path; 39 physical records; synthetic aggregate shards',
    }));
    console.log(JSON.stringify(await runScenario(compiled, options)));
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
}

if (require.main === module)
  main().catch((error) => {
    console.error(`Synthetic write amplification probe failed: ${error.stack || error.message}`);
    process.exitCode = 1;
  });

module.exports = { createBackbone, expectedSums, main, parseOptions };
