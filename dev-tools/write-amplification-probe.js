#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { performance } = require('node:perf_hooks');
const { start, client, applySchema } = require('./temporal-tree/harness');
const { compileFromArgs } = require('./compiler/cli');
const { parseSchema } = require('../src/schema');

const DEFAULT_SIZES = [10, 100, 1000, 10000, 100000, 1000000];
const root = 'rebase_group:root';
const paymentDate = "d'2026-01-01T00:00:00Z'";
const chargeDate = "d'2026-01-02T00:00:00Z'";

function options(argv) {
  const result = { sizes: DEFAULT_SIZES, densities: [0.1, 0.01, 0.001, 1], refundDensity: 0.01, batchSize: 250, storage: 'rocksdb' };
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    const value = argv[++index];
    if (value === undefined) throw new Error(`Missing value for ${key}`);
    if (key === '--sizes') result.sizes = value.split(',').map(Number);
    else if (key === '--densities') result.densities = value.split(',').map(Number);
    else if (key === '--refund-density') result.refundDensity = Number(value);
    else if (key === '--batch-size') result.batchSize = Number(value);
    else if (key === '--storage') result.storage = value;
    else throw new Error(`Unknown option: ${key}`);
  }
  if (!result.sizes.length || result.sizes.some((size) => !Number.isSafeInteger(size) || size < 1))
    throw new Error('--sizes must be comma-separated positive integers');
  if (!result.densities.length || result.densities.some((density) => !Number.isFinite(density) || density <= 0 || density > 1))
    throw new Error('--densities must be between 0 (exclusive) and 1');
  if (!Number.isFinite(result.refundDensity) || result.refundDensity < 0 || result.refundDensity > 1)
    throw new Error('--refund-density must be between 0 and 1');
  if (!Number.isSafeInteger(result.batchSize) || result.batchSize < 1)
    throw new Error('--batch-size must be a positive integer');
  if (!['rocksdb', 'surrealkv'].includes(result.storage))
    throw new Error('--storage must be rocksdb or surrealkv');
  return result;
}

function sizeOf(directory) {
  let bytes = 0;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    bytes += entry.isDirectory() ? sizeOf(target) : fs.statSync(target).size;
  }
  return bytes;
}

async function insertStatements(q, statements, batchSize) {
  let elapsedMs = 0;
  const batchMs = [];
  for (let offset = 0; offset < statements.length; offset += batchSize) {
    const batch = statements.slice(offset, offset + batchSize);
    const startedAt = performance.now();
    await q(`BEGIN TRANSACTION;\n${batch.join('\n')}\nCOMMIT TRANSACTION;`);
    const elapsed = performance.now() - startedAt;
    elapsedMs += elapsed;
    batchMs.push(elapsed);
  }
  const sorted = [...batchMs].sort((left, right) => left - right);
  return {
    elapsedMs,
    medianBatchMs: sorted.length ? sorted[Math.floor((sorted.length - 1) / 2)] : null,
    p95BatchMs: sorted.length ? sorted[Math.ceil(sorted.length * 0.95) - 1] : null,
  };
}

function paymentRows(count) {
  return Array.from({ length: count }, (_, index) => {
    const id = `scale_${String(index).padStart(8, '0')}`;
    return `CREATE payment:${id} SET owned_by=${root},a_from=money_account:bank,a_to=money_account:vendor,a_amount=1000dec,a_effective_at=${paymentDate};`;
  });
}

function chargeRows(count) {
  return Array.from({ length: count }, (_, index) => {
    const id = `scale_${String(index).padStart(8, '0')}`;
    return `CREATE money_charge:charge_${id} SET owned_by=${root},a_original=payment:${id},a_rule=calculation_rule:shared,a_to=money_account:authority,a_effective_at=${chargeDate};`;
  });
}

function refundRows(count) {
  return Array.from({ length: count }, (_, index) => {
    const id = `scale_${String(index).padStart(8, '0')}`;
    return `CREATE money_refund:refund_${id} SET owned_by=${root},a_original=payment:${id},a_note=adjustment_note:refund,a_amount=10dec,a_effective_at=d'2026-01-03T00:00:00Z';`;
  });
}

async function fixture(q, bundle) {
  await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture;');
  await applySchema(q, bundle);
  await q(`CREATE currency:inr SET owned_by=${root},a_code='INR',a_name='Indian Rupee';
    CREATE organization:company SET owned_by=${root},a_name='Company';
    CREATE money_account:company SET owned_by=${root},a_entity=organization:company,a_currency=currency:inr;
    CREATE organization:vendor SET owned_by=${root},a_name='Vendor';
    CREATE money_account:vendor SET owned_by=${root},a_entity=organization:vendor,a_currency=currency:inr;
    CREATE organization:authority SET owned_by=${root},a_name='Authority';
    CREATE money_account:authority SET owned_by=${root},a_entity=organization:authority,a_currency=currency:inr;
    CREATE treasury_account:bank SET owned_by=${root},a_name='Bank',a_organization=organization:company;
    CREATE money_account:bank SET owned_by=${root},a_entity=treasury_account:bank,a_currency=currency:inr;
    CREATE misc_account:funding SET owned_by=${root},a_name='Funding';
    CREATE money_account:funding SET owned_by=${root},a_entity=misc_account:funding,a_currency=currency:inr,a_nonnegative=false;
    CREATE calculation_rule:shared SET owned_by=${root},a_name='Shared charge',a_rate=0.001dec;
    CREATE adjustment_note:refund SET owned_by=${root},a_reason='Scale refunds',a_currency=currency:inr,a_effective_at=d'2026-02-01T00:00:00Z';
    CREATE payment:opening SET owned_by=${root},a_from=money_account:funding,a_to=money_account:bank,a_amount=2000000000dec,a_effective_at=${paymentDate};`);
}

async function runScenario(bundle, total, density, refundDensity, batchSize, storage, slots) {
  const server = await start({ engine: storage });
  const q = client(server.url);
  const dependentRecords = Math.floor(total * density);
  const refundRecords = Math.floor(total * refundDensity);
  const result = {
    engine: server.engine,
    records: total,
    density,
    dependentRecords,
    refundDensity,
    refundRecords,
    batchSize,
    paymentTransactions: Math.ceil(total / batchSize),
    chargeTransactions: Math.ceil(dependentRecords / batchSize),
    refundTransactions: Math.ceil(refundRecords / batchSize),
  };
  try {
    await fixture(q, bundle);
    const paymentInsert = await insertStatements(q, paymentRows(total), batchSize);
    const chargeInsert = await insertStatements(q, chargeRows(dependentRecords), batchSize);
    result.paymentInsertMs = paymentInsert.elapsedMs;
    result.paymentBatchMedianMs = paymentInsert.medianBatchMs;
    result.paymentBatchP95Ms = paymentInsert.p95BatchMs;
    result.chargeInsertMs = chargeInsert.elapsedMs;
    result.chargeBatchMedianMs = chargeInsert.medianBatchMs;
    result.chargeBatchP95Ms = chargeInsert.p95BatchMs;
    const updateStartedAt = performance.now();
    await q('UPDATE calculation_rule:shared SET a_rate=0.002dec;');
    result.ruleRefreshMs = performance.now() - updateStartedAt;
    const refundInsert = await insertStatements(q, refundRows(refundRecords), batchSize);
    result.refundInsertMs = refundInsert.elapsedMs;
    result.refundBatchMedianMs = refundInsert.medianBatchMs;
    result.refundBatchP95Ms = refundInsert.p95BatchMs;
    result.paymentRowsPerSecond = Math.round(total / (result.paymentInsertMs / 1000));
    result.chargeRowsPerSecond = dependentRecords
      ? Math.round(dependentRecords / (result.chargeInsertMs / 1000))
      : null;
    result.maxTreeNodes = Number(await q('RETURN money_account:bank.z_book.summary.count;'));
    result.maxTreeHeight = Number(await q('RETURN money_account:bank.z_book.height;'));
    const paymentResult = await q('SELECT * FROM payment:scale_00000000;');
    const charge = dependentRecords
      ? await q('SELECT * FROM money_charge:charge_scale_00000000;')
      : null;
    const refund = refundRecords
      ? await q('SELECT * FROM money_refund:refund_scale_00000000;')
      : null;
    const paymentRecord = Array.isArray(paymentResult) ? paymentResult[0] : paymentResult;
    const chargeRecordResult = Array.isArray(charge) ? charge[0] : charge;
    result.paymentActiveMemberships = slots.payment.filter((key) => paymentRecord?.[key] != null).length;
    result.chargeActiveMemberships = charge
      ? slots.money_charge.filter((key) => chargeRecordResult?.[key] != null).length
      : null;
    const refundRecord = Array.isArray(refund) ? refund[0] : refund;
    result.refundActiveMemberships = refund
      ? slots.money_refund.filter((key) => refundRecord?.[key] != null).length
      : null;
    result.chargeAmountAfterRuleChange = dependentRecords
      ? Number(await q('RETURN money_charge:charge_scale_00000000.z11_amount;'))
      : null;
    await server.close({ keepData: true });
    result.databaseBytes = sizeOf(server.directory);
    return result;
  } finally {
    await server.close();
  }
}

function tableMemberships(schema) {
  return [...schema.tables.values()]
    .map((table) => ({
      table: table.name,
      m: [...table.fields.values()].filter((field) => /option<object>/i.test(field.definition)).length,
    }))
    .filter((row) => row.m > 0)
    .sort((left, right) => left.table.localeCompare(right.table));
}

function membershipSlots(schema) {
  return Object.fromEntries(
    [...schema.tables.values()].map((table) => [
      table.name,
      [...table.fields.values()]
        .filter((field) => /option<object>/i.test(field.definition))
        .map((field) => field.name),
    ]),
  );
}

async function main(argv = process.argv.slice(2)) {
  const opts = options(argv);
  const output = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-write-amplification-'));
  try {
    const compiled = compileFromArgs({
      projectDir: 'designs/all-in-one',
      frameworkDir: 'framework',
      outputDir: output,
    });
    const parsed = parseSchema(compiled.bundle, '');
    const slots = membershipSlots(parsed);
    const surrealBinary = process.env.REBASE_TREE_SURREAL_BIN || 'surreal';
    const surrealVersion = execFileSync(surrealBinary, ['version'], { encoding: 'utf8' }).trim();
    console.log(JSON.stringify({ surreal: surrealVersion, node: process.version, platform: process.platform, storage: opts.storage, memberships: tableMemberships(parsed) }));
    for (const density of opts.densities) {
      for (let index = 0; index < opts.sizes.length; index += 1) {
        const total = opts.sizes[index];
        const row = await runScenario(compiled.bundle, total, density, opts.refundDensity, opts.batchSize, opts.storage, slots);
        console.log(JSON.stringify(row));
        if (row.chargeAmountAfterRuleChange !== null && row.chargeAmountAfterRuleChange !== 2)
          throw new Error(`Dependent rule edit failed at ${total} rows (${density} density)`);
        const next = opts.sizes[index + 1];
        if (next && next > total) {
          const measuredMs = row.paymentInsertMs + row.chargeInsertMs + row.ruleRefreshMs + row.refundInsertMs;
          const projectedMs = measuredMs * (next / total) * (Math.log2(next) / Math.log2(total));
          if (projectedMs > 300000) {
            console.log(JSON.stringify({
              skippedFollowingScales: opts.sizes.slice(index + 1),
              estimatedNextMinutes: Math.round(projectedMs / 60000),
              reason: 'projected duration exceeds five minutes',
            }));
            break;
          }
        }
      }
    }
  } finally {
    fs.rmSync(output, { recursive: true, force: true });
  }
}

if (require.main === module)
  main().catch((error) => {
    console.error(`Write amplification probe failed: ${error.stack || error.message}`);
    process.exitCode = 1;
  });

module.exports = { main, tableMemberships };
