#!/usr/bin/env node
'use strict';

// Repair gate: intentionally fails while whole-group settlement remains in the
// runtime. Keep it out of the normal green suite until packet B is complete.
// A passing cost result alone does not establish accounting correctness.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, applySchema } = require('./harness');
const { verifyReads } = require('./read-oracle');

const ROOT = path.resolve(__dirname, '../..');
const snapshot = q => q(`RETURN {
  sources:(SELECT * FROM cost_source ORDER BY id),
  readers:(SELECT * FROM cost_reader ORDER BY id),
  tenants:(SELECT * FROM rebase_tenant ORDER BY id),
  rebase_read:(SELECT * FROM rebase_read ORDER BY id),
  rebase_read_group:(SELECT * FROM rebase_read_group ORDER BY id),
  rebase_read_frame:(SELECT * FROM rebase_read_frame ORDER BY id),
  rebase_read_lock:(SELECT * FROM rebase_read_lock ORDER BY id)
};`);

async function main() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-read-cost-'));
  let server;
  try {
    fs.writeFileSync(path.join(directory, 'schema.surql'), `
DEFINE TABLE cost_source SCHEMAFULL;
DEFINE FIELD amount ON cost_source TYPE decimal;
DEFINE TABLE cost_reader SCHEMAFULL;
DEFINE FIELD source ON cost_reader TYPE record<cost_source> REFERENCE ON DELETE REJECT;
DEFINE FIELD amount ON cost_reader TYPE decimal
  VALUE fn::record::read_value($this.source,'amount',0dec) COMMENT '@rebase-derived';
`);
    const compiled = generateBundle(loadMaterials({ groups: [
      { name:'framework', roots:[path.join(ROOT, 'framework')] },
      { name:'project', roots:[directory] },
    ] }));
    // Recounting every group can have correct values while doing quadratic work.
    // Count actual summary pulls in this sequential one-read-per-row fixture.
    const sql = compiled.bundle.replace('DEFINE FUNCTION OVERWRITE fn::tree::pull(',
      'DEFINE FUNCTION OVERWRITE fn::cost::pull(') + `
DEFINE TABLE cost_stats SCHEMALESS PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::tree::pull($link: object, $detached: option<object>) {
  IF record::tb($link.rid) = 'rebase_read' {
    UPSERT cost_stats:one SET pulls=(pulls??0)+1 RETURN NONE;
  };
  RETURN fn::cost::pull($link,$detached);
} PERMISSIONS NONE;
`;
    server = await start({ engine:'surrealkv' });
    const q = client(server.url), measurements = [];
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(q, sql);
    await q('CREATE cost_source:one SET owned_by=rebase_tenant:default,amount=3dec;');
    const check = async () => {
      const state = await snapshot(q);
      const expectedReads = state.readers.map(row => ({
        reader:row.id, phase:'refresh', source_root:'cost_source:one',
        kind:'record', path:'amount', fallback:'0',
      }));
      for (const row of state.readers) assert.equal(row.amount, state.sources[0].amount, row.id);
      verifyReads(state, [...state.sources,...state.readers,...state.tenants], [], () => 0, { expectedReads });
    };
    const mutate = async (statement, size, operation) => {
      await q('UPSERT cost_stats:one SET pulls=0;');
      await q(statement);
      const pulls = await q('RETURN cost_stats:one.pulls;');
      const bound = 3 * Math.ceil(Math.log2(size + 1)) + 3;
      assert(pulls <= bound, `${operation} with ${size} readers: ${pulls} pulls exceeds logarithmic allowance ${bound}`);
      return { operation, size, pulls, bound };
    };
    for (let i = 1; i <= 64; i++) {
      const id = `cost_reader:r${String(i).padStart(3,'0')}`;
      const measurement = await mutate(`CREATE ${id} SET owned_by=rebase_tenant:default,source=cost_source:one;`, i, 'insert');
      if ([1,4,8,16,32,64].includes(i)) { await check(); measurements.push(measurement); }
    }
    await q('UPSERT cost_stats:one SET pulls=0;');
    await q('UPDATE cost_source:one SET amount=5dec;');
    assert.equal(await q('RETURN cost_stats:one.pulls;'), 0, 'retained registrations need no topology repair');
    await check();
    for (let i = 32; i >= 1; i--) {
      const measurement = await mutate(`DELETE ONLY cost_reader:r${String(i).padStart(3,'0')};`, 32+i, 'delete');
      if (i === 32 || i === 1) { await check(); measurements.push(measurement); }
    }
    console.log(JSON.stringify(measurements));
    console.log('PASS bounded subscription insert/delete repair, retained-read stability and complete private trees');
  } finally {
    if (server) await server.close();
    fs.rmSync(directory, { recursive:true, force:true });
  }
}

if (require.main === module) main().catch(error => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
module.exports = { main };
