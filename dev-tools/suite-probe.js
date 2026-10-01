#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict'),
  fs = require('node:fs'),
  os = require('node:os'),
  path = require('node:path');
const { start, client, applySchema } = require('./temporal-tree/harness');
const { verify, equal } = require('./temporal-tree/oracle');
const { compileFromArgs } = require('./compiler/cli');
const root = 'rebase_group:root',
  date = (d) => new Date(Date.UTC(2026, 0, 1 + d)).toISOString();
const tables = [
  'organization',
  'operating_unit',
  'service',
  'crm_case',
  'crm_transition',
  'crm_interaction',
  'employment',
  'leave_account',
  'leave_grant',
  'leave_use',
];
const type = (r) => r.id.split(':')[0];
async function snapshot(q) {
  return q(
    `RETURN array::concat(${tables.map((t) => `(SELECT * FROM ${t})`).join(',')});`,
  );
}
function inspect(rows) {
  const get = (id) => rows.find((r) => r.id === id),
    entries = [];
  function add(row, slot, owner, root, measures, tags = {}) {
    entries.push({
      link: { rid: row.id, slot },
      owner: { rid: owner, slot: root },
      key: [row.a_effective_at, row.id, slot],
      measures,
      tags,
      spans: {},
      dependent: false,
    });
  }
  for (const row of rows) {
    const t = type(row);
    if (t.startsWith('crm_')) {
      const original = t === 'crm_case' ? row : get(row.a_case),
        open =
          t === 'crm_case'
            ? 1
            : t === 'crm_transition'
              ? Number(row.a_open_delta)
              : 0,
        effort = Number(row.a_effort_minutes || 0);
      equal(
        row.z20_ctx,
        {
          origin: original.id,
          party: original.a_organization,
          opened_at: original.a_effective_at,
          open,
          effort,
        },
        row.id,
      );
      add(row, 'z_case', original.id, 'z_history', {
        open,
        effort_minutes: effort,
      });
      add(row, 'z_party', original.a_organization, 'z_cases', {
        open_cases: open,
        effort_minutes: effort,
      });
    }
    if (t === 'leave_account' || t === 'leave_grant' || t === 'leave_use') {
      const account = t === 'leave_account' ? row : get(row.a_account),
        employment = get(account.a_employment);
      const c = {
        employment: employment.id,
        unit: employment.a_unit,
        service: account.a_service,
        start: employment.a_effective_at,
      };
      if (employment.a_until) c.until = employment.a_until;
      equal(row.z20_ctx, c, row.id);
      if (t === 'leave_account') continue;
      const use = t === 'leave_use';
      add(
        row,
        'z_allowance',
        account.id,
        'z_book',
        { quantity: (use ? -1 : 1) * Number(row.a_quantity) },
        { service: account.a_service },
      );
      add(
        row,
        'z_employment',
        employment.id,
        'z_history',
        use ? { uses: 1 } : { grants: 1 },
      );
      add(row, 'z_unit', employment.a_unit, 'z_activity', {
        hr_interactions: 1,
      });
    }
  }
  return verify(rows, rows, entries);
}
async function main() {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-suite-'));
  const built = compileFromArgs({
    projectDir: 'designs/all-in-one',
    frameworkDir: 'framework',
    outputDir: out,
  });
  const server = await start(),
    q = client(server.url);
  async function create(id, day, fields) {
    await q(
      `CREATE ${id} SET owned_by=${root},a_effective_at=d'${date(day)}',${fields};`,
    );
  }
  async function check() {
    return inspect(await snapshot(q));
  }
  async function reject(sql, re) {
    const old = await snapshot(q);
    await assert.rejects(q(sql), re);
    assert.deepEqual(await snapshot(q), old);
  }
  try {
    await q(
      'DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture;',
    );
    await applySchema(q, built.bundle);
    for (const id of ['company', 'client', 'other'])
      await q(`CREATE organization:${id} SET owned_by=${root},a_name='${id}';`);
    for (const id of ['engineering', 'support'])
      await q(
        `CREATE operating_unit:${id} SET owned_by=${root},a_name='${id}',a_organization=organization:company;`,
      );
    await q(
      `CREATE rebase_user:person SET name='Employee',parents=[${root}];CREATE service:leave SET owned_by=${root},a_name='Paid leave',a_unit='hour';`,
    );
    await create(
      'crm_case:case',
      0,
      "a_organization=organization:client,a_subject='Resolve delivery issue'",
    );
    await create(
      'crm_interaction:call',
      1,
      "a_case=crm_case:case,a_description='Customer call',a_effort_minutes=30dec",
    );
    await create(
      'crm_transition:close',
      3,
      "a_case=crm_case:case,a_open_delta=-1dec,a_reason='Resolved'",
    );
    await create(
      'crm_interaction:feedback',
      4,
      "a_case=crm_case:case,a_description='Feedback after resolution',a_effort_minutes=5dec",
    );
    await create(
      'crm_transition:reopen',
      5,
      "a_case=crm_case:case,a_open_delta=1dec,a_reason='Customer supplied new evidence'",
    );
    await create(
      'crm_transition:close_again',
      7,
      "a_case=crm_case:case,a_open_delta=-1dec,a_reason='Resolved new issue'",
    );
    await check();
    equal(
      await q('RETURN crm_case:case.z_history.summary.measures.open.sum;'),
      0,
    );
    equal(
      await q(
        'RETURN organization:client.z_cases.summary.measures.effort_minutes.sum;',
      ),
      35,
    );
    await reject(
      `CREATE crm_transition:double SET owned_by=${root},a_case=crm_case:case,a_open_delta=-1dec,a_reason='Duplicate close',a_effective_at=d'${date(8)}';`,
      /CRM_INVALID_TRANSITION/,
    );
    await reject(
      `UPDATE crm_transition:reopen SET a_effective_at=d'${date(2)}';`,
      /CRM_INVALID_TRANSITION/,
    );
    await reject(
      `UPDATE crm_case:case SET a_effective_at=d'${date(2)}';`,
      /CRM_BEFORE_CASE|CRM_INVALID_TRANSITION/,
    );
    await q('UPDATE crm_case:case SET a_organization=organization:other;');
    await check();
    equal(await q('RETURN organization:client.z_cases.summary.count;'), 0);
    equal(await q('RETURN organization:other.z_cases.summary.count;'), 6);
    await q('DELETE crm_interaction:feedback;');
    await check();
    console.log(
      'PASS CRM dated close/reopen invariants, effort history, edits/deletion and direct organization inheritance',
    );

    await create(
      'employment:person',
      0,
      "a_person=rebase_user:person,a_unit=operating_unit:engineering,a_until=d'2026-12-31T00:00:00Z'",
    );
    await q(
      `CREATE leave_account:person SET owned_by=${root},a_employment=employment:person,a_service=service:leave;`,
    );
    await create(
      'leave_grant:annual',
      1,
      "a_account=leave_account:person,a_quantity=80dec,a_reason='Annual allowance'",
    );
    await create(
      'leave_use:holiday',
      3,
      "a_account=leave_account:person,a_quantity=16dec,a_reason='Approved holiday'",
    );
    await create(
      'leave_grant:extra',
      5,
      "a_account=leave_account:person,a_quantity=8dec,a_reason='Additional allowance'",
    );
    await create(
      'leave_use:appointment',
      7,
      "a_account=leave_account:person,a_quantity=4dec,a_reason='Approved appointment'",
    );
    await check();
    equal(
      await q(
        'RETURN leave_account:person.z_book.summary.measures.quantity.sum;',
      ),
      68,
    );
    await reject(
      `CREATE leave_use:early SET owned_by=${root},a_account=leave_account:person,a_quantity=1dec,a_reason='Before grant',a_effective_at=d'${date(0)}';`,
      /HRM_INSUFFICIENT_ALLOWANCE/,
    );
    await reject(
      'UPDATE leave_grant:annual SET a_quantity=10dec;',
      /HRM_INSUFFICIENT_ALLOWANCE/,
    );
    await reject(
      `UPDATE employment:person SET a_until=d'${date(6)}';`,
      /HRM_OUTSIDE_EMPLOYMENT/,
    );
    await reject(
      `CREATE leave_account:duplicate SET owned_by=${root},a_employment=employment:person,a_service=service:leave;`,
      /unique|index|already contains/i,
    );
    await q('UPDATE employment:person SET a_unit=operating_unit:support;');
    await check();
    equal(
      await q('RETURN operating_unit:engineering.z_activity.summary.count;'),
      0,
    );
    equal(
      await q('RETURN operating_unit:support.z_activity.summary.count;'),
      4,
    );
    await reject('DELETE leave_grant:annual;', /HRM_INSUFFICIENT_ALLOWANCE/);
    await q('UPDATE leave_use:holiday SET a_quantity=12dec;');
    await check();
    await q('DELETE leave_use:appointment;');
    await check();
    equal(
      await q(
        'RETURN leave_account:person.z_book.summary.measures.quantity.sum;',
      ),
      76,
    );
    const before = await snapshot(q);
    await q('UPDATE employment:person SET system_ping=time::now();');
    assert.equal(
      (await snapshot(q)).find((r) => r.id === 'employment:person').updated_at,
      before.find((r) => r.id === 'employment:person').updated_at,
    );
    await check();
    console.log(
      'PASS HRM service allowances, historical capacity, employment bounds, reassignment, corrections, deletion rollback and timestamps',
    );
    const old = await snapshot(q);
    await applySchema(q, built.bundle);
    assert.deepEqual(await snapshot(q), old);
    await check();
    console.log('PASS populated CRM/HRM schema reapplication');
  } finally {
    await server.close();
    fs.rmSync(out, { recursive: true, force: true });
  }
}
if (require.main === module)
  main().catch((e) => {
    console.error(e);
    process.exitCode = 1;
  });
module.exports = { main };
