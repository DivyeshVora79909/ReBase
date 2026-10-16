#!/usr/bin/env node
"use strict";

const path = require("node:path");
const assert = require("node:assert/strict");
const { plan, createModel, withSolver } = require("..");
const { recordId } = require("../model");

// Money crosses the solver boundary as integer cents and the database boundary
// as decimal strings. Neither allocation nor verification uses binary floats.
function money(cents) {
  cents = BigInt(cents);
  const sign = cents < 0n ? "-" : "";
  const amount = cents < 0n ? -cents : cents;
  return `${sign}${amount / 100n}.${String(amount % 100n).padStart(2, "0")}`;
}

async function allocation({ balanceCents, reserveCents, count, feeCents, feeBasisPoints }) {
  return withSolver(async ({ Int, solver, solve }) => {
    const withdrawals = Array.from({ length: count }, (_, index) => Int.const(`withdrawal_${index}`));
    const fees = withdrawals.map((_, index) => Int.const(`fee_${index}`));
    for (let index = 0; index < count; index++) {
      solver.add(withdrawals[index].ge(100),
        fees[index].eq(withdrawals[index].mul(feeBasisPoints).div(10000).add(feeCents)));
      if (index) solver.add(withdrawals[index].ge(withdrawals[index - 1]));
    }
    const total = withdrawals.reduce((sum, value, index) => sum.add(value).add(fees[index]), Int.val(0));
    solver.add(total.eq(balanceCents - reserveCents));
    const solution = await solve();
    return withdrawals.map((value, index) => ({
      withdrawal: solution.eval(value).value(), fee: solution.eval(fees[index]).value(),
    }));
  });
}

/**
 * A small reusable all-in-accounting scenario. The caller supplies the compiled
 * model and an explicitly provisioned tenant; this function opens no connection.
 * Pass space: async transaction => ({ tenants: [...] }) to read existing input
 * in the same transaction as population, or omit it for an offline preview.
 */
function accountingOptions({ model, tenant, seed = "accounting-demo", balanceCents = 10000n,
  reserveCents = 1000n, count = 4, feeCents = 25n, feeBasisPoints = 100n, space } = {}) {
  const owner = String(recordId(tenant));
  if (recordId(owner).table.name !== "rebase_tenant") throw new Error("accountingOptions requires an explicit rebase_tenant id");
  const cents = { balanceCents, reserveCents, feeCents, feeBasisPoints };
  for (const [key, value] of Object.entries(cents)) {
    if (!(typeof value === "bigint" || typeof value === "string" && /^\d+$/.test(value)
      || Number.isSafeInteger(value)) || BigInt(value) < 0n) throw new Error(`${key} must be nonnegative integer cents (or basis points)`);
    cents[key] = BigInt(value);
  }
  if (!Number.isSafeInteger(count) || count < 1 || count > 50) throw new Error("count must be an integer from 1 to 50");
  if (!cents.balanceCents || !cents.feeCents) throw new Error("balanceCents and feeCents must be positive");
  const at = seconds => new Date(Date.UTC(2027, 0, 1, 0, 0, seconds)).toISOString();
  return {
    model, seed, space: space ?? { tenants: [{ id: owner }] },
    recipe: async ({ space: inputs, faker }) => {
      if (!Array.isArray(inputs.tenants) || inputs.tenants.length !== 1 || inputs.tenants[0].id !== owner) {
        throw new Error("Provide exactly the selected tenant in space.tenants");
      }
      const amounts = await allocation({ ...cents, count });
      const owned = { owned_by: "tenants" };
      const entries = (kind, after, amount) => ({
        name: kind, table: "account_entry", count, after,
        refs: { ...owned, account: "cash" },
        values: ({ index }) => ({ description: `${kind} ${index + 1}`,
          real: money(-amount(amounts[index])), receivable: "0", payable: "0",
          effective_at: at(2 + index * 2 + (kind === "fees" ? 1 : 0)) }),
      });
      // Written out of dependency order deliberately: refs and after express
      // the prerequisites. Funding is inserted before every withdrawal or fee.
      return [
        entries("withdrawals", ["funding"], row => row.withdrawal),
        entries("fees", ["withdrawals"], row => row.fee),
        { name: "funding", table: "account_entry", refs: { ...owned, account: "cash" },
          values: { real: money(cents.balanceCents), receivable: "0", payable: "0",
            description: "Opening funding", effective_at: at(1) } },
        { name: "cash", table: "treasury", refs: { ...owned, subsidiary: "business", currency: "currencies" },
          values: { name: "Fixture cash", minimum_real: "0.00", effective_at: at(0) } },
        { name: "business", table: "subsidiary", refs: { ...owned, currency: "currencies" },
          values: { name: faker.company.name(), effective_at: at(0) } },
        { name: "currencies", table: "currency", refs: owned,
          values: { code: faker.string.alpha({ length: 12, casing: "upper" }), name: "Fixture dollar", precision: 2 } },
      ];
    },
    assert: ({ rows, space: planned }) => {
      const postings = rows.filter(row => row.table === "account_entry");
      assert.equal(postings[0].content.description, "Opening funding");
      assert.equal(planned.funding[0].real, money(cents.balanceCents));
      let balance = cents.balanceCents;
      for (const row of [...planned.withdrawals, ...planned.fees].sort((a, b) => a.effective_at.localeCompare(b.effective_at))) {
        const match = /^-(\d+)\.(\d{2})$/.exec(row.real);
        balance -= BigInt(match[1]) * 100n + BigInt(match[2]);
        assert(balance >= 0n, "funding covers every chronological prefix");
      }
      assert.equal(balance, cents.reserveCents, "allocation leaves the requested exact reserve");
    },
  };
}

async function preview() {
  const { compile } = require("../../accounting/acceptance");
  const { loadClientSchemas } = require("../../client-schemas");
  const built = compile();
  const model = createModel({ schema: built.bundle,
    schemas: loadClientSchemas(path.resolve(__dirname, "../../../designs/all-in-accounting/schemas")) });
  const result = await plan(accountingOptions({ model, tenant: "rebase_tenant:preview" }));
  console.log(JSON.stringify({ seed: result.seed, rows: result.rows.map(row => ({
    table: row.table, id: String(row.id), content: row.content,
  })) }, null, 2));
  return result;
}

if (require.main === module) preview().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { accountingOptions, money, preview };
