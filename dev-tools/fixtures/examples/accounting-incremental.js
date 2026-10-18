"use strict";

const { recordId } = require("../model");
const { cents, money } = require("./accounting");

/**
 * Withdraw from explicitly selected, funded treasuries in their reporting
 * currency. Values use current account and subsidiary summaries. This example
 * does not translate arbitrary accounting validators into generation rules.
 */
function withdrawalOptions({ model, tenant, accounts, seed = "withdrawals", count = 10,
  maxCents = 100n, reserveCents = 0n, startAt = "2027-01-02T00:00:00.000Z" } = {}) {
  const owner = recordId(tenant);
  if (owner.table.name !== "rebase_tenant") throw new Error("withdrawalOptions needs an explicit tenant");
  if (!Array.isArray(accounts) || !accounts.length) throw new Error("Provide the treasury IDs to use");
  const ids = [...new Map(accounts.map(value => {
    const id = recordId(value);
    if (id.table.name !== "treasury") throw new Error("This example uses treasury accounts");
    return [String(id), id];
  })).values()];
  for (const [name, value] of Object.entries({ maxCents, reserveCents })) {
    if (!(typeof value === "bigint" || Number.isSafeInteger(value) || typeof value === "string" && /^\d+$/.test(value)) || BigInt(value) < 0n) {
      throw new Error(`${name} must be nonnegative integer cents`);
    }
  }
  maxCents = BigInt(maxCents); reserveCents = BigInt(reserveCents);
  if (maxCents < 1n) throw new Error("maxCents must be positive");
  const start = new Date(startAt).getTime();
  if (!Number.isSafeInteger(count) || count < 0 || !Number.isFinite(start)
    || !Number.isFinite(new Date(start + count * 1000).getTime())) throw new Error("Invalid count or chronological startAt");

  return {
    model, seed, counts: { account_entry: count },
    space: async transaction => {
      const [owners, cash] = await transaction.query(`
        SELECT * FROM $owner;
        SELECT *, currency.precision AS fixture_precision,
          subsidiary.currency AS fixture_currency,
          subsidiary.effective_at AS fixture_since,
          subsidiary.z_history.summary.last[0] AS fixture_last FROM $accounts;
      `, { owner, accounts: ids });
      if (owners.length !== 1 || cash.length !== ids.length) throw new Error("Selected tenant or treasuries do not exist");
      for (const account of cash) {
        if (String(account.owned_by) !== String(owner)) throw new Error("Every selected treasury must belong to the selected tenant");
        if (account.fixture_precision !== 2 || String(account.resource) !== String(account.fixture_currency)) {
          throw new Error("This example needs two-decimal treasuries in their subsidiary's reporting currency");
        }
        for (const boundary of [account.effective_at, account.fixture_since, account.fixture_last, account.z_history?.summary?.last?.[0]]) {
          if (boundary && start <= new Date(String(boundary)).getTime()) throw new Error("startAt must follow all selected account and subsidiary history");
        }
      }
      return [...owners, ...cash];
    },
    rules: { account_entry: {
      refs: { owned_by: {}, account: { skew: -1 } },
      values: async ({ parents, transaction, faker, sequence }) => {
        const account = parents.account;
        const [business] = await transaction.query("SELECT * FROM ONLY $id;", { id: recordId(account.subsidiary) });
        const measures = account.z_history.summary.measures;
        const capacity = [maxCents, cents(measures.real.sum) - reserveCents];
        for (const [measure, field] of [["real", "minimum_real"], ["available", "minimum_available"], ["net", "net_floor"]]) {
          if (account[field] !== undefined) capacity.push(cents(measures[measure].sum) - cents(account[field]));
        }
        if (business.net_floor !== undefined) capacity.push(cents(business.z_history.summary.measures.net.sum) - cents(business.net_floor));
        const available = capacity.reduce((left, right) => left < right ? left : right);
        if (available < 1n) return null;
        return {
          real: money(-faker.number.bigInt({ min: 1n, max: available })), receivable: "0", payable: "0",
          effective_at: new Date(start + sequence * 1000).toISOString(), description: `Generated withdrawal ${sequence + 1}`,
        };
      },
    } },
  };
}

module.exports = { withdrawalOptions };
