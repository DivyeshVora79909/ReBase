"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { compareKeys, readPage, mergePages, filterPage } = require("../experiments/authorization-stress/paging");

// Independent sorted-array server model. The client under test must merge its
// bounded pages without losing rows that it fetched but has not emitted yet.
function server(distribution) {
  const rows = distribution.flatMap((seqs, owner) => seqs.map(seq => ({ id: `fact:r${String(seq).padStart(8, "0")}`,
    seq, rank: Math.floor(seq / 3), owned_by: `owner:${owner}`, read_by: `owner:${owner}`, status: seq % 7 ? "cold" : "hot" })));
  const key = row => [row.rank, row.id, "z0"];
  return { rows, owners: distribution.map((_, index) => `owner:${index}`), async query(sql, args) {
    const page = owner => {
      const ordered = rows.filter(row => row.owned_by === owner).sort((a, b) => compareKeys(key(a), key(b)) * (args.reverse ? -1 : 1))
        .filter(row => args.after == null || (args.reverse ? compareKeys(key(row), args.after) < 0 : compareKeys(key(row), args.after) > 0));
      const items = ordered.slice(0, args.limit).map(row => ({ link: { rid: row.id, slot: "z0" }, key: key(row) }));
      return { items, revision: 5, next: ordered.length > args.limit ? items.at(-1).key : null };
    };
    if (sql.startsWith("SELECT")) return [rows.filter(row => args.ids.includes(row.id)).sort((a, b) => compareKeys(key(a), key(b)) * (/DESC/.test(sql) ? -1 : 1))];
    return [args.owners ? args.owners.map(page) : page(args.owner)];
  } };
}

for (const [name, distribution] of [
  ["interleaved", [[0, 3, 6, 9, 12, 15], [1, 4, 7, 10, 13, 16], [2, 5, 8, 11, 14, 17], []]],
  ["skewed", [Array.from({ length: 45 }, (_, i) => i), [45], [46], []]],
]) for (const reverse of [false, true]) {
  test(`authorization heap pages preserve all ${name} ties and prefetched rows, reverse=${reverse}`, async () => {
    const db = server(distribution);
    const expected = db.rows.map(row => row.seq).sort((a, b) => reverse ? b - a : a - b);
    for (const strategy of ["balanced", "full"]) for (const limit of [1, 7, 50]) for (const fanout of [1, 4]) {
      const all = [];
      let after = null, pages = 0;
      do {
        const page = await readPage(db, db.owners, "z0", { limit, after, reverse, strategy, fanout });
        all.push(...page.rows.map(row => row.seq)); after = page.next;
        assert(++pages <= expected.length + 1, "cursors must advance");
      } while (after);
      assert.deepEqual(all, expected, `${strategy}/${limit}`);
    }
  });
}

test("post-filter cap reports incompleteness and preserves a usable continuation", async () => {
  const db = server([Array.from({ length: 100 }, (_, i) => i)]);
  const first = await filterPage(db, db.owners, "z0", { limit: 5, maxVisited: 10, predicate: row => row.status === "hot" });
  assert.equal(first.truncated, true);
  assert.deepEqual(first.rows.map(row => row.seq), [0, 7]);
  const next = await filterPage(db, db.owners, "z0", { limit: 3, maxVisited: 50, after: first.next, predicate: row => row.status === "hot" });
  assert.deepEqual(next.rows.map(row => row.seq), [14, 21, 28]);
});

test("ownership-partition merge rejects overlapping roots", () => {
  const entry = { link: { rid: "fact:duplicate", slot: "z0" }, key: [0, "fact:duplicate", "z0"] };
  assert.throws(() => mergePages([{ items: [entry] }, { items: [entry] }], 2), /disjoint/);
});
