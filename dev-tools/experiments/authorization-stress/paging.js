"use strict";

const assert = require("node:assert/strict");

// The benchmark uses int order keys and canonical, padded record IDs. Do not
// apply this comparator to arbitrary SDK Decimal/datetime/record business keys.
function compareKeys(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return a.length - b.length;
}

function makeHeap(reverse) {
  const heap = [];
  const less = (a, b) => (reverse ? -1 : 1) * compareKeys(a.item.key, b.item.key) < 0;
  const push = entry => {
    heap.push(entry);
    let index = heap.length - 1;
    while (index) {
      const parent = (index - 1) >> 1;
      if (!less(heap[index], heap[parent])) break;
      [heap[index], heap[parent]] = [heap[parent], heap[index]];
      index = parent;
    }
  };
  const pop = () => {
    const top = heap[0], last = heap.pop();
    if (heap.length) {
      heap[0] = last;
      let index = 0;
      for (;;) {
        let child = index * 2 + 1;
        if (child >= heap.length) break;
        if (child + 1 < heap.length && less(heap[child + 1], heap[child])) child++;
        if (!less(heap[child], heap[index])) break;
        [heap[index], heap[child]] = [heap[child], heap[index]];
        index = child;
      }
    }
    return top;
  };
  return { push, pop, get size() { return heap.length; } };
}

function mergePages(pages, limit, reverse = false) {
  const heap = makeHeap(reverse), consumed = new Array(pages.length).fill(0), items = [];
  pages.forEach((page, stream) => { if (page.items.length) heap.push({ stream, item: page.items[0] }); });
  const seen = new Set();
  while (heap.size && items.length < limit) {
    const { stream, item } = heap.pop();
    // These workload roots partition ownership: duplicates are a fixture bug,
    // not a reason to silently change the measured authorization semantics.
    assert(!seen.has(String(item.link.rid)), "candidate roots must be disjoint");
    seen.add(String(item.link.rid)); items.push(item);
    const next = pages[stream].items[++consumed[stream]];
    if (next) heap.push({ stream, item: next });
  }
  const more = heap.size > 0 || pages.some(page => page.next != null);
  return { items, next: more && items.length ? items.at(-1).key : null,
    candidates: pages.reduce((sum, page) => sum + page.items.length, 0),
    revisions: pages.map(page => page.revision) };
}

async function readPage(db, owners, slot, { limit = 50, after = null, reverse = false, strategy = "balanced", fanout = 1 } = {}) {
  assert(Number.isSafeInteger(fanout) && fanout >= 1 && fanout <= 8, "fanout must be 1..8");
  if (!owners.length) return { rows: [], items: [], next: null, candidates: 0, revisions: [], requests: 0 };
  const chunk = strategy === "full" ? limit : Math.min(200, Math.ceil(limit / owners.length) + 1);
  const width = Math.ceil(owners.length / fanout), groups = [];
  for (let index = 0; index < owners.length; index += width) groups.push(owners.slice(index, index + width));
  const pages = (await Promise.all(groups.map(async group => (await db.query(`RETURN $owners.map(|$owner|
    fn::tree::read($owner,$slot,'page',[$limit,IF $after = NULL THEN NONE ELSE $after END,$reverse]));`,
  { owners: group, slot, limit: chunk, after, reverse }))[0]))).flat();
  let merged, requests = groups.length;
  if (strategy === "full") merged = mergePages(pages, limit, reverse);
  else {
    const heap = makeHeap(reverse), positions = pages.map(() => 0), items = [];
    let candidates = pages.reduce((sum, page) => sum + page.items.length, 0), revisionChanged = false;
    const revisions = pages.map(page => page.revision);
    pages.forEach((page, stream) => { if (page.items.length) heap.push({ stream, item: page.items[0] }); });
    while (heap.size && items.length < limit) {
      const { stream, item } = heap.pop();
      items.push(item); positions[stream]++;
      if (items.length === limit) break;
      if (positions[stream] === pages[stream].items.length && pages[stream].next != null) {
        const [page] = await db.query("RETURN fn::tree::read($owner,$slot,'page',[$limit,$after,$reverse]);",
          { owner: owners[stream], slot, limit: chunk, after: item.key, reverse });
        requests++; candidates += page.items.length;
        revisionChanged ||= page.revision !== revisions[stream]; pages[stream] = page; positions[stream] = 0;
      }
      const next = pages[stream].items[positions[stream]];
      if (next) heap.push({ stream, item: next });
    }
    const more = pages.some((page, stream) => positions[stream] < page.items.length || page.next != null);
    merged = { items, next: more && items.length ? items.at(-1).key : null, candidates, revisions, revisionChanged };
  }
  assert.equal(new Set(merged.items.map(item => String(item.link.rid))).size, merged.items.length, "disjoint roots yield distinct IDs");
  const ids = merged.items.map(item => item.link.rid);
  const [rows] = ids.length ? await db.query(`SELECT id, seq, rank, status, owned_by, read_by
    FROM $ids ORDER BY rank ${reverse ? "DESC" : "ASC"}, id ${reverse ? "DESC" : "ASC"};`, { ids }) : [[]];
  assert.equal(rows.length, ids.length, "native hydration must authorize every returned candidate");
  assert.deepEqual(rows.map(row => String(row.id)), ids.map(String), "merge/hydration preserve the same full order");
  return { ...merged, rows, requests: requests + Number(ids.length > 0) };
}

// A global last-emitted key is valid in every disjoint stream with this same
// ordering. Re-seeking each root after it avoids dropping prefetched items.
// Revisions are reported; multiple requests do not provide snapshot isolation.
async function filterPage(db, owners, slot, { limit = 10, predicate, maxVisited = 2000, after = null } = {}) {
  const rows = [], revisions = [], requested = new Set();
  let visited = 0, candidates = 0, requests = 0, next = after, done = false;
  while (!done && rows.length < limit && visited < maxVisited) {
    const page = await readPage(db, owners, slot, { limit: Math.min(100, maxVisited - visited), after: next });
    requests += page.requests; candidates += page.candidates; revisions.push(page.revisions);
    for (let i = 0; i < page.rows.length; i++) {
      const row = page.rows[i];
      assert(!requested.has(String(row.id)), "post-filter continuation must not revisit a row");
      requested.add(String(row.id)); visited++;
      next = page.items[i].key;
      if (predicate(row)) rows.push(row);
      if (rows.length === limit) break;
    }
    done = page.next == null && rows.length < limit;
    if (!page.rows.length) done = true;
  }
  return { rows, visited, candidates, requests, revisions, truncated: !done && rows.length < limit,
    next: done ? null : next };
}

module.exports = { compareKeys, mergePages, readPage, filterPage };
