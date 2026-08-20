# SurrealDB Instance Scaling — Findings

> SurrealDB v3.2.0, in-memory mode, Node.js WebSocket RPC client  
> Tested: Namespace scaling, Database scaling, Table scaling, Hierarchical tree extraction

---

## Namespaces (up to 5,000)

| Count | Creation | `INFO FOR ROOT` avg | p50 | p95 | RSS |
|-------|----------|---------------------|-----|-----|-----|
| 50 | 8.49ms | 2.20ms | 2.03ms | 3.00ms | 90.80 MB |
| 100 | 6.51ms | 2.68ms | 2.67ms | 3.09ms | 91.21 MB |
| 250 | 16.64ms | 3.03ms | 2.78ms | 4.00ms | 92.13 MB |
| 500 | 21.96ms | 3.15ms | 3.11ms | 3.44ms | 93.54 MB |
| 1,000 | 34.26ms | 4.23ms | 4.19ms | 5.00ms | 95.04 MB |
| 2,500 | 109.12ms | 9.67ms | 9.45ms | 11.04ms | 100.99 MB |
| 5,000 | 162.48ms | 16.48ms | 15.27ms | 20.22ms | 111.88 MB |

**5,000 namespaces costs ~21 MB RAM and ~16ms to list. ~4.2 KB per namespace descriptor.**

---

## Databases in a Single Namespace (up to 5,000)

| Count | Creation | `INFO FOR NS` avg | p50 | p95 | RSS |
|-------|----------|-------------------|-----|-----|-----|
| 50 | 5.31ms | 1.45ms | 1.44ms | 1.58ms | 90.56 MB |
| 100 | 5.08ms | 1.92ms | 1.79ms | 2.75ms | 91.07 MB |
| 250 | 16.50ms | 2.88ms | 2.70ms | 3.45ms | 92.11 MB |
| 500 | 20.63ms | 2.81ms | 2.69ms | 3.24ms | 94.07 MB |
| 1,000 | 37.15ms | 4.20ms | 3.77ms | 5.89ms | 95.99 MB |
| 2,500 | 114.25ms | 8.81ms | 8.49ms | 10.04ms | 101.91 MB |
| 5,000 | 162.27ms | 17.21ms | 16.38ms | 19.46ms | 113.08 MB |

**Nearly identical scaling curve to namespaces. ~22 MB for 5,000 databases.**

---

## Tables in a Single Database (up to 5,000)

| Count | Creation | `INFO FOR DB` avg | Single INSERT | Single SELECT | RSS |
|-------|----------|-------------------|---------------|---------------|-----|
| 50 | 6.29ms | 1.37ms | 2.45ms | 1.76ms | 91.26 MB |
| 100 | 6.58ms | 1.83ms | 1.61ms | 1.61ms | 94.51 MB |
| 250 | 17.96ms | 2.69ms | 1.68ms | 1.53ms | 95.93 MB |
| 500 | 27.29ms | 3.92ms | 1.62ms | 1.37ms | 98.78 MB |
| 1,000 | 49.40ms | 5.75ms | 2.03ms | 1.57ms | 103.61 MB |
| 2,500 | 171.39ms | 13.66ms | 1.33ms | 0.99ms | 117.26 MB |
| 5,000 | 241.63ms | 27.73ms | 2.01ms | 1.84ms | 142.91 MB |

**CRUD latency is constant at ~1–2ms regardless of table count. Table catalog size does not affect data query performance.**

---

## Hierarchical Tree Extraction (NS × DB × Tables)

Three strategies tested:
1. **Sequential** — 1 RPC per node in series
2. **Concurrent** — pool of 25 parallel requests
3. **Composite** — multi-statement batching per NS (`USE NS x DB y; INFO FOR DB;`)

| Topology | Total Tables | Sequential | Concurrent (c=25) | Composite | Best Speedup |
|----------|-------------|------------|-------------------|-----------|-------------|
| 10 NS × 5 DB × 10 Tbl | 500 | 81.56ms | 24.37ms | **17.79ms** | **4.6×** |
| 50 NS × 5 DB × 10 Tbl | 2,500 | 323.37ms | 106.06ms | **67.03ms** | **4.8×** |
| 10 NS × 50 DB × 10 Tbl | 5,000 | 590.43ms | 180.00ms | **86.20ms** | **6.9×** |
| 20 NS × 20 DB × 20 Tbl | 8,000 | 426.25ms | 171.26ms | **131.40ms** | **3.2×** |

**Composite batching delivers the best extraction performance. Deep trees (many DBs per NS) benefit most — up to 6.9× faster.**

---

## Schema Complexity (500 Tables, same DB)

| Type | 500 Table Creation |
|------|--------------------|
| Schemaless | 40.63ms |
| Schemafull + 3 typed fields + 1 index | 370.85ms |

`INFO FOR DB` on 1,000 total tables: **10.76ms**  
`INFO FOR TABLE` (field/index inspection): **1.46ms**

Schemafull is ~9× slower to define than schemaless due to field type AST validation and index catalog entries.

---

## Summary

- Namespaces, databases, and tables all scale linearly with minimal memory overhead.
- CRUD operations are isolated from catalog size — completely unaffected by thousands of tables.
- For programmatic tree extraction, **composite multi-statement batching** is the most efficient strategy (4–7× faster than naive sequential).
- Practical ceiling for a single in-memory instance: comfortably handles 5,000+ namespaces, 5,000+ databases, 5,000+ tables.
