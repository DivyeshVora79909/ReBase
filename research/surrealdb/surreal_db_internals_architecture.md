# SurrealDB Engine Architecture & Internals: Comprehensive Reference Guide

**Engine Version**: SurrealDB 3.3.0-nightly  
**Git Commit**: `c7eac9022af90d2d9658a94e2dc51d45d9c6ff5b`  
**Scope**: Verified source code facts derived exclusively from the SurrealDB repository (`surrealdb/core/src/`).  
**Purpose**: Authoritative reference for database internals, storage formats, operator implementations, and planner mechanics.

---

## 1. Architectural Overview & System Decomposition

SurrealDB decomposes query processing into distinct decoupled subsystems:

```text
                                 SurrealQL Query String
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. Parser Subsystem (`surrealdb/core/src/syn/`)                                          │
│    - Parses tokens into Abstract Syntax Tree (AST) representations                      │
│    - AST Root: `crate::expr::statements::Statement` (e.g. `SelectStatement`)           │
│    - Expressions: `crate::expr::Expr`, `crate::expr::Idiom`, `crate::expr::Part`        │
└──────────────────────────────────────────┬──────────────────────────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ 2. Query Planner (`surrealdb/core/src/exec/planner/`)                                   │
│    - `Planner::with_txn`: Plan-time catalog access & physical operator generation       │
│    - `Planner::new`: Deferred plan generation (emits `DynamicScan`)                     │
│    - `resolve_access_path`: Rule-based heuristics for index & table scan selection      │
│    - Sort elimination via `OutputOrdering` and Limit/Offset pushdown                    │
└──────────────────────────────────────────┬──────────────────────────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ 3. Physical Execution Operators (`surrealdb/core/src/exec/operators/`)                 │
│    - Scan Operators: `TableScan`, `IndexScan`, `ReferenceScan`, `RecordIdScan`, etc.    │
│    - Pipeline Operators: `Filter`, `SelectProject`, `SortByKey`, `ExternalSort`, `Limit`│
│    - Batch Processing: `filter_and_process_batch` in `scan/pipeline.rs`                 │
└──────────────────────────────────────────┬──────────────────────────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ 4. Transaction & Storage Abstraction Layer (`surrealdb/core/src/kvs/`)                  │
│    - `Transaction`: Coordinates mutations, query cache, and index-build reservations    │
│    - `Transactor`: Manages low-level transactions across storage engines                │
│    - `CachePolicy`: `ReadWrite` (point lookups/graph) vs `ReadOnly` (large scans)       │
└──────────────────────────────────────────┬──────────────────────────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ 5. Physical Key Encodings & Storage Engines (`surrealdb/core/src/key/`)                 │
│    - Universal Prefix: `/*` (`0x2F 0x2A`), Big-endian integer sorting                  │
│    - Backends: RocksDB (C++ FFI), SurrealKV (Rust LSM/B+Tree), Memory, TiKV             │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Physical Key Encodings: Complete Keyspace Catalog

Source authority: `surrealdb/core/src/key/category.rs` and submodules in `surrealdb/core/src/key/`.

All physical keys begin with ASCII `/*` (`0x2F 0x2A`) to scope keys to the database subsystem, followed by big-endian identifiers.

### 2.1 Complete Category Prefix Table (`surrealdb/core/src/key/category.rs:12-219`)

| Category Name      | Source File        | Binary Pattern / Byte Layout                                              | Value Payload      | Description                             |
| :----------------- | :----------------- | :------------------------------------------------------------------------ | :----------------- | :-------------------------------------- |
| `StorageVersion`   | `key/version/`     | `/sv`                                                                     | Version bytes      | Datastore schema version                |
| `Root`             | `key/root/`        | `/`                                                                       | Metadata           | Global root partition                   |
| `Access`           | `key/root/access/` | `/!ac{ac}`                                                                | AccessDef          | Root access definition                  |
| `AccessGrant`      | `key/root/access/` | `/*{ac}!gr{gr}`                                                           | GrantDef           | Root access grant                       |
| `Node`             | `key/node/`        | `/!nd{nd}`                                                                | NodeDef            | Cluster node registration               |
| `Namespace`        | `key/root/`        | `/!ns{ns}`                                                                | NamespaceDef       | Namespace definition by ID              |
| `User`             | `key/root/`        | `/!us{us}`                                                                | UserDef            | Root-level user credential              |
| `DatabaseAlias`    | `key/namespace/`   | `/*{ns}!db{db}`                                                           | DatabaseDef        | Database name-to-ID mapping             |
| `NamespaceAccess`  | `key/namespace/`   | `/*{ns}!ac{ac}`                                                           | AccessDef          | Namespace access definition             |
| `NamespaceUser`    | `key/namespace/`   | `/*{ns}!us{us}`                                                           | UserDef            | Namespace-level user                    |
| `DatabaseRoot`     | `key/database/`    | `/*{ns}*{db}`                                                             | Empty              | Database partition prefix               |
| `DatabaseAccess`   | `key/database/`    | `/*{ns}*{db}!ac{ac}`                                                      | AccessDef          | Database access definition              |
| `DatabaseAnalyzer` | `key/database/`    | `/*{ns}*{db}!az{az}`                                                      | AnalyzerDef        | Full-text analyzer configuration        |
| `DatabaseFunction` | `key/database/`    | `/*{ns}*{db}!fn{fc}`                                                      | FunctionDef        | Custom user-defined function            |
| `DatabaseModel`    | `key/database/`    | `/*{ns}*{db}!ml{ml}{vn}`                                                  | ModelDef           | Machine learning model weights          |
| `DatabaseTable`    | `key/database/`    | `/*{ns}*{db}!tb{tb}`                                                      | TableDef           | Table schema definition                 |
| `DatabaseSequence` | `key/database/`    | `/*{ns}*{db}*sq{sq}`                                                      | SequenceDef        | Auto-incrementing sequence definition   |
| `TableRoot`        | `key/table/`       | `/*{ns}*{db}*{tb}`                                                        | Empty              | Table partition prefix boundary         |
| `TableEvent`       | `key/table/`       | `/*{ns}*{db}*{tb}!ev{ev}`                                                 | EventDef           | Table-level event trigger definition    |
| `TableField`       | `key/table/`       | `/*{ns}*{db}*{tb}!fd{fd}`                                                 | FieldDef           | Table field schema definition           |
| `TableView`        | `key/table/`       | `/*{ns}*{db}*{tb}!ft{ft}`                                                 | ViewDef            | Materialized table view definition      |
| `IndexDefinition`  | `key/table/`       | `/*{ns}*{db}*{tb}!ix{ix}`                                                 | IndexDef           | Secondary index catalog definition      |
| `Record`           | `key/record.rs`    | `/*{ns}*{db}*{tb}\0*{id}`                                                 | Revision bytes     | Primary document payload & revisions    |
| `Index` (B-Tree)   | `key/index/mod.rs` | `/*{ns}*{db}*{tb}+{ix}*{val}*{id}`                                        | RecordId (11-16 B) | Secondary B-Tree index entry            |
| `IndexRoot`        | `key/index/mod.rs` | `/*{ns}*{db}*{tb}+{ix}`                                                   | Empty              | Prefix for all keys of a specific index |
| `Ref`              | `key/ref/mod.rs`   | `/*{ns}*{db}*{tgt}&{id}{from_tb}\0{field}\0{src_id}`                      | `()` (0 B)         | Materialized reverse reference link     |
| `Graph` (Edge)     | `key/graph/mod.rs` | `/*{ns}*{db}*{edge_tb}*{edge_id}`                                         | Edge Document      | Graph edge record document              |
| `GraphIn` (`etl`)  | `key/graph/mod.rs` | `/*{ns}*{db}*{edge_tb}~{edge_id}\x01{in_tb}\0{in_id}\0`                   | `()` (0 B)         | Edge inner backward backlink            |
| `GraphOut` (`etr`) | `key/graph/mod.rs` | `/*{ns}*{db}*{edge_tb}~{edge_id}\x00{out_tb}\0{out_id}\0`                 | `()` (0 B)         | Edge inner forward backlink             |
| `GraphLTR` (`ltr`) | `key/graph/mod.rs` | `/*{ns}*{db}*{in_tb}~{in_id}\0{edge_tb}\0{edge_id}\0{out_tb}\0{out_id}\0` | `()` (0 B)         | Origin vertex forward adjacency index   |
| `GraphRTL` (`rtl`) | `key/graph/mod.rs` | `/*{ns}*{db}*{out_tb}~{out_id}\0{edge_tb}\0{edge_id}\0{in_tb}\0{in_id}\0` | `()` (0 B)         | Target vertex reverse adjacency index   |
| `ChangeFeed`       | `key/change/`      | `/*{ns}*{db}#{ts}`                                                        | ChangeLog          | Table live changefeed stream            |
| `LiveQueryEvent`   | `key/lqe/`         | `/*{ns}*{db}%{ts}`                                                        | Event bytes        | Live query notification queue           |
| `SequenceState`    | `key/sequence/`    | `/*{ns}*{db}!sq{sq}!st{nid}`                                              | State bytes        | Node-local sequence state               |
| `SequenceBatch`    | `key/sequence/`    | `/*{ns}*{db}!sq{sq}!ba{start}`                                            | Batch bytes        | Distributed sequence allocation chunk   |

### 2.2 Vector & FullText Index Key Formats (`surrealdb/core/src/key/category.rs:134-179`)

- **HNSW Vector Index**:
  - Elements: `/*{ns}*{db}*{tb}+{ix}!he{id}`
  - Document IDs: `/*{ns}*{db}*{tb}+{ix}!hd{id}`
  - Things: `/*{ns}*{db}*{tb}+{ix}!hi{id}`
  - Raw Vectors: `/*{ns}*{db}*{tb}+{ix}!hv{vec}`
  - Hashed Vectors: `/*{ns}*{db}*{tb}+{ix}!hh{hash}`
- **FullText Search Index**:
  - Term Document List: `/*{ns}*{db}*{tb}+{ix}!bc{id}`
  - B-Tree Node: `/*{ns}*{db}*{tb}+{ix}!bd{id}`
  - Term Frequency: `/*{ns}*{db}*{tb}+{ix}!bf{id}`
  - Document Keys: `/*{ns}*{db}*{tb}+{ix}!bi{id}`
  - Terms: `/*{ns}*{db}*{tb}+{ix}!bu{id}`
  - Document Count & Length: `/*{ns}*{db}*{tb}+{ix}!dc{id}`
  - Term-Document Mapping: `/*{ns}*{db}*{tb}+{ix}!td{term}{id}`

---

## 3. Storage Transaction Architecture (`surrealdb/core/src/kvs/`)

### 3.1 The `Transaction` Struct (`surrealdb/core/src/kvs/tx.rs:94-165`)

The `Transaction` struct coordinates all storage operations, caching, and catalog metadata providers:

- `local: bool`: Distinguishes local embedded stores (RocksDB, Memory) from distributed engines (TiKV).
- `started_at: Instant`: Transaction start wall-clock time.
- `tr: Transactor`: Low-level abstraction managing concrete engine transactions.
- `cache: TransactionCache`: In-memory per-transaction cache for hydrated records.
- `metrics: TransactionMetrics`: Tracks KV operations (`get`, `set`, `scan`, bytes transferred).
- `changefeed: OnceLock<Changefeed>`: Buffers table changefeed mutations until commit.
- `live_events: OnceLock<LiveEventBuffer>`: Staged live query notifications.

### 3.2 Cache Policies (`surrealdb/core/src/kvs/tx.rs:85-92`)

SurrealDB prevents sequential scans from exhausting memory via dual caching semantics:

```rust
pub(crate) enum CachePolicy {
    /// Check cache on read AND populate on miss.
    /// Used for point lookups, graph traversals, KNN, and unique-index equality.
    ReadWrite,
    /// Check cache on read but SKIP population on miss.
    /// Used for index range scans, non-unique equality scans, and full-text scans.
    ReadOnly,
}
```

### 3.3 Storage Engines Supported

1. **RocksDB (`kvs/rocksdb/`)**: Embedded C++ engine accessed via `surrealdb-librocksdb-sys`. High-performance local NVMe storage using LSM trees.
2. **SurrealKV (`kvs/surrealkv/`)**: Native Rust LSM/B+Tree storage engine.
3. **Memory (`kvs/mem/`)**: In-memory transactional engine using concurrent DashMaps and SkipLists.
4. **TiKV (`kvs/tikv/`)**: Distributed ACID transactional KV engine using Raft consensus.

---

## 4. Execution Operators: Complete Inventory

Physical operators implement `ExecOperator` (`surrealdb/core/src/exec/operators/`).

### 4.1 Scan Operators (`surrealdb/core/src/exec/operators/scan/`)

#### 1. `TableScan` (`scan/table.rs`)

- **Execution Mechanism**: Iterates the key range `/*{ns}*{db}*{tb}\0` to `/*{ns}*{db}*{tb}\0\xFF`.
- **Pre-Decode Filtering**: Evaluates predicates against raw CBOR/Strand bytes prior to full document deserialization.
- **TopK Integration**: Accepts `TopKPushdownRequest`. Discards rows whose sort keys are inferior to the current bounded heap's threshold before deserializing the document payload.

#### 2. `IndexScan` (`scan/index.rs`)

- **Execution Mechanism**: Seeks B-Tree secondary index key ranges.
- **Scanning Directions**:
  - `Direction::Forward`: Ascending scan.
  - `Direction::Backward`: Descending scan. Enables sort elimination when `ORDER BY col DESC` matches index order.
- **Covering vs Non-Covering**:
  - Covering: All needed fields exist in index keys; emits documents without reading primary `RecordKey`.
  - Non-Covering: Reads `RecordId` from index entry, issues point lookups to hydrate primary record payloads.

#### 3. `RecordIdScan` (`scan/record_id.rs`)

- **Execution Mechanism**: Direct point lookup on a known `RecordKey`. Bypasses index evaluation and range scans entirely.

#### 4. `ReferenceScan` (`scan/reference.rs`)

- **Execution Mechanism**:
  - Accepts an input operator emitting target `RecordId`s (e.g. `SourceExpr`).
  - For each target ID, computes the prefix: `/*{ns}*{db}*{target_tb}&{target_id}{from_tb}\0{from_field}\0`.
  - Executes a prefix range seek in the `Ref` keyspace.
  - Decodes `from_id` from the key suffix: `&key[prefix.len()..]`.
- **Output Modes**:
  - `ReferenceScanOutput::RecordId`: Emits referencing IDs only.
  - `ReferenceScanOutput::FullRecord`: Hydrates the referencing record documents from storage.

#### 5. `GraphEdgeScan` & `GraphKeys` (`scan/graph.rs`, `scan/graph_keys.rs`)

- **Execution Mechanism**: Scans `ltr` or `rtl` adjacency pointer keys.
- **Optimization (`GraphWithTarget`)**: Destination table and ID are embedded in the key suffix. Traversal decodes the target vertex directly from key bytes without hydrating the intermediate edge document.

#### 6. `DynamicScan` (`scan/dynamic.rs`)

- **Role**: Emitted when a query is planned without an active transaction (`Planner::new`). Access path selection is deferred to runtime.

#### 7. `UnionIndexScan` (`scan/union_index.rs`)

- **Execution Mechanism**: Executes multiple independent index scans concurrently for top-level `OR` clauses, merging and deduplicating record IDs using an in-memory bitset.

#### 8. `CountScan` & `IndexCountScan` (`scan/count.rs`, `scan/index_count.rs`)

- **Role**: Fast-path for `count()` queries.
- **IndexCountScan**: Reads index key counts without fetching documents.
- **Security Check**: Bypassed if any field referenced in the query has restricted permissions (`PERMISSIONS FOR select` is not `Full`), preventing unauthorized cardinality leaks.

#### 9. Specialized Scans

- `FullTextScan` (`scan/fulltext.rs`): BM25 scoring and term-frequency lookups.
- `KnnScan` (`scan/knn.rs`): HNSW vector distance calculations (Cosine, Euclidean, Manhattan).
- `FetchScan` (`scan/fetch.rs`): Traverses and hydrates foreign record references during `FETCH` clauses.
- `EmptyScan` (`scan/empty.rs`): Emits zero records (e.g. when static contradictory predicates like `WHERE false` are detected).

### 4.2 Pipeline & Output Operators (`surrealdb/core/src/exec/operators/`)

- `Filter` (`filter.rs`): Evaluates boolean expressions per record.
- `SelectProject` & `Project` (`project.rs`): Projects requested fields and computed expressions.
- `ProjectValue` (`project_value.rs`): Emits a single scalar value stream (used in subqueries).
- `SortByKey` (`sort.rs`): In-memory quicksort over materialized batches.
- `ExternalSort` (`sort/`): Disk-spilling multi-way merge sort for datasets exceeding memory buffers.
- `Limit` (`limit.rs`): Enforces `LIMIT` and `START AT` offsets on row streams.
- `Distinct` (`distinct.rs`): Hash-set-based deduplication for `SELECT DISTINCT`.
- `Aggregate` (`aggregate.rs`): Computes group aggregates (`count`, `sum`, `avg`, `min`, `max`).
- `Split` (`split.rs`): Unrolls array fields into multiple individual rows (`SPLIT ON`).
- `Destructure` (`mutate.rs`): Expands embedded structures.
- `Timeout` (`timeout.rs`): Aborts query execution when statement timeout expires.

---

## 5. Query Planner Architecture (`surrealdb/core/src/exec/planner/`)

### 5.1 Planner Lifecycle & Constructors (`planner.rs:124-165`)

- `Planner::new(ctx)`: Transaction-less. Defers catalog analysis to execution time via `DynamicScan`.
- `Planner::with_txn(ctx, txn, ns, db)`: Transaction-aware. Inspects schema definitions at plan time to generate concrete scan operators.
- `Planner::with_auth(auth)`: Threads session principal metadata (`Auth`) into the planner.

### 5.2 Access Path Selection: `resolve_access_path` (`planner/select/mod.rs:2463-2555`)

- **Inputs**: `(txn, ns, db, table_name, cond: Option<&Cond>, order: Option<&Ordering>, with: Option<&With>)`.
- **Decision Heuristics**:
  1. `WITH NOINDEX`: Emits `AccessPath::TableScan`.
  2. Inspects `cond`: Parses the query's explicit `WHERE` clause via `IndexAnalyzer`.
  3. Single-Column vs Multi-Column: Prioritizes compound indexes matching multiple predicate terms.
  4. Conjunctions (`AND`): Selects the single best index. Unindexed predicates become residual filters. SurrealDB does not perform multi-index intersection across separate B-Trees.
  5. Disjunctions (`OR`): Emits `AccessPath::UnionIndexScan` if all branches are indexed; otherwise falls back to full table scan.
  6. `ORDER BY` matching: If `cond` is `None` but `order` matches an indexed field, selects an unbounded `IndexScan` in `Forward` or `Backward` direction to satisfy ordering.

### 5.3 Decoupling of Table Permissions from Access Path Selection

In stock SurrealDB, `table_def.permissions.select` is **not a parameter to `resolve_access_path`**.

- Table permissions are not parsed by `IndexAnalyzer`.
- An unindexed query like `SELECT * FROM resource ORDER BY created_at DESC;` has `cond.is_none()`. The planner picks `IndexScan(idx_created_at)` to satisfy the order, scanning all records in the table regardless of permissions.
- Authorization is strictly enforced downstream in `pipeline.rs`.

### 5.4 Sort Elimination via `OutputOrdering`

- Operators implement `output_ordering(&self) -> Option<OutputOrdering>`.
- When `IndexScan` scans an index in `Forward` or `Backward` direction, it emits its physical ordering.
- If the scan's ordering matches the query's `ORDER BY` clause, the planner **omits the `SortByKey` operator entirely**, streaming results without an in-memory sort buffer.
- Sort elimination is disqualified if:
  - The scan is non-covering and hydration order is non-deterministic.
  - A `ReferenceScan` is used (which emits records in `RecordId` order, not attribute order).
  - Field-level permissions mask the sort key.

### 5.5 Limit and Offset Pushdown

- Pushed directly into `IndexScan` or `TableScan` only if:
  1. The scan ordering satisfies the `ORDER BY` clause.
  2. No unconsumed residual `Filter` operators exist downstream.
- If residual filters (such as permission checks) exist, limit pushdown is disallowed because filtered rows would cause early termination before sufficient valid records are produced.

---

## 6. Execution Pipeline: `filter_and_process_batch`

Located in `surrealdb/core/src/exec/operators/scan/pipeline.rs:385-451`:

```text
Incoming Batch of CursorDoc from Storage Scan
  │
  ▼
Step 1: Table-Level SELECT Permission Check (`check_perm!`)
  │ - Permission::Full: Pass.
  │ - Permission::None: Reject all rows.
  │ - Permission::Specific(expr): Evaluate AST expression in memory.
  │ Unauthorized rows are discarded immediately.
  ▼
Step 2: Computed Fields Evaluation (`doc/field.rs`)
  │ Computes dynamic fields defined with `<type> VALUE <expr>`.
  ▼
Step 3: Field-Level SELECT Permission Filtering
  │ Checks individual field permissions; replaces unauthorized fields with NONE / NULL.
  ▼
Step 4: Residual WHERE Clause Evaluation
  │ Evaluates predicates not satisfied by the storage scan operator.
  ▼
Step 5: Output Projection
  │ SelectProject / Project: Extracts projected fields, emits batch downstream.
```

---

## 7. Document Mutation & Secondary Index Maintenance

Source authority: `surrealdb/core/src/doc/field.rs` and `surrealdb/core/src/doc/mod.rs`.

### 7.1 Full Record Rewrite Rule

SurrealDB storage engines operate on whole document payloads. Every mutation (`CREATE`, `UPDATE`, `MERGE`) rewrites the entire document revision via `tx.set_record`.

### 7.2 Secondary Index Maintenance (`doc/field.rs`)

- When a document is updated, SurrealDB does not compute delta patches in secondary indexes.
- It deletes all old index keys for the document and inserts all new index keys.
- **Array Indexing Explosion**: For `DEFINE INDEX idx ON table FIELDS array_col.*`, an update to an array with $K$ elements performs:
  $$K_{\text{old}} \text{ index deletes} + K_{\text{new}} \text{ index inserts} + 1 \text{ primary record set} = 2K + 1 \text{ KV operations}.$$

### 7.3 Reference Key Maintenance (`doc/field.rs:784-794`)

For fields defined with `TYPE ... REFERENCE`:

- SurrealDB executes **incremental set diffing**:
  ```rust
  let old = collect_rids(old);
  let new = collect_rids(val);
  for rid in old.difference(&new) { actions.push(RefAction::Delete(rid)); }
  for rid in new.difference(&old) { actions.push(RefAction::Set(rid)); }
  ```
- Appending a single reference to a list of $K$ elements executes exactly **1 primary record set + 1 reference key put** ($O(1)$ index cost), avoiding the full rewrite penalty of secondary array indexes.

### 7.4 Graph Edge Maintenance (`key/graph/mod.rs`)

Every `RELATE` statement writes exactly **5 physical keys**:

1. Edge document record.
2. In-edge inner pointer (`etl`).
3. Out-edge inner pointer (`etr`).
4. Origin vertex forward adjacency pointer (`ltr`).
5. Destination vertex reverse adjacency pointer (`rtl`).
   Total: 5 KV writes, strictly independent of vertex degree.

---

## 8. In-Memory Data Structures & Micro-Architecture

### 8.1 `Value` Representation (`surrealdb/types/src/value/mod.rs`)

All runtime values in SurrealDB are represented by the `Value` enum:

- `Value::None`, `Value::Null`
- `Value::Bool(bool)`
- `Value::Number(Number)` (Int, Float, Decimal)
- `Value::Strand(Strand)` (UTF-8 string)
- `Value::Duration(Duration)`
- `Value::Datetime(Datetime)`
- `Value::Array(Array)` (wraps `Vec<Value>`)
- `Value::Object(Object)` (wraps `BTreeMap<String, Value>`)
- `Value::RecordId(RecordId)` (Table name + StoreKey identifier)
- `Value::Geometry(Geometry)`
- `Value::Bytes(Bytes)`

### 8.2 Array Containment: `Value::contains` (`surrealdb/core/src/val/mod.rs:400-403`)

Membership testing (`$auth.id IN array`) executes:

```rust
Value::Array(v) => v.iter().any(|v| v.equal(other))
```

- Implemented as a linear scan over contiguous memory in a Rust `Vec<Value>`.
- Evaluates equality with early return upon the first positive match.
- Does not build in-memory hash sets or binary search trees for arrays at query time.

---

## 9. Subquery Evaluation & Scalar Planning

- Subqueries in `WHERE` clauses (e.g. `WHERE col IN (SELECT ... FROM ...)`) are compiled into `ScalarSubquery` wrapping a physical operator plan.
- The outer operator (such as `Filter`) evaluates expressions per candidate row.
- **Lack of Per-Query Memoization**: SurrealDB does not automatically memoize the results of scalar subqueries across iterations of the outer scan. If an unindexed outer scan emits $N$ rows, the scalar subquery is executed $N$ times.
