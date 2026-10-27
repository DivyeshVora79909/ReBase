//! FoundationDB implementation of the transactional storage boundary.
//!
//! The FoundationDB network must be booted by the application before calling
//! [`connect`]. Each storage transaction owns one native FDB transaction; no
//! automatic retry loop is used because the closure that produced its writes
//! cannot safely be replayed here.

use super::{
    Backend, Limits, ReadView, Result, Row, StorageError, TableSpec, ValueKind, WriteView,
};
use crate::diagnostics::{Recorder, Scope, error_outcome};
use foundationdb::{
    Database as FdbDatabase, KeySelector, RangeOption, Transaction,
    options::{ConflictRangeType, TransactionOption},
};
use futures::executor::block_on;
use std::{collections::BTreeMap, ops::Bound, sync::Arc, time::Instant};

const MAX_MUTATION_BYTES: usize = 10_000_000;
const MAX_KEY_BYTES: usize = 10_000;
const MAX_VALUE_BYTES: usize = 100_000;
const CLIENT_TIMEOUT_MS: u64 = 4500;
const CATALOG: u8 = 1;
const DATA: u8 = 2;

/// Connect to a cluster using the optional cluster file and isolate this
/// adapter's keys beneath `namespace`.
pub fn connect(cluster_file: Option<&str>, namespace: &[u8]) -> Result<super::Database> {
    let db = FdbDatabase::new(cluster_file).map_err(|e| fdb_error(e, "storage"))?;
    let backend = FdbBackend {
        db: Arc::new(db),
        prefix: namespace_prefix(namespace)?,
    };
    Ok(super::Database::new(backend))
}

struct FdbBackend {
    db: Arc<FdbDatabase>,
    prefix: Vec<u8>,
}

impl Backend for FdbBackend {
    fn limits(&self) -> Limits {
        Limits {
            max_key_bytes: Some(MAX_KEY_BYTES),
            max_value_bytes: Some(MAX_VALUE_BYTES),
            max_transaction_bytes: Some(MAX_MUTATION_BYTES),
            transaction_lifetime_ms: Some(5000),
        }
    }
    fn begin_read(&self) -> Result<Box<dyn ReadView>> {
        let trx = transaction(&self.db, None)?;
        Ok(Box::new(FdbRead {
            trx,
            prefix: self.prefix.clone(),
            trace: None,
        }))
    }

    fn begin_write(&self) -> Result<Box<dyn WriteView>> {
        let trx = transaction(&self.db, None)?;
        Ok(Box::new(FdbWrite {
            trx,
            prefix: self.prefix.clone(),
            writes: BTreeMap::new(),
            cleared: Vec::new(),
            catalog: BTreeMap::new(),
            bytes: 0,
            started: Instant::now(),
            trace: None,
        }))
    }
    fn begin_read_diagnostic(&self, trace: Recorder) -> Result<Box<dyn ReadView>> {
        let trx = transaction(&self.db, Some(&trace))?;
        Ok(Box::new(FdbRead {
            trx,
            prefix: self.prefix.clone(),
            trace: Some(trace),
        }))
    }
    fn begin_write_diagnostic(&self, trace: Recorder) -> Result<Box<dyn WriteView>> {
        let trx = transaction(&self.db, Some(&trace))?;
        Ok(Box::new(FdbWrite {
            trx,
            prefix: self.prefix.clone(),
            writes: BTreeMap::new(),
            cleared: Vec::new(),
            catalog: BTreeMap::new(),
            bytes: 0,
            started: Instant::now(),
            trace: Some(trace),
        }))
    }
}

struct FdbRead {
    trx: Transaction,
    prefix: Vec<u8>,
    trace: Option<Recorder>,
}
struct FdbWrite {
    trx: Transaction,
    prefix: Vec<u8>,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    cleared: Vec<Vec<u8>>,
    catalog: BTreeMap<String, Option<ValueKind>>,
    bytes: usize,
    started: Instant,
    trace: Option<Recorder>,
}

fn fail(code: &'static str, detail: impl Into<String>) -> StorageError {
    StorageError::new(code, detail.into())
}

fn fdb_error(error: foundationdb::FdbError, fallback: &'static str) -> StorageError {
    // A timeout after commit is submitted may have committed. The same timeout
    // during a read cannot have published application writes.
    let code = if fallback == "outcome_unknown"
        && (error.is_maybe_committed() || matches!(error.code(), 1031 | 1039))
    {
        "outcome_unknown"
    } else if matches!(error.code(), 1007 | 1031 | 2101 | 2102 | 2103) {
        "transaction_limit"
    } else if error.code() == 1020 {
        "transaction_conflict"
    } else if error.is_retryable_not_committed() {
        "transaction_aborted"
    } else {
        fallback
    };
    fail(
        code,
        format!("FoundationDB {} ({})", error.message(), error.code()),
    )
}

fn transaction(db: &FdbDatabase, trace: Option<&Recorder>) -> Result<Transaction> {
    let trx = if let Some(trace) = trace {
        let metrics = foundationdb::metrics::TransactionMetrics::new();
        let trx = db.create_instrumented_trx(metrics.clone()).map_err(|e| {
            e.get_fdb_error().map_or_else(
                || {
                    fail(
                        "storage",
                        "FoundationDB instrumentation initialization failed",
                    )
                },
                |e| fdb_error(e, "storage"),
            )
        })?;
        trace.attach_sdk(metrics);
        trx
    } else {
        db.create_trx().map_err(|e| fdb_error(e, "storage"))?
    };
    trx.set_option(TransactionOption::Timeout(CLIENT_TIMEOUT_MS as i32))
        .map_err(|e| fdb_error(e, "storage"))?;
    trx.set_option(TransactionOption::SizeLimit(MAX_MUTATION_BYTES as i32))
        .map_err(|e| fdb_error(e, "storage"))?;
    Ok(trx)
}

fn validate_key(key: &[u8]) -> Result<()> {
    if key.len() > MAX_KEY_BYTES {
        Err(fail(
            "transaction_limit",
            format!(
                "encoded FoundationDB key is {} bytes; maximum is {MAX_KEY_BYTES}",
                key.len()
            ),
        ))
    } else {
        Ok(())
    }
}
fn validate_value(value: &[u8]) -> Result<()> {
    if value.len() > MAX_VALUE_BYTES {
        Err(fail(
            "transaction_limit",
            format!(
                "FoundationDB value is {} bytes; maximum is {MAX_VALUE_BYTES}",
                value.len()
            ),
        ))
    } else {
        Ok(())
    }
}

fn namespace_prefix(namespace: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(namespace.len()).map_err(|_| fail("storage", "namespace too long"))?;
    // FoundationDB reserves keys beginning with 0xff for system metadata.
    let mut out = b"\x01rebase-storage\0".to_vec();
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(namespace);
    validate_key(&out)?;
    Ok(out)
}

fn successor(prefix: &[u8]) -> Vec<u8> {
    let mut out = prefix.to_vec();
    for i in (0..out.len()).rev() {
        if out[i] != 0xff {
            out[i] += 1;
            out.truncate(i + 1);
            return out;
        }
    }
    out.push(0xff);
    out
}

fn catalog_prefix(prefix: &[u8]) -> Vec<u8> {
    let mut k = prefix.to_vec();
    k.push(CATALOG);
    k
}
fn data_prefix(prefix: &[u8], table: &str) -> Result<Vec<u8>> {
    let name = table.as_bytes();
    let len = u32::try_from(name.len()).map_err(|_| fail("storage", "table name too long"))?;
    let mut k = prefix.to_vec();
    k.push(DATA);
    k.extend_from_slice(&len.to_be_bytes());
    k.extend_from_slice(name);
    validate_key(&k)?;
    Ok(k)
}
fn catalog_key(prefix: &[u8], table: &str) -> Vec<u8> {
    let mut k = catalog_prefix(prefix);
    k.extend_from_slice(table.as_bytes());
    k
}
fn data_key(prefix: &[u8], table: &str, key: &[u8]) -> Result<Vec<u8>> {
    let mut k = data_prefix(prefix, table)?;
    k.extend_from_slice(key);
    validate_key(&k)?;
    Ok(k)
}
fn kind_byte(kind: ValueKind) -> u8 {
    match kind {
        ValueKind::Bytes => 1,
        ValueKind::U16 => 2,
    }
}
fn byte_kind(byte: u8) -> Result<ValueKind> {
    match byte {
        1 => Ok(ValueKind::Bytes),
        2 => Ok(ValueKind::U16),
        _ => Err(fail("storage_corrupt", "invalid table kind")),
    }
}

// These counters name Rust binding invocations, not packets or disk operations.
// Read key bytes count returned keys; missing point reads return zero bytes.
fn finish_read(scope: Option<Scope>, result: &Result<Option<Vec<u8>>>, key_len: usize) {
    if let Some(scope) = scope {
        match result {
            Ok(Some(value)) => scope.finish("found", 1, key_len as u64, value.len() as u64),
            Ok(None) => scope.finish("missing", 0, 0, 0),
            Err(error) => scope.finish(error_outcome(error), 0, 0, 0),
        }
    }
}
fn fetch(
    trx: &Transaction,
    key: &[u8],
    snapshot: bool,
    trace: Option<&Recorder>,
    role: &str,
    control: Option<u64>,
) -> Result<Option<Vec<u8>>> {
    validate_key(key)?;
    let scope = trace.map(|trace| trace.scope("binding", "get", role, None));
    if let Some(scope) = &scope {
        scope.control(control);
    }
    let result = block_on(trx.get(key, snapshot))
        .map(|v| v.map(|b| b.as_ref().to_vec()))
        .map_err(|e| fdb_error(e, "storage"));
    finish_read(scope, &result, key.len());
    result
}
fn catalog_exists(
    trx: &Transaction,
    prefix: &[u8],
    table: &TableSpec,
    trace: Option<&Recorder>,
    read_view: bool,
) -> Result<(bool, Option<u64>)> {
    let key = catalog_key(prefix, &table.name);
    validate_key(&key)?;
    let scope = trace.map(|trace| trace.scope("binding", "get", "catalog", None));
    let id = scope.as_ref().and_then(Scope::id);
    let result = block_on(trx.get(&key, false))
        .map(|v| v.map(|b| b.as_ref().to_vec()))
        .map_err(|e| fdb_error(e, "storage"));
    finish_read(scope, &result, key.len());
    match result? {
        None => Ok((false, id)),
        Some(bytes) if bytes.as_slice() == [kind_byte(table.value)] => Ok((true, id)),
        Some(_) => Err(fail(
            "storage_schema",
            if read_view {
                format!("table {} has another value kind", table.name)
            } else {
                "table value kind mismatch".into()
            },
        )),
    }
}

fn range_rows(
    trx: &Transaction,
    begin: KeySelector<'_>,
    end: KeySelector<'_>,
    limit: usize,
    trace: Option<&Recorder>,
    role: &str,
    control: Option<u64>,
) -> Result<Vec<Row>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut option = RangeOption::from((begin, end));
    option.limit = Some(limit);
    let mut rows = Vec::new();
    let mut iteration = 1;
    loop {
        let scope = trace.map(|trace| trace.scope("binding", "get-range", role, None));
        if let Some(scope) = &scope {
            scope.control(control);
        }
        let result = block_on(trx.get_range(&option, iteration, false))
            .map_err(|error| fdb_error(error, "storage"));
        if let Some(scope) = scope {
            match &result {
                Ok(values) => scope.finish(
                    "success",
                    values.len() as u64,
                    values.iter().map(|kv| kv.key().len() as u64).sum(),
                    values.iter().map(|kv| kv.value().len() as u64).sum(),
                ),
                Err(error) => scope.finish(error_outcome(error), 0, 0, 0),
            }
        }
        let values = result?;
        let more = values.more();
        let next = option.next_range(&values);
        append_range_batch(
            &mut rows,
            values
                .into_iter()
                .map(|kv| (kv.key().to_vec(), kv.value().to_vec()))
                .collect(),
            more,
            limit,
        )?;
        let Some(next) = next else {
            return Ok(rows);
        };
        option = next;
        iteration += 1;
    }
}

// Streaming may return a short batch with more=true. Keep every actual batch;
// these checks reject a stalled or oversized response without changing paging.
fn append_range_batch(
    rows: &mut Vec<Row>,
    batch: Vec<Row>,
    more: bool,
    limit: usize,
) -> Result<()> {
    if batch.is_empty() && more {
        return Err(fail(
            "storage",
            "FoundationDB range made no progress with more=true",
        ));
    }
    rows.extend(batch);
    if rows.len() > limit {
        return Err(fail(
            "storage",
            "FoundationDB range exceeded requested row limit",
        ));
    }
    Ok(())
}

fn selector_start<'a>(bound: &'a Bound<Vec<u8>>, fallback: &'a [u8]) -> KeySelector<'a> {
    match bound {
        Bound::Included(k) => KeySelector::first_greater_or_equal(k.as_slice()),
        Bound::Excluded(k) => KeySelector::first_greater_than(k.as_slice()),
        Bound::Unbounded => KeySelector::first_greater_or_equal(fallback),
    }
}
fn selector_end<'a>(bound: &'a Bound<Vec<u8>>, fallback: &'a [u8]) -> KeySelector<'a> {
    match bound {
        Bound::Included(k) => KeySelector::first_greater_than(k.as_slice()),
        Bound::Excluded(k) => KeySelector::first_greater_or_equal(k.as_slice()),
        Bound::Unbounded => KeySelector::first_greater_or_equal(fallback),
    }
}

fn scan_table(
    trx: &Transaction,
    prefix: &[u8],
    table: &TableSpec,
    start: Bound<Vec<u8>>,
    end: Bound<Vec<u8>>,
    limit: usize,
    diagnostic: (Option<&Recorder>, Option<u64>),
) -> Result<Vec<Row>> {
    let (trace, control) = diagnostic;
    if limit == 0 {
        return Ok(Vec::new());
    }
    let dp = data_prefix(prefix, &table.name)?;
    let start_key = match start {
        Bound::Included(k) => Bound::Included(data_key(prefix, &table.name, &k)?),
        Bound::Excluded(k) => Bound::Excluded(data_key(prefix, &table.name, &k)?),
        Bound::Unbounded => Bound::Unbounded,
    };
    let end_key = match end {
        Bound::Included(k) => Bound::Included(data_key(prefix, &table.name, &k)?),
        Bound::Excluded(k) => Bound::Excluded(data_key(prefix, &table.name, &k)?),
        Bound::Unbounded => Bound::Unbounded,
    };
    let dp_end = successor(&dp);
    // Native limited reads may protect only the portion covered by that page.
    // The portable scan predicate is the complete requested half-open range.
    let lower = match &start_key {
        Bound::Included(key) => key.clone(),
        Bound::Excluded(key) => [key.as_slice(), &[0]].concat(),
        Bound::Unbounded => dp.clone(),
    };
    let upper = match &end_key {
        Bound::Included(key) => [key.as_slice(), &[0]].concat(),
        Bound::Excluded(key) => key.clone(),
        Bound::Unbounded => dp_end.clone(),
    };
    if lower >= upper {
        return Ok(Vec::new());
    }
    trx.add_conflict_range(&lower, &upper, ConflictRangeType::Read)
        .map_err(|error| fdb_error(error, "storage"))?;
    let begin = selector_start(&start_key, &dp);
    let stop = selector_end(&end_key, &dp_end);
    let mut rows = range_rows(trx, begin, stop, limit, trace, "data", control)?;
    rows.retain(|(k, _)| k.starts_with(&dp));
    Ok(rows
        .into_iter()
        .map(|(k, v)| (k[dp.len()..].to_vec(), v))
        .collect())
}

impl ReadView for FdbRead {
    fn table_exists(&self, table: &TableSpec) -> Result<bool> {
        catalog_exists(&self.trx, &self.prefix, table, self.trace.as_ref(), true)
            .map(|(exists, _)| exists)
    }
    fn get(&self, table: &TableSpec, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let (exists, control) =
            catalog_exists(&self.trx, &self.prefix, table, self.trace.as_ref(), true)?;
        if !exists {
            return Err(fail("storage", format!("missing table {}", table.name)));
        }
        fetch(
            &self.trx,
            &data_key(&self.prefix, &table.name, key)?,
            false,
            self.trace.as_ref(),
            "data",
            control,
        )
    }
    fn scan(
        &self,
        table: &TableSpec,
        start: Bound<Vec<u8>>,
        end: Bound<Vec<u8>>,
        limit: usize,
    ) -> Result<Vec<Row>> {
        let (exists, control) =
            catalog_exists(&self.trx, &self.prefix, table, self.trace.as_ref(), true)?;
        if !exists {
            return Err(fail("storage", format!("missing table {}", table.name)));
        }
        scan_table(
            &self.trx,
            &self.prefix,
            table,
            start,
            end,
            limit,
            (self.trace.as_ref(), control),
        )
    }

    fn list_tables(&self) -> Result<Vec<String>> {
        let p = catalog_prefix(&self.prefix);
        let end = successor(&p);
        let rows = range_rows(
            &self.trx,
            KeySelector::first_greater_or_equal(p.as_slice()),
            KeySelector::first_greater_or_equal(end.as_slice()),
            10_001,
            self.trace.as_ref(),
            "catalog",
            None,
        )?;
        if rows.len() > 10_000 {
            return Err(fail("storage_limit", "too many tables to list"));
        }
        rows.into_iter()
            .map(|(k, v)| {
                byte_kind(
                    *v.first()
                        .ok_or_else(|| fail("storage_corrupt", "empty catalog value"))?,
                )?;
                String::from_utf8(k[p.len()..].to_vec())
                    .map_err(|_| fail("storage_corrupt", "invalid table name"))
            })
            .collect()
    }
}

impl FdbWrite {
    fn exists(&self, table: &TableSpec) -> Result<bool> {
        self.exists_control(table).map(|(exists, _)| exists)
    }
    fn exists_control(&self, table: &TableSpec) -> Result<(bool, Option<u64>)> {
        if let Some(kind) = self.catalog.get(&table.name) {
            return match kind {
                Some(k) if *k == table.value => Ok((true, None)),
                Some(_) => Err(fail("storage_schema", "table value kind mismatch")),
                None => Ok((false, None)),
            };
        }
        catalog_exists(&self.trx, &self.prefix, table, self.trace.as_ref(), false)
    }

    fn charge(&mut self, n: usize) -> Result<()> {
        let next = self.bytes.saturating_add(n);
        if next > MAX_MUTATION_BYTES {
            Err(fail("transaction_limit", "staged mutation budget exceeded"))
        } else {
            self.bytes = next;
            Ok(())
        }
    }
    fn buffer(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) -> Result<()> {
        let previous = self
            .writes
            .get(&key)
            .map_or(0, |value| key.len() + value.as_ref().map_or(0, Vec::len));
        let next = self
            .bytes
            .saturating_sub(previous)
            .saturating_add(key.len() + value.as_ref().map_or(0, Vec::len));
        if next > MAX_MUTATION_BYTES {
            return Err(fail(
                "transaction_limit",
                "coalesced staged mutation budget exceeded",
            ));
        }
        self.bytes = next;
        self.writes.insert(key, value);
        Ok(())
    }
    fn read_overlay(&self, full_key: &[u8]) -> Option<Option<Vec<u8>>> {
        if let Some(value) = self.writes.get(full_key) {
            return Some(value.clone());
        }
        if self.cleared.iter().any(|p| full_key.starts_with(p)) {
            return Some(None);
        }
        None
    }
    fn read_scan(
        &self,
        table: &TableSpec,
        start: Bound<Vec<u8>>,
        end: Bound<Vec<u8>>,
        limit: usize,
        control: Option<u64>,
    ) -> Result<Vec<Row>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let dp = data_prefix(&self.prefix, &table.name)?;
        let cleared = self.cleared.iter().any(|p| p == &dp);
        let mut merged = BTreeMap::<Vec<u8>, Vec<u8>>::new();
        let mut cursor = start.clone();
        if !cleared {
            loop {
                // Each native range request remains bounded even when staged
                // deletes force us to continue to a later page.
                let rows = scan_table(
                    &self.trx,
                    &self.prefix,
                    table,
                    cursor,
                    end.clone(),
                    64,
                    (self.trace.as_ref(), control),
                )?;
                if rows.is_empty() {
                    break;
                }
                let last = rows.last().expect("nonempty page").0.clone();
                let short_page = rows.len() < 64;
                for (key, value) in rows {
                    merged.insert(key, value);
                }
                for (full, value) in &self.writes {
                    if !full.starts_with(&dp) {
                        continue;
                    }
                    let key = full[dp.len()..].to_vec();
                    if in_bounds(&key, &start, &end) {
                        if let Some(value) = value {
                            merged.insert(key, value.clone());
                        } else {
                            merged.remove(&key);
                        }
                    }
                }
                // Buffered inserts after `last` may be present in `merged`,
                // but a later base page can still sort before them. Stop only
                // once the first `limit` merged keys are all at or before the
                // last key covered by the base read.
                let covered = merged.keys().take_while(|key| *key <= &last).count();
                if covered >= limit || short_page {
                    break;
                }
                cursor = Bound::Excluded(last);
            }
        }
        for (full, value) in &self.writes {
            if !full.starts_with(&dp) {
                continue;
            }
            let key = full[dp.len()..].to_vec();
            if in_bounds(&key, &start, &end) {
                if let Some(value) = value {
                    merged.insert(key, value.clone());
                } else {
                    merged.remove(&key);
                }
            }
        }
        Ok(merged.into_iter().take(limit).collect())
    }
}

fn in_bounds(key: &[u8], start: &Bound<Vec<u8>>, end: &Bound<Vec<u8>>) -> bool {
    let after_start = match start {
        Bound::Included(v) => key >= v.as_slice(),
        Bound::Excluded(v) => key > v.as_slice(),
        Bound::Unbounded => true,
    };
    let before_end = match end {
        Bound::Included(v) => key <= v.as_slice(),
        Bound::Excluded(v) => key < v.as_slice(),
        Bound::Unbounded => true,
    };
    after_start && before_end
}

impl ReadView for FdbWrite {
    fn table_exists(&self, table: &TableSpec) -> Result<bool> {
        self.exists(table)
    }
    fn get(&self, table: &TableSpec, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let (exists, control) = self.exists_control(table)?;
        if !exists {
            return Err(fail("storage", format!("missing table {}", table.name)));
        }
        let full = data_key(&self.prefix, &table.name, key)?;
        if let Some(value) = self.read_overlay(&full) {
            return Ok(value);
        }
        fetch(
            &self.trx,
            &full,
            false,
            self.trace.as_ref(),
            "data",
            control,
        )
    }
    fn scan(
        &self,
        table: &TableSpec,
        start: Bound<Vec<u8>>,
        end: Bound<Vec<u8>>,
        limit: usize,
    ) -> Result<Vec<Row>> {
        let (exists, control) = self.exists_control(table)?;
        if !exists {
            return Err(fail("storage", format!("missing table {}", table.name)));
        }
        self.read_scan(table, start, end, limit, control)
    }
    fn list_tables(&self) -> Result<Vec<String>> {
        let p = catalog_prefix(&self.prefix);
        let end = successor(&p);
        let rows = range_rows(
            &self.trx,
            KeySelector::first_greater_or_equal(p.as_slice()),
            KeySelector::first_greater_or_equal(end.as_slice()),
            10_001,
            self.trace.as_ref(),
            "catalog",
            None,
        )?;
        if rows.len() > 10_000 {
            return Err(fail("storage_limit", "too many tables to list"));
        }
        let mut names = rows
            .into_iter()
            .map(|(k, v)| {
                byte_kind(
                    *v.first()
                        .ok_or_else(|| fail("storage_corrupt", "empty catalog value"))?,
                )?;
                String::from_utf8(k[p.len()..].to_vec())
                    .map_err(|_| fail("storage_corrupt", "invalid table name"))
            })
            .collect::<Result<Vec<_>>>()?;
        for (name, kind) in &self.catalog {
            if kind.is_some() {
                if !names.contains(name) {
                    names.push(name.clone());
                }
            } else {
                names.retain(|n| n != name);
            }
        }
        names.sort();
        Ok(names)
    }
}

impl WriteView for FdbWrite {
    fn create_table(&mut self, table: &TableSpec) -> Result<()> {
        if self.exists(table)? {
            return Ok(());
        }
        let catalog = catalog_key(&self.prefix, &table.name);
        validate_key(&catalog)?;
        self.charge(catalog.len() + 1)?;
        self.catalog.insert(table.name.clone(), Some(table.value));
        Ok(())
    }
    fn delete_table(&mut self, table: &TableSpec) -> Result<bool> {
        if !self.exists(table)? {
            return Ok(false);
        }
        let dp = data_prefix(&self.prefix, &table.name)?;
        // Protect every populated/absent key before atomic range clearing,
        // including concurrent edits beyond the first native scan page.
        self.trx
            .add_conflict_range(&dp, &successor(&dp), ConflictRangeType::Read)
            .map_err(|error| fdb_error(error, "storage"))?;
        self.cleared.push(dp.clone());
        let removed_bytes = self
            .writes
            .iter()
            .filter(|(key, _)| key.starts_with(&dp))
            .map(|(key, value)| key.len() + value.as_ref().map_or(0, Vec::len))
            .sum::<usize>();
        self.bytes = self.bytes.saturating_sub(removed_bytes);
        self.writes.retain(|k, _| !k.starts_with(&dp));
        self.catalog.insert(table.name.clone(), None);
        self.charge(table.name.len() + 1)?;
        Ok(true)
    }
    fn put(&mut self, table: &TableSpec, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        validate_value(value)?;
        let (exists, control) = self.exists_control(table)?;
        if !exists {
            return Err(fail("storage", format!("missing table {}", table.name)));
        }
        let full = data_key(&self.prefix, &table.name, key)?;
        let old = match self.read_overlay(&full) {
            Some(value) => value,
            None => fetch(
                &self.trx,
                &full,
                false,
                self.trace.as_ref(),
                "data",
                control,
            )?,
        };
        self.buffer(full, Some(value.to_vec()))?;
        Ok(old)
    }
    fn remove(&mut self, table: &TableSpec, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let (exists, control) = self.exists_control(table)?;
        if !exists {
            return Err(fail("storage", format!("missing table {}", table.name)));
        }
        let full = data_key(&self.prefix, &table.name, key)?;
        let old = match self.read_overlay(&full) {
            Some(value) => value,
            None => fetch(
                &self.trx,
                &full,
                false,
                self.trace.as_ref(),
                "data",
                control,
            )?,
        };
        self.buffer(full, None)?;
        Ok(old)
    }
    fn commit(self: Box<Self>) -> Result<()> {
        let FdbWrite {
            trx,
            prefix,
            writes,
            cleared,
            catalog,
            started,
            trace,
            ..
        } = *self;
        if started.elapsed().as_millis() >= u128::from(CLIENT_TIMEOUT_MS) {
            return Err(fail(
                "transaction_limit",
                "FoundationDB adapter lifetime expired before commit submission",
            ));
        }
        for dp in cleared {
            let end = successor(&dp);
            let scope = trace
                .as_ref()
                .map(|t| t.scope("binding", "clear-range", "data", None));
            trx.clear_range(&dp, &end);
            if let Some(scope) = scope {
                scope.finish("success", 0, (dp.len() + end.len()) as u64, 0);
            }
        }
        for (key, value) in writes {
            match value {
                Some(v) => {
                    let scope = trace
                        .as_ref()
                        .map(|t| t.scope("binding", "set", "data", None));
                    trx.set(&key, &v);
                    if let Some(scope) = scope {
                        scope.finish("success", 0, key.len() as u64, v.len() as u64);
                    }
                }
                None => {
                    let scope = trace
                        .as_ref()
                        .map(|t| t.scope("binding", "clear", "data", None));
                    trx.clear(&key);
                    if let Some(scope) = scope {
                        scope.finish("success", 0, key.len() as u64, 0);
                    }
                }
            }
        }
        for (name, kind) in catalog {
            let key = catalog_key(&prefix, &name);
            match kind {
                Some(kind) => {
                    let scope = trace
                        .as_ref()
                        .map(|t| t.scope("binding", "set", "catalog", None));
                    trx.set(&key, &[kind_byte(kind)]);
                    if let Some(scope) = scope {
                        scope.finish("success", 0, key.len() as u64, 1);
                    }
                }
                None => {
                    let scope = trace
                        .as_ref()
                        .map(|t| t.scope("binding", "clear", "catalog", None));
                    trx.clear(&key);
                    if let Some(scope) = scope {
                        scope.finish("success", 0, key.len() as u64, 0);
                    }
                }
            }
        }
        let scope = trace
            .as_ref()
            .map(|t| t.scope("binding", "approximate-size", "other", None));
        let result = block_on(trx.get_approximate_size()).map_err(|e| fdb_error(e, "storage"));
        if let Some(scope) = scope {
            scope.finish(
                result
                    .as_ref()
                    .map_or_else(|e| error_outcome(e), |_| "success"),
                0,
                0,
                0,
            );
        }
        let size = result?;
        if size < 0 || size as usize > MAX_MUTATION_BYTES {
            return Err(fail(
                "transaction_limit",
                "FoundationDB transaction size budget exceeded",
            ));
        }
        let scope = trace
            .as_ref()
            .map(|t| t.scope("commit", "commit", "other", None));
        let result = block_on(trx.commit())
            .map(|_| ())
            .map_err(|e| fdb_error(e.into(), "outcome_unknown"));
        if let Some(scope) = scope {
            scope.finish(
                result
                    .as_ref()
                    .map_or_else(|e| error_outcome(e), |_| "success"),
                0,
                0,
                0,
            );
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definite_commit_abort_retains_conflict_or_limit_classification() {
        assert_eq!(
            fdb_error(foundationdb::FdbError::from_code(1020), "outcome_unknown").code,
            "transaction_conflict"
        );
        for code in [1007, 2101, 2102, 2103] {
            assert_eq!(
                fdb_error(foundationdb::FdbError::from_code(code), "outcome_unknown").code,
                "transaction_limit"
            );
        }
        assert_eq!(
            fdb_error(foundationdb::FdbError::from_code(1009), "outcome_unknown").code,
            "transaction_aborted"
        );
    }

    #[test]
    fn timeout_is_definite_before_submission_and_uncertain_during_commit() {
        assert_eq!(
            fdb_error(foundationdb::FdbError::from_code(1031), "storage").code,
            "transaction_limit"
        );
        for code in [1021, 1031, 1039] {
            assert_eq!(
                fdb_error(foundationdb::FdbError::from_code(code), "outcome_unknown").code,
                "outcome_unknown"
            );
        }
    }
    #[test]
    fn diagnostic_range_accumulation_handles_short_more_empty_and_overshoot() {
        let mut rows = Vec::new();
        append_range_batch(&mut rows, vec![(vec![1], vec![11])], true, 3).unwrap();
        append_range_batch(&mut rows, vec![(vec![2], vec![22])], true, 3).unwrap();
        append_range_batch(&mut rows, vec![(vec![3], vec![33])], false, 3).unwrap();
        assert_eq!(
            rows,
            vec![
                (vec![1], vec![11]),
                (vec![2], vec![22]),
                (vec![3], vec![33])
            ]
        );
        assert!(append_range_batch(&mut Vec::new(), Vec::new(), true, 3).is_err());
        assert!(append_range_batch(&mut rows, vec![(vec![4], vec![44])], false, 3).is_err());
        append_range_batch(&mut Vec::new(), Vec::new(), false, 3).unwrap();
    }
}
