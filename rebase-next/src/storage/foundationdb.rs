//! FoundationDB implementation of the transactional storage boundary.
//!
//! The FoundationDB network must be booted by the application before calling
//! [`connect`]. Each storage transaction owns one native FDB transaction; no
//! automatic retry loop is used because the closure that produced its writes
//! cannot safely be replayed here.

use super::{Backend, ReadView, Result, Row, StorageError, TableSpec, ValueKind, WriteView};
use foundationdb::{Database as FdbDatabase, KeySelector, RangeOption, Transaction};
use futures::executor::block_on;
use std::{collections::BTreeMap, ops::Bound, sync::Arc};

const MAX_MUTATION_BYTES: usize = 10_000_000;
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
    fn begin_read(&self) -> Result<Box<dyn ReadView>> {
        let trx = self.db.create_trx().map_err(|e| fdb_error(e, "storage"))?;
        Ok(Box::new(FdbRead {
            trx,
            prefix: self.prefix.clone(),
        }))
    }

    fn begin_write(&self) -> Result<Box<dyn WriteView>> {
        let trx = self.db.create_trx().map_err(|e| fdb_error(e, "storage"))?;
        Ok(Box::new(FdbWrite {
            trx,
            prefix: self.prefix.clone(),
            writes: BTreeMap::new(),
            cleared: Vec::new(),
            catalog: BTreeMap::new(),
            bytes: 0,
        }))
    }
}

struct FdbRead {
    trx: Transaction,
    prefix: Vec<u8>,
}
struct FdbWrite {
    trx: Transaction,
    prefix: Vec<u8>,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    cleared: Vec<Vec<u8>>,
    catalog: BTreeMap<String, Option<ValueKind>>,
    bytes: usize,
}

fn fail(code: &'static str, detail: impl Into<String>) -> StorageError {
    StorageError::new(code, detail.into())
}

fn fdb_error(error: foundationdb::FdbError, fallback: &'static str) -> StorageError {
    let code = if error.is_maybe_committed() {
        "outcome_unknown"
    } else if error.code() == 2101 {
        "transaction_limit"
    } else if error.code() == 1020 || error.is_retryable_not_committed() {
        "transaction_conflict"
    } else {
        fallback
    };
    fail(
        code,
        format!("FoundationDB {} ({})", error.message(), error.code()),
    )
}

fn namespace_prefix(namespace: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(namespace.len()).map_err(|_| fail("storage", "namespace too long"))?;
    // FoundationDB reserves keys beginning with 0xff for system metadata.
    let mut out = b"\x01rebase-storage\0".to_vec();
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(namespace);
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

fn fetch(trx: &Transaction, key: &[u8], snapshot: bool) -> Result<Option<Vec<u8>>> {
    block_on(trx.get(key, snapshot))
        .map(|v| v.map(|b| b.as_ref().to_vec()))
        .map_err(|e| fdb_error(e, "storage"))
}

fn range_rows(
    trx: &Transaction,
    begin: KeySelector<'_>,
    end: KeySelector<'_>,
    limit: usize,
    snapshot: bool,
) -> Result<Vec<Row>> {
    let mut option = RangeOption::from((begin, end));
    option.limit = Some(limit);
    let values =
        block_on(trx.get_range(&option, 1, snapshot)).map_err(|e| fdb_error(e, "storage"))?;
    Ok(values
        .into_iter()
        .map(|kv| (kv.key().to_vec(), kv.value().to_vec()))
        .collect())
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
) -> Result<Vec<Row>> {
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
    let begin = selector_start(&start_key, &dp);
    let stop = selector_end(&end_key, &dp_end);
    let mut rows = range_rows(trx, begin, stop, limit, false)?;
    rows.retain(|(k, _)| k.starts_with(&dp));
    Ok(rows
        .into_iter()
        .map(|(k, v)| (k[dp.len()..].to_vec(), v))
        .collect())
}

impl ReadView for FdbRead {
    fn table_exists(&self, table: &TableSpec) -> Result<bool> {
        match fetch(&self.trx, &catalog_key(&self.prefix, &table.name), false)? {
            None => Ok(false),
            Some(bytes) if bytes.as_slice() == [kind_byte(table.value)] => Ok(true),
            Some(_) => Err(fail(
                "storage_schema",
                format!("table {} has another value kind", table.name),
            )),
        }
    }
    fn get(&self, table: &TableSpec, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if !self.table_exists(table)? {
            return Err(fail("storage", format!("missing table {}", table.name)));
        }
        fetch(&self.trx, &data_key(&self.prefix, &table.name, key)?, false)
    }
    fn scan(
        &self,
        table: &TableSpec,
        start: Bound<Vec<u8>>,
        end: Bound<Vec<u8>>,
        limit: usize,
    ) -> Result<Vec<Row>> {
        if !self.table_exists(table)? {
            return Err(fail("storage", format!("missing table {}", table.name)));
        }
        scan_table(&self.trx, &self.prefix, table, start, end, limit)
    }
    fn list_tables(&self) -> Result<Vec<String>> {
        let p = catalog_prefix(&self.prefix);
        let end = successor(&p);
        let rows = range_rows(
            &self.trx,
            KeySelector::first_greater_or_equal(p.as_slice()),
            KeySelector::first_greater_or_equal(end.as_slice()),
            10_001,
            false,
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
        if let Some(kind) = self.catalog.get(&table.name) {
            return match kind {
                Some(k) if *k == table.value => Ok(true),
                Some(_) => Err(fail("storage_schema", "table value kind mismatch")),
                None => Ok(false),
            };
        }
        match fetch(&self.trx, &catalog_key(&self.prefix, &table.name), false)? {
            None => Ok(false),
            Some(bytes) if bytes.as_slice() == [kind_byte(table.value)] => Ok(true),
            Some(_) => Err(fail("storage_schema", "table value kind mismatch")),
        }
    }
    fn charge(&mut self, n: usize) -> Result<()> {
        self.bytes = self.bytes.saturating_add(n);
        if self.bytes > MAX_MUTATION_BYTES {
            Err(fail("transaction_limit", "staged mutation budget exceeded"))
        } else {
            Ok(())
        }
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
                let rows = scan_table(&self.trx, &self.prefix, table, cursor, end.clone(), 64)?;
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
        if !self.exists(table)? {
            return Err(fail("storage", format!("missing table {}", table.name)));
        }
        let full = data_key(&self.prefix, &table.name, key)?;
        if let Some(value) = self.read_overlay(&full) {
            return Ok(value);
        }
        fetch(&self.trx, &full, false)
    }
    fn scan(
        &self,
        table: &TableSpec,
        start: Bound<Vec<u8>>,
        end: Bound<Vec<u8>>,
        limit: usize,
    ) -> Result<Vec<Row>> {
        if !self.exists(table)? {
            return Err(fail("storage", format!("missing table {}", table.name)));
        }
        self.read_scan(table, start, end, limit)
    }
    fn list_tables(&self) -> Result<Vec<String>> {
        let p = catalog_prefix(&self.prefix);
        let end = successor(&p);
        let rows = range_rows(
            &self.trx,
            KeySelector::first_greater_or_equal(p.as_slice()),
            KeySelector::first_greater_or_equal(end.as_slice()),
            10_001,
            false,
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
        self.charge(table.name.len() + 1)?;
        self.catalog.insert(table.name.clone(), Some(table.value));
        Ok(())
    }
    fn delete_table(&mut self, table: &TableSpec) -> Result<bool> {
        if !self.exists(table)? {
            return Ok(false);
        }
        let dp = data_prefix(&self.prefix, &table.name)?;
        // A non-snapshot range read records a conflict even when the table is empty.
        let _ = range_rows(
            &self.trx,
            KeySelector::first_greater_or_equal(dp.as_slice()),
            KeySelector::first_greater_or_equal(successor(&dp)),
            1,
            false,
        )?;
        self.cleared.push(dp.clone());
        self.writes.retain(|k, _| !k.starts_with(&dp));
        self.catalog.insert(table.name.clone(), None);
        self.charge(table.name.len() + 1)?;
        Ok(true)
    }
    fn put(&mut self, table: &TableSpec, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        if !self.exists(table)? {
            return Err(fail("storage", format!("missing table {}", table.name)));
        }
        let full = data_key(&self.prefix, &table.name, key)?;
        let old = match self.read_overlay(&full) {
            Some(value) => value,
            None => fetch(&self.trx, &full, false)?,
        };
        self.charge(full.len() + value.len())?;
        self.writes.insert(full, Some(value.to_vec()));
        Ok(old)
    }
    fn remove(&mut self, table: &TableSpec, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if !self.exists(table)? {
            return Err(fail("storage", format!("missing table {}", table.name)));
        }
        let full = data_key(&self.prefix, &table.name, key)?;
        let old = match self.read_overlay(&full) {
            Some(value) => value,
            None => fetch(&self.trx, &full, false)?,
        };
        self.charge(full.len())?;
        self.writes.insert(full, None);
        Ok(old)
    }
    fn commit(self: Box<Self>) -> Result<()> {
        let FdbWrite {
            trx,
            prefix,
            writes,
            cleared,
            catalog,
            ..
        } = *self;
        for dp in cleared {
            trx.clear_range(&dp, &successor(&dp));
        }
        for (key, value) in writes {
            match value {
                Some(v) => trx.set(&key, &v),
                None => trx.clear(&key),
            }
        }
        for (name, kind) in catalog {
            let key = catalog_key(&prefix, &name);
            match kind {
                Some(kind) => trx.set(&key, &[kind_byte(kind)]),
                None => trx.clear(&key),
            }
        }
        let size = block_on(trx.get_approximate_size()).map_err(|e| fdb_error(e, "storage"))?;
        if size < 0 || size as usize > MAX_MUTATION_BYTES {
            return Err(fail(
                "transaction_limit",
                "FoundationDB transaction size budget exceeded",
            ));
        }
        block_on(trx.commit())
            .map(|_| ())
            .map_err(|e| fdb_error(e.into(), "outcome_unknown"))
    }
}
