//! Transactional byte storage boundary shared by the native engine and adapters.
//! Backend scans are protected reads, including empty ranges. All logical spaces
//! opened by a write transaction participate in its single atomic commit.
use std::{
    collections::VecDeque,
    marker::PhantomData,
    ops::{Bound, RangeBounds},
    sync::{Arc, Mutex},
};

pub mod application_checks;
pub mod concurrency_checks;
pub mod conformance;
pub mod coordination_checks;
pub mod diagnostic_checks;
#[cfg(feature = "foundationdb")]
pub mod foundationdb;
pub mod lifecycle_checks;
mod redb;
#[cfg(feature = "surrealkv")]
pub mod surrealkv;
pub mod target;

pub use crate::native_slice::{Error as StorageError, Result};

/// Private-host redb ownership: a wrong expected identity is rejected by a
/// read-only preview before writable maintenance. Recovery is explicitly refused.
/// The acquired owner is checked again before it can service any operation.
pub(crate) fn open_host_redb<B: crate::binding::Binding>(
    path: &std::path::Path,
    model: Arc<crate::model::Prepared<B>>,
    expected_store: uuid::Uuid,
) -> Result<crate::local::Store<B>> {
    open_host_redb_mode(path, model, expected_store, false)
}

pub(crate) fn recover_host_redb<B: crate::binding::Binding>(
    path: &std::path::Path,
    model: Arc<crate::model::Prepared<B>>,
    expected_store: uuid::Uuid,
) -> Result<crate::local::Store<B>> {
    open_host_redb_mode(path, model, expected_store, true)
}

fn open_host_redb_mode<B: crate::binding::Binding>(
    path: &std::path::Path,
    model: Arc<crate::model::Prepared<B>>,
    expected_store: uuid::Uuid,
    recover: bool,
) -> Result<crate::local::Store<B>> {
    use ::redb::ReadableDatabase;
    fn database_error(error: ::redb::DatabaseError) -> StorageError {
        let code = match error {
            ::redb::DatabaseError::DatabaseAlreadyOpen => "store_busy",
            ::redb::DatabaseError::RepairAborted => "recovery_required",
            _ => "storage",
        };
        StorageError::new(code, "guarded redb open failed")
    }
    fn check<B: crate::binding::Binding>(
        read: &ReadTransaction,
        model: &crate::model::Prepared<B>,
        expected: uuid::Uuid,
    ) -> Result<()> {
        let meta = crate::local::read_meta(read)?;
        let header = crate::local::read_header(read)?;
        if meta.model != model.identity()
            || meta.codec != crate::native_codec::CODEC
            || header.store_id != expected
        {
            return Err(StorageError::new(
                "wrong_target",
                "expected model/store differs",
            ));
        }
        crate::local::check_tables(read)?;
        if !read.list_tables()?.any(|t| t.name() == "authority") {
            return Err(StorageError::new(
                "invalid_config",
                "host requires a secured store",
            ));
        }
        Ok(())
    }
    {
        match ::redb::ReadOnlyDatabase::open(path) {
            Ok(preview) => {
                let read = ReadTransaction::from_redb(
                    preview.begin_read().map_err(crate::local::storage)?,
                );
                check(&read, &model, expected_store)?;
            }
            Err(::redb::DatabaseError::RepairAborted) if recover => {}
            Err(error) => return Err(database_error(error)),
        }
    }
    let mut builder = ::redb::Database::builder();
    if !recover {
        builder.set_repair_callback(|session| session.abort());
    }
    let db = Database::from_redb(builder.open(path).map_err(database_error)?);
    check(&db.begin_read()?, &model, expected_store)?;
    crate::local::Store::open_backend(db, model)
}

fn failure(detail: impl Into<String>) -> StorageError {
    StorageError::new("storage", detail.into())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueKind {
    Bytes,
    U16,
}
#[derive(Clone, Debug)]
pub struct TableSpec {
    pub name: String,
    pub value: ValueKind,
}
pub type Row = (Vec<u8>, Vec<u8>);
pub trait ReadView: Send {
    fn table_exists(&self, table: &TableSpec) -> Result<bool>;
    fn get(&self, table: &TableSpec, key: &[u8]) -> Result<Option<Vec<u8>>>;
    fn scan(
        &self,
        table: &TableSpec,
        start: Bound<Vec<u8>>,
        end: Bound<Vec<u8>>,
        limit: usize,
    ) -> Result<Vec<Row>>;
    fn list_tables(&self) -> Result<Vec<String>>;
    fn has_multimap_tables(&self) -> Result<bool> {
        Ok(false)
    }
    fn len(&self, table: &TableSpec) -> Result<u64> {
        let mut start = Bound::Unbounded;
        let mut count = 0;
        loop {
            let rows = self.scan(table, start, Bound::Unbounded, 64)?;
            count += rows.len() as u64;
            if rows.len() < 64 {
                return Ok(count);
            }
            start = Bound::Excluded(rows.last().expect("nonempty page").0.clone());
        }
    }
}
pub trait WriteView: ReadView {
    fn create_table(&mut self, table: &TableSpec) -> Result<()>;
    fn delete_table(&mut self, table: &TableSpec) -> Result<bool>;
    fn put(&mut self, table: &TableSpec, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>>;
    fn remove(&mut self, table: &TableSpec, key: &[u8]) -> Result<Option<Vec<u8>>>;
    fn commit(self: Box<Self>) -> Result<()>;
}
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct Limits {
    pub max_key_bytes: Option<usize>,
    pub max_value_bytes: Option<usize>,
    pub max_transaction_bytes: Option<usize>,
    pub transaction_lifetime_ms: Option<u64>,
}
pub trait Backend: Send + Sync {
    fn limits(&self) -> Limits {
        Limits::default()
    }
    fn begin_read(&self) -> Result<Box<dyn ReadView>>;
    fn begin_write(&self) -> Result<Box<dyn WriteView>>;
    fn begin_read_diagnostic(
        &self,
        _trace: crate::diagnostics::Recorder,
    ) -> Result<Box<dyn ReadView>> {
        self.begin_read()
    }
    fn begin_write_diagnostic(
        &self,
        _trace: crate::diagnostics::Recorder,
    ) -> Result<Box<dyn WriteView>> {
        self.begin_write()
    }
}
pub struct Database {
    backend: Box<dyn Backend>,
}
impl Database {
    pub fn create(path: impl AsRef<std::path::Path>) -> Result<Self> {
        ::redb::Database::create(path)
            .map(Self::from_redb)
            .map_err(|e| failure(e.to_string()))
    }
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        ::redb::Database::open(path)
            .map(Self::from_redb)
            .map_err(|e| failure(e.to_string()))
    }
    pub fn from_redb(db: ::redb::Database) -> Self {
        Self::new(redb::Redb(db))
    }
    pub fn new(backend: impl Backend + 'static) -> Self {
        Self {
            backend: Box::new(backend),
        }
    }
    pub fn limits(&self) -> Limits {
        self.backend.limits()
    }
    pub fn begin_read_diagnostic(
        &self,
        trace: crate::diagnostics::Recorder,
    ) -> Result<ReadTransaction> {
        let inner = self.backend.begin_read_diagnostic(trace.clone())?;
        Ok(ReadTransaction {
            view: Arc::new(Mutex::new(Box::new(DiagnosticRead { inner, trace }))),
        })
    }
    pub fn begin_write_diagnostic(
        &self,
        trace: crate::diagnostics::Recorder,
    ) -> Result<WriteTransaction> {
        let inner = self.backend.begin_write_diagnostic(trace.clone())?;
        Ok(WriteTransaction {
            view: Arc::new(Mutex::new(Box::new(DiagnosticWrite { inner, trace }))),
        })
    }
    pub fn begin_read(&self) -> Result<ReadTransaction> {
        Ok(ReadTransaction {
            view: Arc::new(Mutex::new(self.backend.begin_read()?)),
        })
    }
    pub fn begin_write(&self) -> Result<WriteTransaction> {
        Ok(WriteTransaction {
            view: Arc::new(Mutex::new(self.backend.begin_write()?)),
        })
    }
}
pub struct ReadTransaction {
    view: Arc<Mutex<Box<dyn ReadView>>>,
}
pub struct WriteTransaction {
    view: Arc<Mutex<Box<dyn WriteView>>>,
}
#[derive(Clone)]
enum View {
    Read(Arc<Mutex<Box<dyn ReadView>>>),
    Write(Arc<Mutex<Box<dyn WriteView>>>),
}
impl View {
    fn read<T>(&self, f: impl FnOnce(&dyn ReadView) -> Result<T>) -> Result<T> {
        match self {
            Self::Read(v) => f(v
                .lock()
                .map_err(|_| failure("transaction lock poisoned"))?
                .as_ref()),
            Self::Write(v) => f(v
                .lock()
                .map_err(|_| failure("transaction lock poisoned"))?
                .as_ref()),
        }
    }
}
pub trait Value: 'static {
    type Owned;
    type Ref<'a>;
    const KIND: ValueKind;
    fn decode(bytes: Vec<u8>) -> Result<Self::Owned>;
    fn value(value: &Self::Owned) -> Self::Ref<'_>;
    fn encode(value: Self::Ref<'_>) -> Vec<u8>;
}
impl Value for &'static [u8] {
    type Owned = Vec<u8>;
    type Ref<'a> = &'a [u8];
    const KIND: ValueKind = ValueKind::Bytes;
    fn decode(bytes: Vec<u8>) -> Result<Vec<u8>> {
        Ok(bytes)
    }
    fn value(value: &Vec<u8>) -> &[u8] {
        value
    }
    fn encode(value: &[u8]) -> Vec<u8> {
        value.to_vec()
    }
}
impl Value for u16 {
    type Owned = u16;
    type Ref<'a> = u16;
    const KIND: ValueKind = ValueKind::U16;
    fn decode(bytes: Vec<u8>) -> Result<u16> {
        Ok(u16::from_be_bytes(
            bytes
                .try_into()
                .map_err(|_| failure("invalid u16 storage value"))?,
        ))
    }
    fn value(value: &u16) -> u16 {
        *value
    }
    fn encode(value: u16) -> Vec<u8> {
        value.to_be_bytes().to_vec()
    }
}
pub struct TableDefinition<'a, K, V> {
    name: &'a str,
    marker: PhantomData<(K, V)>,
}
impl<K, V> Copy for TableDefinition<'_, K, V> {}
impl<K, V> Clone for TableDefinition<'_, K, V> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, K, V> TableDefinition<'a, K, V> {
    pub const fn new(name: &'a str) -> Self {
        Self {
            name,
            marker: PhantomData,
        }
    }
    pub fn name(&self) -> &str {
        self.name
    }
}
impl<K, V: Value> TableDefinition<'_, K, V> {
    fn spec(&self) -> TableSpec {
        TableSpec {
            name: self.name.into(),
            value: V::KIND,
        }
    }
}
pub struct AccessGuard<V: Value> {
    value: V::Owned,
}
impl<V: Value> AccessGuard<V> {
    pub fn value(&self) -> V::Ref<'_> {
        V::value(&self.value)
    }
    fn decode(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self {
            value: V::decode(bytes)?,
        })
    }
}
pub struct Table<K, V> {
    spec: TableSpec,
    view: View,
    marker: PhantomData<(K, V)>,
}
impl ReadTransaction {
    pub fn has_multimap_tables(&self) -> Result<bool> {
        self.view
            .lock()
            .map_err(|_| failure("transaction lock poisoned"))?
            .has_multimap_tables()
    }
    pub fn from_redb(read: ::redb::ReadTransaction) -> Self {
        Self {
            view: Arc::new(Mutex::new(Box::new(redb::Read(read)))),
        }
    }
    pub fn open_table<K, V: Value>(&self, table: TableDefinition<'_, K, V>) -> Result<Table<K, V>> {
        let spec = table.spec();
        if !self
            .view
            .lock()
            .map_err(|_| failure("transaction lock poisoned"))?
            .table_exists(&spec)?
        {
            return Err(failure(format!("missing table {}", spec.name)));
        }
        Ok(Table {
            spec,
            view: View::Read(self.view.clone()),
            marker: PhantomData,
        })
    }
    pub fn list_tables(&self) -> Result<impl Iterator<Item = TableName>> {
        Ok(self
            .view
            .lock()
            .map_err(|_| failure("transaction lock poisoned"))?
            .list_tables()?
            .into_iter()
            .map(TableName))
    }
}
impl WriteTransaction {
    pub fn list_tables(&self) -> Result<impl Iterator<Item = TableName>> {
        Ok(self
            .view
            .lock()
            .map_err(|_| failure("transaction lock poisoned"))?
            .list_tables()?
            .into_iter()
            .map(TableName))
    }
    pub fn open_table<K, V: Value>(&self, table: TableDefinition<'_, K, V>) -> Result<Table<K, V>> {
        let spec = table.spec();
        self.view
            .lock()
            .map_err(|_| failure("transaction lock poisoned"))?
            .create_table(&spec)?;
        Ok(Table {
            spec,
            view: View::Write(self.view.clone()),
            marker: PhantomData,
        })
    }
    pub fn delete_table<K, V: Value>(&self, table: TableDefinition<'_, K, V>) -> Result<bool> {
        self.view
            .lock()
            .map_err(|_| failure("transaction lock poisoned"))?
            .delete_table(&table.spec())
    }
    pub fn commit(self) -> Result<()> {
        Arc::try_unwrap(self.view)
            .map_err(|_| failure("transaction still has open tables"))?
            .into_inner()
            .map_err(|_| failure("transaction lock poisoned"))?
            .commit()
    }
}
pub struct TableName(String);
impl TableName {
    pub fn name(&self) -> &str {
        &self.0
    }
}
pub trait ReadableTable<K, V: Value> {
    fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<AccessGuard<V>>>;
}
impl<K, V: Value> ReadableTable<K, V> for Table<K, V> {
    fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<AccessGuard<V>>> {
        self.view
            .read(|v| v.get(&self.spec, key.as_ref()))?
            .map(AccessGuard::decode)
            .transpose()
    }
}
impl<K, V: Value> Table<K, V> {
    pub fn len(&self) -> Result<u64> {
        self.view.read(|view| view.len(&self.spec))
    }
    pub fn is_empty(&self) -> Result<bool> {
        self.view.read(|view| {
            Ok(view
                .scan(&self.spec, Bound::Unbounded, Bound::Unbounded, 1)?
                .is_empty())
        })
    }
    pub fn iter(&self) -> Result<Range<'_, K, V>> {
        self.range::<&[u8]>(..)
    }
    pub fn range<T: AsRef<[u8]>>(&self, bounds: impl RangeBounds<T>) -> Result<Range<'_, K, V>> {
        let own = |b: Bound<&T>| b.map(|v| v.as_ref().to_vec());
        Ok(Range {
            spec: self.spec.clone(),
            view: self.view.clone(),
            start: own(bounds.start_bound()),
            end: own(bounds.end_bound()),
            rows: VecDeque::new(),
            done: false,
            marker: PhantomData,
        })
    }
    pub fn insert(
        &mut self,
        key: impl AsRef<[u8]>,
        value: V::Ref<'_>,
    ) -> Result<Option<AccessGuard<V>>> {
        let View::Write(view) = &self.view else {
            return Err(failure("read-only transaction"));
        };
        view.lock()
            .map_err(|_| failure("transaction lock poisoned"))?
            .put(&self.spec, key.as_ref(), &V::encode(value))?
            .map(AccessGuard::decode)
            .transpose()
    }
    pub fn remove(&mut self, key: impl AsRef<[u8]>) -> Result<Option<AccessGuard<V>>> {
        let View::Write(view) = &self.view else {
            return Err(failure("read-only transaction"));
        };
        view.lock()
            .map_err(|_| failure("transaction lock poisoned"))?
            .remove(&self.spec, key.as_ref())?
            .map(AccessGuard::decode)
            .transpose()
    }
}
pub struct Range<'a, K, V: Value> {
    spec: TableSpec,
    view: View,
    start: Bound<Vec<u8>>,
    end: Bound<Vec<u8>>,
    rows: VecDeque<Row>,
    done: bool,
    marker: PhantomData<(&'a (), K, V)>,
}
impl<K, V: Value> Iterator for Range<'_, K, V> {
    type Item = Result<(AccessGuard<&'static [u8]>, AccessGuard<V>)>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.rows.is_empty() && !self.done {
            match self
                .view
                .read(|v| v.scan(&self.spec, self.start.clone(), self.end.clone(), 64))
            {
                Ok(rows) => {
                    self.done = rows.len() < 64;
                    self.rows = rows.into();
                }
                Err(e) => {
                    self.done = true;
                    return Some(Err(e));
                }
            }
        }
        let (key, value) = self.rows.pop_front()?;
        self.start = Bound::Excluded(key.clone());
        Some(AccessGuard::decode(key).and_then(|key| Ok((key, AccessGuard::decode(value)?))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const BYTES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("bytes");
    const INDEX: TableDefinition<&[u8], u16> = TableDefinition::new("index");
    #[test]
    fn legacy_adapter_preserves_atomic_spaces_and_read_snapshot() {
        let path = std::env::temp_dir().join(format!("rebase-port-{}.redb", uuid::Uuid::new_v4()));
        let db = Database::from_redb(::redb::Database::create(&path).unwrap());
        let write = db.begin_write().unwrap();
        write
            .open_table(BYTES)
            .unwrap()
            .insert(b"a", b"old".as_slice())
            .unwrap();
        write.open_table(INDEX).unwrap().insert(b"a", 7).unwrap();
        write.commit().unwrap();
        let old = db.begin_read().unwrap();
        let write = db.begin_write().unwrap();
        write
            .open_table(BYTES)
            .unwrap()
            .insert(b"a", b"new".as_slice())
            .unwrap();
        write.open_table(INDEX).unwrap().insert(b"a", 9).unwrap();
        write.commit().unwrap();
        assert_eq!(
            old.open_table(BYTES)
                .unwrap()
                .get(b"a")
                .unwrap()
                .unwrap()
                .value(),
            b"old"
        );
        assert_eq!(
            old.open_table(INDEX)
                .unwrap()
                .get(b"a")
                .unwrap()
                .unwrap()
                .value(),
            7
        );
        {
            let write = db.begin_write().unwrap();
            write.open_table(BYTES).unwrap().remove(b"a").unwrap();
            write.open_table(INDEX).unwrap().remove(b"a").unwrap();
        }
        let read = db.begin_read().unwrap();
        assert_eq!(
            read.open_table(BYTES)
                .unwrap()
                .get(b"a")
                .unwrap()
                .unwrap()
                .value(),
            b"new"
        );
        assert_eq!(
            read.open_table(INDEX)
                .unwrap()
                .get(b"a")
                .unwrap()
                .unwrap()
                .value(),
            9
        );
        drop(read);
        drop(old);
        drop(db);
        std::fs::remove_file(path).unwrap();
    }
}

// Scoped facade instrumentation is allocated only by explicit diagnostic begins.
struct DiagnosticRead {
    inner: Box<dyn ReadView>,
    trace: crate::diagnostics::Recorder,
}
struct DiagnosticWrite {
    inner: Box<dyn WriteView>,
    trace: crate::diagnostics::Recorder,
}
fn diagnostic_get(
    inner: &dyn ReadView,
    trace: &crate::diagnostics::Recorder,
    table: &TableSpec,
    key: &[u8],
) -> Result<Option<Vec<u8>>> {
    let scope = trace.scope("facade", "get", "native", Some(key));
    let result = inner.get(table, key);
    match &result {
        Ok(value) => scope.finish(
            if value.is_some() { "found" } else { "missing" },
            u64::from(value.is_some()),
            if value.is_some() { key.len() as u64 } else { 0 },
            value.as_ref().map_or(0, |v| v.len() as u64),
        ),
        Err(e) => scope.finish(crate::diagnostics::error_outcome(e), 0, 0, 0),
    }
    result
}
fn diagnostic_scan(
    inner: &dyn ReadView,
    trace: &crate::diagnostics::Recorder,
    table: &TableSpec,
    start: Bound<Vec<u8>>,
    end: Bound<Vec<u8>>,
    limit: usize,
) -> Result<Vec<Row>> {
    let scope = trace.scope("facade", "scan", "native", None);
    let result = inner.scan(table, start, end, limit);
    match &result {
        Ok(rows) => scope.finish(
            "success",
            rows.len() as u64,
            rows.iter().map(|r| r.0.len() as u64).sum(),
            rows.iter().map(|r| r.1.len() as u64).sum(),
        ),
        Err(e) => scope.finish(crate::diagnostics::error_outcome(e), 0, 0, 0),
    }
    result
}
macro_rules! diagnostic_read {
    ($ty:ty) => {
        impl ReadView for $ty {
            fn table_exists(&self, t: &TableSpec) -> Result<bool> {
                self.inner.table_exists(t)
            }
            fn get(&self, t: &TableSpec, k: &[u8]) -> Result<Option<Vec<u8>>> {
                diagnostic_get(self.inner.as_ref(), &self.trace, t, k)
            }
            fn scan(
                &self,
                t: &TableSpec,
                s: Bound<Vec<u8>>,
                e: Bound<Vec<u8>>,
                l: usize,
            ) -> Result<Vec<Row>> {
                diagnostic_scan(self.inner.as_ref(), &self.trace, t, s, e, l)
            }
            fn list_tables(&self) -> Result<Vec<String>> {
                self.inner.list_tables()
            }
            fn has_multimap_tables(&self) -> Result<bool> {
                self.inner.has_multimap_tables()
            }
        }
    };
}
diagnostic_read!(DiagnosticRead);
diagnostic_read!(DiagnosticWrite);
impl WriteView for DiagnosticWrite {
    fn create_table(&mut self, t: &TableSpec) -> Result<()> {
        self.inner.create_table(t)
    }
    fn delete_table(&mut self, t: &TableSpec) -> Result<bool> {
        self.inner.delete_table(t)
    }
    fn put(&mut self, t: &TableSpec, k: &[u8], v: &[u8]) -> Result<Option<Vec<u8>>> {
        let scope = self.trace.scope("facade", "put", "native", Some(k));
        let result = self.inner.put(t, k, v);
        scope.finish(
            result
                .as_ref()
                .map_or_else(|e| crate::diagnostics::error_outcome(e), |_| "success"),
            0,
            k.len() as u64,
            v.len() as u64,
        );
        result
    }
    fn remove(&mut self, t: &TableSpec, k: &[u8]) -> Result<Option<Vec<u8>>> {
        let scope = self.trace.scope("facade", "remove", "native", Some(k));
        let result = self.inner.remove(t, k);
        scope.finish(
            result
                .as_ref()
                .map_or_else(|e| crate::diagnostics::error_outcome(e), |_| "success"),
            0,
            k.len() as u64,
            0,
        );
        result
    }
    fn commit(self: Box<Self>) -> Result<()> {
        let Self { inner, trace } = *self;
        // FDB records its actual submitted commit after staged mutations/size checks.
        let scope =
            (!trace.is_foundationdb()).then(|| trace.scope("commit", "commit", "other", None));
        let result = inner.commit();
        if let Some(scope) = scope {
            scope.finish(
                result
                    .as_ref()
                    .map_or_else(|e| crate::diagnostics::error_outcome(e), |_| "success"),
                0,
                0,
                0,
            );
        }
        result
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    use crate::diagnostics::Recorder;
    const DATA: TableDefinition<&[u8], &[u8]> = TableDefinition::new("diagnostic_bytes");

    #[test]
    fn diagnostic_redb_facade_preserves_results_and_counts_selected_primitive_bytes() {
        let path =
            std::env::temp_dir().join(format!("rebase-diagnostic-{}.redb", uuid::Uuid::new_v4()));
        let db = Database::from_redb(::redb::Database::create(&path).unwrap());
        let write = db.begin_write().unwrap();
        write
            .open_table(DATA)
            .unwrap()
            .insert(b"a", b"old".as_slice())
            .unwrap();
        write
            .open_table(DATA)
            .unwrap()
            .insert(b"b", b"keep".as_slice())
            .unwrap();
        write.commit().unwrap();
        let trace = Recorder::new("facade", "attempt", "redb", "Store-control", "control");
        let read = db.begin_read_diagnostic(trace.clone()).unwrap();
        let data = read.open_table(DATA).unwrap();
        assert_eq!(data.get(b"a").unwrap().unwrap().value(), b"old");
        assert!(data.get(b"missing").unwrap().is_none());
        assert_eq!(data.iter().unwrap().count(), 2);
        let report = trace.snapshot("success", 0, None);
        assert_eq!(report.counters.facade_get, 2);
        assert_eq!(report.counters.facade_scan, 1);
        assert_eq!(report.counters.returned_rows, 3);
        assert_eq!(report.counters.read_key_bytes, 3);
        assert_eq!(report.counters.read_value_bytes, 10);
        assert_eq!(report.counters.binding_get, None);
        drop(data);
        drop(read);
        let trace = Recorder::new(
            "facade-write",
            "attempt",
            "redb",
            "Store-control",
            "control",
        );
        let write = db.begin_write_diagnostic(trace.clone()).unwrap();
        assert_eq!(
            write
                .open_table(DATA)
                .unwrap()
                .insert(b"a", b"newer".as_slice())
                .unwrap()
                .unwrap()
                .value(),
            b"old"
        );
        assert_eq!(
            write
                .open_table(DATA)
                .unwrap()
                .remove(b"b")
                .unwrap()
                .unwrap()
                .value(),
            b"keep"
        );
        write.commit().unwrap();
        let report = trace.snapshot("success", 0, None);
        assert!(report.complete);
        assert_eq!(report.counters.returned_rows, 0);
        assert_eq!(report.counters.read_key_bytes, 0);
        assert_eq!(report.counters.read_value_bytes, 0);
        assert_eq!(report.counters.write_key_bytes, 2);
        assert_eq!(report.counters.write_value_bytes, 5);
        assert_eq!(
            report.events.iter().filter(|e| e.layer == "commit").count(),
            1
        );
        assert!(report.commit_ns.is_some());
        let read = db.begin_read().unwrap();
        assert_eq!(
            read.open_table(DATA)
                .unwrap()
                .get(b"a")
                .unwrap()
                .unwrap()
                .value(),
            b"newer"
        );
        assert!(read.open_table(DATA).unwrap().get(b"b").unwrap().is_none());
        drop(read);
        drop(db);
        std::fs::remove_file(path).unwrap();
    }
}
