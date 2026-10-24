//! SurrealKV adapter with validated point reads and conservative range guards.
//!
//! A range read validates all 256 guard buckets for its logical table. Each
//! mutation writes only its key's deterministic bucket. Disjoint point writers
//! can commit independently when their buckets differ; bucket collisions and
//! scans can cause bounded false conflicts. This is deliberately conservative,
//! pending narrower authored range scopes.
use super::{
    Backend, Database, ReadView, Result, Row, StorageError, TableSpec, ValueKind, WriteView,
};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, ops::Bound, path::Path, sync::Arc};
use surrealkv::{Durability, LSMIterator, Mode, Transaction, Tree, TreeBuilder};
use tokio::runtime::{Builder, Runtime};

const CATALOG: &[u8] = b"\0rebase/catalog/";
const CATALOG_GUARD: &[u8] = b"\0rebase/catalog-guard";
const GUARD: &[u8] = b"\0rebase/guard/";
const DATA: &[u8] = b"\0rebase/data/";

struct RuntimeHost(Option<Runtime>);
impl RuntimeHost {
    fn runtime(&self) -> &Runtime {
        self.0.as_ref().expect("live runtime")
    }
}
impl Drop for RuntimeHost {
    fn drop(&mut self) {
        // Dropping a database from an async request must not block/drop a
        // runtime in that request's Tokio context.
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

/// Open a SurrealKV database at `path`. Its dedicated runtime drives the WAL
/// pipeline throughout the backend and every outstanding transaction's life.
pub fn connect(path: impl AsRef<Path>) -> Result<Database> {
    let runtime = RuntimeHost(Some(
        Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(storage)?,
    ));
    let tree = {
        let _entered = runtime.runtime().enter();
        TreeBuilder::new()
            .with_path(path.as_ref().to_path_buf())
            .build()
            .map_err(storage)?
    };
    Ok(Database::new(SurrealBackend {
        host: Arc::new(TreeHost { tree, runtime }),
    }))
}

struct TreeHost {
    tree: Tree,
    runtime: RuntimeHost,
}
impl Drop for TreeHost {
    fn drop(&mut self) {
        // Finish the WAL pipeline and release the directory lock before the
        // runtime goes away. Transactions retain this host until they finish.
        let _entered = self.runtime.runtime().enter();
        let _ = futures::executor::block_on(self.tree.close());
    }
}
struct SurrealBackend {
    host: Arc<TreeHost>,
}
impl Backend for SurrealBackend {
    fn begin_read(&self) -> Result<Box<dyn ReadView>> {
        let tx = self
            .host
            .tree
            .begin_with_mode(Mode::ReadOnly)
            .map_err(storage)?;
        Ok(Box::new(ReadTx {
            tx,
            _host: self.host.clone(),
        }))
    }
    fn begin_write(&self) -> Result<Box<dyn WriteView>> {
        let tx = self
            .host
            .tree
            .begin_with_mode(Mode::ReadWrite)
            .map_err(storage)?
            .with_durability(Durability::Immediate);
        Ok(Box::new(WriteTx {
            tx: RefCell::new(tx),
            host: self.host.clone(),
        }))
    }
}
struct ReadTx {
    tx: Transaction,
    _host: Arc<TreeHost>,
}
// The public port serializes access with its outer mutex. RefCell allows
// get_for_update's mutable bookkeeping through ReadView's shared methods.
struct WriteTx {
    tx: RefCell<Transaction>,
    host: Arc<TreeHost>,
}
fn storage(e: impl std::fmt::Display) -> StorageError {
    StorageError::new("storage", e.to_string())
}
fn cat(t: &TableSpec) -> Vec<u8> {
    [CATALOG, t.name.as_bytes()].concat()
}
fn prefix(t: &TableSpec) -> Vec<u8> {
    [DATA, t.name.as_bytes(), b"\0"].concat()
}
fn key(t: &TableSpec, k: &[u8]) -> Vec<u8> {
    [prefix(t).as_slice(), k].concat()
}
fn guard(t: &TableSpec, bucket: u8) -> Vec<u8> {
    [GUARD, t.name.as_bytes(), b"\0", &[bucket]].concat()
}
fn prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    let last = end
        .iter()
        .rposition(|byte| *byte != 255)
        .expect("internal prefix has successor");
    end[last] += 1;
    end.truncate(last + 1);
    end
}
fn kind(value: Vec<u8>) -> Result<ValueKind> {
    match value.as_slice() {
        [0] => Ok(ValueKind::Bytes),
        [1] => Ok(ValueKind::U16),
        _ => Err(storage("invalid table catalog value")),
    }
}
fn kind_value(value: ValueKind) -> Vec<u8> {
    vec![match value {
        ValueKind::Bytes => 0,
        ValueKind::U16 => 1,
    }]
}
fn validate_kind(value: Option<Vec<u8>>, table: &TableSpec) -> Result<bool> {
    match value {
        Some(value) => {
            if kind(value)? == table.value {
                Ok(true)
            } else {
                Err(storage(format!(
                    "table {} has a different value type",
                    table.name
                )))
            }
        }
        None => Ok(false),
    }
}
fn require(tx: &mut Transaction, table: &TableSpec) -> Result<()> {
    if validate_kind(tx.get_for_update(cat(table)).map_err(storage)?, table)? {
        Ok(())
    } else {
        Err(storage(format!("missing table {}", table.name)))
    }
}
fn protect_range(tx: &mut Transaction, table: &TableSpec) -> Result<()> {
    require(tx, table)?;
    for bucket in 0..=255 {
        tx.get_for_update(guard(table, bucket)).map_err(storage)?;
    }
    Ok(())
}
fn dirty_bucket(tx: &mut Transaction, table: &TableSpec, key: &[u8]) -> Result<()> {
    let bucket = Sha256::digest(key)[0];
    let guard = guard(table, bucket);
    tx.get_for_update(guard.clone()).map_err(storage)?;
    tx.set(guard, uuid::Uuid::new_v4().as_bytes().to_vec())
        .map_err(storage)
}
fn scan(
    tx: &Transaction,
    table: &TableSpec,
    start: Bound<Vec<u8>>,
    end: Bound<Vec<u8>>,
    limit: usize,
) -> Result<Vec<Row>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let prefix = prefix(table);
    let lower = match start {
        Bound::Included(key) => [prefix.as_slice(), &key].concat(),
        Bound::Excluded(key) => [prefix.as_slice(), &key, &[0]].concat(),
        Bound::Unbounded => prefix.clone(),
    };
    let upper = match end {
        Bound::Included(key) => [prefix.as_slice(), &key, &[0]].concat(),
        Bound::Excluded(key) => [prefix.as_slice(), &key].concat(),
        Bound::Unbounded => prefix_end(&prefix),
    };
    if lower >= upper {
        return Ok(Vec::new());
    }
    let mut iterator = tx.range(lower, upper).map_err(storage)?;
    let mut rows = Vec::new();
    if iterator.seek_first().map_err(storage)? {
        while iterator.valid() && rows.len() < limit {
            let key = iterator.key().user_key();
            if !key.starts_with(&prefix) {
                break;
            }
            rows.push((
                key[prefix.len()..].to_vec(),
                iterator.value().map_err(storage)?,
            ));
            if rows.len() == limit || !iterator.next().map_err(storage)? {
                break;
            }
        }
    }
    Ok(rows)
}
fn tables(tx: &Transaction) -> Result<Vec<String>> {
    let mut iterator = tx
        .range(CATALOG.to_vec(), prefix_end(CATALOG))
        .map_err(storage)?;
    let mut names = Vec::new();
    if iterator.seek_first().map_err(storage)? {
        while iterator.valid() {
            let key = iterator.key().user_key();
            if !key.starts_with(CATALOG) {
                break;
            }
            kind(iterator.value().map_err(storage)?)?;
            names.push(String::from_utf8(key[CATALOG.len()..].to_vec()).map_err(storage)?);
            if !iterator.next().map_err(storage)? {
                break;
            }
        }
    }
    Ok(names)
}
impl ReadView for ReadTx {
    fn table_exists(&self, table: &TableSpec) -> Result<bool> {
        validate_kind(self.tx.get(cat(table)).map_err(storage)?, table)
    }
    fn get(&self, table: &TableSpec, k: &[u8]) -> Result<Option<Vec<u8>>> {
        self.tx.get(key(table, k)).map_err(storage)
    }
    fn scan(
        &self,
        table: &TableSpec,
        start: Bound<Vec<u8>>,
        end: Bound<Vec<u8>>,
        limit: usize,
    ) -> Result<Vec<Row>> {
        scan(&self.tx, table, start, end, limit)
    }
    fn list_tables(&self) -> Result<Vec<String>> {
        tables(&self.tx)
    }
}
impl ReadView for WriteTx {
    fn table_exists(&self, table: &TableSpec) -> Result<bool> {
        validate_kind(
            self.tx
                .borrow_mut()
                .get_for_update(cat(table))
                .map_err(storage)?,
            table,
        )
    }
    fn get(&self, table: &TableSpec, k: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut tx = self.tx.borrow_mut();
        require(&mut tx, table)?;
        tx.get_for_update(key(table, k)).map_err(storage)
    }
    fn scan(
        &self,
        table: &TableSpec,
        start: Bound<Vec<u8>>,
        end: Bound<Vec<u8>>,
        limit: usize,
    ) -> Result<Vec<Row>> {
        let mut tx = self.tx.borrow_mut();
        protect_range(&mut tx, table)?;
        scan(&tx, table, start, end, limit)
    }
    fn list_tables(&self) -> Result<Vec<String>> {
        let mut tx = self.tx.borrow_mut();
        tx.get_for_update(CATALOG_GUARD.to_vec()).map_err(storage)?;
        tables(&tx)
    }
}
impl WriteView for WriteTx {
    fn create_table(&mut self, table: &TableSpec) -> Result<()> {
        let tx = self.tx.get_mut();
        if !validate_kind(tx.get_for_update(cat(table)).map_err(storage)?, table)? {
            tx.get_for_update(CATALOG_GUARD.to_vec()).map_err(storage)?;
            tx.set(cat(table), kind_value(table.value))
                .map_err(storage)?;
            tx.set(
                CATALOG_GUARD.to_vec(),
                uuid::Uuid::new_v4().as_bytes().to_vec(),
            )
            .map_err(storage)?;
        }
        Ok(())
    }
    fn delete_table(&mut self, table: &TableSpec) -> Result<bool> {
        let tx = self.tx.get_mut();
        if !validate_kind(tx.get_for_update(cat(table)).map_err(storage)?, table)? {
            return Ok(false);
        }
        protect_range(tx, table)?;
        tx.get_for_update(CATALOG_GUARD.to_vec()).map_err(storage)?;
        let prefix = prefix(table);
        tx.delete_range(prefix.clone(), prefix_end(&prefix))
            .map_err(storage)?;
        tx.delete(cat(table)).map_err(storage)?;
        tx.set(
            CATALOG_GUARD.to_vec(),
            uuid::Uuid::new_v4().as_bytes().to_vec(),
        )
        .map_err(storage)?;
        Ok(true)
    }
    fn put(&mut self, table: &TableSpec, k: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        let tx = self.tx.get_mut();
        require(tx, table)?;
        dirty_bucket(tx, table, k)?;
        let key = key(table, k);
        let old = tx.get_for_update(key.clone()).map_err(storage)?;
        tx.set(key, value.to_vec()).map_err(storage)?;
        Ok(old)
    }
    fn remove(&mut self, table: &TableSpec, k: &[u8]) -> Result<Option<Vec<u8>>> {
        let tx = self.tx.get_mut();
        require(tx, table)?;
        let key = key(table, k);
        let old = tx.get_for_update(key.clone()).map_err(storage)?;
        if old.is_some() {
            dirty_bucket(tx, table, k)?;
            tx.delete(key).map_err(storage)?;
        }
        Ok(old)
    }
    fn commit(self: Box<Self>) -> Result<()> {
        let WriteTx { tx, host } = *self;
        let mut tx = tx.into_inner();
        let _entered = host.runtime.runtime().enter();
        futures::executor::block_on(tx.commit()).map_err(|error| {
            let code = match &error {
                surrealkv::Error::TransactionWriteConflict | surrealkv::Error::TransactionRetry => {
                    "transaction_conflict"
                }
                surrealkv::Error::DatabaseStopped(_) => "outcome_unknown",
                _ => "storage",
            };
            StorageError::new(code, error.to_string())
        })
    }
}
