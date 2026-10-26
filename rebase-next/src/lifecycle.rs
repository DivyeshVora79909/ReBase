//! Offline/operator lifecycle. These operations are never public RPC methods.
use crate::binding::Binding;
use crate::storage::{Database, ReadableTable, WriteTransaction};
use crate::{
    local::{self, HEADER, KV, PUBLIC, RECEIPTS, RUNTIME, RuntimeHeader, Store},
    model::Prepared,
    native_codec::{self, Key, StoredValue},
    native_slice::{Error, Meta, Population, Result},
    security::{AUTHORITY, READERS},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

pub const MAX_BACKUP_BYTES: u64 = 64 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Backup {
    format: String,
    sha256: String,
    payload: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    format: String,
    complete: bool,
    tables: std::collections::BTreeMap<String, Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ByteRow {
    key: String,
    value: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexRow {
    key: String,
    contract: u16,
}
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
fn new_temporary(destination: &Path) -> Result<(Temporary, File)> {
    let path = parent(destination).join(format!(".rebase-{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path).map_err(local::storage)?;
    Ok((Temporary(path), file))
}
fn publish(temp: &Temporary, destination: &Path) -> Result<()> {
    // hard_link is atomic and refuses an existing file/symlink. Never silently
    // overwrite a running or stale database/backup supplied by the operator.
    fs::hard_link(&temp.0, destination).map_err(local::storage)?;
    File::open(parent(destination))
        .and_then(|f| f.sync_all())
        .map_err(local::storage)
}
impl<B: Binding> Store<B> {
    pub fn backup(&self, destination: impl AsRef<Path>) -> Result<Value> {
        self.backup_scoped(destination, None)
    }

    pub(crate) fn backup_scoped(
        &self,
        destination: impl AsRef<Path>,
        expected_store: Option<Uuid>,
    ) -> Result<Value> {
        self.check_integrity()?;
        let (read, _, header) = self.read(self.model().identity())?;
        if expected_store.is_some_and(|expected| expected != header.store_id) {
            return Err(Error::new("wrong_target", "backup store scope changed"));
        }
        let payload = local::observe(&read)?; // one consistent snapshot
        let receipt_count = payload["tables"][RECEIPTS.name()]
            .as_array()
            .ok_or_else(|| local::corrupt("backup receipt inventory"))?
            .len();
        let digest = native_codec::hex(&Sha256::digest(local::encode(&payload)?));
        let bytes = local::encode(&Backup {
            format: "rebase-backup-1".into(),
            sha256: digest.clone(),
            payload,
        })?;
        if bytes.len() as u64 > MAX_BACKUP_BYTES {
            return Err(Error::new("work_limit", "backup byte limit"));
        }
        let destination = destination.as_ref();
        let (temp, mut file) = new_temporary(destination)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(local::storage)?;
        drop(file);
        publish(&temp, destination)?;
        Ok(
            json!({"status":"backed_up","bytes":bytes.len(),"sha256":digest,"path":destination,
            "store":header.store_id,"operation_epoch":header.operation_epoch.to_string(),"receipts":receipt_count}),
        )
    }

    pub fn archive_receipts(&self, destination: impl AsRef<Path>) -> Result<Value> {
        self.archive_receipts_scoped(destination, None)
    }

    pub(crate) fn archive_receipts_scoped(
        &self,
        destination: impl AsRef<Path>,
        expected_store: Option<Uuid>,
    ) -> Result<Value> {
        let backup = self.backup_scoped(destination, expected_store)?;
        let write = self.begin_write().map_err(local::storage)?;
        self.archive_cleanup(write, &backup)
    }

    /// The caller supplies the already published complete backup. This seam
    /// also permits real adapter schedules to stage cleanup before a competitor.
    pub(crate) fn archive_cleanup(&self, write: WriteTransaction, backup: &Value) -> Result<Value> {
        // Protect every table/range through cleanup commit, including effects
        // and authority changes that need not alter any domain record token.
        let image = local::observe_write(&write)?;
        let digest = native_codec::hex(&Sha256::digest(local::encode(&image)?));
        if backup["sha256"] != digest {
            return Err(Error::new(
                "stale_version",
                "store changed during archive; backup retained, receipts unchanged",
            ));
        }
        let mut header: RuntimeHeader = local::decode(
            write
                .open_table(RUNTIME)
                .map_err(local::storage)?
                .get(HEADER)
                .map_err(local::storage)?
                .ok_or_else(|| local::corrupt("missing header"))?
                .value(),
        )?;
        local::validate_header(&header)?;
        header.operation_epoch = header
            .operation_epoch
            .checked_add(1)
            .ok_or_else(|| Error::new("revision_exhausted", "operation epoch"))?;
        for table in [RECEIPTS, crate::receipts::SLOTS] {
            write.delete_table(table).map_err(local::storage)?;
            write.open_table(table).map_err(local::storage)?;
        }
        write
            .open_table(RUNTIME)
            .map_err(local::storage)?
            .insert(HEADER, local::encode(&header)?.as_slice())
            .map_err(local::storage)?;
        write.commit()?;
        Ok(
            json!({"status":"archived","backup":backup,"operation_epoch":header.operation_epoch.to_string()}),
        )
    }

    /// All-or-nothing clearing for a disposable store. Principals/grants remain,
    /// but every credential epoch advances and store/cursor identities change.
    /// The explicit expected UUID prevents resetting a different opened store.
    pub fn reset(&self, expected_store: Uuid) -> Result<Value> {
        let write = self.begin_write().map_err(local::storage)?;
        let header: RuntimeHeader = local::decode(
            write
                .open_table(RUNTIME)
                .map_err(local::storage)?
                .get(HEADER)
                .map_err(local::storage)?
                .ok_or_else(|| local::corrupt("missing header"))?
                .value(),
        )?;
        if header.store_id != expected_store {
            return Err(Error::new(
                "invalid_input",
                "reset store confirmation differs",
            ));
        }
        crate::effects::reset_tables::<B>(&write)?;
        let mut graph = if self.secured {
            Some(crate::security::write_graph(&write)?.graph)
        } else {
            None
        };
        if let Some(graph) = &mut graph {
            for p in &mut graph.principals {
                p.credential_epoch = p
                    .credential_epoch
                    .checked_add(1)
                    .ok_or_else(|| Error::new("revision_exhausted", "credential epoch"))?;
            }
        }
        for def in [
            KV,
            RECEIPTS,
            RUNTIME,
            crate::receipts::SLOTS,
            crate::query::EPOCHS,
        ] {
            write.delete_table(def).map_err(local::storage)?;
            write.open_table(def).map_err(local::storage)?;
        }
        write.delete_table(PUBLIC).map_err(local::storage)?;
        write.open_table(PUBLIC).map_err(local::storage)?;
        if self.secured {
            write.delete_table(AUTHORITY).map_err(local::storage)?;
            write.delete_table(READERS).map_err(local::storage)?;
            write.open_table(READERS).map_err(local::storage)?;
        }
        let meta = Meta {
            model: self.model().identity().into(),
            codec: native_codec::CODEC.into(),
            tenant: self.context.tenant,
            actor: self.bootstrap_actor,
        };
        write
            .open_table(KV)
            .map_err(local::storage)?
            .insert(
                Key::Meta.encode().as_slice(),
                native_codec::encode_for::<B>(&Key::Meta, &StoredValue::Meta(meta))?.as_slice(),
            )
            .map_err(local::storage)?;
        let population = Population {
            counts: self.model.contracts().map(|c| (c.code, 0)).collect(),
            reserved: 0,
        };
        write
            .open_table(KV)
            .map_err(local::storage)?
            .insert(
                Key::Population.encode().as_slice(),
                native_codec::encode_for::<B>(
                    &Key::Population,
                    &StoredValue::Population(population),
                )?
                .as_slice(),
            )
            .map_err(local::storage)?;
        let fresh = RuntimeHeader::fresh();
        write
            .open_table(RUNTIME)
            .map_err(local::storage)?
            .insert(HEADER, local::encode(&fresh)?.as_slice())
            .map_err(local::storage)?;
        if let Some(graph) = graph {
            crate::security::store_graph(&write, &graph.prepare()?)?;
        }
        write.commit()?;
        Ok(
            json!({"status":"reset","store":fresh.store_id,"credential_epochs_advanced":self.secured}),
        )
    }
}

fn read_backup_image(backup: impl AsRef<Path>) -> Result<Observation> {
    let mut bytes = vec![];
    File::open(backup)
        .map_err(local::storage)?
        .take(MAX_BACKUP_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(local::storage)?;
    let backup: Backup = serde_json::from_value(crate::json::parse_bounded(
        &bytes,
        MAX_BACKUP_BYTES as usize,
    )?)
    .map_err(local::storage)?;
    if backup.format != "rebase-backup-1"
        || backup.sha256 != native_codec::hex(&Sha256::digest(local::encode(&backup.payload)?))
    {
        return Err(Error::new("invalid_input", "backup format/checksum"));
    }
    let image: Observation = serde_json::from_value(backup.payload).map_err(local::storage)?;
    let secured = image.tables.contains_key("authority");
    let expected: BTreeSet<_> = local::table_names(secured).into_iter().collect();
    if !image.complete
        || image.tables.keys().cloned().collect::<BTreeSet<_>>() != expected
        || image.format
            != if secured {
                "rebase-authorized-observation-1"
            } else {
                "rebase-local-observation-1"
            }
    {
        return Err(Error::new(
            "invalid_input",
            "complete backup inventory required",
        ));
    }
    Ok(image)
}

/// Read only protected backup metadata before activating a requested destination.
pub(crate) fn backup_store(backup: impl AsRef<Path>) -> Result<Uuid> {
    let image = read_backup_image(backup)?;
    let rows: Vec<ByteRow> = serde_json::from_value(
        image
            .tables
            .get(RUNTIME.name())
            .cloned()
            .ok_or_else(|| local::corrupt("backup header table"))?,
    )
    .map_err(local::storage)?;
    if rows.len() != 1 || rows[0].key != native_codec::hex(HEADER) {
        return Err(local::corrupt("backup header inventory"));
    }
    let header: RuntimeHeader = local::decode(&local::unhex(&rows[0].value)?)?;
    local::validate_header(&header)?;
    Ok(header.store_id)
}

pub fn restore<B: Binding>(
    backup: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    model: Arc<Prepared<B>>,
) -> Result<Value> {
    let image = read_backup_image(backup)?;
    let destination = destination.as_ref();
    let (temp, file) = new_temporary(destination)?;
    let db = redb::Database::builder()
        .create_file(file)
        .map_err(local::storage)?;
    let db = Database::from_redb(db);
    let write = db.begin_write().map_err(local::storage)?;
    import_image(&write, &image)?;
    write.commit().map_err(local::storage)?;
    drop(db);
    let restored = Store::open(&temp.0, model)?;
    // Validate the supplied image before changing its activation. Never repair
    // a corrupt backup into something that passes validation.
    let checked = restored.check_integrity()?;
    let write = restored.db.begin_write().map_err(local::storage)?;
    let changed = crate::effects::quarantine_restore::<B>(&write)?;
    write.commit().map_err(local::storage)?;
    let checked = if changed {
        restored.check_integrity()?
    } else {
        checked
    };
    drop(restored);
    publish(&temp, destination)?;
    Ok(json!({"status":"restored","path":destination,"integrity":checked}))
}

/// Restore a validated, quarantined image into a fresh transactional backend.
/// Validation runs in a disposable redb store before the destination is opened
/// for publication; the destination receives every application table at once.
pub fn restore_to_backend<B: Binding>(
    backup: impl AsRef<Path>,
    db: Database,
    model: Arc<Prepared<B>>,
) -> Result<Value> {
    restore_backend_after_validation(backup, model, || Ok(db))
}

/// The destination opener runs only after native validation and quarantine.
pub(crate) fn restore_backend_after_validation<B: Binding>(
    backup: impl AsRef<Path>,
    model: Arc<Prepared<B>>,
    create: impl FnOnce() -> Result<Database>,
) -> Result<Value> {
    let validation_path =
        std::env::temp_dir().join(format!("rebase-restore-validation-{}.redb", Uuid::new_v4()));
    restore(backup, &validation_path, model.clone())?;
    // The existing restore publishes with create-only semantics. Own cleanup
    // only after publication succeeds, so an existing destination is untouched.
    let validation = Temporary(validation_path);
    let quarantined = Store::open(&validation.0, model.clone())?;
    let image: Observation =
        serde_json::from_value(quarantined.observe_for_verification()?).map_err(local::storage)?;
    drop(quarantined);

    let db = create()?;
    let write = db.begin_write().map_err(local::storage)?;
    if write.list_tables()?.next().is_some() {
        return Err(Error::new("storage_exists", "destination must be empty"));
    }
    import_image(&write, &image)?;
    write.commit().map_err(local::storage)?;
    let restored = Store::open_backend(db, model)?;
    let checked = restored.check_integrity()?;
    Ok(json!({"status":"restored","integrity":checked}))
}

fn import_image(write: &WriteTransaction, image: &Observation) -> Result<()> {
    for def in [
        KV,
        RECEIPTS,
        RUNTIME,
        AUTHORITY,
        crate::receipts::SLOTS,
        crate::query::EPOCHS,
    ]
    .into_iter()
    .chain(crate::effects::TABLES.iter().map(|(def, _)| *def))
    {
        let Some(rows) = image.tables.get(def.name()) else {
            continue;
        };
        let rows: Vec<ByteRow> = serde_json::from_value(rows.clone()).map_err(local::storage)?;
        let mut table = write.open_table(def).map_err(local::storage)?;
        for row in rows {
            let key = local::unhex(&row.key)?;
            let value = local::unhex(&row.value)?;
            if table
                .insert(key.as_slice(), value.as_slice())
                .map_err(local::storage)?
                .is_some()
            {
                return Err(Error::new("invalid_input", "duplicate backup key"));
            }
        }
    }
    for def in [PUBLIC, READERS] {
        let Some(rows) = image.tables.get(def.name()) else {
            continue;
        };
        let rows: Vec<IndexRow> = serde_json::from_value(rows.clone()).map_err(local::storage)?;
        let mut table = write.open_table(def).map_err(local::storage)?;
        for row in rows {
            let key = local::unhex(&row.key)?;
            if table
                .insert(key.as_slice(), row.contract)
                .map_err(local::storage)?
                .is_some()
            {
                return Err(Error::new("invalid_input", "duplicate backup index key"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod scoped_tests {
    use super::*;

    #[test]
    fn invalid_restore_never_calls_the_optional_backend_opener() {
        let path =
            std::env::temp_dir().join(format!("rebase-invalid-backup-{}.json", Uuid::new_v4()));
        fs::write(&path, b"{}").unwrap();
        let opened = std::cell::Cell::new(false);
        let result = restore_backend_after_validation(
            &path,
            Arc::new(crate::model::PreparedModel::load().unwrap()),
            || {
                opened.set(true);
                Err(Error::new("internal", "must not open destination"))
            },
        );
        assert!(result.is_err());
        assert!(!opened.get());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn stale_scope_cannot_publish_backup_or_archive_a_reset_store() {
        let directory =
            std::env::temp_dir().join(format!("rebase-scoped-archive-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let model = Arc::new(crate::model::PreparedModel::load().unwrap());
        let store = crate::local::LocalStore::create_secured(
            directory.join("store.redb"),
            model.clone(),
            crate::native_slice::Context {
                tenant: Uuid::from_u128(1),
                actor: Uuid::from_u128(2),
            },
        )
        .unwrap();
        let (_, _, header) = store.read(model.identity()).unwrap();
        let backup = store.backup(directory.join("before.json")).unwrap();
        store.reset(header.store_id).unwrap();
        let before = store.observe_for_verification().unwrap();
        for archive in [false, true] {
            let destination = directory.join(format!("rejected-{archive}.json"));
            let result = if archive {
                store.archive_receipts_scoped(&destination, Some(header.store_id))
            } else {
                store.backup_scoped(&destination, Some(header.store_id))
            };
            assert_eq!(result.unwrap_err().code, "wrong_target");
            assert!(!destination.exists());
        }
        // A reset after a correctly scoped backup must also fence cleanup.
        assert_eq!(
            store
                .archive_cleanup(store.db.begin_write().unwrap(), &backup)
                .unwrap_err()
                .code,
            "stale_version"
        );
        assert_eq!(store.observe_for_verification().unwrap(), before);
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }
}
