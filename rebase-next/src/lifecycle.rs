//! Offline/operator lifecycle. These operations are never public RPC methods.
use crate::{
    local::{self, HEADER, KV, LocalStore, PUBLIC, RECEIPTS, RUNTIME, RuntimeHeader},
    model::PreparedModel,
    native_codec::{self, Key, Stored},
    native_slice::{Error, Meta, Result},
    security::{AUTHORITY, READERS},
};
use redb::{Database, ReadableTable, TableHandle};
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
impl LocalStore {
    pub fn backup(&self, destination: impl AsRef<Path>) -> Result<Value> {
        self.check_integrity()?;
        let (read, meta, header) = self.read(self.model().identity())?;
        let payload = local::observe(&read)?; // one consistent snapshot
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
            "store":header.store_id,"revision":meta.revision.to_string(),"operation_epoch":header.operation_epoch.to_string(),"receipts":header.receipts}),
        )
    }

    pub fn archive_receipts(&self, destination: impl AsRef<Path>) -> Result<Value> {
        let backup = self.backup(destination)?;
        let write = self.db.begin_write().map_err(local::storage)?;
        let mut header: RuntimeHeader = local::decode(
            write
                .open_table(RUNTIME)
                .map_err(local::storage)?
                .get(HEADER)
                .map_err(local::storage)?
                .ok_or_else(|| local::corrupt("missing header"))?
                .value(),
        )?;
        let meta = match native_codec::decode(
            &Key::Meta,
            write
                .open_table(KV)
                .map_err(local::storage)?
                .get(Key::Meta.encode().as_slice())
                .map_err(local::storage)?
                .ok_or_else(|| local::corrupt("missing meta"))?
                .value(),
        )? {
            Stored::Meta(meta) => meta,
            _ => return Err(local::corrupt("meta type")),
        };
        if backup["store"] != header.store_id.to_string()
            || backup["revision"]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok())
                != Some(meta.revision)
            || backup["operation_epoch"]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok())
                != Some(header.operation_epoch)
            || backup["receipts"] != header.receipts
        {
            return Err(Error::new(
                "stale_version",
                "store changed during archive; backup retained, receipts unchanged",
            ));
        }
        header.operation_epoch = header
            .operation_epoch
            .checked_add(1)
            .ok_or_else(|| Error::new("revision_exhausted", "operation epoch"))?;
        header.receipts = 0;
        write.delete_table(RECEIPTS).map_err(local::storage)?;
        write.open_table(RECEIPTS).map_err(local::storage)?;
        write
            .open_table(RUNTIME)
            .map_err(local::storage)?
            .insert(HEADER, local::encode(&header)?.as_slice())
            .map_err(local::storage)?;
        write
            .commit()
            .map_err(|e| Error::new("outcome_unknown", e.to_string()))?;
        Ok(
            json!({"status":"archived","backup":backup,"operation_epoch":header.operation_epoch.to_string()}),
        )
    }

    /// All-or-nothing clearing for a disposable store. Principals/grants remain,
    /// but every credential epoch advances and store/cursor identities change.
    /// The explicit expected UUID prevents resetting a different opened store.
    pub fn reset(&self, expected_store: Uuid) -> Result<Value> {
        let write = self.db.begin_write().map_err(local::storage)?;
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
        for def in [KV, RECEIPTS, RUNTIME] {
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
            revision: 0,
            counts: [0; 12],
            reserved: 0,
        };
        write
            .open_table(KV)
            .map_err(local::storage)?
            .insert(
                Key::Meta.encode().as_slice(),
                native_codec::encode(&Key::Meta, &Stored::Meta(meta))?.as_slice(),
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
        write
            .commit()
            .map_err(|e| Error::new("outcome_unknown", e.to_string()))?;
        Ok(
            json!({"status":"reset","store":fresh.store_id,"credential_epochs_advanced":self.secured}),
        )
    }
}

pub fn restore(
    backup: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    model: Arc<PreparedModel>,
) -> Result<Value> {
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
    let expected: BTreeSet<_> = if secured {
        vec![
            "authority",
            "local_runtime",
            "native_kv",
            "operations",
            "public_records",
            "reader_records",
        ]
    } else {
        vec!["local_runtime", "native_kv", "operations", "public_records"]
    }
    .into_iter()
    .map(str::to_owned)
    .collect();
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
    let destination = destination.as_ref();
    let (temp, file) = new_temporary(destination)?;
    let db = Database::builder()
        .create_file(file)
        .map_err(local::storage)?;
    let write = db.begin_write().map_err(local::storage)?;
    for def in [KV, RECEIPTS, RUNTIME, AUTHORITY] {
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
    write.commit().map_err(local::storage)?;
    drop(db);
    let restored = LocalStore::open(&temp.0, model)?;
    let checked = restored.check_integrity()?;
    drop(restored);
    publish(&temp, destination)?;
    Ok(json!({"status":"restored","path":destination,"integrity":checked}))
}
