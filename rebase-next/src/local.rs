//! Embedded local adapter. Engine data, reader index and operation receipts share
//! one redb write transaction. Public API entrypoints never enable fixture mode.

use std::{collections::BTreeSet, fs::OpenOptions, path::Path, sync::Arc};

use redb::{
    Database, ReadTransaction, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition, TableHandle,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    model::{PreparedModel, Visibility},
    native_codec::{self, Key, Stored, decimal, uuid_text},
    native_slice::{
        Command, Context, Error, Input, Meta, Record, Result, Workspace, settle_with_ids,
    },
};

pub(crate) const KV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("native_kv");
pub(crate) const PUBLIC: TableDefinition<&[u8], u16> = TableDefinition::new("public_records");
pub(crate) const RECEIPTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("operations");
pub(crate) const RUNTIME: TableDefinition<&[u8], &[u8]> = TableDefinition::new("local_runtime");
pub(crate) const HEADER: &[u8] = b"header";
pub const STORE_FORMAT: &str = "rebase-local-store-1";
pub const MAX_RECEIPTS: u16 = 1024;
pub const MUTATION_WORK_LIMIT: u64 = 200_000;

pub(crate) fn storage(error: impl std::fmt::Display) -> Error {
    Error::new("storage", error.to_string())
}

pub(crate) fn corrupt(detail: &str) -> Error {
    Error::new("corrupt_state", detail)
}

pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| Error::new("codec", e.to_string()))
}

pub(crate) fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|e| Error::new("corrupt_state", e.to_string()))
}

pub(crate) fn unhex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::new("invalid_cursor", "canonical hex required"));
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| {
                if b.is_ascii_digit() {
                    b - b'0'
                } else {
                    b - b'a' + 10
                }
            };
            Ok(digit(pair[0]) * 16 + digit(pair[1]))
        })
        .collect()
}

mod canonical_ids {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};
    use uuid::Uuid;
    pub fn serialize<S: Serializer>(ids: &[Uuid], serializer: S) -> Result<S::Ok, S::Error> {
        ids.serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Uuid>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|text| {
                let id = Uuid::parse_str(&text).map_err(D::Error::custom)?;
                if id.to_string() != text {
                    return Err(D::Error::custom("noncanonical UUID"));
                }
                Ok(id)
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mutation {
    pub model: String,
    #[serde(with = "uuid_text")]
    pub operation_id: Uuid,
    pub commands: Vec<Command>,
    #[serde(with = "canonical_ids")]
    pub returning: Vec<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicRecord {
    #[serde(with = "uuid_text")]
    pub id: Uuid,
    pub contract: u16,
    #[serde(with = "decimal")]
    pub version: u64,
    pub input: Input,
    pub derived: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Returned {
    #[serde(with = "uuid_text")]
    pub id: Uuid,
    pub record: Option<PublicRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Committed {
    #[serde(with = "uuid_text")]
    pub operation_id: Uuid,
    #[serde(with = "decimal")]
    pub revision: u64,
    pub records: Vec<Returned>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    model: String,
    #[serde(with = "uuid_text")]
    tenant: Uuid,
    #[serde(with = "uuid_text")]
    actor: Uuid,
    request_hash: String,
    pub(crate) result: Committed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeHeader {
    format: String,
    #[serde(with = "uuid_text")]
    pub(crate) store_id: Uuid,
    pub(crate) cursor_key: String,
    receipts: u16,
}

pub struct LocalStore {
    pub(crate) db: Database,
    pub(crate) model: Arc<PreparedModel>,
    pub(crate) context: Context,
}

impl LocalStore {
    pub fn create(
        path: impl AsRef<Path>,
        model: Arc<PreparedModel>,
        context: Context,
    ) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(storage)?;
        let db = Database::builder().create_file(file).map_err(storage)?;
        let write = db.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(KV).map_err(storage)?;
            let meta = Meta {
                model: model.identity().into(),
                codec: native_codec::CODEC.into(),
                tenant: context.tenant,
                actor: context.actor,
                revision: 0,
                counts: [0; 12],
                reserved: 0,
            };
            let bytes = native_codec::encode(&Key::Meta, &Stored::Meta(meta))?;
            table
                .insert(Key::Meta.encode().as_slice(), bytes.as_slice())
                .map_err(storage)?;
            write.open_table(PUBLIC).map_err(storage)?;
            write.open_table(RECEIPTS).map_err(storage)?;
            let mut key = vec![];
            key.extend_from_slice(Uuid::new_v4().as_bytes());
            key.extend_from_slice(Uuid::new_v4().as_bytes());
            let header = RuntimeHeader {
                format: STORE_FORMAT.into(),
                store_id: Uuid::new_v4(),
                cursor_key: native_codec::hex(&key),
                receipts: 0,
            };
            write
                .open_table(RUNTIME)
                .map_err(storage)?
                .insert(HEADER, encode(&header)?.as_slice())
                .map_err(storage)?;
        }
        write
            .commit()
            .map_err(|e| Error::new("outcome_unknown", e.to_string()))?;
        Ok(Self { db, model, context })
    }

    pub fn open(path: impl AsRef<Path>, model: Arc<PreparedModel>) -> Result<Self> {
        let db = Database::open(path).map_err(storage)?;
        let read = db.begin_read().map_err(storage)?;
        check_tables(&read)?;
        let meta = read_meta(&read)?;
        let context = Context {
            tenant: meta.tenant,
            actor: meta.actor,
        };
        let store = Self { db, model, context };
        store.check_meta(&meta, store.model.identity())?;
        read_header(&read)?;
        let public = read.open_table(PUBLIC).map_err(storage)?;
        if public.len().map_err(storage)?
            != meta.counts[..10].iter().map(|&n| u64::from(n)).sum::<u64>()
        {
            return Err(corrupt("public index population"));
        }
        let header = read_header(&read)?;
        if read
            .open_table(RECEIPTS)
            .map_err(storage)?
            .len()
            .map_err(storage)?
            != u64::from(header.receipts)
        {
            return Err(corrupt("receipt population"));
        }
        Ok(store)
    }

    pub fn model(&self) -> &PreparedModel {
        &self.model
    }
    pub fn context(&self) -> Context {
        self.context
    }

    pub(crate) fn check_meta(&self, meta: &Meta, requested: &str) -> Result<()> {
        if requested != self.model.identity()
            || meta.model != self.model.identity()
            || meta.codec != native_codec::CODEC
        {
            return Err(Error::new("model_mismatch", "store/model identity differs"));
        }
        if meta.tenant != self.context.tenant || meta.actor != self.context.actor {
            return Err(Error::new("forbidden", "local context differs"));
        }
        Ok(())
    }

    pub(crate) fn read(&self, requested: &str) -> Result<(ReadTransaction, Meta, RuntimeHeader)> {
        let read = self.db.begin_read().map_err(storage)?;
        let meta = read_meta(&read)?;
        self.check_meta(&meta, requested)?;
        let header = read_header(&read)?;
        Ok((read, meta, header))
    }

    pub(crate) fn project(&self, id: Uuid, record: Option<Record>) -> Option<PublicRecord> {
        let record = record?;
        if record.tenant != self.context.tenant
            || record.reader != self.context.actor
            || self.model.contract(record.contract).ok()?.visibility != Visibility::Public
        {
            return None;
        }
        let declared = self.model.contract(record.contract).ok()?;
        let derived = record.derived.map(|value| {
            let all = serde_json::to_value(value).expect("exact derived scalars serialize");
            Value::Object(
                declared
                    .published
                    .iter()
                    .filter_map(|field| {
                        all.get(field.name)
                            .map(|value| (field.name.into(), value.clone()))
                    })
                    .collect(),
            )
        });
        Some(PublicRecord {
            id,
            contract: record.contract,
            version: record.version,
            input: record.input,
            derived,
        })
    }

    pub fn get(&self, model: &str, id: Uuid) -> Result<Option<PublicRecord>> {
        let (read, _, _) = self.read(model)?;
        let table = read.open_table(KV).map_err(storage)?;
        let mut ws = Workspace::new(
            |key: &[u8]| {
                table
                    .get(key)
                    .map(|v| v.map(|v| v.value().to_vec()))
                    .map_err(storage)
            },
            1000,
        );
        Ok(self.project(id, ws.record(id)?))
    }

    pub fn mutate(&self, request: &Mutation) -> Result<Value> {
        self.mutate_with_ids(request, &mut || Ok(Uuid::new_v4()))
    }

    /// Trusted adapter-check seam, never selected by a client request. It uses
    /// the same public command path and cannot create fixture-only Pin records.
    pub fn mutate_with_ids(
        &self,
        request: &Mutation,
        allocate: &mut dyn FnMut() -> Result<Uuid>,
    ) -> Result<Value> {
        self.mutate_inner(request, allocate, None)
    }

    fn mutate_inner(
        &self,
        request: &Mutation,
        allocate: &mut dyn FnMut() -> Result<Uuid>,
        abort_after: Option<usize>,
    ) -> Result<Value> {
        if request.returning.len() > 32
            || request.returning.iter().collect::<BTreeSet<_>>().len() != request.returning.len()
        {
            return Err(Error::new(
                "invalid_input",
                "returning requires at most 32 unique IDs",
            ));
        }
        let normalized = encode(&serde_json::to_value(request).map_err(storage)?)?;
        if normalized.len() > crate::json::MAX_REQUEST_BYTES {
            return Err(Error::new("request_limit", "normalized request byte limit"));
        }
        let mut hash = Sha256::new();
        hash.update(b"rebase-local-operation-v1\0");
        hash.update(self.context.tenant.as_bytes());
        hash.update(self.context.actor.as_bytes());
        hash.update(&normalized);
        let request_hash = native_codec::hex(&hash.finalize());
        let write = self.db.begin_write().map_err(storage)?;
        let mut header: RuntimeHeader;
        let (batch, result) = {
            let table = write.open_table(KV).map_err(storage)?;
            let mut ws = Workspace::new(
                |key: &[u8]| {
                    table
                        .get(key)
                        .map(|v| v.map(|v| v.value().to_vec()))
                        .map_err(storage)
                },
                MUTATION_WORK_LIMIT,
            );
            let Some(Stored::Meta(meta)) = ws.get(&Key::Meta)? else {
                return Err(corrupt("missing model header"));
            };
            self.check_meta(&meta, &request.model)?;
            header = decode(
                write
                    .open_table(RUNTIME)
                    .map_err(storage)?
                    .get(HEADER)
                    .map_err(storage)?
                    .ok_or_else(|| corrupt("missing runtime header"))?
                    .value(),
            )?;
            validate_header(&header)?;
            let receipts = write.open_table(RECEIPTS).map_err(storage)?;
            if let Some(bytes) = receipts
                .get(request.operation_id.as_bytes().as_slice())
                .map_err(storage)?
            {
                let receipt: Receipt = decode(bytes.value())?;
                self.check_receipt(&receipt, request.operation_id)?;
                if receipt.request_hash != request_hash {
                    return Err(Error::new(
                        "operation_conflict",
                        "operation ID bound to different request",
                    ));
                }
                return Ok(json!({"status":"committed","replayed":true,"result":receipt.result}));
            }
            if header.receipts >= MAX_RECEIPTS {
                return Err(Error::new("receipt_limit", "receipt retention exhausted"));
            }
            for command in &request.commands {
                match command {
                    Command::Create {
                        contract, fields, ..
                    } => {
                        self.model.public_contract(*contract)?;
                        self.model.validate(*contract, fields)?;
                    }
                    Command::Update { id, set, unset, .. } => {
                        if let Some(record) = ws.record(*id)? {
                            let contract = self.model.public_contract(record.contract)?;
                            if !unset.is_empty()
                                || set.keys().any(|k| {
                                    !contract.fields.iter().any(|f| f.name == k && f.mutable)
                                })
                            {
                                return Err(Error::new(
                                    "invalid_input",
                                    "protected or required field",
                                ));
                            }
                            let mut input = serde_json::to_value(&record.input).map_err(storage)?;
                            input
                                .as_object_mut()
                                .expect("typed input")
                                .extend(set.clone());
                            self.model.validate(record.contract, &input)?;
                        }
                    }
                    Command::Delete { .. } => {}
                }
            }
            let settled = settle_with_ids(
                &mut ws,
                self.model.engine(),
                self.context,
                &request.commands,
                allocate,
            )?;
            let mut records = vec![];
            for &id in &request.returning {
                records.push(Returned {
                    id,
                    record: self.project(id, ws.record(id)?),
                });
            }
            let result = Committed {
                operation_id: request.operation_id,
                revision: settled.revision,
                records,
            };
            (ws.finish()?, result)
        };
        {
            let mut table = write.open_table(KV).map_err(storage)?;
            let mut index = write.open_table(PUBLIC).map_err(storage)?;
            for (i, (key, value)) in batch.iter().enumerate() {
                if let Key::Record(id) = Key::decode(key)? {
                    match value
                        .as_deref()
                        .map(|v| native_codec::decode(&Key::Record(id), v))
                        .transpose()?
                    {
                        Some(Stored::Record(record))
                            if self.model.contract(record.contract)?.visibility
                                == Visibility::Public =>
                        {
                            index
                                .insert(id.as_bytes().as_slice(), record.contract)
                                .map_err(storage)?;
                        }
                        _ => {
                            index.remove(id.as_bytes().as_slice()).map_err(storage)?;
                        }
                    }
                }
                match value {
                    Some(value) => {
                        table
                            .insert(key.as_slice(), value.as_slice())
                            .map_err(storage)?;
                    }
                    None => {
                        table.remove(key.as_slice()).map_err(storage)?;
                    }
                }
                if abort_after == Some(i + 1) {
                    return Err(Error::new(
                        "injected_abort",
                        "adapter check after physical writes",
                    ));
                }
            }
        }
        let receipt = Receipt {
            model: self.model.identity().into(),
            tenant: self.context.tenant,
            actor: self.context.actor,
            request_hash,
            result: result.clone(),
        };
        {
            write
                .open_table(RECEIPTS)
                .map_err(storage)?
                .insert(
                    request.operation_id.as_bytes().as_slice(),
                    encode(&receipt)?.as_slice(),
                )
                .map_err(storage)?;
            header.receipts += 1;
            write
                .open_table(RUNTIME)
                .map_err(storage)?
                .insert(HEADER, encode(&header)?.as_slice())
                .map_err(storage)?;
        }
        if abort_after == Some(usize::MAX) {
            return Err(Error::new(
                "injected_abort",
                "adapter check after receipt write",
            ));
        }
        write
            .commit()
            .map_err(|e| Error::new("outcome_unknown", e.to_string()))?;
        Ok(json!({"status":"committed","replayed":false,"result":result}))
    }

    fn check_receipt(&self, receipt: &Receipt, id: Uuid) -> Result<()> {
        if receipt.model != self.model.identity()
            || receipt.tenant != self.context.tenant
            || receipt.actor != self.context.actor
            || receipt.result.operation_id != id
        {
            return Err(corrupt("receipt binding"));
        }
        Ok(())
    }

    pub fn operation_status(&self, model: &str, id: Uuid) -> Result<Value> {
        let (read, _, _) = self.read(model)?;
        let table = read.open_table(RECEIPTS).map_err(storage)?;
        let Some(value) = table.get(id.as_bytes().as_slice()).map_err(storage)? else {
            return Ok(json!({"status":"not_observed"}));
        };
        let receipt: Receipt = decode(value.value())?;
        self.check_receipt(&receipt, id)?;
        Ok(json!({"status":"committed","result":receipt.result}))
    }

    /// Trusted local developer view. No signing material or raw storage write API.
    pub fn inspect(&self) -> Result<Value> {
        let (read, meta, header) = self.read(self.model.identity())?;
        check_tables(&read)?;
        let table = read.open_table(KV).map_err(storage)?;
        let mut records = vec![];
        let mut roots = vec![];
        let mut queries = vec![];
        let mut roles = vec![];
        for (i, row) in table.iter().map_err(storage)?.enumerate() {
            if i >= 4096 {
                return Err(Error::new("work_limit", "inspection row limit"));
            }
            let (key, value) = row.map_err(storage)?;
            let key = Key::decode(key.value())?;
            match (&key,native_codec::decode(&key,value.value())?) {
                (Key::Record(id),Stored::Record(record))=>records.push(json!({"id":id,"record":record})),
                (Key::Root(address),Stored::Root(root))=>roots.push(json!({"root":address,"revision":root.revision.to_string(),"summary":root.summary})),
                (Key::Query(address),Stored::Query(query))=>queries.push(json!({"query":address,"descriptor":query})),
                (Key::Role(address),Stored::Role(role))=>roles.push(json!({"source_role":address,"binding":role})),
                _=>{}
            }
        }
        Ok(
            json!({"model":meta.model,"codec":meta.codec,"store":header.store_id,"revision":meta.revision.to_string(),
            "tenant":meta.tenant,"actor":meta.actor,"receipt_count":header.receipts,"records":records,"roots":roots,"queries":queries,"roles":roles}),
        )
    }
    /// Complete privileged application-table observation for independent local
    /// checks. This is absent from the public RPC operation list. Runtime bytes
    /// include this disposable test store's signing material.
    pub fn observe_for_verification(&self) -> Result<Value> {
        let (read, _, _) = self.read(self.model.identity())?;
        observe(&read)
    }
}

fn observe(read: &ReadTransaction) -> Result<Value> {
    check_tables(read)?;
    let mut tables = serde_json::Map::new();
    for (definition, limit) in [
        (KV, 4096),
        (RUNTIME, 1),
        (RECEIPTS, usize::from(MAX_RECEIPTS)),
    ] {
        let table = read.open_table(definition).map_err(storage)?;
        let mut rows = vec![];
        for (i, row) in table.iter().map_err(storage)?.enumerate() {
            if i >= limit {
                return Err(Error::new("work_limit", "observation is incomplete"));
            }
            let (key, value) = row.map_err(storage)?;
            rows.push(json!({"key":native_codec::hex(key.value()),"value":native_codec::hex(value.value())}));
        }
        tables.insert(definition.name().into(), json!(rows));
    }
    let table = read.open_table(PUBLIC).map_err(storage)?;
    let mut rows = vec![];
    for (i, row) in table.iter().map_err(storage)?.enumerate() {
        if i >= 64 {
            return Err(Error::new(
                "work_limit",
                "public index observation is incomplete",
            ));
        }
        let (key, code) = row.map_err(storage)?;
        rows.push(json!({"key":native_codec::hex(key.value()),"contract":code.value()}));
    }
    tables.insert(PUBLIC.name().into(), json!(rows));
    Ok(json!({"format":"rebase-local-observation-1","complete":true,"tables":tables}))
}

pub(crate) fn read_meta(read: &ReadTransaction) -> Result<Meta> {
    let table = read.open_table(KV).map_err(storage)?;
    let value = table
        .get(Key::Meta.encode().as_slice())
        .map_err(storage)?
        .ok_or_else(|| corrupt("missing meta"))?;
    match native_codec::decode(&Key::Meta, value.value())? {
        Stored::Meta(meta) => Ok(meta),
        _ => Err(corrupt("meta type")),
    }
}

fn validate_header(header: &RuntimeHeader) -> Result<()> {
    if header.format != STORE_FORMAT {
        return Err(Error::new("model_mismatch", "runtime format differs"));
    }
    if header.receipts > MAX_RECEIPTS
        || unhex(&header.cursor_key).is_err()
        || header.cursor_key.len() != 64
    {
        return Err(corrupt("runtime header"));
    }
    Ok(())
}

pub(crate) fn read_header(read: &ReadTransaction) -> Result<RuntimeHeader> {
    let table = read.open_table(RUNTIME).map_err(storage)?;
    if table.len().map_err(storage)? != 1 {
        return Err(corrupt("runtime header inventory"));
    }
    let value = table
        .get(HEADER)
        .map_err(storage)?
        .ok_or_else(|| corrupt("missing runtime header"))?;
    let header = decode(value.value())?;
    validate_header(&header)?;
    Ok(header)
}

pub(crate) fn check_tables(read: &ReadTransaction) -> Result<()> {
    let mut names: Vec<_> = read
        .list_tables()
        .map_err(storage)?
        .map(|t| t.name().to_owned())
        .collect();
    names.sort();
    if names != ["local_runtime", "native_kv", "operations", "public_records"]
        || read
            .list_multimap_tables()
            .map_err(storage)?
            .next()
            .is_some()
    {
        return Err(corrupt("unexpected local table inventory"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target/local-tests")
                .join(Uuid::new_v4().to_string());
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn file(&self) -> PathBuf {
            self.0.join("check.redb")
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn partial_writes_and_receipt_writes_abort_all_application_tables() {
        let dir = Directory::new();
        let store = LocalStore::create(
            dir.file(),
            Arc::new(PreparedModel::load().unwrap()),
            Context {
                tenant: Uuid::from_u128(1),
                actor: Uuid::from_u128(2),
            },
        )
        .unwrap();
        let before = store.observe_for_verification().unwrap();
        let old = store.db.begin_read().unwrap();
        let request:Mutation=serde_json::from_value(json!({"model":store.model.identity(),"operation_id":Uuid::from_u128(3),
            "commands":[{"op":"create","id":Uuid::from_u128(4),"contract":7,"fields":{"at":"9223372036854775807"}}],"returning":[Uuid::from_u128(4)]})).unwrap();
        for abort in [2, usize::MAX] {
            let error = store
                .mutate_inner(&request, &mut || Ok(Uuid::new_v4()), Some(abort))
                .unwrap_err();
            assert_eq!(error.code, "injected_abort");
            assert_eq!(store.observe_for_verification().unwrap(), before);
            assert_eq!(observe(&old).unwrap(), before);
        }
        let result = store.mutate(&request).unwrap();
        assert_eq!(result["result"]["revision"], "1");
        assert_eq!(observe(&old).unwrap(), before);
        drop(old);
        let after = store.observe_for_verification().unwrap();
        assert_eq!(
            after["tables"]["public_records"].as_array().unwrap().len(),
            1
        );
        assert_eq!(after["tables"]["operations"].as_array().unwrap().len(), 1);
        drop(store);
        let reopened =
            LocalStore::open(dir.file(), Arc::new(PreparedModel::load().unwrap())).unwrap();
        assert_eq!(reopened.observe_for_verification().unwrap(), after);
        assert_eq!(reopened.mutate(&request).unwrap()["replayed"], true);
    }

    #[test]
    fn active_model_context_and_table_inventory_are_checked_before_use() {
        let dir = Directory::new();
        let model = Arc::new(PreparedModel::load().unwrap());
        let store = LocalStore::create(
            dir.file(),
            model.clone(),
            Context {
                tenant: Uuid::from_u128(1),
                actor: Uuid::from_u128(2),
            },
        )
        .unwrap();
        assert!(LocalStore::create(dir.file(), model.clone(), store.context).is_err());
        assert_eq!(
            store.get("stale", Uuid::from_u128(3)).unwrap_err().code,
            "model_mismatch"
        );
        let original = read_meta(&store.db.begin_read().unwrap()).unwrap();
        for context_change in [true, false] {
            let mut meta = original.clone();
            if context_change {
                meta.actor = Uuid::from_u128(99);
            } else {
                meta.model = "different".into();
            }
            let write = store.db.begin_write().unwrap();
            write
                .open_table(KV)
                .unwrap()
                .insert(
                    Key::Meta.encode().as_slice(),
                    native_codec::encode(&Key::Meta, &Stored::Meta(meta))
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            write.commit().unwrap();
            assert_eq!(
                store
                    .get(model.identity(), Uuid::from_u128(3))
                    .unwrap_err()
                    .code,
                if context_change {
                    "forbidden"
                } else {
                    "model_mismatch"
                }
            );
        }
        drop(store);
        assert!(matches!(
            LocalStore::open(dir.file(), model),
            Err(Error {
                code: "model_mismatch",
                ..
            })
        ));
    }
}
