//! Shared application persistence. Engine data, reader indexes and receipts share
//! one adapter transaction. Public API entrypoints never enable fixture mode.

use std::{collections::BTreeSet, fs::OpenOptions, path::Path, sync::Arc};

use crate::storage::{Database, ReadTransaction, ReadableTable, TableDefinition};
use redb::{DatabaseError, ReadOnlyDatabase, ReadableDatabase};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    access::{Action, Scope},
    binding::{Binding, Calculation, NativeInput},
    model::{Prepared, Visibility},
    native_codec::{self, Key, StoredValue, decimal, uuid_text},
    native_slice::{Attempt, Command, Context, Error, Meta, ModelRecord, Population, Result},
};

pub(crate) const KV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("native_kv");
pub(crate) const PUBLIC: TableDefinition<&[u8], u16> = TableDefinition::new("public_records");
pub(crate) const RECEIPTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("operations");
pub(crate) const RUNTIME: TableDefinition<&[u8], &[u8]> = TableDefinition::new("local_runtime");
pub(crate) const HEADER: &[u8] = b"header";
pub const STORE_FORMAT: &str = "rebase-store-10";
pub const MAX_RECEIPTS: u16 = 1024;
pub const MUTATION_WORK_LIMIT: u64 = 200_000;

pub(crate) fn storage(error: impl std::fmt::Display + 'static) -> Error {
    if let Some(error) = (&error as &dyn std::any::Any).downcast_ref::<Error>() {
        return error.clone();
    }
    Error::new("storage", error.to_string())
}

pub(crate) fn corrupt(detail: &str) -> Error {
    Error::new("corrupt_state", detail)
}

fn check_model_identity(meta: &Meta, expected: &str) -> Result<()> {
    if meta.model != expected || meta.codec != native_codec::CODEC {
        return Err(Error::new("model_mismatch", "store/model identity differs"));
    }
    Ok(())
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
    pub context: String,
    #[serde(with = "uuid_text")]
    pub operation_id: Uuid,
    pub commands: Vec<Command>,
    #[serde(with = "canonical_ids")]
    pub returning: Vec<Uuid>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, bound(serialize = "", deserialize = ""))]
pub struct PublicRecordValue<B: Binding> {
    #[serde(with = "uuid_text")]
    pub id: Uuid,
    pub contract: u16,
    #[serde(with = "uuid_text")]
    pub version: Uuid,
    pub input: B::Input,
    pub derived: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, bound(serialize = "", deserialize = ""))]
pub struct ReturnedValue<B: Binding> {
    #[serde(with = "uuid_text")]
    pub id: Uuid,
    pub record: Option<PublicRecordValue<B>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, bound(serialize = "", deserialize = ""))]
pub struct CommittedValue<B: Binding> {
    #[serde(with = "uuid_text")]
    pub operation_id: Uuid,
    #[serde(with = "uuid_text")]
    pub revision: Uuid,
    pub records: Vec<ReturnedValue<B>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub executions: Vec<crate::effects::Created>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReceiptKind {
    Records,
    Cancel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged, bound(serialize = "", deserialize = ""))]
pub(crate) enum ReceiptResult<B: Binding> {
    Records(CommittedValue<B>),
    Cancel(crate::effects::CancelledValue),
}
impl<B: Binding> ReceiptResult<B> {
    pub(crate) fn kind(&self) -> ReceiptKind {
        match self {
            Self::Records(_) => ReceiptKind::Records,
            Self::Cancel(_) => ReceiptKind::Cancel,
        }
    }
    pub(crate) fn operation_id(&self) -> Uuid {
        match self {
            Self::Records(r) => r.operation_id,
            Self::Cancel(r) => r.operation_id,
        }
    }
    pub(crate) fn revision(&self) -> Uuid {
        match self {
            Self::Records(r) => r.revision,
            Self::Cancel(r) => r.revision,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(serialize = "", deserialize = ""))]
pub(crate) struct ReceiptValue<B: Binding> {
    pub(crate) slot: u16,
    pub(crate) kind: ReceiptKind,
    pub(crate) context: String,
    pub(crate) model: String,
    #[serde(with = "uuid_text")]
    pub(crate) tenant: Uuid,
    #[serde(with = "uuid_text")]
    pub(crate) actor: Uuid,
    pub(crate) request_hash: String,
    pub(crate) result: ReceiptResult<B>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeHeader {
    pub(crate) format: String,
    #[serde(with = "uuid_text")]
    pub(crate) store_id: Uuid,
    pub(crate) cursor_key: String,
    #[serde(with = "decimal")]
    pub(crate) operation_epoch: u64,
}

impl RuntimeHeader {
    pub(crate) fn fresh() -> Self {
        let key = [
            Uuid::new_v4().as_bytes().as_slice(),
            Uuid::new_v4().as_bytes().as_slice(),
        ]
        .concat();
        Self {
            format: STORE_FORMAT.into(),
            store_id: Uuid::new_v4(),
            cursor_key: native_codec::hex(&key),
            operation_epoch: 0,
        }
    }
}

pub struct Store<B: Binding> {
    pub(crate) db: Arc<Database>,
    pub(crate) model: Arc<Prepared<B>>,
    pub(crate) context: Context,
    pub(crate) bootstrap_actor: Uuid,
    pub(crate) secured: bool,
    pub(crate) credential_epoch: Option<u64>,
}

pub type LocalStore = Store<Calculation>;

impl<B: Binding> Store<B> {
    pub fn check_integrity(&self) -> Result<Value> {
        B::check(self)
    }
    pub(crate) fn create_redb_database(path: impl AsRef<Path>) -> Result<Database> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(storage)?;
        Ok(Database::from_redb(
            redb::Database::builder()
                .create_file(file)
                .map_err(storage)?,
        ))
    }
    pub fn create(
        path: impl AsRef<Path>,
        model: Arc<Prepared<B>>,
        context: Context,
    ) -> Result<Self> {
        let db = Self::create_redb_database(path)?;
        Self::create_backend(db, model, context)
    }

    pub fn create_backend(db: Database, model: Arc<Prepared<B>>, context: Context) -> Result<Self> {
        Self::create_backend_inner(db, model, context, false)
    }
    pub fn create_backend_secured(
        db: Database,
        model: Arc<Prepared<B>>,
        context: Context,
    ) -> Result<Self> {
        Self::create_backend_inner(db, model, context, true)
    }
    fn create_backend_inner(
        db: Database,
        model: Arc<Prepared<B>>,
        context: Context,
        secured: bool,
    ) -> Result<Self> {
        let write = db.begin_write().map_err(storage)?;
        if write.list_tables()?.next().is_some() {
            return Err(Error::new("storage_exists", "destination must be empty"));
        }
        {
            let mut table = write.open_table(KV).map_err(storage)?;
            let meta = Meta {
                model: model.identity().into(),
                codec: native_codec::CODEC.into(),
                tenant: context.tenant,
                actor: context.actor,
            };
            let bytes = native_codec::encode_for::<B>(&Key::Meta, &StoredValue::Meta(meta))?;
            table
                .insert(Key::Meta.encode().as_slice(), bytes.as_slice())
                .map_err(storage)?;
            let population = Population {
                counts: model.contracts().map(|c| (c.code, 0)).collect(),
                reserved: 0,
            };
            table.insert(
                Key::Population.encode().as_slice(),
                native_codec::encode_for::<B>(
                    &Key::Population,
                    &StoredValue::Population(population),
                )?
                .as_slice(),
            )?;
            write.open_table(PUBLIC).map_err(storage)?;
            write.open_table(RECEIPTS).map_err(storage)?;
            write.open_table(crate::receipts::SLOTS)?;
            write.open_table(crate::query::EPOCHS)?;
            crate::effects::create_tables(&write)?;
            if secured {
                crate::security::store_graph(&write, &crate::access::Graph::bootstrap(context)?)?;
                write.open_table(crate::security::READERS)?;
            }
            let header = RuntimeHeader::fresh();
            write
                .open_table(RUNTIME)
                .map_err(storage)?
                .insert(HEADER, encode(&header)?.as_slice())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(Self {
            db: Arc::new(db),
            model,
            context,
            bootstrap_actor: context.actor,
            secured,
            credential_epoch: None,
        })
    }

    pub fn open(path: impl AsRef<Path>, model: Arc<Prepared<B>>) -> Result<Self> {
        // A writable redb open can change maintenance bytes even with no user
        // transaction. Reject clean incompatible stores before acquiring it.
        // A crashed file can require allocator recovery before a read-only open
        // is possible; retain normal recovery and recheck identity afterwards.
        match ReadOnlyDatabase::open(path.as_ref()) {
            Ok(preview) => {
                let read = ReadTransaction::from_redb(preview.begin_read().map_err(storage)?);
                read_header(&read)?;
                check_tables(&read)?;
                check_model_identity(&read_meta(&read)?, model.identity())?;
            }
            Err(DatabaseError::RepairAborted) => {}
            Err(error) => return Err(storage(error)),
        }
        let db = Database::open(path.as_ref())?;
        Self::open_backend(db, model)
    }

    pub fn open_backend(db: Database, model: Arc<Prepared<B>>) -> Result<Self> {
        let read = db.begin_read().map_err(storage)?;
        read_header(&read)?;
        check_tables(&read)?;
        let meta = read_meta(&read)?;
        let population = read_population(&read)?;
        let context = Context {
            tenant: meta.tenant,
            actor: meta.actor,
        };
        let secured = read
            .list_tables()
            .map_err(storage)?
            .any(|t| t.name() == "authority");
        let store = Self {
            db: Arc::new(db),
            model,
            context,
            bootstrap_actor: context.actor,
            secured,
            credential_epoch: None,
        };
        store.check_meta(&meta, store.model.identity())?;
        let public = read.open_table(PUBLIC).map_err(storage)?;
        if public.len().map_err(storage)?
            != store
                .model
                .contracts()
                .filter(|c| c.visibility == Visibility::Public)
                .map(|c| u64::from(*population.counts.get(&c.code).unwrap_or(&0)))
                .sum::<u64>()
        {
            return Err(corrupt("public index population"));
        }
        crate::receipts::check::<B>(&read, secured)?;
        Ok(store)
    }

    pub fn model(&self) -> &Prepared<B> {
        &self.model
    }
    pub fn context(&self) -> Context {
        self.context
    }

    pub(crate) fn check_meta(&self, meta: &Meta, requested: &str) -> Result<()> {
        if requested != self.model.identity() {
            return Err(Error::new("model_mismatch", "store/model identity differs"));
        }
        check_model_identity(meta, self.model.identity())?;
        if meta.tenant != self.context.tenant || meta.actor != self.bootstrap_actor {
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

    pub(crate) fn project(
        &self,
        scope: &Scope,
        id: Uuid,
        record: Option<ModelRecord<B>>,
    ) -> Option<PublicRecordValue<B>> {
        let record = record?;
        if !scope.can_read(&record)
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
        Some(PublicRecordValue {
            id,
            contract: record.contract,
            version: record.version,
            input: record.input,
            derived,
        })
    }

    pub fn get(&self, model: &str, id: Uuid) -> Result<Option<PublicRecordValue<B>>> {
        let (read, _, _) = self.read(model)?;
        let scope = self.authority(&read)?;
        let table = read.open_table(KV).map_err(storage)?;
        let mut ws = Attempt::<_, B>::new(
            |key: &[u8]| {
                table
                    .get(key)
                    .map(|v| v.map(|v| v.value().to_vec()))
                    .map_err(storage)
            },
            1000,
        );
        Ok(self.project(&scope, id, ws.record(id)?))
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

    pub(crate) fn mutate_inner(
        &self,
        request: &Mutation,
        allocate: &mut dyn FnMut() -> Result<Uuid>,
        abort_after: Option<usize>,
    ) -> Result<Value> {
        self.mutate_controlled(request, allocate, abort_after, &mut || Ok(()), false)
    }

    pub(crate) fn mutate_controlled(
        &self,
        request: &Mutation,
        allocate: &mut dyn FnMut() -> Result<Uuid>,
        abort_after: Option<usize>,
        before_commit: &mut dyn FnMut() -> Result<()>,
        lose_response: bool,
    ) -> Result<Value> {
        if request.returning.len() > 32
            || request.returning.iter().collect::<BTreeSet<_>>().len() != request.returning.len()
        {
            return Err(Error::new(
                "invalid_input",
                "returning requires at most 32 unique IDs",
            ));
        }
        let request_hash = self.request_hash("records.mutate", request)?;
        let write = self.db.begin_write().map_err(storage)?;
        let scope = self.write_authority(&write)?;
        let header: RuntimeHeader;
        let (batch, result, disclosed, intents, work) = {
            let table = write.open_table(KV).map_err(storage)?;
            let mut ws = Attempt::<_, B>::new(
                |key: &[u8]| {
                    table
                        .get(key)
                        .map(|v| v.map(|v| v.value().to_vec()))
                        .map_err(storage)
                },
                MUTATION_WORK_LIMIT,
            );
            let Some(StoredValue::Meta(meta)) = ws.get(&Key::Meta)? else {
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
            crate::security::check_operation_context(
                &request.context,
                &header,
                self.context,
                self.model.identity(),
            )?;
            let receipts = write.open_table(RECEIPTS).map_err(storage)?;
            if let Some(bytes) = receipts
                .get(self.receipt_key(request.operation_id).as_slice())
                .map_err(storage)?
            {
                let receipt: ReceiptValue<B> = decode(bytes.value())?;
                self.check_receipt(&receipt, request.operation_id, &header)?;
                if receipt.kind != ReceiptKind::Records || receipt.request_hash != request_hash {
                    return Err(Error::new(
                        "operation_conflict",
                        "operation ID bound to different request",
                    ));
                }
                let result = self.disclose_result(&scope, receipt.result, &mut ws)?;
                return Ok(json!({"status":"committed","replayed":true,"result":result}));
            }
            let settled = crate::mutation::settle_authorized(
                &mut ws,
                &self.model,
                self.context,
                &request.commands,
                allocate,
                false,
                &mut |ws, command, old, new| {
                    let action = match command {
                        Command::Create { contract, .. } => {
                            if !scope.grants.allows(*contract, Action::Create) {
                                return Err(crate::access::denied());
                            }
                            Action::Create
                        }
                        Command::Update { .. } => Action::Update,
                        Command::Delete { .. } => Action::Delete,
                    };
                    if old.is_some_and(|r| !scope.can_write(r, action)) {
                        return Err(crate::access::denied());
                    }
                    if let Some(new) = new {
                        self.model.public_contract(new.contract)?;
                        self.model.validate(
                            new.contract,
                            &serde_json::to_value(&new.input).map_err(storage)?,
                        )?;
                        if let Command::Update { set, unset, .. } = command {
                            let contract = self.model.public_contract(new.contract)?;
                            if !unset.is_empty()
                                || set.keys().any(|key| {
                                    !contract.fields.iter().any(|f| f.name == key && f.mutable)
                                })
                            {
                                return Err(Error::new(
                                    "invalid_input",
                                    "protected or required field",
                                ));
                            }
                        }
                        let old_refs = old.map(|r| r.input.references()).unwrap_or_default();
                        for (target, _, slot) in new.input.references() {
                            if old_refs
                                .iter()
                                .any(|(id, _, s)| *id == target && *s == slot)
                            {
                                continue;
                            }
                            let target = ws.record(target)?.ok_or_else(crate::access::denied)?;
                            if !scope.can_read(&target) {
                                return Err(crate::access::denied());
                            }
                        }
                    }
                    Ok(())
                },
            )?;
            if self.secured {
                let ids = ws.changed_records();
                let mut dominance = std::collections::BTreeMap::new();
                crate::security::repair_readers(
                    &mut ws,
                    &self.model,
                    ids,
                    settled.revision,
                    &mut |owners, fallback| {
                        crate::security::stored_reader(&write, owners, fallback, &mut dominance)
                    },
                )?;
            }
            let mut records = vec![];
            for &id in &request.returning {
                records.push(ReturnedValue {
                    id,
                    record: self.project(&scope, id, ws.record(id)?),
                });
            }
            let intents = crate::effects::prepare(
                &write,
                &mut ws,
                &self.model,
                &scope,
                &header,
                request.operation_id,
                &request.commands,
                allocate,
            )?;
            let result = ReceiptResult::Records(CommittedValue {
                operation_id: request.operation_id,
                revision: settled.revision,
                records,
                executions: intents.as_ref().map(|v| v.created()).unwrap_or_default(),
            });
            let disclosed = self.disclose_result(&scope, result.clone(), &mut ws)?;
            (ws.finish()?, result, disclosed, intents, ws.work)
        };
        self.publish_native(&write, &batch, abort_after)?;
        crate::effects::publish(&write, intents, abort_after)?;
        let receipt = ReceiptValue {
            slot: crate::receipts::allocate(&write, &self.receipt_key(request.operation_id))?,
            kind: ReceiptKind::Records,
            context: request.context.clone(),
            model: self.model.identity().into(),
            tenant: self.context.tenant,
            actor: self.context.actor,
            request_hash,
            result,
        };
        self.publish_receipt(&write, &receipt)?;
        if abort_after == Some(usize::MAX) {
            return Err(Error::new(
                "injected_abort",
                "adapter check after receipt write",
            ));
        }
        before_commit()?;
        write.commit().map_err(storage)?;
        if lose_response {
            return Err(Error::new(
                "outcome_unknown",
                "injected loss of successful commit response; reconcile original operation ID",
            ));
        }
        eprintln!(
            "{}",
            json!({"event":"mutation_work","operation_id":request.operation_id,"work":work})
        );
        Ok(json!({"status":"committed","replayed":false,"result":disclosed}))
    }

    /// Publish the one engine attempt and its public/reader indexes in the
    /// caller's transaction. Typed effect application uses this same writer.
    pub(crate) fn publish_native(
        &self,
        write: &crate::storage::WriteTransaction,
        batch: &crate::staging::Batch,
        abort_after: Option<usize>,
    ) -> Result<()> {
        crate::query::publish_epochs::<B>(write, &self.model, batch)?;
        {
            let mut table = write.open_table(KV).map_err(storage)?;
            let mut index = write.open_table(PUBLIC).map_err(storage)?;
            for (i, (key, value)) in batch.iter().enumerate() {
                if let Key::Record(id) = Key::decode(key)? {
                    if self.secured {
                        crate::security::update_reader_index(
                            write,
                            &table,
                            &self.model,
                            id,
                            value.as_deref(),
                        )?;
                    }
                    match value
                        .as_deref()
                        .map(|v| native_codec::decode_for::<B>(&Key::Record(id), v))
                        .transpose()?
                    {
                        Some(StoredValue::Record(record))
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
        Ok(())
    }

    pub(crate) fn publish_receipt(
        &self,
        write: &crate::storage::WriteTransaction,
        receipt: &ReceiptValue<B>,
    ) -> Result<()> {
        crate::receipts::publish(
            write,
            &self.receipt_key(receipt.result.operation_id()),
            receipt,
        )
    }

    pub(crate) fn request_hash<T: Serialize>(&self, method: &str, request: &T) -> Result<String> {
        let normalized = encode(&serde_json::to_value(request).map_err(storage)?)?;
        if normalized.len() > crate::json::MAX_REQUEST_BYTES {
            return Err(Error::new("request_limit", "normalized request byte limit"));
        }
        let mut hash = Sha256::new();
        hash.update(b"rebase-local-operation-v2\0");
        hash.update(self.context.tenant.as_bytes());
        hash.update(self.context.actor.as_bytes());
        hash.update((method.len() as u64).to_be_bytes());
        hash.update(method.as_bytes());
        hash.update(normalized);
        Ok(native_codec::hex(&hash.finalize()))
    }

    pub(crate) fn check_receipt(
        &self,
        receipt: &ReceiptValue<B>,
        id: Uuid,
        header: &RuntimeHeader,
    ) -> Result<()> {
        if receipt.model != self.model.identity()
            || receipt.tenant != self.context.tenant
            || receipt.actor != self.context.actor
            || receipt.result.operation_id() != id
            || receipt.kind != receipt.result.kind()
        {
            return Err(corrupt("receipt binding"));
        }
        crate::security::check_operation_context(
            &receipt.context,
            header,
            self.context,
            self.model.identity(),
        )?;
        Ok(())
    }

    pub fn operation_status(&self, model: &str, context: &str, id: Uuid) -> Result<Value> {
        let (read, _, header) = self.read(model)?;
        let scope = self.authority(&read)?;
        crate::security::check_operation_context(context, &header, self.context, model)?;
        let table = read.open_table(RECEIPTS).map_err(storage)?;
        let Some(value) = table
            .get(self.receipt_key(id).as_slice())
            .map_err(storage)?
        else {
            return Ok(json!({"status":"not_observed"}));
        };
        let receipt: ReceiptValue<B> = decode(value.value())?;
        self.check_receipt(&receipt, id, &header)?;
        let native = read.open_table(KV).map_err(storage)?;
        let mut ws = Attempt::<_, B>::new(
            |key: &[u8]| {
                native
                    .get(key)
                    .map(|v| v.map(|v| v.value().to_vec()))
                    .map_err(storage)
            },
            1000,
        );
        let result = self.disclose_result(&scope, receipt.result, &mut ws)?;
        Ok(json!({"status":"committed","result":result}))
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
            if i >= crate::binding::MAX_INVENTORY_ROWS {
                return Err(Error::new("work_limit", "inspection row limit"));
            }
            let (key, value) = row.map_err(storage)?;
            let key = Key::decode(key.value())?;
            match (&key,native_codec::decode_for::<B>(&key,value.value())?) {
                (Key::Record(id),StoredValue::Record(record))=>records.push(json!({"id":id,"record":record})),
                (Key::Root(address),StoredValue::Root(root))=>roots.push(json!({"root":address,"revision":root.revision.to_string(),"summary":root.summary})),
                (Key::Query(address),StoredValue::Query(query))=>queries.push(json!({"query":address,"descriptor":query})),
                (Key::Role(address),StoredValue::Role(role))=>roles.push(json!({"source_role":address,"binding":role})),
                _=>{}
            }
        }
        Ok(
            json!({"model":meta.model,"codec":meta.codec,"store":header.store_id,
            "tenant":meta.tenant,"actor":meta.actor,"receipt_count":crate::receipts::check::<B>(&read,self.secured)?,"records":records,"roots":roots,"queries":queries,"roles":roles}),
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

pub(crate) fn observe(read: &ReadTransaction) -> Result<Value> {
    check_tables(read)?;
    let secured = read
        .list_tables()
        .map_err(storage)?
        .any(|t| t.name() == "authority");
    observe_tables(
        secured,
        |definition| read.open_table(definition),
        |definition| read.open_table(definition),
    )
}

/// The archive compares the identical complete image inside its cleanup
/// transaction. Every scanned range, including empty tables, stays protected.
pub(crate) fn observe_write(write: &crate::storage::WriteTransaction) -> Result<Value> {
    let mut names: Vec<_> = write.list_tables()?.map(|t| t.name().to_owned()).collect();
    names.sort();
    let secured = names.iter().any(|name| name == "authority");
    if names != table_names(secured) {
        return Err(corrupt("unexpected local table inventory"));
    }
    observe_tables(
        secured,
        |definition| write.open_table(definition),
        |definition| write.open_table(definition),
    )
}

fn observe_tables(
    secured: bool,
    bytes: impl Fn(
        TableDefinition<'static, &'static [u8], &'static [u8]>,
    ) -> Result<crate::storage::Table<&'static [u8], &'static [u8]>>,
    index: impl Fn(
        TableDefinition<'static, &'static [u8], u16>,
    ) -> Result<crate::storage::Table<&'static [u8], u16>>,
) -> Result<Value> {
    let mut tables = serde_json::Map::new();
    let mut definitions = vec![
        (KV, crate::binding::MAX_INVENTORY_ROWS),
        (RUNTIME, 1),
        (RECEIPTS, usize::from(MAX_RECEIPTS)),
        (crate::receipts::SLOTS, usize::from(MAX_RECEIPTS)),
        (crate::query::EPOCHS, crate::query::MAX_EPOCHS),
    ];
    definitions.extend(crate::effects::TABLES);
    if secured {
        definitions.push((
            crate::security::AUTHORITY,
            crate::access::MAX_PRINCIPALS + 2,
        ));
    }
    for (definition, limit) in definitions {
        let table = bytes(definition)?;
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
    let table = index(PUBLIC)?;
    let mut rows = vec![];
    for (i, row) in table.iter().map_err(storage)?.enumerate() {
        if i >= usize::from(crate::binding::MAX_PUBLIC_RECORDS) {
            return Err(Error::new(
                "work_limit",
                "public index observation is incomplete",
            ));
        }
        let (key, code) = row.map_err(storage)?;
        rows.push(json!({"key":native_codec::hex(key.value()),"contract":code.value()}));
    }
    tables.insert(PUBLIC.name().into(), json!(rows));
    if secured {
        let table = index(crate::security::READERS)?;
        let mut rows = vec![];
        for (i, row) in table.iter().map_err(storage)?.enumerate() {
            if i >= usize::from(crate::binding::MAX_PUBLIC_RECORDS) {
                return Err(Error::new(
                    "work_limit",
                    "reader index observation incomplete",
                ));
            }
            let (key, code) = row.map_err(storage)?;
            rows.push(json!({"key":native_codec::hex(key.value()),"contract":code.value()}));
        }
        tables.insert("reader_records".into(), json!(rows));
    }
    Ok(
        json!({"format":if secured {"rebase-authorized-observation-1"} else {"rebase-local-observation-1"},"complete":true,"tables":tables}),
    )
}

pub(crate) fn read_meta(read: &ReadTransaction) -> Result<Meta> {
    let table = read.open_table(KV).map_err(storage)?;
    let value = table
        .get(Key::Meta.encode().as_slice())
        .map_err(storage)?
        .ok_or_else(|| corrupt("missing meta"))?;
    match native_codec::decode(&Key::Meta, value.value())? {
        native_codec::Stored::Meta(meta) => Ok(meta),
        _ => Err(corrupt("meta type")),
    }
}

pub(crate) fn read_population(read: &ReadTransaction) -> Result<Population> {
    let table = read.open_table(KV)?;
    let value = table
        .get(Key::Population.encode())?
        .ok_or_else(|| corrupt("missing population"))?;
    match native_codec::decode(&Key::Population, value.value())? {
        native_codec::Stored::Population(population) => Ok(population),
        _ => Err(corrupt("population type")),
    }
}

pub(crate) fn validate_header(header: &RuntimeHeader) -> Result<()> {
    if header.format != STORE_FORMAT {
        return Err(Error::new("model_mismatch", "runtime format differs"));
    }
    if unhex(&header.cursor_key).is_err() || header.cursor_key.len() != 64 {
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
    let expected = table_names(names.iter().any(|name| name == "authority"));
    if names != expected || read.has_multimap_tables()? {
        return Err(corrupt("unexpected local table inventory"));
    }
    Ok(())
}

pub(crate) fn table_names(secured: bool) -> Vec<String> {
    let mut names = vec![
        "local_runtime",
        "native_kv",
        "operations",
        "public_records",
        "receipt_slots",
        "query_epochs",
    ];
    names.extend(crate::effects::TABLES.iter().map(|(table, _)| table.name()));
    if secured {
        names.extend(["authority", "reader_records"]);
    }
    names.sort();
    names.into_iter().map(str::to_owned).collect()
}

pub type PublicRecord = PublicRecordValue<Calculation>;
pub type Returned = ReturnedValue<Calculation>;
pub type Committed = CommittedValue<Calculation>;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::PreparedModel, native_codec::Stored};
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
        let request:Mutation=serde_json::from_value(json!({"model":store.model.identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":Uuid::from_u128(3),
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
        let revision = Uuid::parse_str(result["result"]["revision"].as_str().unwrap()).unwrap();
        assert!(!revision.is_nil());
        assert_eq!(
            result["result"]["records"][0]["record"]["version"],
            revision.to_string()
        );
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
    fn secured_physical_aborts_include_authority_and_reader_tables() {
        let dir = Directory::new();
        let store = LocalStore::create_secured(
            dir.file(),
            Arc::new(PreparedModel::load().unwrap()),
            Context {
                tenant: Uuid::from_u128(1),
                actor: Uuid::from_u128(2),
            },
        )
        .unwrap();
        let before = store.observe_for_verification().unwrap();
        assert_eq!(before["tables"].as_object().unwrap().len(), 13);
        let request: Mutation = serde_json::from_value(json!({"model":store.model.identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":Uuid::from_u128(3),
            "commands":[{"op":"create","id":Uuid::from_u128(4),"contract":7,"fields":{"at":"1"}}],"returning":[]})).unwrap();
        for abort in [2, usize::MAX] {
            assert_eq!(
                store
                    .mutate_inner(&request, &mut || Ok(Uuid::new_v4()), Some(abort))
                    .unwrap_err()
                    .code,
                "injected_abort"
            );
            assert_eq!(store.observe_for_verification().unwrap(), before);
        }
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
        let before = std::fs::read(dir.file()).unwrap();
        assert!(matches!(
            LocalStore::open(dir.file(), model),
            Err(Error {
                code: "model_mismatch",
                ..
            })
        ));
        assert_eq!(std::fs::read(dir.file()).unwrap(), before);
    }
    #[test]
    fn old_store_format_is_rejected_before_decoding_legacy_meta() {
        for previous_format in ["rebase-store-2", "rebase-store-3"] {
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
            let mut header = read_header(&store.db.begin_read().unwrap()).unwrap();
            header.format = previous_format.into();
            let write = store.db.begin_write().unwrap();
            write
                .open_table(RUNTIME)
                .unwrap()
                .insert(HEADER, encode(&header).unwrap().as_slice())
                .unwrap();
            // A legacy array-shaped Meta cannot decode under format 4. The runtime
            // header must reject this store before any native payload decoding.
            write
                .open_table(KV)
                .unwrap()
                .insert(
                    Key::Meta.encode().as_slice(),
                    b"legacy-array-meta".as_slice(),
                )
                .unwrap();
            write.commit().unwrap();
            drop(store);
            let before = std::fs::read(dir.file()).unwrap();
            assert!(matches!(
                LocalStore::open(dir.file(), model),
                Err(Error {
                    code: "model_mismatch",
                    ..
                })
            ));
            assert_eq!(std::fs::read(dir.file()).unwrap(), before);
        }
    }
}
