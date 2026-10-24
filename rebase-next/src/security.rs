//! Embedded authority persistence. No token parsing or domain calculation here.

use crate::binding::{Binding, NativeInput};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use crate::storage::{ReadTransaction, ReadableTable, TableDefinition, WriteTransaction};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    access::{Graph, PreparedGraph, Scope, denied},
    local::{CommittedValue, KV, Store, corrupt, decode, encode, storage},
    model::Prepared,
    native_codec::{self, Key, StoredValue, decimal},
    native_slice::{Attempt, Context, Error, ModelRecord, Result},
};

pub(crate) const AUTHORITY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("authority");
pub(crate) const READERS: TableDefinition<&[u8], u16> = TableDefinition::new("reader_records");
const GRAPH: &[u8] = b"graph";

fn operation_mac(
    header: &crate::local::RuntimeHeader,
    context: Context,
    model: &str,
) -> Result<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&crate::local::unhex(&header.cursor_key)?)
        .map_err(|_| corrupt("operation context key"))?;
    mac.update(b"rebase-operation-context-1\0");
    mac.update(header.store_id.as_bytes());
    mac.update(&header.operation_epoch.to_be_bytes());
    mac.update(context.tenant.as_bytes());
    mac.update(context.actor.as_bytes());
    mac.update(model.as_bytes());
    Ok(mac)
}
pub(crate) fn operation_context(
    header: &crate::local::RuntimeHeader,
    context: Context,
    model: &str,
) -> Result<String> {
    Ok(native_codec::hex(
        &operation_mac(header, context, model)?
            .finalize()
            .into_bytes(),
    ))
}
pub(crate) fn check_operation_context(
    tag: &str,
    header: &crate::local::RuntimeHeader,
    context: Context,
    model: &str,
) -> Result<()> {
    let expired = || {
        Error::new(
            "operation_expired",
            "request context differs; reconcile using its archive, never refresh an uncertain request",
        )
    };
    if tag.len() != 64 {
        return Err(expired());
    }
    operation_mac(header, context, model)?
        .verify_slice(&crate::local::unhex(tag).map_err(|_| expired())?)
        .map_err(|_| expired())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceGraph {
    pub model: String,
    #[serde(with = "decimal")]
    pub if_revision: u64,
    pub graph: Graph,
}

fn scope_key(actor: Uuid) -> Vec<u8> {
    let mut key = vec![b's'];
    key.extend_from_slice(actor.as_bytes());
    key
}

pub(crate) fn reader_key(reader: Uuid, contract: u16, id: Uuid) -> Vec<u8> {
    [
        reader.as_bytes().as_slice(),
        contract.to_be_bytes().as_slice(),
        id.as_bytes().as_slice(),
    ]
    .concat()
}

fn load_scope(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    actor: Uuid,
) -> Result<Scope> {
    let bytes = table
        .get(scope_key(actor).as_slice())
        .map_err(storage)?
        .ok_or_else(denied)?;
    decode(bytes.value())
}

pub(crate) fn write_graph(write: &WriteTransaction) -> Result<PreparedGraph> {
    let table = write.open_table(AUTHORITY).map_err(storage)?;
    let bytes = table
        .get(GRAPH)
        .map_err(storage)?
        .ok_or_else(|| corrupt("missing principal graph"))?;
    let graph: Graph = decode(bytes.value())?;
    graph
        .prepare()
        .map_err(|_| corrupt("invalid principal graph"))
}

pub(crate) fn store_graph(write: &WriteTransaction, graph: &PreparedGraph) -> Result<()> {
    let mut table = write.open_table(AUTHORITY).map_err(storage)?;
    table
        .insert(GRAPH, encode(&graph.graph)?.as_slice())
        .map_err(storage)?;
    for (&id, scope) in &graph.scopes {
        table
            .insert(scope_key(id).as_slice(), encode(scope)?.as_slice())
            .map_err(storage)?;
    }
    Ok(())
}

pub(crate) fn repair_readers<B: Binding, L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    ids: BTreeSet<Uuid>,
    revision: u64,
    select: &mut impl FnMut(&[Uuid], Uuid) -> Result<Uuid>,
) -> Result<()> {
    // Public readers use immediate owners, so there is no recursive reader fold.
    // Managed outputs inherit their producer only after public repair completes.
    for private in [false, true] {
        for &id in &ids {
            let Some(mut record) = ws.record(id)? else {
                continue;
            };
            if record.input.managed().is_none()
                && model.contract(record.contract)?.visibility != crate::model::Visibility::Public
            {
                continue;
            }
            if record.input.managed().is_some() != private {
                continue;
            }
            let reader = if let Some((producer, _)) = record.input.managed() {
                ws.record(producer)?
                    .ok_or_else(|| corrupt("missing output producer"))?
                    .reader
            } else {
                let contract = model.contract(record.contract)?;
                let mut owners = vec![];
                for (target, _, slot) in record.input.references() {
                    if contract
                        .references
                        .iter()
                        .any(|r| r.slot == slot && r.reader)
                    {
                        let target = ws
                            .record(target)?
                            .ok_or_else(|| corrupt("missing reader reference"))?;
                        owners.push(target.owner);
                    }
                }
                ws.charge("reader", owners.len() as u64 + 1)?;
                select(&owners, record.owner)?
            };
            if record.reader != reader {
                record.reader = reader;
                record.version = revision;
                ws.put(Key::Record(id), Some(StoredValue::Record(record)))?;
            }
        }
    }
    Ok(())
}

pub(crate) fn stored_reader(
    write: &WriteTransaction,
    owners: &[Uuid],
    fallback: Uuid,
    cache: &mut BTreeMap<Uuid, BTreeSet<Uuid>>,
) -> Result<Uuid> {
    let mut selected = owners.first().copied().unwrap_or(fallback);
    let table = write.open_table(AUTHORITY).map_err(storage)?;
    for &next in owners.iter().skip(1) {
        if let std::collections::btree_map::Entry::Vacant(entry) = cache.entry(selected) {
            entry.insert(load_scope(&table, selected)?.descendants);
        }
        if cache[&selected].contains(&next) {
            selected = next;
        }
    }
    Ok(selected)
}

pub(crate) fn update_reader_index<B: Binding>(
    write: &WriteTransaction,
    native: &impl ReadableTable<&'static [u8], &'static [u8]>,
    model: &Prepared<B>,
    id: Uuid,
    new: Option<&[u8]>,
) -> Result<()> {
    let record = |bytes: &[u8]| -> Result<Option<ModelRecord<B>>> {
        match native_codec::decode_for::<B>(&Key::Record(id), bytes)? {
            StoredValue::Record(r)
                if model.contract(r.contract)?.visibility == crate::model::Visibility::Public =>
            {
                Ok(Some(r))
            }
            StoredValue::Record(_) => Ok(None),
            _ => Err(corrupt("record index type")),
        }
    };
    let old = native
        .get(Key::Record(id).encode().as_slice())
        .map_err(storage)?
        .map(|b| record(b.value()))
        .transpose()?
        .flatten();
    let new = new.map(record).transpose()?.flatten();
    let entry = |r: &ModelRecord<B>| (reader_key(r.reader, r.contract, id), r.contract);
    let old = old.as_ref().map(entry);
    let new = new.as_ref().map(entry);
    if old != new {
        let mut table = write.open_table(READERS).map_err(storage)?;
        if let Some((key, _)) = old {
            table.remove(key.as_slice()).map_err(storage)?;
        }
        if let Some((key, code)) = new {
            table.insert(key.as_slice(), code).map_err(storage)?;
        }
    }
    Ok(())
}

impl<B: Binding> Store<B> {
    pub fn operation_context(&self, model: &str) -> Result<String> {
        let (read, _, header) = self.read(model)?;
        self.authority(&read)?;
        operation_context(&header, self.context, model)
    }
    pub fn create_secured(
        path: impl AsRef<std::path::Path>,
        model: Arc<Prepared<B>>,
        context: Context,
    ) -> Result<Self> {
        Self::create_backend_secured(Self::create_redb_database(path)?, model, context)
    }

    /// Trusted identity-adapter seam. Network code must verify a credential
    /// before constructing this session. Current authority is checked per call.
    pub fn session(&self, actor: Uuid, credential_epoch: u64) -> Result<Self> {
        if !self.secured {
            return Err(Error::new("invalid_input", "authenticated store required"));
        }
        Ok(Self {
            db: self.db.clone(),
            model: self.model.clone(),
            context: Context {
                tenant: self.context.tenant,
                actor,
            },
            bootstrap_actor: self.bootstrap_actor,
            secured: true,
            credential_epoch: Some(credential_epoch),
        })
    }

    fn check_scope(&self, scope: Scope) -> Result<Scope> {
        if scope.tenant != self.context.tenant || scope.actor != self.context.actor {
            return Err(corrupt("principal scope binding"));
        }
        scope.require_active()?;
        if self
            .credential_epoch
            .is_some_and(|e| e != scope.credential_epoch)
        {
            return Err(denied());
        }
        Ok(scope)
    }

    pub(crate) fn authority(&self, read: &ReadTransaction) -> Result<Scope> {
        if !self.secured {
            return Ok(Scope::local(self.context));
        }
        self.check_scope(load_scope(
            &read.open_table(AUTHORITY).map_err(storage)?,
            self.context.actor,
        )?)
    }

    pub(crate) fn write_authority(&self, write: &WriteTransaction) -> Result<Scope> {
        if !self.secured {
            return Ok(Scope::local(self.context));
        }
        self.check_scope(load_scope(
            &write.open_table(AUTHORITY).map_err(storage)?,
            self.context.actor,
        )?)
    }

    pub(crate) fn receipt_key(&self, operation: Uuid) -> Vec<u8> {
        if self.secured {
            [
                self.context.actor.as_bytes().as_slice(),
                operation.as_bytes().as_slice(),
            ]
            .concat()
        } else {
            operation.as_bytes().to_vec()
        }
    }

    pub(crate) fn disclose<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        &self,
        scope: &Scope,
        mut result: CommittedValue<B>,
        ws: &mut Attempt<L, B>,
    ) -> Result<CommittedValue<B>> {
        if self.secured {
            for returned in &mut result.records {
                let current = self.project(scope, returned.id, ws.record(returned.id)?);
                if !matches!((&returned.record, current), (Some(old), Some(now)) if old.version == now.version)
                {
                    returned.record = None;
                }
            }
        }
        Ok(result)
    }

    pub(crate) fn disclose_result<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        &self,
        scope: &Scope,
        result: crate::local::ReceiptResult<B>,
        ws: &mut Attempt<L, B>,
    ) -> Result<Value> {
        match result {
            crate::local::ReceiptResult::Records(result) => {
                let mut result = self.disclose(scope, result, ws)?;
                let mut visible = vec![];
                for execution in result.executions {
                    if ws
                        .record(execution.target)?
                        .is_some_and(|r| scope.can_read(&r))
                    {
                        visible.push(execution);
                    }
                }
                result.executions = visible;
                serde_json::to_value(result).map_err(storage)
            }
            crate::local::ReceiptResult::Cancel(result) => {
                if ws
                    .record(result.target)?
                    .is_some_and(|r| scope.can_read(&r))
                {
                    serde_json::to_value(result).map_err(storage)
                } else {
                    Ok(Value::Null)
                }
            }
        }
    }

    pub fn access_graph(&self, model: &str) -> Result<Value> {
        let (read, meta, _) = self.read(model)?;
        if !self.secured || !self.authority(&read)?.grants.admin {
            return Err(denied());
        }
        let table = read.open_table(AUTHORITY).map_err(storage)?;
        let graph: Graph = decode(
            table
                .get(GRAPH)
                .map_err(storage)?
                .ok_or_else(|| corrupt("missing graph"))?
                .value(),
        )?;
        Ok(json!({"revision":meta.revision.to_string(),"graph":graph}))
    }

    /// Separate compare-and-set administration. No domain batch can grant its
    /// own permissions. Unknown outcomes are reconciled by reading the graph.
    pub fn replace_access(&self, request: &ReplaceGraph) -> Result<Value> {
        if !self.secured {
            return Err(denied());
        }
        let write = self.db.begin_write().map_err(storage)?;
        if !self.write_authority(&write)?.grants.admin {
            return Err(denied());
        }
        let mut native = write.open_table(KV).map_err(storage)?;
        let mut meta = match native_codec::decode_for::<B>(
            &Key::Meta,
            native
                .get(Key::Meta.encode().as_slice())
                .map_err(storage)?
                .ok_or_else(|| corrupt("missing meta"))?
                .value(),
        )? {
            StoredValue::Meta(meta) => meta,
            _ => return Err(corrupt("meta type")),
        };
        self.check_meta(&meta, &request.model)?;
        if meta.revision != request.if_revision {
            return Err(Error::new("stale_version", "authority revision changed"));
        }
        if request.graph.tenant != meta.tenant {
            return Err(denied());
        }
        let graph = request.graph.clone().prepare()?;
        for p in &graph.graph.principals {
            for &code in p.grants.contracts.keys() {
                self.model.public_contract(code)?;
            }
        }
        let old = write_graph(&write)?;
        for p in &old.graph.principals {
            let next = graph
                .graph
                .principals
                .iter()
                .find(|n| n.id == p.id)
                .ok_or_else(|| {
                    Error::new(
                        "invalid_input",
                        "disable principals instead of deleting identities",
                    )
                })?;
            if p.kind != next.kind
                || next.credential_epoch < p.credential_epoch
                || (!p.active && next.active && next.credential_epoch == p.credential_epoch)
            {
                return Err(Error::new(
                    "invalid_input",
                    "principal identity/credential lifecycle",
                ));
            }
        }
        if old.graph == graph.graph {
            return Ok(json!({"revision":meta.revision.to_string(),"changed":false}));
        }
        meta.revision = meta
            .revision
            .checked_add(1)
            .ok_or_else(|| Error::new("revision_exhausted", "store counter"))?;
        let mut ws = Attempt::<_, B>::new(
            |key: &[u8]| {
                native
                    .get(key)
                    .map(|v| v.map(|v| v.value().to_vec()))
                    .map_err(storage)
            },
            crate::local::MUTATION_WORK_LIMIT,
        );
        let mut ids = BTreeSet::new();
        for row in native.iter().map_err(storage)? {
            ws.charge("inventory", 1)?;
            let (key, _) = row.map_err(storage)?;
            if let Key::Record(id) = Key::decode(key.value())? {
                ids.insert(id);
            }
        }
        repair_readers(
            &mut ws,
            &self.model,
            ids,
            meta.revision,
            &mut |owners, fallback| {
                if !graph.scopes.contains_key(&fallback) {
                    return Err(corrupt("unknown owner"));
                }
                Ok(graph.reader(owners, fallback))
            },
        )?;
        ws.put(Key::Meta, Some(StoredValue::Meta(meta.clone())))?;
        let batch = ws.finish()?;
        drop(ws);
        for (key, value) in &batch {
            if let Key::Record(id) = Key::decode(key)? {
                update_reader_index(&write, &native, &self.model, id, value.as_deref())?;
            }
            if let Some(bytes) = value {
                native
                    .insert(key.as_slice(), bytes.as_slice())
                    .map_err(storage)?;
            } else {
                native.remove(key.as_slice()).map_err(storage)?;
            }
        }
        drop(native);
        store_graph(&write, &graph)?;
        write.commit().map_err(storage)?;
        Ok(json!({"revision":meta.revision.to_string(),"changed":true}))
    }
}
