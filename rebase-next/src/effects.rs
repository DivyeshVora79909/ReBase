//! Bounded immutable intent, committed by the ordinary domain transaction.
//! G5a supports ready/cancelled only. There is no provider I/O or dispatch loop.
use crate::{
    access::{Action, Scope},
    binding::{Binding, NativeInput},
    local::{
        self, HEADER, KV, RECEIPTS, RUNTIME, ReceiptKind, ReceiptResult, ReceiptValue,
        RuntimeHeader, Store,
    },
    model::Prepared,
    native_codec::{self, Key, StoredValue, decimal, uuid_text},
    native_slice::{Attempt, Command, Error, Meta, ModelRecord, Result},
};
use redb::{
    ReadTransaction, ReadableTable, ReadableTableMetadata, TableDefinition, WriteTransaction,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub const CODEC: &str = "rebase-effects-1";
pub const MAX_UNRESOLVED: u16 = 64;
pub const MAX_RETAINED: u16 = 256;
pub const MAX_FACTS: usize = 1024;
pub const MAX_INBOX: usize = 256;
pub const MAX_REQUEST: usize = 1024;
pub const MAX_BYTES: u64 = 8 * 1024 * 1024;
const HEADER_ALLOWANCE: u64 = 4096;
const RESULT_RESERVE: u64 = 4096;
const DAY: i64 = 86_400_000;
pub(crate) const EXECUTIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("effect_executions");
pub(crate) const DUE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("effect_due");
pub(crate) const FACTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("effect_facts");
pub(crate) const INBOX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("effect_inbox");
pub(crate) const EFFECT_RUNTIME: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("effect_runtime");
#[allow(clippy::type_complexity)]
pub(crate) const TABLES: [(TableDefinition<&[u8], &[u8]>, usize); 5] = [
    (EXECUTIONS, MAX_RETAINED as usize),
    (DUE, MAX_UNRESOLVED as usize),
    (FACTS, MAX_FACTS),
    (INBOX, MAX_INBOX),
    (EFFECT_RUNTIME, 1),
];

#[derive(Clone, Debug, Serialize)]
pub struct ActionDeclaration {
    pub code: u16,
    pub name: &'static str,
    pub version: &'static str,
    pub source_contract: u16,
    pub reference_slot: u16,
    pub target_contract: u16,
    pub provider_account: &'static str,
}
pub(crate) fn capabilities(action: &ActionDeclaration) -> Value {
    json!({"action":action,"request_contract":action.source_contract,"codec":CODEC,
        "creation":"records.mutate creates an immutable Dispatch and returns executions",
        "status":{"method":"effects.status","params":["model","execution_id"],"visibility":"current target Account read"},
        "cancel":{"method":"effects.cancel","params":["model","context","operation_id","execution_id","if_revision"],"authority":"current target Update and requester or administrator"},
        "phases":["ready","cancelled"],"dispatch_enabled":false,
        "limits":{"unresolved":MAX_UNRESOLVED,"retained":MAX_RETAINED,"request_bytes":MAX_REQUEST,"private_bytes":MAX_BYTES},
        "restore":"effect-bearing stores receive a fresh disabled, quarantined activation"})
}
#[derive(Clone, Debug)]
pub struct Template {
    pub target: Uuid,
    pub execute_at: Option<i64>,
    pub not_after: Option<i64>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Ready,
    Cancelled,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Cancellation {
    Requested,
    Expired,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Runtime {
    pub codec: String,
    #[serde(with = "uuid_text")]
    pub activation: Uuid,
    pub dispatch_enabled: bool,
    pub quarantined: bool,
    pub retained: u16,
    pub unresolved: u16,
    pub reserved_facts: u16,
    pub accounted_bytes: u64,
}
impl Runtime {
    fn fresh() -> Self {
        Self {
            codec: CODEC.into(),
            activation: Uuid::new_v4(),
            dispatch_enabled: false,
            quarantined: false,
            retained: 0,
            unresolved: 0,
            reserved_facts: 0,
            accounted_bytes: HEADER_ALLOWANCE,
        }
    }
    fn validate(&self) -> Result<()> {
        ensure(
            self.codec == CODEC && !self.activation.is_nil() && !self.dispatch_enabled,
            "effect runtime identity/activation",
        )?;
        ensure(
            self.unresolved <= MAX_UNRESOLVED
                && self.retained <= MAX_RETAINED
                && self.unresolved <= self.retained
                && self.reserved_facts == self.unresolved
                && self.accounted_bytes <= MAX_BYTES
                && self.accounted_bytes >= HEADER_ALLOWANCE
                && (HEADER.len() + local::encode(self)?.len()) as u64 <= HEADER_ALLOWANCE,
            "effect runtime bounds",
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(serialize = "", deserialize = ""))]
pub(crate) struct Execution<B: Binding> {
    #[serde(with = "uuid_text")]
    pub id: Uuid,
    pub codec: String,
    pub model: String,
    #[serde(with = "uuid_text")]
    pub store: Uuid,
    #[serde(with = "uuid_text")]
    pub tenant: Uuid,
    #[serde(with = "uuid_text")]
    pub requester: Uuid,
    pub credential_epoch: u64,
    #[serde(with = "uuid_text")]
    pub operation_id: Uuid,
    pub operation_epoch: u64,
    #[serde(with = "uuid_text")]
    pub source: Uuid,
    pub action: u16,
    pub action_version: String,
    pub provider_account: String,
    #[serde(with = "uuid_text")]
    pub target: Uuid,
    pub request: B::Input,
    pub request_hash: String,
    #[serde(with = "decimal")]
    pub created_at: i64,
    #[serde(with = "decimal")]
    pub execute_at: i64,
    #[serde(with = "decimal")]
    pub not_after: i64,
    #[serde(with = "decimal")]
    pub revision: u64,
    pub phase: Phase,
    pub cancellation: Option<Cancellation>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Created {
    #[serde(with = "uuid_text")]
    pub execution_id: Uuid,
    #[serde(with = "uuid_text")]
    pub source: Uuid,
    #[serde(with = "uuid_text")]
    pub target: Uuid,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cancel {
    pub model: String,
    pub context: String,
    #[serde(with = "uuid_text")]
    pub operation_id: Uuid,
    #[serde(with = "uuid_text")]
    pub execution_id: Uuid,
    #[serde(with = "decimal")]
    pub if_revision: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CancelledValue {
    #[serde(with = "uuid_text")]
    pub operation_id: Uuid,
    #[serde(with = "decimal")]
    pub revision: u64,
    #[serde(with = "uuid_text")]
    pub execution_id: Uuid,
    #[serde(with = "uuid_text")]
    pub target: Uuid,
    #[serde(with = "decimal")]
    pub execution_revision: u64,
    pub phase: Phase,
}
fn ensure(ok: bool, what: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(local::corrupt(what))
    }
}
pub(crate) fn now_millis() -> Result<i64> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(local::storage)?
        .as_millis();
    i64::try_from(ms).map_err(|_| Error::new("overflow", "wall clock milliseconds"))
}
fn schedule(template: &Template, now: i64) -> Result<(i64, i64)> {
    let low = now.saturating_sub(DAY).max(0);
    let high = now
        .checked_add(DAY)
        .ok_or_else(|| Error::new("overflow", "effect deadline"))?;
    let at = template.execute_at.unwrap_or(now);
    let end = template.not_after.unwrap_or(
        now.checked_add(60_000)
            .ok_or_else(|| Error::new("overflow", "effect expiry"))?,
    );
    if now < 0 || !(low..=high).contains(&at) || end <= now || end > high || at >= end {
        return Err(Error::new(
            "invalid_input",
            "effect schedule must fit creation window and expiry",
        ));
    }
    Ok((at, end))
}
fn hash_request<B: Binding>(request: &B::Input, action: &ActionDeclaration) -> Result<String> {
    Ok(native_codec::hex(&Sha256::digest(local::encode(&(
        action, request,
    ))?)))
}
fn due_key(at: i64, id: Uuid) -> Vec<u8> {
    [
        (at as u64 ^ (1u64 << 63)).to_be_bytes().as_slice(),
        id.as_bytes(),
    ]
    .concat()
}
fn row_bytes<B: Binding>(row: &Execution<B>) -> Result<u64> {
    Ok(16 + local::encode(row)?.len() as u64)
}
fn write_runtime(write: &WriteTransaction, runtime: &Runtime) -> Result<()> {
    runtime.validate()?;
    write
        .open_table(EFFECT_RUNTIME)
        .map_err(local::storage)?
        .insert(HEADER, local::encode(runtime)?.as_slice())
        .map_err(local::storage)?;
    Ok(())
}
pub(crate) fn runtime_write(write: &WriteTransaction) -> Result<Runtime> {
    let table = write.open_table(EFFECT_RUNTIME).map_err(local::storage)?;
    ensure(
        table.len().map_err(local::storage)? == 1,
        "effect runtime inventory",
    )?;
    let value = table
        .get(HEADER)
        .map_err(local::storage)?
        .ok_or_else(|| local::corrupt("missing effect runtime"))?;
    let result: Runtime = local::decode(value.value())?;
    result.validate()?;
    Ok(result)
}
pub(crate) fn create_tables(write: &WriteTransaction) -> Result<()> {
    for (table, _) in TABLES {
        write.open_table(table).map_err(local::storage)?;
    }
    write_runtime(write, &Runtime::fresh())
}
pub(crate) fn reset_tables(write: &WriteTransaction) -> Result<()> {
    let old = runtime_write(write)?;
    if old.unresolved != 0
        || write
            .open_table(FACTS)
            .map_err(local::storage)?
            .len()
            .map_err(local::storage)?
            != 0
        || write
            .open_table(INBOX)
            .map_err(local::storage)?
            .len()
            .map_err(local::storage)?
            != 0
    {
        return Err(Error::new(
            "invariant",
            "unresolved external work prevents reset",
        ));
    }
    for (table, _) in TABLES {
        write.delete_table(table).map_err(local::storage)?;
    }
    create_tables(write)
}
pub(crate) fn quarantine_restore(write: &WriteTransaction) -> Result<bool> {
    let mut runtime = runtime_write(write)?;
    if runtime.retained > 0 {
        runtime.activation = Uuid::new_v4();
        runtime.dispatch_enabled = false;
        runtime.quarantined = true;
        write_runtime(write, &runtime)?;
        return Ok(true);
    }
    Ok(false)
}

pub(crate) struct PreparedIntents<B: Binding> {
    rows: Vec<Execution<B>>,
    runtime: Runtime,
}
impl<B: Binding> PreparedIntents<B> {
    pub fn created(&self) -> Vec<Created> {
        self.rows
            .iter()
            .map(|r| Created {
                execution_id: r.id,
                source: r.source,
                target: r.target,
            })
            .collect()
    }
}
/// Runs only after receipt replay and successful final domain settlement.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    write: &WriteTransaction,
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    scope: &Scope,
    header: &RuntimeHeader,
    operation_id: Uuid,
    commands: &[Command],
    allocate: &mut dyn FnMut() -> Result<Uuid>,
) -> Result<Option<PreparedIntents<B>>> {
    let Some(action) = B::effect_action() else {
        return Ok(None);
    };
    let table = write.open_table(EXECUTIONS).map_err(local::storage)?;
    // Retained executions outlive source deletion; their pinned targets cannot be reused.
    let removed: BTreeSet<_> = commands
        .iter()
        .filter_map(|c| match c {
            Command::Delete { id, .. } => Some(*id),
            _ => None,
        })
        .collect();
    if !removed.is_empty() {
        for (n, row) in table.iter().map_err(local::storage)?.enumerate() {
            if n >= MAX_RETAINED as usize {
                return Err(local::corrupt("effect population"));
            }
            ws.charge("dependency", 1)?;
            let (_, bytes) = row.map_err(local::storage)?;
            let row: Execution<B> = local::decode(bytes.value())?;
            if removed.contains(&row.target) {
                return Err(Error::new(
                    "unavailable_reference",
                    "retained execution pins target",
                ));
            }
        }
    }
    if !commands.iter().any(
        |c| matches!(c, Command::Create { contract, .. } if *contract == action.source_contract),
    ) {
        return Ok(None);
    }
    let mut runtime = runtime_write(write)?;
    let now = now_millis()?;
    let mut rows = vec![];
    let mut generated = BTreeSet::new();
    for command in commands {
        let Command::Create { id, contract, .. } = command else {
            continue;
        };
        if *contract != action.source_contract {
            continue;
        }
        ws.charge("dependency", 1)?;
        let source = ws
            .record(*id)?
            .ok_or_else(|| local::corrupt("settled effect source missing"))?;
        let template = B::effect_template(&source.input)?
            .ok_or_else(|| Error::new("model", "effect declaration/template disagree"))?;
        ensure(
            source.contract == action.source_contract
                && source
                    .input
                    .references()
                    .iter()
                    .filter(|(_, _, slot)| *slot == action.reference_slot)
                    .copied()
                    .collect::<Vec<_>>()
                    == [(
                        template.target,
                        action.target_contract,
                        action.reference_slot,
                    )],
            "effect template reference differs",
        )?;
        let target = ws
            .record(template.target)?
            .ok_or_else(|| Error::new("unavailable_reference", "effect target missing"))?;
        if target.contract != action.target_contract || target.tenant != scope.tenant {
            return Err(Error::new(
                "unavailable_reference",
                "effect target type/tenant",
            ));
        }
        if !scope.grants.allows(source.contract, Action::Create)
            || !scope.can_write(&target, Action::Update)
        {
            return Err(crate::access::denied());
        }
        let request_bytes = local::encode(&source.input)?;
        if request_bytes.len() > MAX_REQUEST {
            return Err(Error::new("request_limit", "effect request bytes"));
        }
        let (execute_at, not_after) = schedule(&template, now)?;
        if runtime.retained >= MAX_RETAINED || runtime.unresolved >= MAX_UNRESOLVED {
            return Err(Error::new("state_limit", "effect retention capacity"));
        }
        let execution_id = allocate()?;
        if execution_id.is_nil()
            || execution_id == *id
            || execution_id == template.target
            || !generated.insert(execution_id)
            || table
                .get(execution_id.as_bytes().as_slice())
                .map_err(local::storage)?
                .is_some()
            || ws.record(execution_id)?.is_some()
        {
            return Err(Error::new(
                "allocation_collision",
                "effect execution identity",
            ));
        }
        let row = Execution {
            id: execution_id,
            codec: CODEC.into(),
            model: model.identity().into(),
            store: header.store_id,
            tenant: scope.tenant,
            requester: scope.actor,
            credential_epoch: scope.credential_epoch,
            operation_id,
            operation_epoch: header.operation_epoch,
            source: *id,
            action: action.code,
            action_version: action.version.into(),
            provider_account: action.provider_account.into(),
            target: template.target,
            request_hash: hash_request::<B>(&source.input, &action)?,
            request: source.input,
            created_at: now,
            execute_at,
            not_after,
            revision: 1,
            phase: Phase::Ready,
            cancellation: None,
        };
        runtime.retained += 1;
        runtime.unresolved += 1;
        runtime.reserved_facts += 1;
        runtime.accounted_bytes = runtime
            .accounted_bytes
            .checked_add(row_bytes(&row)? + 24 + RESULT_RESERVE)
            .ok_or_else(|| Error::new("overflow", "effect bytes"))?;
        if runtime.accounted_bytes > MAX_BYTES {
            return Err(Error::new("state_limit", "effect private byte capacity"));
        }
        rows.push(row);
    }
    Ok(Some(PreparedIntents { rows, runtime }))
}
/// The caller still owns the uncommitted domain transaction and its receipt.
pub(crate) fn publish<B: Binding>(
    write: &WriteTransaction,
    intents: Option<PreparedIntents<B>>,
    abort_after: Option<usize>,
) -> Result<()> {
    let Some(intents) = intents else {
        return Ok(());
    };
    for row in intents.rows {
        write
            .open_table(EXECUTIONS)
            .map_err(local::storage)?
            .insert(
                row.id.as_bytes().as_slice(),
                local::encode(&row)?.as_slice(),
            )
            .map_err(local::storage)?;
        injected(abort_after, usize::MAX - 1)?;
        write
            .open_table(DUE)
            .map_err(local::storage)?
            .insert(due_key(row.execute_at, row.id).as_slice(), b"".as_slice())
            .map_err(local::storage)?;
        injected(abort_after, usize::MAX - 2)?;
    }
    write_runtime(write, &intents.runtime)?;
    injected(abort_after, usize::MAX - 3)
}
fn injected(abort: Option<usize>, point: usize) -> Result<()> {
    if abort == Some(point) {
        Err(Error::new(
            "injected_abort",
            "adapter check after effect write",
        ))
    } else {
        Ok(())
    }
}

impl<B: Binding> Store<B> {
    pub fn effect_status(&self, model: &str, id: Uuid) -> Result<Value> {
        if B::effect_action().is_none() {
            return Err(Error::new("unsupported_query", "model has no effects"));
        }
        let (read, _, _) = self.read(model)?;
        let scope = self.authority(&read)?;
        let executions = read.open_table(EXECUTIONS).map_err(local::storage)?;
        let Some(bytes) = executions
            .get(id.as_bytes().as_slice())
            .map_err(local::storage)?
        else {
            return Ok(Value::Null);
        };
        let row: Execution<B> = local::decode(bytes.value())?;
        let table = read.open_table(KV).map_err(local::storage)?;
        let mut ws = Attempt::<_, B>::new(
            |key: &[u8]| {
                table
                    .get(key)
                    .map(|v| v.map(|v| v.value().to_vec()))
                    .map_err(local::storage)
            },
            1000,
        );
        if ws.record(row.target)?.is_none_or(|r| !scope.can_read(&r)) {
            return Ok(Value::Null);
        }
        Ok(
            json!({"execution_id":row.id,"source":row.source,"target":row.target,"revision":row.revision.to_string(),
            "phase":row.phase,"request":row.request,"created_at":row.created_at.to_string(),"execute_at":row.execute_at.to_string(),
            "not_after":row.not_after.to_string(),"cancellation":row.cancellation,"provider_key":format!("{}/{}",row.id,row.action),"dispatch_enabled":false}),
        )
    }
    pub fn cancel_effect(&self, request: &Cancel) -> Result<Value> {
        self.cancel_effect_inner(request, None)
    }
    pub(crate) fn cancel_effect_inner(
        &self,
        request: &Cancel,
        abort_after: Option<usize>,
    ) -> Result<Value> {
        if B::effect_action().is_none() {
            return Err(Error::new("unsupported_query", "model has no effects"));
        }
        let hash = self.request_hash("effects.cancel", request)?;
        let write = self.db.begin_write().map_err(local::storage)?;
        let scope = self.write_authority(&write)?;
        let mut header: RuntimeHeader = local::decode(
            write
                .open_table(RUNTIME)
                .map_err(local::storage)?
                .get(HEADER)
                .map_err(local::storage)?
                .ok_or_else(|| local::corrupt("runtime header"))?
                .value(),
        )?;
        local::validate_header(&header)?;
        crate::security::check_operation_context(
            &request.context,
            &header,
            self.context(),
            self.model().identity(),
        )?;
        let mut meta;
        let (result, disclosed) = {
            let table = write.open_table(KV).map_err(local::storage)?;
            let mut ws = Attempt::<_, B>::new(
                |key: &[u8]| {
                    table
                        .get(key)
                        .map(|v| v.map(|v| v.value().to_vec()))
                        .map_err(local::storage)
                },
                local::MUTATION_WORK_LIMIT,
            );
            let Some(StoredValue::Meta(found)) = ws.get(&Key::Meta)? else {
                return Err(local::corrupt("meta"));
            };
            meta = found;
            self.check_meta(&meta, &request.model)?;
            let receipts = write.open_table(RECEIPTS).map_err(local::storage)?;
            if let Some(bytes) = receipts
                .get(self.receipt_key(request.operation_id).as_slice())
                .map_err(local::storage)?
            {
                let receipt: ReceiptValue<B> = local::decode(bytes.value())?;
                self.check_receipt(&receipt, request.operation_id, &header)?;
                if receipt.kind != ReceiptKind::Cancel || receipt.request_hash != hash {
                    return Err(Error::new(
                        "operation_conflict",
                        "operation ID bound to different request",
                    ));
                }
                return Ok(
                    json!({"status":"committed","replayed":true,"result":self.disclose_result(&scope,receipt.result,&mut ws)?}),
                );
            }
            if header.receipts >= local::MAX_RECEIPTS {
                return Err(Error::new("receipt_limit", "receipt retention exhausted"));
            }
            let executions = write.open_table(EXECUTIONS).map_err(local::storage)?;
            let bytes = executions
                .get(request.execution_id.as_bytes().as_slice())
                .map_err(local::storage)?
                .ok_or_else(|| Error::new("not_found", "execution unavailable"))?;
            let mut row: Execution<B> = local::decode(bytes.value())?;
            drop(bytes);
            drop(executions);
            let target = ws
                .record(row.target)?
                .ok_or_else(|| local::corrupt("effect target missing"))?;
            if !scope.can_write(&target, Action::Update)
                || (scope.actor != row.requester && !scope.grants.admin)
            {
                return Err(crate::access::denied());
            }
            if row.revision != request.if_revision {
                return Err(Error::new("stale_version", "execution revision differs"));
            }
            let mut runtime = runtime_write(&write)?;
            let old_bytes = row_bytes(&row)?;
            if row.phase == Phase::Ready {
                row.phase = Phase::Cancelled;
                row.cancellation = Some(Cancellation::Requested);
                row.revision = row
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| Error::new("revision_exhausted", "execution revision"))?;
                runtime.unresolved = runtime
                    .unresolved
                    .checked_sub(1)
                    .ok_or_else(|| local::corrupt("effect unresolved underflow"))?;
                runtime.reserved_facts = runtime
                    .reserved_facts
                    .checked_sub(1)
                    .ok_or_else(|| local::corrupt("effect reservation underflow"))?;
                runtime.accounted_bytes = runtime
                    .accounted_bytes
                    .checked_sub(old_bytes + 24 + RESULT_RESERVE)
                    .and_then(|n| n.checked_add(row_bytes(&row).ok()?))
                    .ok_or_else(|| local::corrupt("effect cancellation bytes"))?;
                ensure(
                    write
                        .open_table(DUE)
                        .map_err(local::storage)?
                        .remove(due_key(row.execute_at, row.id).as_slice())
                        .map_err(local::storage)?
                        .is_some(),
                    "cancelled effect due row missing",
                )?;
                injected(abort_after, usize::MAX - 2)?;
                write
                    .open_table(EXECUTIONS)
                    .map_err(local::storage)?
                    .insert(
                        row.id.as_bytes().as_slice(),
                        local::encode(&row)?.as_slice(),
                    )
                    .map_err(local::storage)?;
                injected(abort_after, usize::MAX - 1)?;
                write_runtime(&write, &runtime)?;
                injected(abort_after, usize::MAX - 3)?;
            }
            meta.revision = meta
                .revision
                .checked_add(1)
                .ok_or_else(|| Error::new("revision_exhausted", "store revision"))?;
            let result = CancelledValue {
                operation_id: request.operation_id,
                revision: meta.revision,
                execution_id: row.id,
                target: row.target,
                execution_revision: row.revision,
                phase: row.phase,
            };
            let disclosed =
                self.disclose_result(&scope, ReceiptResult::Cancel(result.clone()), &mut ws)?;
            (result, disclosed)
        };
        write
            .open_table(KV)
            .map_err(local::storage)?
            .insert(
                Key::Meta.encode().as_slice(),
                native_codec::encode_for::<B>(&Key::Meta, &StoredValue::Meta(meta))?.as_slice(),
            )
            .map_err(local::storage)?;
        let receipt = ReceiptValue {
            kind: ReceiptKind::Cancel,
            context: request.context.clone(),
            model: self.model().identity().into(),
            tenant: self.context().tenant,
            actor: self.context().actor,
            request_hash: hash,
            result: ReceiptResult::Cancel(result.clone()),
        };
        self.publish_receipt(&write, &mut header, &receipt)?;
        injected(abort_after, usize::MAX)?;
        write
            .commit()
            .map_err(|e| Error::new("outcome_unknown", e.to_string()))?;
        Ok(json!({"status":"committed","replayed":false,"result":disclosed}))
    }
}

/// Complete independent inventory reconstruction; no cached due/count value is trusted.
pub(crate) fn check<B: Binding>(
    read: &ReadTransaction,
    model: &Prepared<B>,
    meta: &Meta,
    header: &RuntimeHeader,
    records: &BTreeMap<Uuid, ModelRecord<B>>,
    secured: bool,
) -> Result<Value> {
    let table = read.open_table(EFFECT_RUNTIME).map_err(local::storage)?;
    ensure(
        table.len().map_err(local::storage)? == 1,
        "effect header inventory",
    )?;
    let runtime: Runtime = local::decode(
        table
            .get(HEADER)
            .map_err(local::storage)?
            .ok_or_else(|| local::corrupt("effect header"))?
            .value(),
    )?;
    runtime.validate()?;
    // Future native writers must establish their own typed inventory before these admit rows.
    ensure(
        read.open_table(FACTS)
            .map_err(local::storage)?
            .len()
            .map_err(local::storage)?
            == 0
            && read
                .open_table(INBOX)
                .map_err(local::storage)?
                .len()
                .map_err(local::storage)?
                == 0,
        "G5a has no provider fact/inbox writers",
    )?;
    let mut due = BTreeMap::new();
    let mut origins = BTreeSet::new();
    let mut retained = 0;
    let mut bytes = HEADER_ALLOWANCE;
    let mut unresolved = 0;
    let action = B::effect_action();
    for item in read
        .open_table(EXECUTIONS)
        .map_err(local::storage)?
        .iter()
        .map_err(local::storage)?
    {
        let (key, value) = item.map_err(local::storage)?;
        retained += 1;
        ensure(retained <= MAX_RETAINED, "retained effect population")?;
        let action = action
            .as_ref()
            .ok_or_else(|| local::corrupt("effect row without model action"))?;
        let row: Execution<B> = local::decode(value.value())?;
        ensure(
            local::encode(&row)? == value.value()
                && row.id.as_bytes().as_slice() == key.value()
                && !row.id.is_nil()
                && row.id != row.source
                && row.id != row.target
                && row.codec == CODEC
                && row.model == model.identity()
                && row.store == header.store_id
                && row.tenant == meta.tenant
                && row.action == action.code
                && row.action_version == action.version
                && row.provider_account == action.provider_account
                && row.operation_epoch <= header.operation_epoch,
            "effect identity/version/origin",
        )?;
        ensure(
            origins.insert((
                row.requester,
                row.operation_epoch,
                row.operation_id,
                row.source,
                row.action,
            )),
            "duplicate execution origin",
        )?;
        if row.operation_epoch == header.operation_epoch {
            let receipts = read.open_table(RECEIPTS).map_err(local::storage)?;
            let key = if secured {
                [
                    row.requester.as_bytes().as_slice(),
                    row.operation_id.as_bytes().as_slice(),
                ]
                .concat()
            } else {
                row.operation_id.as_bytes().to_vec()
            };
            let value = receipts
                .get(key.as_slice())
                .map_err(local::storage)?
                .ok_or_else(|| local::corrupt("execution origin receipt missing"))?;
            let receipt: ReceiptValue<B> = local::decode(value.value())?;
            ensure(
                receipt.kind == ReceiptKind::Records
                    && receipt.actor == row.requester
                    && matches!(&receipt.result,ReceiptResult::Records(result) if result.operation_id==row.operation_id && result.executions.iter().any(|e|e.execution_id==row.id && e.source==row.source && e.target==row.target)),
                "execution origin receipt differs",
            )?;
        }
        model.validate(
            action.source_contract,
            &serde_json::to_value(&row.request).map_err(local::storage)?,
        )?;
        ensure(
            row.request.contract() == action.source_contract
                && local::encode(&row.request)?.len() <= MAX_REQUEST
                && row.request_hash == hash_request::<B>(&row.request, action)?,
            "effect frozen request/hash",
        )?;
        let template = B::effect_template(&row.request)?
            .ok_or_else(|| local::corrupt("effect frozen template"))?;
        ensure(
            row.request
                .references()
                .iter()
                .filter(|(_, _, slot)| *slot == action.reference_slot)
                .copied()
                .collect::<Vec<_>>()
                == [(row.target, action.target_contract, action.reference_slot)],
            "frozen request reference binding",
        )?;
        ensure(
            template.target == row.target
                && schedule(&template, row.created_at)? == (row.execute_at, row.not_after),
            "effect frozen target/schedule",
        )?;
        ensure(
            records
                .get(&row.target)
                .is_some_and(|r| r.contract == action.target_contract && r.tenant == meta.tenant),
            "retained effect target",
        )?;
        ensure(
            row.revision > 0
                && match row.phase {
                    Phase::Ready => row.cancellation.is_none() && row.revision == 1,
                    Phase::Cancelled => row.cancellation.is_some() && row.revision == 2,
                },
            "effect phase/revision",
        )?;
        bytes += key.value().len() as u64 + value.value().len() as u64;
        if row.phase == Phase::Ready {
            unresolved += 1;
            due.insert(due_key(row.execute_at, row.id), Vec::<u8>::new());
            bytes += 24 + RESULT_RESERVE;
        }
    }
    let due_table = read.open_table(DUE).map_err(local::storage)?;
    ensure(
        due_table.len().map_err(local::storage)? <= u64::from(MAX_UNRESOLVED),
        "due inventory bound",
    )?;
    let actual = due_table
        .iter()
        .map_err(local::storage)?
        .map(|r| {
            r.map(|(k, v)| (k.value().to_vec(), v.value().to_vec()))
                .map_err(local::storage)
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure(actual == due, "effect due inventory")?;
    ensure(
        runtime.retained == retained
            && runtime.unresolved == unresolved
            && runtime.reserved_facts == unresolved
            && runtime.accounted_bytes == bytes,
        "effect counts/reserved bytes",
    )?;
    Ok(
        json!({"retained":retained,"unresolved":unresolved,"reserved_facts":unresolved,"accounted_bytes":bytes,"dispatch_enabled":false,"quarantined":runtime.quarantined}),
    )
}

pub(crate) fn check_receipt<B: Binding>(
    read: &ReadTransaction,
    receipt: &ReceiptValue<B>,
    header: &RuntimeHeader,
) -> Result<()> {
    let table = read.open_table(EXECUTIONS).map_err(local::storage)?;
    let execution = |id: Uuid| -> Result<Execution<B>> {
        let bytes = table
            .get(id.as_bytes().as_slice())
            .map_err(local::storage)?
            .ok_or_else(|| local::corrupt("receipt effect missing"))?;
        local::decode(bytes.value())
    };
    match &receipt.result {
        ReceiptResult::Records(result) => {
            ensure(
                result.executions.len() <= MAX_UNRESOLVED as usize
                    && result
                        .executions
                        .iter()
                        .map(|e| e.execution_id)
                        .collect::<BTreeSet<_>>()
                        .len()
                        == result.executions.len(),
                "receipt effect inventory",
            )?;
            for created in &result.executions {
                let row = execution(created.execution_id)?;
                ensure(
                    row.id == created.execution_id
                        && row.source == created.source
                        && row.target == created.target
                        && row.requester == receipt.actor
                        && row.operation_epoch == header.operation_epoch
                        && row.operation_id == result.operation_id,
                    "receipt effect origin binding",
                )?;
            }
        }
        ReceiptResult::Cancel(result) => {
            let row = execution(result.execution_id)?;
            ensure(
                row.id == result.execution_id
                    && row.target == result.target
                    && result.execution_revision == 2
                    && row.revision >= result.execution_revision
                    && result.phase == Phase::Cancelled,
                "receipt cancellation binding",
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_defaults_and_twenty_four_hour_boundaries_are_exact() {
        let now = 1_000_000_000;
        let template = Template {
            target: Uuid::from_u128(1),
            execute_at: None,
            not_after: None,
        };
        assert_eq!(schedule(&template, now).unwrap(), (now, now + 60_000));
        assert_eq!(
            schedule(
                &Template {
                    execute_at: Some(now - DAY),
                    not_after: Some(now + DAY),
                    ..template
                },
                now
            )
            .unwrap(),
            (now - DAY, now + DAY)
        );
        for (at, end) in [
            (now - DAY - 1, now + 1),
            (now + DAY, now + DAY),
            (now, now),
            (now, now + DAY + 1),
        ] {
            assert_eq!(
                schedule(
                    &Template {
                        execute_at: Some(at),
                        not_after: Some(end),
                        ..template
                    },
                    now
                )
                .unwrap_err()
                .code,
                "invalid_input"
            );
        }
    }

    #[test]
    fn due_key_preserves_full_signed_time_and_uuid_order() {
        let keys: Vec<_> = [i64::MIN, -1, 0, 1, i64::MAX]
            .into_iter()
            .flat_map(|at| {
                [Uuid::nil(), Uuid::from_u128(u128::MAX)]
                    .into_iter()
                    .map(move |id| due_key(at, id))
            })
            .collect();
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(keys.iter().all(|key| key.len() == 24));
    }
}
