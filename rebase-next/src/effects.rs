//! Bounded immutable intent, committed by the ordinary domain transaction.
//! Provider calls are owned by the worker and never occur in a transaction.
mod application;
pub mod conformance;
pub mod fake;
pub(crate) mod inbox;
mod state;
mod worker;
#[cfg(test)]
mod worker_tests;
use crate::storage::{ReadTransaction, ReadableTable, TableDefinition, WriteTransaction};
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
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
pub use state::Disposition;
pub use state::WorkerMode;
use state::{Application, Fact, Lease, Start, Sweep};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub const CODEC: &str = "rebase-effects-3";
pub const MAX_UNRESOLVED: u16 = 64;
pub const MAX_RETAINED: u16 = 256;
pub const MAX_FACTS: usize = 1024;
pub const MAX_INBOX: usize = 256;
pub const MAX_REQUEST: usize = 1024;
pub const MAX_OUTCOME: usize = 2048;
pub const MAX_WEBHOOK: usize = 8192;
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
    pub application_fields: Vec<&'static str>,
}
pub(crate) fn capabilities<B: Binding>(action: &ActionDeclaration) -> Value {
    json!({"action":action,"request_contract":action.source_contract,"codec":CODEC,
        "creation":"records.mutate creates an immutable Dispatch and returns executions",
        "status":{"method":"effects.status","params":["model","execution_id"],"visibility":"current target Account read"},
        "cancel":{"method":"effects.cancel","params":["model","context","operation_id","execution_id","if_revision"],"authority":"current target Update and requester or administrator"},
        "outcome":B::effect_outcome_schema(),
        "phases":["ready","waiting","uncertain","succeeded","failed","cancelled"],"default_worker_mode":"disabled",
        "ingress":{"path":"/effects/fake","authentication":"HMAC SHA-256 over account/event/timestamp and exact bytes","raw_bytes":MAX_WEBHOOK},
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
    Waiting,
    Uncertain,
    Succeeded,
    Failed,
    Cancelled,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Cancellation {
    Requested,
    Expired,
    Revoked,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Runtime {
    pub codec: String,
    #[serde(with = "uuid_text")]
    pub activation: Uuid,
    pub mode: WorkerMode,
    pub quarantined: bool,
    pub retained: u16,
    pub unresolved: u16,
    pub reserved_facts: u16,
    pub facts: u16,
    pub inbox: u16,
    pub inbox_pending: u16,
    pub inbox_cursor: Option<String>,
    pub inbox_end: Option<String>,
    pub next_class: u8,
    pub sweeps: [Sweep; 4],
    pub accounted_bytes: u64,
}
impl Runtime {
    fn fresh() -> Self {
        Self {
            codec: CODEC.into(),
            activation: Uuid::new_v4(),
            mode: WorkerMode::Disabled,
            quarantined: false,
            retained: 0,
            unresolved: 0,
            reserved_facts: 0,
            facts: 0,
            inbox: 0,
            inbox_pending: 0,
            inbox_cursor: None,
            inbox_end: None,
            next_class: 0,
            sweeps: Default::default(),
            accounted_bytes: HEADER_ALLOWANCE,
        }
    }
    fn validate(&self) -> Result<()> {
        for (class, sweep) in self.sweeps.iter().enumerate() {
            sweep.validate(class as u8)?;
        }
        ensure(
            self.codec == CODEC
                && !self.activation.is_nil()
                && !(self.quarantined && self.mode == WorkerMode::Delivery),
            "effect runtime identity/activation",
        )?;
        ensure(
            self.unresolved <= MAX_UNRESOLVED
                && self.retained <= MAX_RETAINED
                && self.unresolved <= self.retained
                && self.reserved_facts <= self.unresolved
                && usize::from(self.facts) + usize::from(self.reserved_facts) <= MAX_FACTS
                && usize::from(self.inbox) <= MAX_INBOX
                && self.inbox_pending <= self.inbox
                && self.next_class < 4
                && self.accounted_bytes <= MAX_BYTES
                && self.accounted_bytes >= HEADER_ALLOWANCE
                && (HEADER.len() + local::encode(self)?.len()) as u64 <= HEADER_ALLOWANCE,
            "effect runtime bounds",
        )?;
        ensure(
            self.inbox_cursor.is_none() || self.inbox_end.is_some(),
            "inbox cursor without end",
        )?;
        for key in self.inbox_cursor.iter().chain(self.inbox_end.iter()) {
            inbox::validate_key(&local::unhex(key)?)?;
        }
        ensure(
            self.inbox_cursor
                .as_ref()
                .zip(self.inbox_end.as_ref())
                .is_none_or(|(cursor, end)| cursor <= end),
            "inbox sweep order",
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
    pub attempts: u8,
    pub observations: u8,
    #[serde(with = "decimal")]
    pub next_at: i64,
    pub lease: Option<Lease>,
    pub started: Option<Start>,
    pub last_fact: Option<String>,
    pub terminal_fact: Option<String>,
    pub application: Application,
    pub reservation: bool,
    pub quarantined: bool,
    pub conflict: bool,
    pub diagnostic: Option<String>,
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
fn runtime_read(read: &ReadTransaction) -> Result<Runtime> {
    let table = read.open_table(EFFECT_RUNTIME).map_err(local::storage)?;
    ensure(
        table.len().map_err(local::storage)? == 1,
        "effect runtime inventory",
    )?;
    let bytes = table
        .get(HEADER)
        .map_err(local::storage)?
        .ok_or_else(|| local::corrupt("missing effect runtime"))?;
    let runtime: Runtime = local::decode(bytes.value())?;
    runtime.validate()?;
    Ok(runtime)
}
fn load_execution<B: Binding>(write: &WriteTransaction, id: Uuid) -> Result<Execution<B>> {
    let table = write.open_table(EXECUTIONS).map_err(local::storage)?;
    let bytes = table
        .get(id.as_bytes().as_slice())
        .map_err(local::storage)?
        .ok_or_else(|| Error::new("not_found", "execution unavailable"))?;
    let row: Execution<B> = local::decode(bytes.value())?;
    ensure(
        row.id == id && local::encode(&row)? == bytes.value(),
        "canonical execution",
    )?;
    Ok(row)
}
/// All lifecycle changes share exact index/counter publication and one CAS.
fn replace_execution<B: Binding>(
    write: &WriteTransaction,
    runtime: &mut Runtime,
    before: &Execution<B>,
    row: &Execution<B>,
    abort: Option<usize>,
) -> Result<()> {
    ensure(before.same_intent(row), "immutable execution changed")?;
    ensure(
        row.revision > before.revision,
        "execution revision did not advance",
    )?;
    ensure(
        local::encode(&load_execution::<B>(write, row.id)?)? == local::encode(before)?,
        "execution CAS",
    )?;
    row.validate_state(runtime)?;
    runtime.unresolved = runtime
        .unresolved
        .checked_sub(u16::from(before.unresolved()))
        .and_then(|n| n.checked_add(u16::from(row.unresolved())))
        .ok_or_else(|| local::corrupt("effect unresolved count"))?;
    runtime.reserved_facts = runtime
        .reserved_facts
        .checked_sub(u16::from(before.reservation))
        .and_then(|n| n.checked_add(u16::from(row.reservation)))
        .ok_or_else(|| local::corrupt("effect reservation count"))?;
    runtime.accounted_bytes = runtime
        .accounted_bytes
        .checked_sub(before.accounted_bytes()?)
        .and_then(|n| n.checked_add(row.accounted_bytes().ok()?))
        .ok_or_else(|| local::corrupt("effect byte accounting"))?;
    if runtime.unresolved > MAX_UNRESOLVED
        || usize::from(runtime.facts) + usize::from(runtime.reserved_facts) > MAX_FACTS
        || runtime.accounted_bytes > MAX_BYTES
    {
        return Err(Error::new("state_limit", "effect recovery capacity"));
    }
    {
        let mut due = write.open_table(DUE).map_err(local::storage)?;
        if let Some(key) = before.due() {
            ensure(
                due.remove(key.as_slice())
                    .map_err(local::storage)?
                    .is_some(),
                "previous effect due row missing",
            )?;
        }
        if let Some(key) = row.due() {
            due.insert(key.as_slice(), b"".as_slice())
                .map_err(local::storage)?;
        }
    }
    injected(abort, usize::MAX - 2)?;
    write
        .open_table(EXECUTIONS)
        .map_err(local::storage)?
        .insert(row.id.as_bytes().as_slice(), local::encode(row)?.as_slice())
        .map_err(local::storage)?;
    injected(abort, usize::MAX - 1)?;
    write_runtime(write, runtime)?;
    injected(abort, usize::MAX - 3)
}
pub(crate) fn create_tables(write: &WriteTransaction) -> Result<()> {
    for (table, _) in TABLES {
        write.open_table(table).map_err(local::storage)?;
    }
    write_runtime(write, &Runtime::fresh())
}
pub(crate) fn reset_tables<B: Binding>(write: &WriteTransaction) -> Result<()> {
    let old = runtime_write(write)?;
    if old.mode.active() || old.unresolved != 0 || old.inbox_pending != 0 {
        return Err(Error::new(
            "invariant",
            "unresolved external work prevents reset",
        ));
    }
    for row in write
        .open_table(FACTS)
        .map_err(local::storage)?
        .iter()
        .map_err(local::storage)?
    {
        let (_, value) = row.map_err(local::storage)?;
        let fact: state::Fact<B> = local::decode(value.value())?;
        if fact.disposition == Disposition::Succeeded && fact.applied_revision.is_none() {
            return Err(Error::new(
                "invariant",
                "unapplied provider fact prevents reset",
            ));
        }
    }
    for (table, _) in TABLES {
        write.delete_table(table).map_err(local::storage)?;
    }
    create_tables(write)
}
pub(crate) fn quarantine_restore<B: Binding>(write: &WriteTransaction) -> Result<bool> {
    let mut runtime = runtime_write(write)?;
    if runtime.retained > 0 {
        runtime.activation = Uuid::new_v4();
        runtime.mode = WorkerMode::Disabled;
        runtime.quarantined = true;
        runtime.sweeps = Default::default();
        runtime.inbox_cursor = None;
        runtime.inbox_end = None;
        let rows = write
            .open_table(EXECUTIONS)
            .map_err(local::storage)?
            .iter()
            .map_err(local::storage)?
            .map(|v| {
                let (_, v) = v.map_err(local::storage)?;
                local::decode::<Execution<B>>(v.value())
            })
            .collect::<Result<Vec<_>>>()?;
        let now = now_millis()?;
        for before in rows {
            if !before.unresolved() {
                continue;
            }
            let mut row = before.clone();
            row.quarantined = true;
            row.lease = None;
            row.next_at = now;
            if row.phase == Phase::Ready && row.started.is_some() {
                row.phase = Phase::Uncertain;
            }
            row.advance()?;
            replace_execution(write, &mut runtime, &before, &row, None)?;
        }
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
    if runtime.quarantined {
        return Err(Error::new(
            "invalid_input",
            "restored store permits reconciliation and domain repair only",
        ));
    }
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
        if runtime.retained >= MAX_RETAINED
            || runtime.unresolved >= MAX_UNRESOLVED
            || usize::from(runtime.facts) + usize::from(runtime.reserved_facts) >= MAX_FACTS
        {
            return Err(Error::new("state_limit", "effect retention capacity"));
        }
        ws.charge("allocate", 1)?;
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
            attempts: 0,
            observations: 0,
            next_at: execute_at,
            lease: None,
            started: None,
            last_fact: None,
            terminal_fact: None,
            application: Application::None,
            reservation: true,
            quarantined: runtime.quarantined,
            conflict: false,
            diagnostic: None,
        };
        runtime.retained += 1;
        runtime.unresolved += 1;
        runtime.reserved_facts += 1;
        runtime.accounted_bytes = runtime
            .accounted_bytes
            .checked_add(row.accounted_bytes()?)
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
            .insert(
                row.due()
                    .ok_or_else(|| local::corrupt("new intent due"))?
                    .as_slice(),
                b"".as_slice(),
            )
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
        let runtime = runtime_read(&read)?;
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
        let outcome = row
            .terminal_fact
            .as_ref()
            .or(row.last_fact.as_ref())
            .map(|digest| {
                let facts = read.open_table(FACTS).map_err(local::storage)?;
                let value = facts
                    .get(state::fact_key(row.id, digest)?.as_slice())
                    .map_err(local::storage)?
                    .ok_or_else(|| local::corrupt("linked effect fact missing"))?;
                let fact: Fact<B> = local::decode(value.value())?;
                serde_json::to_value(fact.outcome).map_err(local::storage)
            })
            .transpose()?;
        Ok(
            json!({"execution_id":row.id,"source":row.source,"target":row.target,"revision":row.revision.to_string(),
            "phase":row.phase,"request":row.request,"created_at":row.created_at.to_string(),"execute_at":row.execute_at.to_string(),
            "not_after":row.not_after.to_string(),"cancellation":row.cancellation,"provider_key":format!("{}/{}",row.id,row.action),
            "worker_mode":runtime.mode,"application":row.application,"outcome":outcome,
            "attempts":row.attempts,"observations":row.observations,"next_eligible":row.next_at.to_string(),
            "running":row.lease.as_ref().is_some_and(|l| l.expires_at > now_millis().unwrap_or(i64::MAX)),
            "quarantined":row.quarantined,"conflict":row.conflict,"diagnostic":row.diagnostic}),
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
            let before = row.clone();
            if matches!(row.phase, Phase::Ready | Phase::Waiting | Phase::Uncertain) {
                row.cancellation = Some(Cancellation::Requested);
                row.lease = None;
                // A restored prestart image also cannot establish nonexecution.
                if row.started.is_none() && row.phase == Phase::Ready && !row.quarantined {
                    row.phase = Phase::Cancelled;
                    row.reservation = false;
                } else {
                    row.phase = Phase::Uncertain;
                    row.next_at = now_millis()?;
                }
                row.advance()?;
                replace_execution(&write, &mut runtime, &before, &row, abort_after)?;
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
        write.commit()?;
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
    let mut executions = BTreeMap::new();
    let mut reserved = 0;
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
        row.validate_state(&runtime)?;
        bytes += row.accounted_bytes()?;
        unresolved += u16::from(row.unresolved());
        reserved += u16::from(row.reservation);
        if let Some(key) = row.due() {
            due.insert(key, Vec::<u8>::new());
        }
        executions.insert(row.id, row);
    }
    let mut facts = BTreeMap::new();
    for item in read
        .open_table(FACTS)
        .map_err(local::storage)?
        .iter()
        .map_err(local::storage)?
    {
        let (key, value) = item.map_err(local::storage)?;
        ensure(facts.len() < MAX_FACTS, "provider fact population")?;
        let fact: Fact<B> = local::decode(value.value())?;
        let row = executions
            .get(&fact.execution)
            .ok_or_else(|| local::corrupt("orphan provider fact"))?;
        ensure(
            local::encode(&fact)? == value.value()
                && fact.codec == CODEC
                && state::fact_key(fact.execution, &fact.digest)? == key.value()
                && fact.digest == state::outcome_digest::<B>(&fact.outcome)?
                && fact.request_hash == row.request_hash
                && fact.observed_at >= row.created_at
                && local::encode(&fact.outcome)?.len() <= MAX_OUTCOME
                && B::effect_outcome(&row.request, row.id, &fact.outcome)? == fact.disposition,
            "provider fact binding/hash",
        )?;
        if let Some(revision) = fact.applied_revision {
            ensure(
                revision > 0
                    && revision <= meta.revision
                    && fact.disposition == Disposition::Succeeded
                    && row.terminal_fact.as_ref() == Some(&fact.digest)
                    && row.application == Application::Applied,
                "fact application revision/binding",
            )?;
        }
        bytes += (key.value().len() + value.value().len()) as u64;
        facts.insert((fact.execution, fact.digest.clone()), fact);
    }
    for row in executions.values() {
        for digest in row.last_fact.iter().chain(row.terminal_fact.iter()) {
            ensure(
                facts.contains_key(&(row.id, digest.clone())),
                "execution fact link",
            )?;
        }
        if let Some(digest) = &row.terminal_fact {
            let fact = &facts[&(row.id, digest.clone())];
            ensure(
                match row.phase {
                    Phase::Succeeded => {
                        fact.disposition == Disposition::Succeeded
                            && (fact.applied_revision.is_some()
                                == (row.application == Application::Applied))
                    }
                    Phase::Failed => matches!(
                        fact.disposition,
                        Disposition::Failed | Disposition::NotAccepted
                    ),
                    _ => false,
                },
                "terminal provider fact/application",
            )?;
        }
    }
    let (inbox_count, inbox_pending, inbox_bytes) = inbox::check(read, &executions, &facts)?;
    bytes += inbox_bytes;
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
            && runtime.reserved_facts == reserved
            && usize::from(runtime.facts) == facts.len()
            && runtime.inbox == inbox_count
            && runtime.inbox_pending == inbox_pending
            && runtime.accounted_bytes == bytes,
        "effect counts/reserved bytes",
    )?;
    let now = now_millis()?;
    let oldest_eligible_age = executions
        .values()
        .filter_map(|row| row.due())
        .filter_map(|key| {
            let at = (u64::from_be_bytes(key[1..9].try_into().ok()?) ^ (1u64 << 63)) as i64;
            (at <= now).then(|| now.saturating_sub(at))
        })
        .max();
    Ok(
        json!({"retained":retained,"unresolved":unresolved,"reserved_facts":reserved,"facts":facts.len(),
            "accounted_bytes":bytes,"worker_mode":runtime.mode,"quarantined":runtime.quarantined,
            "inbox":inbox_count,"inbox_pending":inbox_pending,
            "oldest_eligible_age_ms":oldest_eligible_age.map(|age|age.to_string()),
            "expired_leases":executions.values().filter(|r|r.lease.as_ref().is_some_and(|l|l.expires_at<=now)).count(),
            "blocked":executions.values().filter(|r|r.application==Application::Blocked).count(),
            "uncertain":executions.values().filter(|r|r.phase==Phase::Uncertain).count()}),
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
                    && result.execution_revision > 0
                    && row.revision >= result.execution_revision
                    && result.phase != Phase::Ready,
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
