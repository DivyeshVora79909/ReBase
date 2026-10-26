//! Verified raw events are durable before ACK. Consumption and provider facts
//! share a transaction; the domain application remains a separate transaction.
use super::*;
use crate::native_codec::optional_decimal;
use hmac::{Hmac, Mac};
use std::{io::Read, ops::Bound, path::Path};

pub(crate) const ACCOUNT: &str = "fake-account-1";
const SKEW_MS: u64 = 300_000;
// A pending row reserves the largest encoded consumption revision.
const CONSUMPTION_RESERVE: u64 = 32;

pub(crate) struct Secret(Vec<u8>);
impl Secret {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err(Error::new(
                "invalid_input",
                "webhook secret file must be absolute",
            ));
        }
        let mut bytes = vec![];
        std::fs::File::open(path)
            .and_then(|file| file.take(129).read_to_end(&mut bytes))
            .map_err(|_| Error::new("invalid_input", "webhook secret file unavailable"))?;
        Self::new(bytes)
    }
    pub(super) fn new(bytes: Vec<u8>) -> Result<Self> {
        if !(32..=128).contains(&bytes.len()) {
            return Err(Error::new(
                "invalid_input",
                "webhook secret requires 32 to 128 raw bytes",
            ));
        }
        Ok(Self(bytes))
    }
    pub(crate) fn verify<B: Binding>(
        &self,
        account: &str,
        event: &str,
        timestamp: &str,
        signature: &str,
        body: &[u8],
        now: i64,
    ) -> Result<Verified<B>> {
        if body.len() > MAX_WEBHOOK {
            return Err(Error::new("request_limit", "webhook byte limit"));
        }
        let denied = || Error::new("unauthenticated", "invalid webhook authentication");
        let event_id = Uuid::parse_str(event).map_err(|_| denied())?;
        let signed_at: i64 = timestamp.parse().map_err(|_| denied())?;
        if account != ACCOUNT
            || event_id.is_nil()
            || event_id.to_string() != event
            || signed_at < 0
            || signed_at.to_string() != timestamp
            || now < 0
            || now.abs_diff(signed_at) > SKEW_MS
            || signature.len() != 64
        {
            return Err(denied());
        }
        let signature = local::unhex(signature).map_err(|_| denied())?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).map_err(|_| denied())?;
        for part in [
            account.as_bytes(),
            b"\n",
            event.as_bytes(),
            b"\n",
            timestamp.as_bytes(),
            b"\n",
            body,
        ] {
            mac.update(part);
        }
        mac.verify_slice(&signature).map_err(|_| denied())?;
        // Authentication covers the exact bytes, including whitespace; parsing
        // also rejects duplicate keys and unknown typed fields.
        let payload = parse::<B>(body)?;
        Ok(Verified {
            event: event_id,
            signed_at,
            received_at: now,
            body: std::str::from_utf8(body)
                .map_err(|_| Error::new("invalid_input", "webhook UTF-8"))?
                .to_owned(),
            payload,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, bound(serialize = "", deserialize = ""))]
struct Payload<B: Binding> {
    #[serde(with = "uuid_text")]
    execution_id: Uuid,
    outcome: B::Outcome,
}
fn parse<B: Binding>(body: &[u8]) -> Result<Payload<B>> {
    let payload: Payload<B> =
        serde_json::from_value(crate::json::parse_bounded(body, MAX_WEBHOOK)?)
            .map_err(|_| Error::new("invalid_input", "webhook payload"))?;
    if payload.execution_id.is_nil() || local::encode(&payload.outcome)?.len() > MAX_OUTCOME {
        return Err(Error::new("invalid_input", "webhook outcome size/identity"));
    }
    Ok(payload)
}

pub(crate) struct Verified<B: Binding> {
    event: Uuid,
    signed_at: i64,
    received_at: i64,
    body: String,
    payload: Payload<B>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(serialize = "", deserialize = ""))]
pub(super) struct Row<B: Binding> {
    codec: String,
    account: String,
    #[serde(with = "uuid_text")]
    event: Uuid,
    #[serde(with = "uuid_text")]
    store: Uuid,
    request_hash: String,
    body: String,
    body_hash: String,
    payload: Payload<B>,
    #[serde(with = "decimal")]
    signed_at: i64,
    #[serde(with = "decimal")]
    received_at: i64,
    #[serde(with = "optional_decimal")]
    consumed_revision: Option<u64>,
}
fn key(event: Uuid) -> Vec<u8> {
    [ACCOUNT.as_bytes(), &[0], event.as_bytes()].concat()
}
pub(super) fn validate_key(bytes: &[u8]) -> Result<()> {
    let prefix = ACCOUNT.len() + 1;
    ensure(
        bytes.len() == prefix + 16 && bytes[..prefix] == [ACCOUNT.as_bytes(), &[0]].concat(),
        "inbox key",
    )?;
    ensure(
        Uuid::from_slice(&bytes[prefix..]).is_ok_and(|event| !event.is_nil()),
        "inbox event identity",
    )
}
fn accounted<B: Binding>(row: &Row<B>) -> Result<u64> {
    Ok((key(row.event).len() + local::encode(row)?.len()) as u64
        + if row.consumed_revision.is_none() {
            CONSUMPTION_RESERVE
        } else {
            0
        })
}
fn load<B: Binding>(write: &WriteTransaction, key: &[u8]) -> Result<Row<B>> {
    validate_key(key)?;
    let table = write.open_table(INBOX).map_err(local::storage)?;
    let value = table
        .get(key)
        .map_err(local::storage)?
        .ok_or_else(|| local::corrupt("inbox row missing"))?;
    let row: Row<B> = local::decode(value.value())?;
    ensure(
        local::encode(&row)? == value.value() && self::key(row.event) == key,
        "canonical inbox row",
    )?;
    Ok(row)
}

impl<B: Binding> Store<B> {
    /// A verified event is the only ingress capability. Errors, including an
    /// unknown commit acknowledgement, never authorize a positive ACK.
    pub(crate) fn accept_effect_event(
        &self,
        event: Verified<B>,
        abort: Option<usize>,
    ) -> Result<Value> {
        let write = self.begin_write().map_err(local::storage)?;
        let mut runtime = runtime_write(&write)?;
        let execution = load_execution::<B>(&write, event.payload.execution_id)?;
        if execution.provider_account != ACCOUNT || event.received_at < execution.created_at {
            return Err(Error::new("invalid_input", "webhook execution binding"));
        }
        B::effect_outcome(&execution.request, execution.id, &event.payload.outcome)?;
        let event_key = key(event.event);
        {
            let table = write.open_table(INBOX).map_err(local::storage)?;
            if let Some(value) = table.get(event_key.as_slice()).map_err(local::storage)? {
                let old: Row<B> = local::decode(value.value())?;
                if old.body != event.body
                    || old.payload.execution_id != execution.id
                    || old.account != ACCOUNT
                {
                    return Err(Error::new(
                        "content_conflict",
                        "webhook event content differs",
                    ));
                }
                return Ok(json!({"status":"accepted","duplicate":true}));
            }
        }
        if usize::from(runtime.inbox) >= MAX_INBOX {
            return Err(Error::new("state_limit", "webhook inbox capacity"));
        }
        let row = Row {
            codec: CODEC.into(),
            account: ACCOUNT.into(),
            event: event.event,
            store: execution.store,
            request_hash: execution.request_hash,
            body_hash: native_codec::hex(&Sha256::digest(event.body.as_bytes())),
            body: event.body,
            payload: event.payload,
            signed_at: event.signed_at,
            received_at: event.received_at,
            consumed_revision: None,
        };
        runtime.inbox += 1;
        runtime.inbox_pending += 1;
        runtime.accounted_bytes = runtime
            .accounted_bytes
            .checked_add(accounted(&row)?)
            .filter(|bytes| *bytes <= MAX_BYTES)
            .ok_or_else(|| Error::new("state_limit", "webhook byte capacity"))?;
        write
            .open_table(INBOX)
            .map_err(local::storage)?
            .insert(event_key.as_slice(), local::encode(&row)?.as_slice())
            .map_err(local::storage)?;
        injected(abort, usize::MAX - 6)?;
        write_runtime(&write, &runtime)?;
        injected(abort, usize::MAX - 7)?;
        write.commit()?;
        Ok(json!({"status":"accepted","duplicate":false}))
    }

    /// Stable-key cursor visits at most sixteen rows, including consumed rows.
    /// A failed consumer cannot pin the cursor or starve a later event.
    pub(super) fn scan_effect_inbox(&self, activation: Uuid) -> Result<Vec<Vec<u8>>> {
        let write = self.begin_write().map_err(local::storage)?;
        let mut runtime = runtime_write(&write)?;
        if runtime.activation != activation || !runtime.mode.active() {
            return Err(Error::new("stale_version", "inbox activation changed"));
        }
        if runtime.inbox_pending == 0 {
            return Ok(vec![]);
        }
        let mut keys = vec![];
        {
            let table = write.open_table(INBOX).map_err(local::storage)?;
            if runtime.inbox_end.is_none() {
                runtime.inbox_cursor = None;
                runtime.inbox_end = table
                    .iter()
                    .map_err(local::storage)?
                    .last()
                    .transpose()
                    .map_err(local::storage)?
                    .map(|(key, _)| native_codec::hex(key.value()));
            }
            if let Some(end) = &runtime.inbox_end {
                let end = local::unhex(end)?;
                let cursor = runtime
                    .inbox_cursor
                    .as_ref()
                    .map(|key| local::unhex(key))
                    .transpose()?;
                let low = cursor.as_deref().map_or(Bound::Unbounded, Bound::Excluded);
                let started = std::time::Instant::now();
                for item in table
                    .range::<&[u8]>((low, Bound::Included(end.as_slice())))
                    .map_err(local::storage)?
                {
                    let (key, _) = item.map_err(local::storage)?;
                    validate_key(key.value())?;
                    keys.push(key.value().to_vec());
                    runtime.inbox_cursor = Some(native_codec::hex(key.value()));
                    if keys.len() == 16 || started.elapsed().as_millis() >= 100 {
                        break;
                    }
                }
                if keys.is_empty() || runtime.inbox_cursor == runtime.inbox_end {
                    runtime.inbox_cursor = None;
                    runtime.inbox_end = None;
                }
            }
        }
        write_runtime(&write, &runtime)?;
        write.commit()?;
        Ok(keys)
    }

    pub(super) fn consume_effect_event(
        &self,
        activation: Uuid,
        key: &[u8],
        supplied: Option<i64>,
        abort: Option<usize>,
    ) -> Result<bool> {
        let write = self.begin_write().map_err(local::storage)?;
        let mut runtime = runtime_write(&write)?;
        if runtime.activation != activation || !runtime.mode.active() {
            return Err(Error::new("stale_version", "inbox activation changed"));
        }
        let mut event = load::<B>(&write, key)?;
        if event.consumed_revision.is_some() {
            return Ok(false);
        }
        let before = load_execution::<B>(&write, event.payload.execution_id)?;
        ensure(
            event.store == before.store && event.request_hash == before.request_hash,
            "inbox execution binding",
        )?;
        let now = supplied.map_or_else(now_millis, Ok)?;
        if now < event.received_at {
            return Err(Error::new("stale_version", "inbox clock precedes receipt"));
        }
        let mut row = before.clone();
        row.lease = None;
        worker::record_fact(
            &write,
            &mut runtime,
            &mut row,
            &event.payload.outcome,
            now,
            false,
        )?;
        injected(abort, usize::MAX - 4)?;
        row.advance()?;
        let old_bytes = accounted(&event)?;
        event.consumed_revision = Some(row.revision);
        runtime.inbox_pending = runtime
            .inbox_pending
            .checked_sub(1)
            .ok_or_else(|| local::corrupt("inbox pending count"))?;
        runtime.accounted_bytes = runtime
            .accounted_bytes
            .checked_sub(old_bytes)
            .and_then(|bytes| bytes.checked_add(accounted(&event).ok()?))
            .ok_or_else(|| local::corrupt("inbox consumption bytes"))?;
        write
            .open_table(INBOX)
            .map_err(local::storage)?
            .insert(key, local::encode(&event)?.as_slice())
            .map_err(local::storage)?;
        injected(abort, usize::MAX - 6)?;
        replace_execution(&write, &mut runtime, &before, &row, abort)?;
        write.commit()?;
        Ok(true)
    }
}

pub(super) fn check<B: Binding>(
    read: &ReadTransaction,
    executions: &BTreeMap<Uuid, Execution<B>>,
    facts: &BTreeMap<(Uuid, String), Fact<B>>,
) -> Result<(u16, u16, u64)> {
    let mut count = 0;
    let mut pending = 0;
    let mut bytes = 0;
    for item in read
        .open_table(INBOX)
        .map_err(local::storage)?
        .iter()
        .map_err(local::storage)?
    {
        let (key, value) = item.map_err(local::storage)?;
        ensure(usize::from(count) < MAX_INBOX, "inbox population")?;
        validate_key(key.value())?;
        let event: Row<B> = local::decode(value.value())?;
        let row = executions
            .get(&event.payload.execution_id)
            .ok_or_else(|| local::corrupt("orphan inbox event"))?;
        ensure(
            local::encode(&event)? == value.value()
                && self::key(event.event) == key.value()
                && event.codec == CODEC
                && event.account == row.provider_account
                && event.account == ACCOUNT
                && event.store == row.store
                && event.request_hash == row.request_hash
                && event.body_hash == native_codec::hex(&Sha256::digest(event.body.as_bytes()))
                && event.signed_at >= 0
                && event.received_at >= row.created_at
                && event.received_at.abs_diff(event.signed_at) <= SKEW_MS,
            "inbox identity/hash/time",
        )?;
        let parsed = parse::<B>(event.body.as_bytes())?;
        ensure(
            parsed.execution_id == event.payload.execution_id
                && parsed.outcome == event.payload.outcome,
            "inbox normalized payload",
        )?;
        B::effect_outcome(&row.request, row.id, &event.payload.outcome)?;
        if let Some(revision) = event.consumed_revision {
            let digest = state::outcome_digest::<B>(&event.payload.outcome)?;
            ensure(
                revision > 0
                    && revision <= row.revision
                    && facts
                        .get(&(row.id, digest))
                        .is_some_and(|fact| fact.outcome == event.payload.outcome),
                "inbox consumed fact/revision",
            )?;
        } else {
            pending += 1;
        }
        count += 1;
        bytes += accounted(&event)?;
    }
    Ok((count, pending, bytes))
}
