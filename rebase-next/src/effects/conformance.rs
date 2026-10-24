//! Trusted application controls over a real persistence adapter. Provider
//! outcomes enter through the ordinary signed fake inbox and worker fact paths;
//! no transport or external delivery guarantee is implied.
use super::*;
use crate::{
    local::Mutation,
    models::effect_demo::{EffectDemo, Input, Outcome, ProviderPhase},
    native_slice::Context,
    storage::Database,
};
use hmac::{Hmac, Mac};
use state::{Candidate, Claim, WorkClass};
use std::sync::Arc;

const SECRET: &[u8] = b"g7-disposable-inbox-secret-32-bytes";

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}
fn require(ok: bool, detail: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::new("effect_conformance", detail))
    }
}
fn image(store: &Store<EffectDemo>) -> Result<Value> {
    let image = store.observe_for_verification()?;
    let expected: BTreeSet<_> = local::table_names(true).into_iter().collect();
    let actual: BTreeSet<_> = image["tables"]
        .as_object()
        .ok_or_else(|| Error::new("effect_conformance", "missing table inventory"))?
        .keys()
        .cloned()
        .collect();
    require(
        image["complete"] == true && actual == expected,
        "incomplete effect application observation",
    )?;
    Ok(image)
}
fn rejected<T>(
    store: &Store<EffectDemo>,
    before: &Value,
    result: Result<T>,
    code: &str,
) -> Result<()> {
    let error = match result {
        Ok(_) => return Err(Error::new("effect_conformance", "rejection required")),
        Err(error) => error,
    };
    require(
        error.code == code,
        &format!("expected {code}, received {error}"),
    )?;
    let after = image(store)?;
    require(
        after["tables"]["operations"] == before["tables"]["operations"],
        "rejected effect attempt published a receipt",
    )?;
    require(after == *before, "rejected effect attempt changed tables")?;
    store.check_integrity()?;
    Ok(())
}
fn mutate(store: &Store<EffectDemo>, commands: Value) -> Result<Value> {
    let request: Mutation = serde_json::from_value(json!({
        "model":store.model().identity(),
        "context":store.operation_context(store.model().identity())?,
        "operation_id":Uuid::new_v4(),"commands":commands,"returning":[]
    }))
    .map_err(local::storage)?;
    store.mutate(&request)
}
fn dispatch(record: Uuid, units: &str) -> Value {
    json!({"op":"create","id":record,"contract":205,"fields":{
        "account":id(10),"units":units,"execute_at":null,"not_after":null}})
}
fn execution(result: &Value) -> Result<Uuid> {
    result["result"]["executions"][0]["execution_id"]
        .as_str()
        .ok_or_else(|| Error::new("effect_conformance", "missing created execution"))?
        .parse()
        .map_err(local::storage)
}
fn row(store: &Store<EffectDemo>, execution: Uuid) -> Result<Execution<EffectDemo>> {
    let write = store.db.begin_write()?;
    load_execution(&write, execution)
}
fn candidate(store: &Store<EffectDemo>, execution: Uuid, class: WorkClass) -> Result<Candidate> {
    let write = store.db.begin_write()?;
    let runtime = runtime_write(&write)?;
    let row = load_execution::<EffectDemo>(&write, execution)?;
    Ok(Candidate {
        store: row.store,
        activation: runtime.activation,
        execution,
        revision: row.revision,
        class,
    })
}
fn begin(store: &Store<EffectDemo>, execution: Uuid) -> Result<(Claim, i64)> {
    let now = row(store, execution)?.created_at + 1;
    let claim = store
        .claim_effect_at(&candidate(store, execution, WorkClass::Submit)?, Some(now))?
        .ok_or_else(|| Error::new("effect_conformance", "submission claim unavailable"))?;
    let started = store
        .start_effect_at(&claim, Some(now))?
        .ok_or_else(|| Error::new("effect_conformance", "submission start unavailable"))?;
    Ok((started, now))
}
fn outcome(execution: Uuid, units: i128) -> Outcome {
    Outcome {
        execution_id: execution,
        account: "fake-account-1".into(),
        action: 1,
        units,
        phase: ProviderPhase::Succeeded,
        receipt: Some(id(999).to_string()),
    }
}
fn verified(event: Uuid, bytes: &[u8], now: i64) -> Result<inbox::Verified<EffectDemo>> {
    let event = event.to_string();
    let timestamp = now.to_string();
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).map_err(local::storage)?;
    mac.update(format!("fake-account-1\n{event}\n{timestamp}\n").as_bytes());
    mac.update(bytes);
    let signature = native_codec::hex(&mac.finalize().into_bytes());
    inbox::Secret::new(SECRET.to_vec())?.verify(
        inbox::ACCOUNT,
        &event,
        &timestamp,
        &signature,
        bytes,
        now,
    )
}
fn balance(store: &Store<EffectDemo>, expected: i128) -> Result<()> {
    let account = store
        .get(store.model().identity(), id(10))?
        .ok_or_else(|| Error::new("effect_conformance", "missing target account"))?;
    require(
        matches!(account.input, Input::Account { balance } if balance == expected),
        "account balance differs from independent literal expectation",
    )
}
fn count(image: &Value, table: &str, expected: usize) -> Result<()> {
    require(
        image["tables"][table]
            .as_array()
            .is_some_and(|rows| rows.len() == expected),
        &format!("unexpected population in {table}"),
    )
}
fn decoded_rows(image: &Value, table: &str) -> Result<Vec<Value>> {
    image["tables"][table]
        .as_array()
        .ok_or_else(|| Error::new("effect_conformance", "missing observed table"))?
        .iter()
        .map(|row| {
            let bytes = row["value"]
                .as_str()
                .ok_or_else(|| Error::new("effect_conformance", "missing observed value"))?;
            local::decode(&local::unhex(bytes)?)
        })
        .collect()
}

/// Return the same persisted destination for repeated family names and a fresh
/// isolated destination for each new name. This control uses `effect-publication`.
/// Calls are synchronous and must run outside an async executor worker thread.
pub fn run(factory: impl Fn(&str) -> Result<Database>) -> Result<Value> {
    let model = Arc::new(Prepared::<EffectDemo>::load()?);
    let store = Store::create_backend_secured(
        factory("effect-publication")?,
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )?;
    let mut cases = Vec::new();
    let first = execution(&mutate(
        &store,
        json!([
            {"op":"create","id":id(10),"contract":101,"fields":{"balance":"12"}},
            dispatch(id(20), "3")
        ]),
    )?)?;
    store.activate_effect_worker(WorkerMode::Delivery)?;
    let (old_claim, now) = begin(&store, first)?;
    let event = id(500);
    let bytes = local::encode(&json!({"execution_id":first,"outcome":outcome(first,3)}))?;
    let before = image(&store)?;
    for (name, abort) in [
        ("signed-inbox-row-abort", usize::MAX - 6),
        ("signed-inbox-runtime-abort", usize::MAX - 7),
    ] {
        rejected(
            &store,
            &before,
            store.accept_effect_event(verified(event, &bytes, now + 1)?, Some(abort)),
            "injected_abort",
        )?;
        cases.push(name);
    }
    require(
        store.accept_effect_event(verified(event, &bytes, now + 1)?, None)?
            == json!({"status":"accepted","duplicate":false}),
        "signed event was not durably accepted",
    )?;
    let received = image(&store)?;
    count(&received, "effect_inbox", 1)?;
    count(&received, "effect_facts", 0)?;
    balance(&store, 12)?;
    cases.push("signed-inbox-durable-ack-precedes-fact-and-domain");
    require(
        store.accept_effect_event(verified(event, &bytes, now + 2)?, None)?
            == json!({"status":"accepted","duplicate":true})
            && image(&store)? == received,
        "duplicate event changed tables",
    )?;
    cases.push("signed-inbox-dedup-preserves-complete-inventory");
    let mut different = bytes.clone();
    different.push(b' ');
    rejected(
        &store,
        &received,
        store.accept_effect_event(verified(event, &different, now + 2)?, None),
        "content_conflict",
    )?;
    cases.push("signed-inbox-content-conflict-preserves-complete-inventory");
    let key = [b"fake-account-1\0".as_slice(), event.as_bytes()].concat();
    for (name, abort) in [
        ("inbox-consume-fact-abort", usize::MAX - 4),
        ("inbox-consume-row-abort", usize::MAX - 6),
        ("inbox-consume-due-abort", usize::MAX - 2),
        ("inbox-consume-execution-abort", usize::MAX - 1),
        ("inbox-consume-runtime-abort", usize::MAX - 3),
    ] {
        rejected(
            &store,
            &received,
            store.consume_effect_event(old_claim.activation, &key, Some(now + 3), Some(abort)),
            "injected_abort",
        )?;
        cases.push(name);
    }
    require(
        store.consume_effect_event(old_claim.activation, &key, Some(now + 3), None)?,
        "inbox fact was not consumed",
    )?;
    let consumed = image(&store)?;
    count(&consumed, "effect_facts", 1)?;
    balance(&store, 12)?;
    require(
        !store.consume_effect_event(old_claim.activation, &key, Some(now + 3), None)?
            && image(&store)? == consumed,
        "duplicate consumption changed tables",
    )?;
    cases.push("inbox-consumption-fact-atomic-and-idempotent");
    rejected(
        &store,
        &consumed,
        store.finish_effect_at(&old_claim, Some(&outcome(first, 3)), Some(now + 3), None),
        "stale_version",
    )?;
    cases.push("inbox-consumption-fences-old-worker-claim");
    let apply = candidate(&store, first, WorkClass::Apply)?;
    for (name, abort) in [
        ("application-first-native-write-abort", 1),
        ("application-native-public-reader-abort", usize::MAX - 5),
        ("application-fact-revision-abort", usize::MAX - 4),
        ("application-due-abort", usize::MAX - 2),
        ("application-execution-abort", usize::MAX - 1),
        ("application-runtime-abort", usize::MAX - 3),
    ] {
        rejected(
            &store,
            &consumed,
            store.apply_effect_inner(&apply, Some(abort)),
            "injected_abort",
        )?;
        cases.push(name);
    }
    require(
        store.apply_effect(&apply)?,
        "effect domain application failed",
    )?;
    balance(&store, 9)?;
    let applied = image(&store)?;
    let first_row = row(&store, first)?;
    require(
        first_row.phase == Phase::Succeeded && first_row.application == Application::Applied,
        "inbox success was not terminal and applied",
    )?;
    require(
        !store.apply_effect(&apply)? && image(&store)? == applied,
        "old application candidate applied twice",
    )?;
    store.check_integrity()?;
    cases.push("inbox-success-applies-domain-once-literal-balance-nine");

    let second = execution(&mutate(&store, json!([dispatch(id(21), "3")]))?)?;
    let (claim, now) = begin(&store, second)?;
    let before = image(&store)?;
    for (name, abort) in [
        ("worker-fact-abort", usize::MAX - 4),
        ("worker-fact-due-abort", usize::MAX - 2),
        ("worker-fact-execution-abort", usize::MAX - 1),
        ("worker-fact-runtime-abort", usize::MAX - 3),
    ] {
        rejected(
            &store,
            &before,
            store.finish_effect_at(
                &claim,
                Some(&outcome(second, 3)),
                Some(now + 1),
                Some(abort),
            ),
            "injected_abort",
        )?;
        cases.push(name);
    }
    store.finish_effect_at(&claim, Some(&outcome(second, 3)), Some(now + 1), None)?;
    balance(&store, 9)?;
    require(
        store.apply_effect(&candidate(&store, second, WorkClass::Apply)?)?,
        "worker fact application failed",
    )?;
    balance(&store, 6)?;
    cases.push("worker-success-fact-and-domain-publication-literal-balance-six");

    let third = execution(&mutate(&store, json!([dispatch(id(22), "10")]))?)?;
    let (claim, now) = begin(&store, third)?;
    store.finish_effect_at(&claim, Some(&outcome(third, 10)), Some(now + 1), None)?;
    let apply = candidate(&store, third, WorkClass::Apply)?;
    let before = image(&store)?;
    rejected(
        &store,
        &before,
        store.apply_effect_inner(&apply, None),
        "invariant",
    )?;
    cases.push("insufficient-balance-rejects-domain-with-durable-fact-unchanged");
    require(!store.apply_effect(&apply)?, "invalid debit was applied")?;
    balance(&store, 6)?;
    let blocked = row(&store, third)?;
    require(
        blocked.phase == Phase::Succeeded
            && blocked.application == Application::Blocked
            && blocked.diagnostic.as_deref() == Some("invariant"),
        "domain rejection lost the provider success or blocked diagnostic",
    )?;
    let complete = image(&store)?;
    for (table, expected) in [
        ("effect_executions", 3),
        ("effect_facts", 3),
        ("effect_inbox", 1),
        ("effect_due", 0),
    ] {
        count(&complete, table, expected)?;
    }
    let facts = decoded_rows(&complete, "effect_facts")?;
    for (execution, units, applied) in [
        (first, "3", true),
        (second, "3", true),
        (third, "10", false),
    ] {
        let matching: Vec<_> = facts
            .iter()
            .filter(|fact| fact["execution"] == execution.to_string())
            .collect();
        require(
            matching.len() == 1
                && matching[0]["disposition"] == "succeeded"
                && matching[0]["outcome"]["units"] == units
                && matching[0]["outcome"]["account"] == "fake-account-1"
                && matching[0]["applied_revision"].is_string() == applied,
            "persisted success fact/application marker differs from literal expectation",
        )?;
    }
    let inbox = decoded_rows(&complete, "effect_inbox")?;
    require(
        inbox[0]["event"] == event.to_string()
            && inbox[0]["payload"]["execution_id"] == first.to_string()
            && inbox[0]["body"] == std::str::from_utf8(&bytes).map_err(local::storage)?
            && inbox[0]["consumed_revision"].is_string(),
        "persisted signed inbox binding/body/consumption differs",
    )?;
    let integrity = store.check_integrity()?;
    require(
        integrity["effects"]["facts"] == 3 && integrity["effects"]["inbox_pending"] == 0,
        "effect fact/inbox integrity counts differ",
    )?;
    cases.push("blocked-application-preserves-fact-and-literal-domain");
    drop(store);
    let reopened = Store::open_backend(factory("effect-publication")?, model)?;
    require(
        image(&reopened)? == complete,
        "reopen changed complete nonempty effect/application inventory",
    )?;
    balance(&reopened, 6)?;
    reopened.check_integrity()?;
    cases.push("persistent-reopen-nonempty-facts-inbox-and-domain");
    Ok(json!({
        "status":"passed","case_count":cases.len(),"cases":cases,
        "table_inventory":local::table_names(true),"automatic_retries":false,
        "literal_balances":[12,9,6],"persisted_facts":3,"persisted_inbox":1,
        "limitations":[
            "Signed fake events and typed provider outcomes run in-process; no HTTP provider transport or external delivery is certified.",
            "Reopen checks persistent storage in this process; process restart and distributed network faults are separate controls."
        ]
    }))
}
