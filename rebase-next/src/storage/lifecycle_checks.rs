//! G7.5 receipt capacity and archive schedules against actual adapter transactions.
//! Only the retained-receipt capacity fixture is written directly; contenders,
//! graph changes, effect activation, replay and cleanup use ordinary Store paths.
use super::{Backend, Database, Limits, ReadView, ReadableTable, Row, TableSpec, WriteView};
use crate::{
    access::{Grants, Graph, Principal, PrincipalKind},
    binding::Binding,
    effects::WorkerMode,
    local::{self, Mutation, ReceiptResult, ReceiptValue, Store},
    model::Prepared,
    models::{
        effect_demo::EffectDemo,
        quantity::{self, Quantity},
    },
    native_slice::{Context, Error, Result},
    query::{PageRequest, RecordQuery},
    receipts,
    security::ReplaceGraph,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

fn id(number: u128) -> Uuid {
    Uuid::from_u128(number)
}
fn require(condition: bool, detail: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::new("lifecycle_conformance", detail))
    }
}
fn create<B: Binding>(db: Database) -> Result<Store<B>> {
    Store::create_backend_secured(
        db,
        Arc::new(Prepared::load()?),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
}
fn request<B: Binding>(store: &Store<B>, commands: Value) -> Result<Mutation> {
    serde_json::from_value(json!({"model":store.model().identity(),
        "context":store.operation_context(store.model().identity())?,"operation_id":Uuid::new_v4(),
        "commands":commands,"returning":[]}))
    .map_err(local::storage)
}
fn noop(store: &Store<Quantity>) -> Result<Mutation> {
    let record = store
        .get(store.model().identity(), id(10))?
        .ok_or_else(|| Error::new("lifecycle_conformance", "missing source"))?;
    request(
        store,
        json!([{"op":"update","id":id(10),"if_version":record.version,
        "set":{},"unset":[]}]),
    )
}
fn image<B: Binding>(store: &Store<B>) -> Result<Value> {
    let image = store.observe_for_verification()?;
    let actual: BTreeSet<_> = image["tables"]
        .as_object()
        .ok_or_else(|| Error::new("lifecycle_conformance", "missing table image"))?
        .keys()
        .cloned()
        .collect();
    let expected: BTreeSet<_> = local::table_names(true).into_iter().collect();
    require(
        image["complete"] == true && actual == expected,
        "incomplete application image",
    )?;
    Ok(image)
}
fn without_receipts(image: &Value) -> Value {
    let mut tables = image["tables"].clone();
    if let Some(map) = tables.as_object_mut() {
        map.remove(local::RECEIPTS.name());
        map.remove(receipts::SLOTS.name());
    }
    tables
}
fn stored_receipt<B: Binding>(
    store: &Store<B>,
    operation: Uuid,
) -> Result<Option<ReceiptValue<B>>> {
    store
        .db
        .begin_read()?
        .open_table(local::RECEIPTS)?
        .get(store.receipt_key(operation))?
        .map(|row| local::decode(row.value()))
        .transpose()
}
fn rejected<B: Binding, T>(
    store: &Store<B>,
    before: &Value,
    result: Result<T>,
    code: &str,
) -> Result<()> {
    let error = match result {
        Ok(_) => return Err(Error::new("lifecycle_conformance", "expected rejection")),
        Err(error) => error,
    };
    require(
        error.code == code,
        &format!("expected {code}, received {error}"),
    )?;
    require(
        image(store)? == *before,
        "rejection changed complete application tables",
    )?;
    store.check_integrity()?;
    Ok(())
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!("rebase-g75-lifecycle-{}", Uuid::new_v4()));
        std::fs::create_dir(&path).map_err(local::storage)?;
        Ok(Self(path))
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct Control {
    before_commit: Option<Box<dyn FnOnce() -> Result<()> + Send>>,
    commits: usize,
}
type Controls = Arc<Mutex<Control>>;
fn lock(controls: &Controls) -> Result<std::sync::MutexGuard<'_, Control>> {
    controls
        .lock()
        .map_err(|_| Error::new("lifecycle_conformance", "control lock poisoned"))
}
struct Controlled {
    db: Database,
    controls: Controls,
}
impl Backend for Controlled {
    fn limits(&self) -> Limits {
        self.db.limits()
    }
    fn begin_read(&self) -> Result<Box<dyn ReadView>> {
        self.db.backend.begin_read()
    }
    fn begin_write(&self) -> Result<Box<dyn WriteView>> {
        Ok(Box::new(ControlledWrite {
            inner: self.db.backend.begin_write()?,
            controls: self.controls.clone(),
        }))
    }
}
struct ControlledWrite {
    inner: Box<dyn WriteView>,
    controls: Controls,
}
impl ReadView for ControlledWrite {
    fn table_exists(&self, table: &TableSpec) -> Result<bool> {
        self.inner.table_exists(table)
    }
    fn get(&self, table: &TableSpec, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.inner.get(table, key)
    }
    fn scan(
        &self,
        table: &TableSpec,
        start: Bound<Vec<u8>>,
        end: Bound<Vec<u8>>,
        limit: usize,
    ) -> Result<Vec<Row>> {
        self.inner.scan(table, start, end, limit)
    }
    fn list_tables(&self) -> Result<Vec<String>> {
        self.inner.list_tables()
    }
    fn has_multimap_tables(&self) -> Result<bool> {
        self.inner.has_multimap_tables()
    }
}
impl WriteView for ControlledWrite {
    fn create_table(&mut self, table: &TableSpec) -> Result<()> {
        self.inner.create_table(table)
    }
    fn delete_table(&mut self, table: &TableSpec) -> Result<bool> {
        self.inner.delete_table(table)
    }
    fn put(&mut self, table: &TableSpec, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        self.inner.put(table, key, value)
    }
    fn remove(&mut self, table: &TableSpec, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.inner.remove(table, key)
    }
    fn commit(self: Box<Self>) -> Result<()> {
        let hook = {
            let mut control = lock(&self.controls)?;
            control.commits += 1;
            control.before_commit.take()
        };
        if let Some(hook) = hook {
            hook()?;
        }
        self.inner.commit()
    }
}

fn authority_change<B: Binding>(store: &Store<B>, principal: Uuid) -> Result<()> {
    let current = store.access_graph(store.model().identity())?;
    let mut graph: Graph =
        serde_json::from_value(current["graph"].clone()).map_err(local::storage)?;
    graph.principals.push(Principal {
        id: principal,
        kind: PrincipalKind::User,
        parents: vec![id(1)],
        active: true,
        credential_epoch: 0,
        grants: Grants::default(),
    });
    let request: ReplaceGraph = serde_json::from_value(json!({"model":store.model().identity(),
        "if_revision":current["revision"],"graph":graph}))
    .map_err(local::storage)?;
    store.replace_access(&request)?;
    Ok(())
}

/// Prepare 1023 structurally valid retained receipts with one known free slot.
/// This is a direct capacity fixture, not evidence that 1023 historical requests
/// executed. Its contexts, request hashes and slot bindings pass full integrity.
fn fill_retention(store: &Store<Quantity>, template: &Mutation) -> Result<u16> {
    let sample = stored_receipt(store, template.operation_id)?
        .ok_or_else(|| Error::new("lifecycle_conformance", "missing fixture receipt"))?;
    let write = store.db.begin_write()?;
    let mut slots = write.open_table(receipts::SLOTS)?;
    let mut operations = write.open_table(local::RECEIPTS)?;
    let free = (0..local::MAX_RECEIPTS)
        .find_map(|slot| match slots.get(slot.to_be_bytes()) {
            Ok(None) => Some(Ok(slot)),
            Ok(Some(_)) => None,
            Err(error) => Some(Err(error)),
        })
        .transpose()?
        .ok_or_else(|| Error::new("lifecycle_conformance", "no fixture hole"))?;
    for slot in 0..local::MAX_RECEIPTS {
        if slot == free || slots.get(slot.to_be_bytes())?.is_some() {
            continue;
        }
        let mut req = template.clone();
        req.operation_id = id(100_000 + u128::from(slot));
        let mut receipt = sample.clone();
        receipt.slot = slot;
        receipt.request_hash = store.request_hash("records.mutate", &req)?;
        let ReceiptResult::Records(result) = &mut receipt.result else {
            return Err(Error::new("lifecycle_conformance", "fixture receipt kind"));
        };
        result.operation_id = req.operation_id;
        result.revision = Uuid::new_v4();
        let key = store.receipt_key(req.operation_id);
        require(
            operations.get(&key)?.is_none(),
            "fixture operation collision",
        )?;
        slots.insert(slot.to_be_bytes(), &key)?;
        operations.insert(&key, local::encode(&receipt)?.as_slice())?;
    }
    drop((slots, operations));
    write.commit()?;
    let checked = store.check_integrity()?;
    require(
        checked["receipts"] == local::MAX_RECEIPTS - 1,
        "capacity fixture count",
    )?;
    Ok(free)
}

fn collision_requests(store: &Store<Quantity>) -> Result<(Mutation, Mutation)> {
    let occupied: BTreeSet<_> = store
        .db
        .begin_read()?
        .open_table(receipts::SLOTS)?
        .iter()?
        .map(|row| row.map(|(key, _)| u16::from_be_bytes(key.value().try_into().unwrap())))
        .collect::<Result<_>>()?;
    let template = noop(store)?;
    let mut candidates = BTreeMap::new();
    for candidate in 1_000..100_000 {
        let operation = id(candidate);
        let start = receipts::start_slot(&store.receipt_key(operation));
        if occupied.contains(&start) || occupied.contains(&((start + 1) % local::MAX_RECEIPTS)) {
            continue;
        }
        if let Some(first) = candidates.insert(start, operation) {
            let mut left = template.clone();
            left.operation_id = first;
            let mut right = template;
            right.operation_id = operation;
            return Ok((left, right));
        }
    }
    Err(Error::new(
        "lifecycle_conformance",
        "collision fixture search exhausted",
    ))
}

pub fn run(factory: impl Fn(&str) -> Result<Database>, concurrent: bool) -> Result<Value> {
    let directory = Directory::new()?;
    let mut cases = Vec::new();
    let store = create::<Quantity>(factory("g75-life-capacity")?)?;
    store.mutate(&request(
        &store,
        json!([{"op":"create","id":id(10),
        "contract":quantity::SOURCE,"fields":{"value":"12"}}]),
    )?)?;
    let original = store
        .get(store.model().identity(), id(10))?
        .ok_or_else(|| Error::new("lifecycle_conformance", "missing created source"))?;
    require(
        original.input == (quantity::Input::Source { value: 12 })
            && original.derived == Some(json!({"quantity":"12"}))
            && !original.version.is_nil(),
        "literal source/publication/token oracle differs",
    )?;
    let before = image(&store)?;
    let (collision_a, collision_b) = collision_requests(&store)?;
    store.mutate(&collision_a)?;
    store.mutate(&collision_b)?;
    let a = stored_receipt(&store, collision_a.operation_id)?.unwrap();
    let b = stored_receipt(&store, collision_b.operation_id)?.unwrap();
    require(
        a.slot == receipts::start_slot(&store.receipt_key(collision_a.operation_id))
            && b.slot == (a.slot + 1) % local::MAX_RECEIPTS,
        "ordinary colliding operations did not linearly probe",
    )?;
    require(
        without_receipts(&image(&store)?) == without_receipts(&before),
        "true no-op changed domain/authority/runtime state",
    )?;
    cases.push("ordinary-operation-hash-collision-linear-probe-and-unchanged-domain");

    let free = fill_retention(&store, &collision_a)?;
    cases.push("direct-valid-1023-receipt-fixture-complete-slot-bijection");
    let first = noop(&store)?;
    let second = noop(&store)?;
    let mut final_winner = Value::Null;
    let winner_request = if concurrent {
        let mut barriers = 0;
        let error = store
            .mutate_controlled(
                &first,
                &mut || Ok(Uuid::new_v4()),
                None,
                &mut || {
                    barriers += 1;
                    store.mutate(&second)?;
                    final_winner = image(&store)?;
                    Ok(())
                },
                false,
            )
            .expect_err("two final-slot contenders must not both commit");
        require(
            error.code == "transaction_conflict" && barriers == 1,
            "final-slot loser did not conflict once without retry",
        )?;
        require(
            image(&store)? == final_winner && stored_receipt(&store, first.operation_id)?.is_none(),
            "final-slot loser partially published",
        )?;
        cases.push("final-slot-concurrent-noop-contenders-single-commit-complete-rollback");
        &second
    } else {
        store.mutate(&first)?;
        cases.push("final-slot-sequential-noop-commit");
        &first
    };
    require(
        stored_receipt(&store, winner_request.operation_id)?.is_some_and(|r| r.slot == free),
        "final contender did not consume the sole free slot",
    )?;
    require(
        store.check_integrity()?["receipts"] == local::MAX_RECEIPTS,
        "exact capacity differs",
    )?;
    let before = image(&store)?;
    let known = store.operation_status(
        &winner_request.model,
        &winner_request.context,
        winner_request.operation_id,
    )?;
    let replay = store.mutate(winner_request)?;
    require(
        replay["result"] == known["result"]
            && replay["replayed"] == true
            && image(&store)? == before,
        "full-capacity replay changed tables or returned a new result",
    )?;
    cases.push("full-capacity-original-id-replay-unchanged-complete-tables");
    let rejected_request = noop(&store)?;
    rejected(
        &store,
        &before,
        store.mutate(&rejected_request),
        "receipt_limit",
    )?;
    require(
        stored_receipt(&store, rejected_request.operation_id)?.is_none(),
        "quota rejection retained receipt",
    )?;
    cases.push("exact-capacity-new-operation-rejection-and-all-table-rollback");
    require(
        store.get(store.model().identity(), id(10))? == Some(original),
        "capacity changed source publication",
    )?;

    let prearchive = image(&store)?;
    store.archive_receipts(directory.path("capacity-archive.json"))?;
    let afterarchive = image(&store)?;
    require(
        afterarchive["tables"]["operations"] == json!([])
            && afterarchive["tables"]["receipt_slots"] == json!([]),
        "archive did not clear complete retention",
    )?;
    let mut expected = prearchive["tables"].clone();
    expected["operations"] = json!([]);
    expected["receipt_slots"] = json!([]);
    expected["local_runtime"] = afterarchive["tables"]["local_runtime"].clone();
    require(
        afterarchive["tables"] == expected,
        "archive changed state outside receipt/context lifecycle",
    )?;
    rejected(
        &store,
        &afterarchive,
        store.mutate(winner_request),
        "operation_expired",
    )?;
    rejected(
        &store,
        &afterarchive,
        store.operation_status(
            &winner_request.model,
            &winner_request.context,
            winner_request.operation_id,
        ),
        "operation_expired",
    )?;
    let fresh = noop(&store)?;
    store.mutate(&fresh)?;
    require(
        store.check_integrity()?["receipts"] == 1,
        "archive did not free capacity",
    )?;
    cases.push("archive-atomic-clear-old-context-expiry-and-new-context-capacity");

    if concurrent {
        let inflight = noop(&store)?;
        let backup = store.backup(directory.path("inflight-archive.json"))?;
        let mut winner = Value::Null;
        let mut barriers = 0;
        let error = store
            .mutate_controlled(
                &inflight,
                &mut || Ok(Uuid::new_v4()),
                None,
                &mut || {
                    barriers += 1;
                    store.archive_cleanup(store.db.begin_write()?, &backup)?;
                    winner = image(&store)?;
                    Ok(())
                },
                false,
            )
            .expect_err("stale in-flight mutation after archive must abort");
        require(
            error.code == "transaction_conflict"
                && barriers == 1
                && image(&store)? == winner
                && stored_receipt(&store, inflight.operation_id)?.is_none(),
            "archive did not fence an already-staged original-context mutation",
        )?;
        store.check_integrity()?;
        cases.push("archive-commit-fences-stale-inflight-mutation-and-receipt");
    }

    // Each contender below changes a real non-domain family. The saved digest
    // must notice it even when all source, population and receipt bytes match.
    let controls = Controls::default();
    let effect = create::<EffectDemo>(Database::new(Controlled {
        db: factory("g75-life-archive-races")?,
        controls: controls.clone(),
    }))?;
    effect.mutate(&request(
        &effect,
        json!([{"op":"create","id":id(20),"contract":101,
        "fields":{"balance":"12"}}]),
    )?)?;
    for (name, principal, mode) in [
        ("authority", Some(id(30)), None),
        ("effect-activation", None, Some(WorkerMode::Delivery)),
    ] {
        let backup = effect.backup(directory.path(&format!("before-{name}.json")))?;
        let old = image(&effect)?;
        if let Some(principal) = principal {
            authority_change(&effect, principal)?;
        }
        if let Some(mode) = mode {
            effect.activate_effect_worker(mode)?;
        }
        let after = image(&effect)?;
        require(
            old != after
                && old["tables"]["operations"] == after["tables"]["operations"]
                && old["tables"]["receipt_slots"] == after["tables"]["receipt_slots"]
                && old["tables"]["native_kv"] == after["tables"]["native_kv"],
            "non-domain archive contender changed the wrong table families",
        )?;
        rejected(
            &effect,
            &after,
            effect.archive_cleanup(effect.db.begin_write()?, &backup),
            "stale_version",
        )?;
        cases.push(if name == "authority" {
            "archive-digest-detects-authority-only-change"
        } else {
            "archive-digest-detects-real-effect-activation-change"
        });
    }
    if concurrent {
        for (name, principal, mode) in [
            ("authority", Some(id(31)), None),
            ("effect-activation", None, Some(WorkerMode::Reconcile)),
        ] {
            let backup = effect.backup(directory.path(&format!("racing-{name}.json")))?;
            let competitor = effect.session(id(2), 0)?;
            let winning_image = Arc::new(Mutex::new(Value::Null));
            let capture = winning_image.clone();
            let before_commits = lock(&controls)?.commits;
            lock(&controls)?.before_commit = Some(Box::new(move || {
                if let Some(principal) = principal {
                    authority_change(&competitor, principal)?;
                }
                if let Some(mode) = mode {
                    competitor.activate_effect_worker(mode)?;
                }
                *capture
                    .lock()
                    .map_err(|_| Error::new("lifecycle_conformance", "winner lock"))? =
                    image(&competitor)?;
                Ok(())
            }));
            let error = effect
                .archive_cleanup(effect.db.begin_write()?, &backup)
                .expect_err("cleanup must conflict with after-digest contender");
            let winner = winning_image
                .lock()
                .map_err(|_| Error::new("lifecycle_conformance", "winner lock"))?
                .clone();
            require(
                error.code == "transaction_conflict"
                    && lock(&controls)?.commits == before_commits + 2
                    && image(&effect)? == winner,
                "archive after-digest conflict changed tables or retried",
            )?;
            effect.check_integrity()?;
            cases.push(if name == "authority" {
                "archive-after-digest-authority-commit-conflict"
            } else {
                "archive-after-digest-effect-activation-commit-conflict"
            });
        }
    }
    let backup = effect.backup(directory.path("current-archive.json"))?;
    effect.archive_cleanup(effect.db.begin_write()?, &backup)?;
    require(
        effect.check_integrity()?["receipts"] == 0,
        "unchanged complete backup cannot archive",
    )?;
    cases.push("current-complete-backup-archive-succeeds-after-rejected-races");

    let current_graph = effect.access_graph(effect.model().identity())?;
    let graph_noop: ReplaceGraph = serde_json::from_value(json!({
        "model":effect.model().identity(),"if_revision":current_graph["revision"],
        "graph":current_graph["graph"]
    }))
    .map_err(local::storage)?;
    let page_request = PageRequest {
        model: effect.model().identity().into(),
        query: RecordQuery {
            contract: Some(101),
            ..RecordQuery::default()
        },
        limit: 1,
        visit_budget: 8,
        cursor: None,
    };
    let page = effect.page(&page_request)?;
    require(
        page.cursor.is_some(),
        "graph no-op cursor fixture is exhausted",
    )?;
    let resume = PageRequest {
        cursor: page.cursor,
        ..page_request
    };
    let before = image(&effect)?;
    let unchanged = effect.replace_access(&graph_noop)?;
    require(
        unchanged["changed"] == false
            && unchanged["revision"] == current_graph["revision"]
            && image(&effect)? == before
            && effect.page(&resume)?.revision == page.revision,
        "authority no-op changed complete tables, revision or scoped cursor",
    )?;
    cases.push("authority-noop-preserves-complete-image-counter-and-cursor");
    if concurrent {
        let competitor = effect.session(id(2), 0)?;
        let winning_image = Arc::new(Mutex::new(Value::Null));
        let capture = winning_image.clone();
        let before_commits = lock(&controls)?.commits;
        lock(&controls)?.before_commit = Some(Box::new(move || {
            authority_change(&competitor, id(32))?;
            *capture
                .lock()
                .map_err(|_| Error::new("lifecycle_conformance", "winner lock"))? =
                image(&competitor)?;
            Ok(())
        }));
        let error = effect
            .replace_access(&graph_noop)
            .expect_err("authority no-op must validate tracked graph reads");
        let winner = winning_image
            .lock()
            .map_err(|_| Error::new("lifecycle_conformance", "winner lock"))?
            .clone();
        require(
            error.code == "transaction_conflict"
                && lock(&controls)?.commits == before_commits + 2
                && image(&effect)? == winner,
            "authority no-op did not conflict exactly once or changed winner tables",
        )?;
        require(
            effect
                .page(&resume)
                .expect_err("replacement must invalidate cursor")
                .code
                == "query_changed",
            "winning authority revision did not invalidate scoped cursor",
        )?;
        effect.check_integrity()?;
        cases.push("authority-noop-versus-replacement-real-commit-conflict");
    }

    Ok(
        json!({"status":"passed","cases":cases,"case_count":cases.len(),
        "concurrent_schedules":concurrent,"automatic_retries":false,
        "receipt_capacity":local::MAX_RECEIPTS,"table_inventory":local::table_names(true),
        "limitations":[
            "1023 retained receipts are a direct structurally validated fixture, not 1023 executed requests.",
            "Final contenders, collisions, replay, quota rejection, authority, effect activation and archive use real Store paths.",
            "Redb serializes writes and runs sequential lifecycle controls; overlapping commit barriers run only on optimistic adapters.",
            "These are bounded correctness schedules, not throughput, replicated failover or native commit-ack fault injection."]}),
    )
}
