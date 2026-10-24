//! G7.5 scoped-coordination controls over the selected real adapter. The wrapper
//! records application writes; it never manufactures a commit or conflict.
use super::{Backend, Database, Limits, ReadView, ReadableTable, Row, TableSpec, WriteView};
use crate::{
    access::{Action, Grants, Graph, Principal, PrincipalKind},
    binding::{Binding, Calculation},
    local::{self, Mutation, Store},
    model::Prepared,
    models::quantity::{self, Quantity},
    native_codec::{self, Key, StoredValue},
    native_slice::{Context, Error, Result},
    query::{PageRequest, RecordQuery, RootRead, RootRequest},
    security::ReplaceGraph,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ops::Bound,
    sync::{Arc, Mutex},
    time::Instant,
};
use uuid::Uuid;

type Written = BTreeSet<(String, Vec<u8>)>;
#[derive(Clone)]
struct Trace {
    label: String,
    reads: Written,
    writes: Written,
    scanned_tables: BTreeSet<String>,
    outcome: String,
    commit_us: u128,
}
#[derive(Default)]
struct Capture {
    label: String,
    traces: Vec<Trace>,
}
type Captures = Arc<Mutex<Capture>>;
fn capture(c: &Captures) -> Result<std::sync::MutexGuard<'_, Capture>> {
    c.lock().map_err(|_| failure("capture mutex poisoned"))
}
fn label(c: &Captures, name: &str) -> Result<()> {
    capture(c)?.label = name.into();
    Ok(())
}
struct Recording {
    db: Database,
    captures: Captures,
}
impl Backend for Recording {
    fn limits(&self) -> Limits {
        self.db.limits()
    }
    fn begin_read(&self) -> Result<Box<dyn ReadView>> {
        self.db.backend.begin_read()
    }
    fn begin_write(&self) -> Result<Box<dyn WriteView>> {
        let inner = self.db.backend.begin_write()?;
        let mut c = capture(&self.captures)?;
        let index = c.traces.len();
        let name = c.label.clone();
        c.traces.push(Trace {
            label: name,
            reads: Written::new(),
            writes: Written::new(),
            scanned_tables: BTreeSet::new(),
            outcome: "not_committed".into(),
            commit_us: 0,
        });
        Ok(Box::new(RecordingWrite {
            inner,
            captures: self.captures.clone(),
            index,
        }))
    }
}
struct RecordingWrite {
    inner: Box<dyn WriteView>,
    captures: Captures,
    index: usize,
}
impl ReadView for RecordingWrite {
    fn table_exists(&self, t: &TableSpec) -> Result<bool> {
        self.inner.table_exists(t)
    }
    fn get(&self, t: &TableSpec, k: &[u8]) -> Result<Option<Vec<u8>>> {
        let result = self.inner.get(t, k)?;
        capture(&self.captures)?.traces[self.index]
            .reads
            .insert((t.name.clone(), k.to_vec()));
        Ok(result)
    }
    fn scan(
        &self,
        t: &TableSpec,
        a: Bound<Vec<u8>>,
        b: Bound<Vec<u8>>,
        n: usize,
    ) -> Result<Vec<Row>> {
        capture(&self.captures)?.traces[self.index]
            .scanned_tables
            .insert(t.name.clone());
        self.inner.scan(t, a, b, n)
    }
    fn list_tables(&self) -> Result<Vec<String>> {
        self.inner.list_tables()
    }
    fn has_multimap_tables(&self) -> Result<bool> {
        self.inner.has_multimap_tables()
    }
}
impl WriteView for RecordingWrite {
    fn create_table(&mut self, t: &TableSpec) -> Result<()> {
        self.inner.create_table(t)
    }
    fn delete_table(&mut self, t: &TableSpec) -> Result<bool> {
        self.inner.delete_table(t)
    }
    fn put(&mut self, t: &TableSpec, k: &[u8], v: &[u8]) -> Result<Option<Vec<u8>>> {
        let old = self.inner.put(t, k, v)?;
        capture(&self.captures)?.traces[self.index]
            .writes
            .insert((t.name.clone(), k.to_vec()));
        Ok(old)
    }
    fn remove(&mut self, t: &TableSpec, k: &[u8]) -> Result<Option<Vec<u8>>> {
        let old = self.inner.remove(t, k)?;
        if old.is_some() {
            capture(&self.captures)?.traces[self.index]
                .writes
                .insert((t.name.clone(), k.to_vec()));
        }
        Ok(old)
    }
    fn commit(self: Box<Self>) -> Result<()> {
        let Self {
            inner,
            captures,
            index,
        } = *self;
        let started = Instant::now();
        let result = inner.commit();
        let mut c = capture(&captures)?;
        c.traces[index].outcome = result
            .as_ref()
            .map_or_else(|e| e.code, |_| "committed")
            .into();
        c.traces[index].commit_us = started.elapsed().as_micros();
        result
    }
}
fn failure(detail: &str) -> Error {
    Error::new("coordination_conformance", detail)
}
fn require(ok: bool, detail: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(failure(detail)) }
}
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn context() -> Context {
    Context {
        tenant: id(1),
        actor: id(2),
    }
}
fn create<B: Binding>(db: Database) -> Result<Store<B>> {
    Store::create_backend_secured(db, Arc::new(Prepared::load()?), context())
}
fn graph<B: Binding>(store: &Store<B>, codes: &[u16]) -> Result<()> {
    let mut graph = Graph::bootstrap(context())?.graph;
    for person in [3, 4] {
        graph.principals.push(Principal {
            id: id(person),
            kind: PrincipalKind::User,
            parents: vec![id(1)],
            active: true,
            credential_epoch: 0,
            grants: Grants {
                admin: false,
                contracts: codes
                    .iter()
                    .map(|code| {
                        (
                            *code,
                            BTreeSet::from([
                                Action::Read,
                                Action::Create,
                                Action::Update,
                                Action::Delete,
                            ]),
                        )
                    })
                    .collect(),
            },
        });
    }
    store.replace_access(&graph_request(store, graph)?)?;
    Ok(())
}
fn graph_request<B: Binding>(store: &Store<B>, graph: Graph) -> Result<ReplaceGraph> {
    serde_json::from_value(json!({"model":store.model().identity(),
        "if_revision":store.access_graph(store.model().identity())?["revision"],"graph":graph}))
    .map_err(local::storage)
}
fn request<B: Binding>(store: &Store<B>, operation: Uuid, commands: Value) -> Result<Mutation> {
    serde_json::from_value(json!({"model":store.model().identity(),
        "context":store.operation_context(store.model().identity())?,"operation_id":operation,
        "commands":commands,"returning":[]}))
    .map_err(local::storage)
}
fn update<B: Binding>(store: &Store<B>, record: Uuid, set: Value) -> Result<Value> {
    let version = store
        .get(store.model().identity(), record)?
        .ok_or_else(|| failure("missing update record"))?
        .version;
    Ok(json!({"op":"update","id":record,"if_version":version.to_string(),"set":set,"unset":[]}))
}
fn image<B: Binding>(store: &Store<B>) -> Result<Value> {
    let image = store.observe_for_verification()?;
    let names: BTreeSet<_> = image["tables"]
        .as_object()
        .ok_or_else(|| failure("missing tables"))?
        .keys()
        .cloned()
        .collect();
    require(
        image["complete"] == true && names == local::table_names(true).into_iter().collect(),
        "incomplete application inventory",
    )?;
    Ok(image)
}
fn receipt<B: Binding>(store: &Store<B>, req: &Mutation, present: bool) -> Result<()> {
    let state = store.operation_status(&req.model, &req.context, req.operation_id)?;
    require(
        state["status"] == if present { "committed" } else { "not_observed" },
        "original-ID receipt presence differs",
    )
}
fn root(store: &Store<Calculation>, account: Uuid, sum: &str) -> Result<Value> {
    let value = store.root_read(&RootRequest {
        model: store.model().identity().into(),
        owner: account,
        slot: 2,
        read: RootRead::Summary,
    })?;
    require(
        value["value"]["sum"] == sum,
        "account sum differs from independent literal arithmetic",
    )?;
    Ok(value)
}
fn seed(store: &Store<Calculation>, base: u128, operation: u128) -> Result<()> {
    store.mutate(&request(store,id(operation),json!([
        {"op":"create","id":id(base),"contract":4,"fields":{"native_unit":1}},
        {"op":"create","id":id(base+1),"contract":8,"fields":{"account":id(base),"at":"0","amount":"10"}},
        {"op":"create","id":id(base+2),"contract":8,"fields":{"account":id(base),"at":"1","amount":"0"}},
        {"op":"create","id":id(base+3),"contract":8,"fields":{"account":id(base),"at":"2","amount":"0"}}
    ]))?)?;
    root(store, id(base), "10")?;
    Ok(())
}
fn page<B: Binding>(store: &Store<B>, contract: u16) -> Result<PageRequest> {
    let mut request = PageRequest {
        model: store.model().identity().into(),
        query: RecordQuery {
            contract: Some(contract),
            ..RecordQuery::default()
        },
        limit: 1,
        visit_budget: 32,
        cursor: None,
    };
    let first = store.page(&request)?;
    require(
        !first.records.is_empty() && first.cursor.is_some(),
        "fixture did not produce a continuation",
    )?;
    require(
        first.cursor.as_ref().is_some_and(|s| s.len() <= 4096),
        "scoped digest exceeded cursor byte bound",
    )?;
    request.cursor = first.cursor;
    Ok(request)
}
fn changed<B: Binding>(store: &Store<B>, request: &PageRequest) -> Result<()> {
    match store.page(request) {
        Err(e) if e.code == "query_changed" => Ok(()),
        result => Err(failure(&format!(
            "expected scoped query change, got {}",
            result.is_ok()
        ))),
    }
}
// Fixture selection is read-only and precedes both attempts. It selects free,
// distinct hash starts and distinct SurrealKV point-guard buckets; it is not an
// automatic retry of a mutation or a relaxation of the allocation capacity.
fn operation<B: Binding>(store: &Store<B>, start: u128, avoid: Option<&[u8]>) -> Result<Uuid> {
    let read = store.db.begin_read()?;
    let slots = read.open_table(crate::receipts::SLOTS)?;
    for n in start..start + 4096 {
        let operation = id(n);
        let key = store.receipt_key(operation);
        let slot = crate::receipts::start_slot(&key);
        if slots.get(slot.to_be_bytes())?.is_some() {
            continue;
        }
        if let Some(other) = avoid {
            let other_slot = crate::receipts::start_slot(other);
            if slot == other_slot
                || Sha256::digest(slot.to_be_bytes())[0]
                    == Sha256::digest(other_slot.to_be_bytes())[0]
                || Sha256::digest(&key)[0] == Sha256::digest(other)[0]
            {
                continue;
            }
        }
        return Ok(operation);
    }
    Err(failure(
        "unable to select bounded independent receipt fixture",
    ))
}
fn trace_value(trace: &Trace) -> Value {
    json!({"attempt":trace.label,"outcome":trace.outcome,"commit_us":trace.commit_us,
        "application_reads":trace.reads.iter().map(|(table,key)|json!({"table":table,"key":native_codec::hex(key)})).collect::<Vec<_>>(),
        "scanned_tables":trace.scanned_tables,
        "application_writes":trace.writes.iter().map(|(table,key)|json!({"table":table,"key":native_codec::hex(key)})).collect::<Vec<_>>()})
}
fn guard_buckets(writes: &Written) -> BTreeSet<(String, u8)> {
    writes
        .iter()
        .map(|(table, key)| (table.clone(), Sha256::digest(key)[0]))
        .collect()
}
fn no_global_writes(writes: &Written) -> Result<()> {
    for key in [Key::Meta, Key::Population] {
        require(
            !writes.contains(&(local::KV.name().into(), key.encode())),
            "existing-record attempt rewrote global native coordination",
        )?;
    }
    require(
        !writes.contains(&(local::RUNTIME.name().into(), local::HEADER.to_vec())),
        "ordinary mutation rewrote receipt header",
    )
}
fn check_actor(store: &Store<Calculation>, record: Uuid, actor: Uuid, amount: &str) -> Result<()> {
    let read = store.db.begin_read()?;
    let bytes = read
        .open_table(local::KV)?
        .get(Key::Record(record).encode())?
        .ok_or_else(|| failure("missing actor record"))?;
    let StoredValue::Record(observed) =
        native_codec::decode_for::<Calculation>(&Key::Record(record), bytes.value())?
    else {
        return Err(failure("actor record type"));
    };
    require(
        observed.reader == actor
            && observed.owner == actor
            && serde_json::to_value(observed.input).map_err(local::storage)?["amount"] == amount,
        "reader partition or authored amount differs",
    )
}

/// Repeated family names reopen the same destination. Only optimistic adapters
/// overlap writes; redb executes the same state transitions sequentially.
pub fn run(factory: impl Fn(&str) -> Result<Database>, concurrent: bool) -> Result<Value> {
    let mut cases = Vec::new();
    let captures = Captures::default();
    let store = create::<Calculation>(Database::new(Recording {
        db: factory("g75-independent")?,
        captures: captures.clone(),
    }))?;
    graph(&store, &[4, 8])?;
    let left = store.session(id(3), 0)?;
    let right = store.session(id(4), 0)?;
    seed(&left, 100, 1001)?;
    seed(&right, 300, 1002)?;
    let first_op = operation(&left, 10001, None)?;
    let second_op = operation(&right, 20001, Some(&left.receipt_key(first_op)))?;
    let first = request(
        &left,
        first_op,
        json!([update(&left, id(102), json!({"amount":"-2"}))?]),
    )?;
    let second = request(
        &right,
        second_op,
        json!([update(&right, id(302), json!({"amount":"-3"}))?]),
    )?;
    capture(&captures)?.traces.clear();
    label(&captures, "independent-left")?;
    let mut barrier_calls = 0;
    if concurrent {
        left.mutate_controlled(
            &first,
            &mut || Ok(Uuid::new_v4()),
            None,
            &mut || {
                barrier_calls += 1;
                label(&captures, "independent-right")?;
                right.mutate(&second)?;
                Ok(())
            },
            false,
        )?;
    } else {
        left.mutate(&first)?;
        label(&captures, "independent-right")?;
        right.mutate(&second)?;
    }
    require(
        barrier_calls == usize::from(concurrent),
        "unexpected independent commit barrier count",
    )?;
    let independent = capture(&captures)?.traces.clone();
    require(
        independent.len() == 2 && independent.iter().all(|t| t.outcome == "committed"),
        "independent attempts did not both commit exactly once",
    )?;
    for t in &independent {
        no_global_writes(&t.writes)?;
        require(
            t.scanned_tables.is_empty(),
            "independent witness used a table range guard",
        )?;
    }
    let common: Vec<_> = independent[0]
        .writes
        .intersection(&independent[1].writes)
        .collect();
    require(
        common.is_empty(),
        "independent roots share an application write key",
    )?;
    let buckets_a = guard_buckets(&independent[0].writes);
    let buckets_b = guard_buckets(&independent[1].writes);
    let shared_buckets: Vec<_> = buckets_a.intersection(&buckets_b).cloned().collect();
    require(
        shared_buckets.is_empty(),
        "independent fixture has a conservative SurrealKV guard collision",
    )?;
    let balances = json!([
        root(&left, id(100), "8")?["value"],
        root(&right, id(300), "7")?["value"]
    ]);
    check_actor(&store, id(102), id(3), "-2")?;
    check_actor(&store, id(302), id(4), "-3")?;
    receipt(&left, &first, true)?;
    receipt(&right, &second, true)?;
    let accepted = image(&store)?;
    left.mutate(&first)?;
    right.mutate(&second)?;
    require(
        image(&store)? == accepted,
        "same-ID replay changed independent results",
    )?;
    store.check_integrity()?;
    cases.push("independent-populated-business-roots-distinct-readers-and-slots");
    cases.push("complete-independent-write-sets-no-meta-population-or-header-write");
    cases.push("original-id-replay-preserves-all-application-tables");

    let left_cursor = page(&left, 8)?;
    let account_cursor = page(&left, 4)?;
    let other = request(
        &right,
        id(21001),
        json!([update(&right, id(302), json!({"amount":"-4"}))?]),
    )?;
    right.mutate(&other)?;
    left.page(&left_cursor)?;
    left.page(&account_cursor)?;
    let noop = request(
        &left,
        id(21002),
        json!([update(&left, id(102), json!({"amount":"-2"}))?]),
    )?;
    label(&captures, "genuine-noop")?;
    left.mutate(&noop)?;
    let noop_trace = capture(&captures)?
        .traces
        .last()
        .cloned()
        .ok_or_else(|| failure("missing no-op trace"))?;
    no_global_writes(&noop_trace.writes)?;
    require(
        noop_trace
            .writes
            .iter()
            .all(|(table, _)| ["receipt_slots", "operations"].contains(&table.as_str())),
        "genuine no-op rewrote domain or query epochs",
    )?;
    left.page(&left_cursor)?;
    cases.push("scoped-cursor-survives-other-reader-other-contract-and-genuine-noop");
    let local_edit = request(
        &left,
        id(21003),
        json!([update(&left, id(102), json!({"amount":"-1"}))?]),
    )?;
    left.mutate(&local_edit)?;
    changed(&left, &left_cursor)?;
    left.page(&account_cursor)?;
    root(&left, id(100), "9")?;
    cases.push("same-reader-contract-change-invalidates-only-affected-cursor");

    // Distinct existing source IDs compete on one already-populated invariant
    // root. Neither attempt needs a population counter or output reservation.
    let a_id = operation(&left, 22001, None)?;
    let b_id = operation(&left, 22501, Some(&left.receipt_key(a_id)))?;
    let a = request(
        &left,
        a_id,
        json!([update(&left, id(102), json!({"amount":"-8"}))?]),
    )?;
    let b = request(
        &left,
        b_id,
        json!([update(&left, id(103), json!({"amount":"-5"}))?]),
    )?;
    let before_count = capture(&captures)?.traces.len();
    if concurrent {
        label(&captures, "same-root-loser")?;
        let mut winner = Value::Null;
        let mut calls = 0;
        let error = left
            .mutate_controlled(
                &a,
                &mut || Ok(Uuid::new_v4()),
                None,
                &mut || {
                    calls += 1;
                    label(&captures, "same-root-winner")?;
                    left.mutate(&b)?;
                    winner = image(&store)?;
                    Ok(())
                },
                false,
            )
            .expect_err("same-root stale attempt must conflict");
        require(
            error.code == "transaction_conflict" && calls == 1,
            "same-root conflict was hidden or retried",
        )?;
        require(
            image(&store)? == winner,
            "same-root loser changed complete tables",
        )?;
        receipt(&left, &a, false)?;
    } else {
        left.mutate(&b)?;
        let before = image(&store)?;
        let error = left
            .mutate(&a)
            .expect_err("combined debit exceeds account balance");
        require(
            error.code == "invariant" && image(&store)? == before,
            "sequential invariant rejection changed tables",
        )?;
        receipt(&left, &a, false)?;
    }
    let same_root = capture(&captures)?.traces[before_count..].to_vec();
    for trace in &same_root {
        no_global_writes(&trace.writes)?;
    }
    if concurrent {
        let root_key = (
            local::KV.name().into(),
            Key::Root(crate::native_codec::Address::new(id(100), 2)).encode(),
        );
        require(
            same_root.len() == 2 && same_root.iter().all(|t| t.writes.contains(&root_key)),
            "same-root invariant attempts did not both protect the business root",
        )?;
    }
    root(&left, id(100), "4")?;
    receipt(&left, &b, true)?;
    store.check_integrity()?;
    cases.push("same-root-existing-record-invariant-race-and-complete-rollback");

    let mut noop_race = Vec::new();
    if concurrent {
        let pending_id = operation(&right, 23001, None)?;
        let edit_id = operation(&right, 23501, Some(&right.receipt_key(pending_id)))?;
        let pending = request(
            &right,
            pending_id,
            json!([update(&right, id(302), json!({"amount":"-4"}))?]),
        )?;
        let edit = request(
            &right,
            edit_id,
            json!([update(&right, id(302), json!({"amount":"-3"}))?]),
        )?;
        let before_count = capture(&captures)?.traces.len();
        label(&captures, "tracked-noop-loser")?;
        let mut winner = Value::Null;
        let mut calls = 0;
        let error = right
            .mutate_controlled(
                &pending,
                &mut || Ok(Uuid::new_v4()),
                None,
                &mut || {
                    calls += 1;
                    label(&captures, "tracked-noop-edit-winner")?;
                    right.mutate(&edit)?;
                    winner = image(&store)?;
                    Ok(())
                },
                false,
            )
            .expect_err("tracked no-op must conflict with changed read");
        require(
            error.code == "transaction_conflict" && calls == 1 && image(&store)? == winner,
            "no-op read lost protection or partially published",
        )?;
        noop_race = capture(&captures)?.traces[before_count..].to_vec();
        require(
            noop_race.len() == 2
                && noop_race.iter().all(|t| t.scanned_tables.is_empty())
                && noop_race[0]
                    .writes
                    .iter()
                    .all(|(table, _)| ["receipt_slots", "operations"].contains(&table.as_str()))
                && noop_race[0].writes.is_disjoint(&noop_race[1].writes)
                && guard_buckets(&noop_race[0].writes)
                    .is_disjoint(&guard_buckets(&noop_race[1].writes)),
            "no-op conflict was masked by common writes or receipt guard buckets",
        )?;
        receipt(&right, &pending, false)?;
        receipt(&right, &edit, true)?;
        root(&right, id(300), "7")?;
        cases.push("genuine-noop-tracked-read-versus-edit-commit-barrier");
    }

    let record = id(303);
    let old = right
        .get(right.model().identity(), record)?
        .ok_or_else(|| failure("missing ABA source"))?
        .version;
    right.mutate(&request(
        &right,
        id(24001),
        json!([{"op":"delete","id":record,"if_version":old.to_string()}]),
    )?)?;
    right.mutate(&request(&right,id(24002),json!([{"op":"create","id":record,"contract":8,"fields":{"account":id(300),"at":"2","amount":"0"}}]))?)?;
    let new = right
        .get(right.model().identity(), record)?
        .ok_or_else(|| failure("missing recreated source"))?
        .version;
    require(old != new, "delete/recreate reused a CAS token")?;
    let stale = request(
        &right,
        id(24003),
        json!([{"op":"update","id":record,"if_version":old.to_string(),"set":{"amount":"-1"},"unset":[]}]),
    )?;
    let before = image(&store)?;
    require(
        right
            .mutate(&stale)
            .expect_err("stale pre-delete token")
            .code
            == "stale_version"
            && image(&store)? == before,
        "ABA request changed tables",
    )?;
    receipt(&right, &stale, false)?;
    cases.push("delete-recreate-aba-rejects-original-token-with-complete-rollback");
    store.check_integrity()?;
    let accepted = image(&store)?;
    drop((left, right, store));
    let reopened = Store::<Calculation>::open_backend(
        factory("g75-independent")?,
        Arc::new(Prepared::load()?),
    )?;
    require(
        image(&reopened)? == accepted,
        "reopen changed all-table image",
    )?;
    reopened.check_integrity()?;
    cases.push("scoped-tokens-slots-and-business-state-persist-on-reopen");
    drop(reopened);

    scoped_derived(&factory, &mut cases)?;
    let references = if concurrent {
        reference_schedules(&factory, &mut cases)?
    } else {
        Vec::new()
    };
    Ok(
        json!({"status":"passed","case_count":cases.len(),"cases":cases,
        "concurrent_application_schedules":concurrent,"automatic_retries":false,
        "independent_attempts":independent.iter().map(trace_value).collect::<Vec<_>>(),
        "same_root_attempts":same_root.iter().map(trace_value).collect::<Vec<_>>(),
        "tracked_noop_attempts":noop_race.iter().map(trace_value).collect::<Vec<_>>(),
        "reference_schedules":references,
        "independent_balances":balances,"common_application_write_keys":[],"common_surreal_guard_buckets":shared_buckets,
        "receipt_hash_starts":[crate::receipts::start_slot(&[id(3).as_bytes().as_slice(),first_op.as_bytes()].concat()),crate::receipts::start_slot(&[id(4).as_bytes().as_slice(),second_op.as_bytes()].concat())],
        "genuine_noop":trace_value(&noop_trace),"table_inventory":local::table_names(true),
        "limitations":["The independent witness changes existing members of two invariant roots in different reader partitions; creates and new output reservations still coordinate on exact population capacity.","The write recorder delegates actual adapter transactions. SurrealKV adds its documented per-table hash guard keys; this witness selects disjoint buckets, while collisions and ranges can still cause conservative conflicts.","redb runs sequential controls because it serializes native writers. In-process reopen is not process or replicated-node failover.","One scoped reader/contract epoch still coordinates changes in that query partition. No throughput or general capacity claim is made."]}),
    )
}

fn scoped_derived(
    factory: &impl Fn(&str) -> Result<Database>,
    cases: &mut Vec<&'static str>,
) -> Result<()> {
    let store = create::<Quantity>(factory("g75-scoped-derived")?)?;
    graph(&store, &[quantity::SOURCE, quantity::SCALE])?;
    let left = store.session(id(3), 0)?;
    let right = store.session(id(4), 0)?;
    left.mutate(&request(
        &left,
        id(30001),
        json!([{"op":"create","id":id(10),"contract":quantity::SOURCE,"fields":{"value":"12"}}]),
    )?)?;
    right.mutate(&request(
        &right,
        id(30002),
        json!([{"op":"create","id":id(20),"contract":quantity::SOURCE,"fields":{"value":"6"}}]),
    )?)?;
    let scale = |record, parent| json!({"op":"create","id":record,"contract":quantity::SCALE,"fields":{"parent":parent,"factor":{"numerator":"1","denominator":"2"},"rounding":"exact"}});
    store.mutate(&request(
        &store,
        id(30003),
        json!([
            scale(id(30), id(10)),
            scale(id(31), id(10)),
            scale(id(40), id(20))
        ]),
    )?)?;
    let a = page(&left, quantity::SCALE)?;
    let b = page(&right, quantity::SCALE)?;
    let before = left
        .get(left.model().identity(), id(30))?
        .ok_or_else(|| failure("missing scale"))?;
    left.mutate(&request(
        &left,
        id(30004),
        json!([update(&left, id(10), json!({"value":"18"}))?]),
    )?)?;
    let after = left
        .get(left.model().identity(), id(30))?
        .ok_or_else(|| failure("missing derived scale"))?;
    require(
        before.input == after.input
            && before.version != after.version
            && after.derived.as_ref().is_some_and(|d| d["quantity"] == "9"),
        "derived-only publication token or literal quantity differs",
    )?;
    changed(&left, &a)?;
    right.page(&b)?;
    cases.push("derived-only-publication-invalidates-reader-contract-cursor");

    let a = page(&left, quantity::SCALE)?;
    let b = page(&right, quantity::SCALE)?;
    store.mutate(&request(
        &store,
        id(30005),
        json!([update(&store, id(31), json!({"parent":id(20)}))?]),
    )?)?;
    changed(&left, &a)?;
    changed(&right, &b)?;
    require(
        left.get(left.model().identity(), id(31))?.is_none()
            && right
                .get(right.model().identity(), id(31))?
                .is_some_and(|r| r.derived.as_ref().is_some_and(|d| d["quantity"] == "3")),
        "reader move exposed wrong projection",
    )?;
    cases.push("reader-move-invalidates-old-and-new-partition-cursors");

    let stable = page(&left, quantity::SCALE)?;
    let before = image(&store)?;
    let bad = request(
        &left,
        id(30006),
        json!([update(&left, id(10), json!({"value":"19"}))?]),
    )?;
    require(
        left.mutate(&bad).expect_err("inexact half").code == "inexact" && image(&store)? == before,
        "rejected derivation changed epochs or other tables",
    )?;
    receipt(&left, &bad, false)?;
    left.page(&stable)?;
    cases.push("rejected-derived-change-preserves-cursors-and-complete-tables");

    let authority_cursor = page(&store, quantity::SCALE)?;
    let mut next: Graph =
        serde_json::from_value(store.access_graph(store.model().identity())?["graph"].clone())
            .map_err(local::storage)?;
    next.principals.push(Principal {
        id: id(5),
        kind: PrincipalKind::User,
        parents: vec![id(1)],
        active: true,
        credential_epoch: 0,
        grants: Grants::default(),
    });
    store.replace_access(&graph_request(&store, next)?)?;
    changed(&store, &authority_cursor)?;
    cases.push("authority-administration-invalidates-snapshot-cursors");
    store.check_integrity()?;
    Ok(())
}

fn reference_schedules(
    factory: &impl Fn(&str) -> Result<Database>,
    cases: &mut Vec<&'static str>,
) -> Result<Vec<Value>> {
    let mut evidence = Vec::new();
    for (family, source_first) in [
        ("g75-reference-discovery", true),
        ("g75-reference-parent-read", false),
    ] {
        let captures = Captures::default();
        let store = create::<Quantity>(Database::new(Recording {
            db: factory(family)?,
            captures: captures.clone(),
        }))?;
        store.mutate(&request(&store, id(40001), json!([
            {"op":"create","id":id(10),"contract":quantity::SOURCE,"fields":{"value":"12"}},
            {"op":"create","id":id(20),"contract":quantity::SOURCE,"fields":{"value":"18"}},
            {"op":"create","id":id(30),"contract":quantity::SCALE,"fields":{"parent":id(10),"factor":{"numerator":"1","denominator":"2"},"rounding":"exact"}}
        ]))?)?;
        let population = store
            .db
            .begin_read()?
            .open_table(local::KV)?
            .get(Key::Population.encode())?
            .ok_or_else(|| failure("missing population"))?
            .value()
            .to_vec();
        let source_id = operation(&store, 41001, None)?;
        let retarget_id = operation(&store, 42001, Some(&store.receipt_key(source_id)))?;
        let source = request(
            &store,
            source_id,
            json!([update(&store, id(20), json!({"value":"24"}))?]),
        )?;
        let retarget = request(
            &store,
            retarget_id,
            json!([update(&store, id(30), json!({"parent":id(20)}))?]),
        )?;
        let (first, winner, expected_source, expected_scale, expected_parent) = if source_first {
            (&source, &retarget, "18", "9", id(20))
        } else {
            (&retarget, &source, "24", "6", id(10))
        };
        capture(&captures)?.traces.clear();
        label(
            &captures,
            if source_first {
                "empty-reverse-discovery-loser"
            } else {
                "parent-read-retarget-loser"
            },
        )?;
        let mut accepted = Value::Null;
        let mut barriers = 0;
        let error = store
            .mutate_controlled(
                first,
                &mut || Ok(Uuid::new_v4()),
                None,
                &mut || {
                    barriers += 1;
                    label(
                        &captures,
                        if source_first {
                            "retarget-winner"
                        } else {
                            "source-change-winner"
                        },
                    )?;
                    store.mutate(winner)?;
                    accepted = image(&store)?;
                    Ok(())
                },
                false,
            )
            .expect_err("changed reference predicate must conflict");
        require(
            error.code == "transaction_conflict" && barriers == 1,
            "reference conflict was missing, normalized incorrectly, or retried",
        )?;
        require(
            image(&store)? == accepted,
            "reference loser changed complete winner image",
        )?;
        receipt(&store, first, false)?;
        receipt(&store, winner, true)?;
        let traces = capture(&captures)?.traces.clone();
        require(
            traces.len() == 2
                && traces[0].outcome == "transaction_conflict"
                && traces[1].outcome == "committed",
            "reference attempt outcome inventory",
        )?;
        for trace in &traces {
            no_global_writes(&trace.writes)?;
            require(
                trace.scanned_tables.is_empty(),
                "reference witness used a table range guard",
            )?;
        }
        require(
            traces[0].writes.is_disjoint(&traces[1].writes)
                && guard_buckets(&traces[0].writes).is_disjoint(&guard_buckets(&traces[1].writes)),
            "reference conflict was masked by shared writes or hashed guard buckets",
        )?;
        let protected = if source_first {
            Key::Direct(id(20))
        } else {
            Key::Record(id(20))
        };
        let protected = (local::KV.name().into(), protected.encode());
        require(
            traces[0].reads.contains(&protected) && traces[1].writes.contains(&protected),
            "reference witness did not observe and invalidate the required exact predicate",
        )?;
        let after_population = store
            .db
            .begin_read()?
            .open_table(local::KV)?
            .get(Key::Population.encode())?
            .ok_or_else(|| failure("missing population after reference race"))?
            .value()
            .to_vec();
        require(
            population == after_population,
            "reference race changed exact population counters",
        )?;
        let source = store
            .get(store.model().identity(), id(20))?
            .ok_or_else(|| failure("reference oracle source missing"))?;
        let scale = store
            .get(store.model().identity(), id(30))?
            .ok_or_else(|| failure("reference oracle scale missing"))?;
        require(
            serde_json::to_value(&source.input).map_err(local::storage)?
                == json!({"value":expected_source})
                && source
                    .derived
                    .as_ref()
                    .is_some_and(|d| d["quantity"] == expected_source)
                && serde_json::to_value(&scale.input).map_err(local::storage)?
                    == json!({"parent":expected_parent,"factor":{"numerator":"1","denominator":"2"},"rounding":"exact"})
                && scale
                    .derived
                    .as_ref()
                    .is_some_and(|d| d["quantity"] == expected_scale),
            "reference schedule differs from independent source and half-value oracle",
        )?;
        store.check_integrity()?;
        cases.push(if source_first {
            "existing-source-discovery-versus-existing-reference-retarget-no-common-writes"
        } else {
            "existing-reference-parent-read-versus-source-change-no-common-writes"
        });
        evidence.push(json!({"family":family,"expected_source":expected_source,
            "expected_scale":expected_scale,"expected_parent":expected_parent,
            "protected_key":native_codec::hex(&protected.1),"population_unchanged":true,
            "common_application_writes":[],"common_surreal_guard_buckets":[],
            "attempts":traces.iter().map(trace_value).collect::<Vec<_>>() }));
    }
    Ok(evidence)
}
