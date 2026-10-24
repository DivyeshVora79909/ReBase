//! Bounded G7.3 application controls. Every scheduled attempt delegates to a
//! real adapter transaction; the wrapper only stops an attempt after a staged
//! write or runs its one-shot competitor immediately before native commit.
use super::{Backend, Database, Limits, ReadView, ReadableTable, Row, TableSpec, WriteView};
use crate::{
    access::{Action, Grants, Graph, Principal, PrincipalKind},
    local::{self, Mutation, Store},
    model::Prepared,
    models::quantity::{self, Quantity},
    native_codec::{self, Key, StoredValue},
    native_slice::{Context, Error, Result},
    security::ReplaceGraph,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    ops::Bound,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn require(ok: bool, detail: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::new("application_conformance", detail))
    }
}
fn context() -> Context {
    Context {
        tenant: id(1),
        actor: id(2),
    }
}
fn create(db: Database) -> Result<Store<Quantity>> {
    Store::create_backend_secured(db, Arc::new(Prepared::load()?), context())
}
fn request(store: &Store<Quantity>, commands: Value) -> Result<Mutation> {
    serde_json::from_value(json!({"model":store.model().identity(),
        "context":store.operation_context(store.model().identity())?,
        "operation_id":Uuid::new_v4(),"commands":commands,"returning":[]}))
    .map_err(local::storage)
}
fn source(record: Uuid, value: &str) -> Value {
    json!({"op":"create","id":record,"contract":quantity::SOURCE,"fields":{"value":value}})
}
fn scale(record: Uuid, parent: Uuid) -> Value {
    json!({"op":"create","id":record,"contract":quantity::SCALE,
        "fields":{"parent":parent,"factor":{"numerator":"1","denominator":"2"},"rounding":"exact"}})
}
fn delete(store: &Store<Quantity>, record: Uuid) -> Result<Value> {
    let record_version = store
        .get(store.model().identity(), record)?
        .ok_or_else(|| Error::new("application_conformance", "missing delete source"))?
        .version;
    Ok(json!({"op":"delete","id":record,"if_version":record_version.to_string()}))
}
fn image(store: &Store<Quantity>) -> Result<Value> {
    let observed = store.observe_for_verification()?;
    let expected: BTreeSet<_> = local::table_names(true).into_iter().collect();
    let actual: BTreeSet<_> = observed["tables"]
        .as_object()
        .ok_or_else(|| Error::new("application_conformance", "missing table inventory"))?
        .keys()
        .cloned()
        .collect();
    require(
        observed["complete"] == true && actual == expected,
        "incomplete application observation",
    )?;
    Ok(observed)
}
fn receipt_absent(store: &Store<Quantity>, operation: Uuid) -> Result<()> {
    require(
        store
            .db
            .begin_read()?
            .open_table(local::RECEIPTS)?
            .get(store.receipt_key(operation))?
            .is_none(),
        "rejected attempt published a receipt",
    )
}
fn reopen(
    factory: &impl Fn(&str) -> Result<Database>,
    family: &str,
    expected: &Value,
) -> Result<()> {
    let store = Store::<Quantity>::open_backend(factory(family)?, Arc::new(Prepared::load()?))?;
    require(
        image(&store)? == *expected,
        "reopen changed complete tables",
    )?;
    store.check_integrity()?;
    Ok(())
}

/// The oracle is authored literals, not another invocation of settlement or
/// integrity. It also checks original inputs, ownership and immediate readers.
fn quantity(
    store: &Store<Quantity>,
    record: Uuid,
    fields: Value,
    published: &str,
    owner: Uuid,
    reader: Uuid,
) -> Result<()> {
    let read = store.db.begin_read()?;
    let native = read.open_table(local::KV)?;
    let bytes = native
        .get(Key::Record(record).encode())?
        .ok_or_else(|| Error::new("application_conformance", "missing oracle source"))?;
    let StoredValue::Record(observed) =
        native_codec::decode_for::<Quantity>(&Key::Record(record), bytes.value())?
    else {
        return Err(Error::new("application_conformance", "oracle record type"));
    };
    require(
        serde_json::to_value(observed.input).map_err(local::storage)? == fields
            && serde_json::to_value(observed.derived).map_err(local::storage)?["quantity"]
                == published
            && observed.owner == owner
            && observed.reader == reader,
        "quantity source/publication/authority differs from literal oracle",
    )
}

#[derive(Clone)]
struct Fault {
    table: &'static str,
    key: Option<Vec<u8>>,
}
#[derive(Default)]
struct Control {
    fault: Option<Fault>,
    failures: usize,
    commits: usize,
    before_commit: Option<Box<dyn FnOnce() -> Result<()> + Send>>,
}
type Controls = Arc<Mutex<Control>>;
fn lock(controls: &Controls) -> Result<std::sync::MutexGuard<'_, Control>> {
    controls
        .lock()
        .map_err(|_| Error::new("application_conformance", "control lock poisoned"))
}
struct Controlled {
    db: Arc<Database>,
    controls: Controls,
}
fn controlled(db: Arc<Database>, controls: &Controls) -> Database {
    Database::new(Controlled {
        db,
        controls: controls.clone(),
    })
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
impl ControlledWrite {
    fn after_write(&self, table: &TableSpec, key: &[u8]) -> Result<()> {
        let mut control = lock(&self.controls)?;
        if control.fault.as_ref().is_some_and(|fault| {
            fault.table == table.name && fault.key.as_deref().is_none_or(|k| k == key)
        }) {
            control.fault = None;
            control.failures += 1;
            return Err(Error::new(
                "injected_abort",
                "after real staged adapter write",
            ));
        }
        Ok(())
    }
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
        let result = self.inner.put(table, key, value)?;
        self.after_write(table, key)?;
        Ok(result)
    }
    fn remove(&mut self, table: &TableSpec, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let result = self.inner.remove(table, key)?;
        self.after_write(table, key)?;
        Ok(result)
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

fn graph_request(store: &Store<Quantity>, graph: Graph) -> Result<ReplaceGraph> {
    serde_json::from_value(json!({"model":store.model().identity(),
        "if_revision":store.access_graph(store.model().identity())?["revision"],"graph":graph}))
    .map_err(local::storage)
}
fn graph_fixture() -> Result<Graph> {
    let mut graph = Graph::bootstrap(context())?.graph;
    for (person, parents) in [(3, vec![id(1)]), (4, vec![id(3)])] {
        graph.principals.push(Principal {
            id: id(person),
            kind: PrincipalKind::User,
            parents,
            active: true,
            credential_epoch: 0,
            grants: Grants {
                admin: false,
                contracts: [quantity::SOURCE, quantity::SCALE, quantity::JOIN]
                    .into_iter()
                    .map(|contract| {
                        (
                            contract,
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
    Ok(graph)
}
fn check_reader_inventory(store: &Store<Quantity>, join_reader: Uuid) -> Result<()> {
    let expected = [
        (id(3), 101, id(10)),
        (id(4), 101, id(11)),
        (join_reader, 309, id(12)),
    ]
    .map(|(reader, contract, record)| {
        json!({"key":format!("{}{:04x}{}",reader.simple(),contract,record.simple()),
                "contract":contract})
    });
    let mut expected = expected.to_vec();
    expected.sort_by(|a, b| a["key"].as_str().cmp(&b["key"].as_str()));
    let observed = image(store)?;
    require(
        observed["tables"]["reader_records"] == json!(expected)
            && observed["tables"]["public_records"]
                == json!([
                    {"key":id(10).simple().to_string(),"contract":101},
                    {"key":id(11).simple().to_string(),"contract":101},
                    {"key":id(12).simple().to_string(),"contract":309}]),
        "reader/public inventory differs from independently authored keys",
    )?;
    quantity(store, id(10), json!({"value":"12"}), "12", id(3), id(3))?;
    quantity(store, id(11), json!({"value":"6"}), "6", id(4), id(4))?;
    quantity(
        store,
        id(12),
        json!({"left":id(10),"right":id(11)}),
        "18",
        id(3),
        join_reader,
    )
}

fn reference_race(store: &Store<Quantity>, first: &Mutation, winner: &Mutation) -> Result<()> {
    let mut calls = 0;
    let mut accepted = Value::Null;
    let error = store
        .mutate_controlled(
            first,
            &mut || Ok(Uuid::new_v4()),
            None,
            &mut || {
                calls += 1;
                store.mutate(winner)?;
                accepted = image(store)?;
                Ok(())
            },
            false,
        )
        .expect_err("stale reference attempt must conflict");
    require(
        error.code == "transaction_conflict" && calls == 1,
        "reference loser did not abort exactly once without retry",
    )?;
    require(
        image(store)? == accepted,
        "reference loser partially published",
    )?;
    receipt_absent(store, first.operation_id)?;
    require(
        store.operation_status(&winner.model, &winner.context, winner.operation_id)?["status"]
            == "committed",
        "reference winner receipt absent",
    )?;
    store.check_integrity()?;
    Ok(())
}

/// Repeated family names identify the same persistent destination; each new
/// family name must identify a fresh destination. Redb uses sequential controls.
pub fn run(factory: impl Fn(&str) -> Result<Database>, concurrent: bool) -> Result<Value> {
    let mut cases = Vec::new();
    let family = "g73-authority-repair";
    let db = Arc::new(factory(family)?);
    let controls = Controls::default();
    let store = create(controlled(db.clone(), &controls))?;
    store.replace_access(&graph_request(&store, graph_fixture()?)?)?;
    let manager = store.session(id(3), 0)?;
    let child = store.session(id(4), 0)?;
    manager.mutate(&request(&manager, json!([source(id(10), "12")]))?)?;
    child.mutate(&request(&child, json!([source(id(11), "6")]))?)?;
    manager.mutate(&request(
        &manager,
        json!([{"op":"create","id":id(12),
        "contract":quantity::JOIN,"fields":{"left":id(10),"right":id(11)}}]),
    )?)?;
    check_reader_inventory(&store, id(4))?;
    let mut changed = graph_fixture()?;
    changed
        .principals
        .iter_mut()
        .find(|p| p.id == id(4))
        .expect("child")
        .parents = vec![id(1)];
    let replacement = graph_request(&store, changed)?;
    for (name, fault) in [
        (
            "authority-reader-index-write-abort",
            Fault {
                table: "reader_records",
                key: None,
            },
        ),
        (
            "authority-repaired-native-record-write-abort",
            Fault {
                table: "native_kv",
                key: Some(Key::Record(id(12)).encode()),
            },
        ),
        (
            "authority-graph-write-abort",
            Fault {
                table: "authority",
                key: Some(b"graph".to_vec()),
            },
        ),
        (
            "authority-prepared-scope-write-abort",
            Fault {
                table: "authority",
                key: Some([b"s".as_slice(), id(4).as_bytes()].concat()),
            },
        ),
    ] {
        let before = image(&store)?;
        let failures = lock(&controls)?.failures;
        lock(&controls)?.fault = Some(fault);
        let error = store
            .replace_access(&replacement)
            .expect_err("injected authority abort");
        require(
            error.code == "injected_abort",
            "authority failure classification changed",
        )?;
        require(
            lock(&controls)?.failures == failures + 1 && image(&store)? == before,
            "authority abort did not preserve all application tables/receipts",
        )?;
        check_reader_inventory(&store, id(4))?;
        store.check_integrity()?;
        // A second logical handle uses the same native database handle. A fresh
        // factory open below additionally verifies actual backend persistence.
        let reopened = Store::<Quantity>::open_backend(
            controlled(db.clone(), &controls),
            Arc::new(Prepared::load()?),
        )?;
        require(
            image(&reopened)? == before,
            "authority abort changed reopened tables",
        )?;
        reopened.check_integrity()?;
        cases.push(name);
    }
    store.replace_access(&replacement)?;
    check_reader_inventory(&store, id(3))?;
    require(
        manager.get(manager.model().identity(), id(11))?.is_none()
            && manager.get(manager.model().identity(), id(12))?.is_some()
            && child.get(child.model().identity(), id(12))?.is_none(),
        "authority reader repair exposed the wrong candidates",
    )?;
    let accepted = image(&store)?;
    let error = store
        .replace_access(&replacement)
        .expect_err("stale graph CAS");
    require(
        error.code == "stale_version" && image(&store)? == accepted,
        "stale authority replacement changed tables",
    )?;
    store.check_integrity()?;
    cases.push("authority-reader-repair-commit-literal-inventory-and-stale-cas");
    drop((manager, child, store, db));
    reopen(&factory, family, &accepted)?;
    cases.push("authority-repair-persistent-reopen");

    // Complement the overlapping schedules with normal sequential rejection and
    // teardown on every adapter, including the serialized redb writer.
    let family = "g73-reference-sequential";
    let store = create(factory(family)?)?;
    store.mutate(&request(
        &store,
        json!([source(id(20), "12"), scale(id(21), id(20))]),
    )?)?;
    let before = image(&store)?;
    let rejected = request(&store, json!([delete(&store, id(20))?]))?;
    let error = store
        .mutate(&rejected)
        .expect_err("referenced parent deletion");
    require(
        error.code == "unavailable_reference" && image(&store)? == before,
        "referenced deletion changed tables",
    )?;
    receipt_absent(&store, rejected.operation_id)?;
    quantity(&store, id(20), json!({"value":"12"}), "12", id(2), id(2))?;
    quantity(
        &store,
        id(21),
        json!({"parent":id(20),"factor":{"numerator":"1","denominator":"2"},"rounding":"exact"}),
        "6",
        id(2),
        id(2),
    )?;
    store.check_integrity()?;
    cases.push("reference-delete-reject-complete-inventory-and-no-receipt");
    store.mutate(&request(
        &store,
        json!([delete(&store, id(21))?, delete(&store, id(20))?]),
    )?)?;
    let accepted = image(&store)?;
    require(
        accepted["tables"]["public_records"] == json!([])
            && accepted["tables"]["reader_records"] == json!([]),
        "reference teardown retained public candidates",
    )?;
    store.check_integrity()?;
    drop(store);
    reopen(&factory, family, &accepted)?;
    cases.push("reference-teardown-persistent-reopen");

    if concurrent {
        for (family, insertion_first) in [
            ("g73-reference-insert-first", true),
            ("g73-reference-delete-first", false),
        ] {
            let store = create(factory(family)?)?;
            store.mutate(&request(&store, json!([source(id(30), "12")]))?)?;
            let insert = request(&store, json!([scale(id(31), id(30))]))?;
            let remove = request(&store, json!([delete(&store, id(30))?]))?;
            let (first, winner) = if insertion_first {
                (&insert, &remove)
            } else {
                (&remove, &insert)
            };
            reference_race(&store, first, winner)?;
            if insertion_first {
                require(
                    store.get(store.model().identity(), id(30))?.is_none()
                        && store.get(store.model().identity(), id(31))?.is_none(),
                    "losing reference survived winning parent deletion",
                )?;
            } else {
                quantity(&store, id(30), json!({"value":"12"}), "12", id(2), id(2))?;
                quantity(
                    &store,
                    id(31),
                    json!({"parent":id(30),"factor":{"numerator":"1","denominator":"2"},"rounding":"exact"}),
                    "6",
                    id(2),
                    id(2),
                )?;
            }
            let accepted = image(&store)?;
            drop(store);
            reopen(&factory, family, &accepted)?;
            cases.push(if insertion_first {
                "reference-create-versus-parent-delete-barrier-and-reopen"
            } else {
                "reverse-discovery-versus-reference-create-barrier-and-reopen"
            });
        }
    }

    let family = "g73-initialization";
    let db = Arc::new(factory(family)?);
    let controls = Controls::default();
    let accepted = if concurrent {
        let winner_image = Arc::new(Mutex::new(Value::Null));
        let competitor_image = winner_image.clone();
        let competitor_db = db.clone();
        let competitor_controls = controls.clone();
        lock(&controls)?.before_commit = Some(Box::new(move || {
            let winner = create(controlled(competitor_db, &competitor_controls))?;
            winner.check_integrity()?;
            *competitor_image.lock().map_err(|_| {
                Error::new("application_conformance", "winner image lock poisoned")
            })? = image(&winner)?;
            Ok(())
        }));
        let error = match create(controlled(db.clone(), &controls)) {
            Ok(_) => {
                return Err(Error::new(
                    "application_conformance",
                    "both initializations committed",
                ));
            }
            Err(error) => error,
        };
        require(
            error.code == "transaction_conflict" && lock(&controls)?.commits == 2,
            "initialization loser did not conflict exactly once without retry",
        )?;
        let accepted = winner_image
            .lock()
            .map_err(|_| Error::new("application_conformance", "winner image lock poisoned"))?
            .clone();
        let reopened = Store::<Quantity>::open_backend(
            controlled(db.clone(), &controls),
            Arc::new(Prepared::load()?),
        )?;
        require(
            image(&reopened)? == accepted,
            "initialization loser changed winner tables",
        )?;
        reopened.check_integrity()?;
        cases.push("concurrent-empty-catalog-initialization-barrier-no-retry");
        accepted
    } else {
        let store = create(controlled(db.clone(), &controls))?;
        let accepted = image(&store)?;
        store.check_integrity()?;
        accepted
    };
    let error = match create(controlled(db.clone(), &controls)) {
        Ok(_) => {
            return Err(Error::new(
                "application_conformance",
                "populated initialization committed",
            ));
        }
        Err(error) => error,
    };
    require(
        error.code == "storage_exists",
        "populated initialization was not rejected",
    )?;
    let reopened = Store::<Quantity>::open_backend(
        controlled(db.clone(), &controls),
        Arc::new(Prepared::load()?),
    )?;
    require(
        image(&reopened)? == accepted
            && accepted["tables"]["public_records"] == json!([])
            && accepted["tables"]["reader_records"] == json!([])
            && accepted["tables"]["operations"] == json!([])
            && accepted["tables"]["receipt_slots"] == json!([])
            && accepted["tables"]["query_epochs"] == json!([])
            && accepted["tables"]["native_kv"]
                .as_array()
                .is_some_and(|rows| {
                    rows.len() == 2 && rows[0]["key"] == "00" && rows[1]["key"] == "0d"
                })
            && accepted["tables"]["authority"]
                .as_array()
                .is_some_and(|rows| rows.len() == 4),
        "initialization did not preserve its literal empty/bootstrap inventory",
    )?;
    reopened.check_integrity()?;
    drop((reopened, db));
    reopen(&factory, family, &accepted)?;
    cases.push("initialization-populated-rejection-complete-inventory-and-reopen");

    Ok(
        json!({"status":"passed","cases":cases,"case_count":cases.len(),
        "concurrent_application_schedules":concurrent,"automatic_retries":false,
        "table_inventory":local::table_names(true),
        "limitations":[
            "The wrapper delegates actual adapter transactions; it injects no synthetic conflict result.",
            "Creating/deleting attempts can still coordinate on exact Population capacity; G7.5's existing-record reference controls isolate dependency guards without that masking.",
            "Concurrent controls use deterministic overlapping transactions; redb runs the sequential controls only.",
            "Persistent reopen is in-process evidence, not process restart or distributed failover."]}),
    )
}
