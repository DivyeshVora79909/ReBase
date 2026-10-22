use rebase_semantic_proof::{
    access::{Action, Grants, Graph, Principal, PrincipalKind},
    local::{LocalStore, Mutation},
    model::PreparedModel,
    native_slice::{Context, Error},
    query::{PageRequest, RecordQuery},
    security::ReplaceGraph,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};
use uuid::Uuid;

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn grants() -> Grants {
    Grants {
        admin: false,
        contracts: (1..=10)
            .map(|code| {
                (
                    code,
                    BTreeSet::from([Action::Read, Action::Create, Action::Update, Action::Delete]),
                )
            })
            .collect(),
    }
}
fn person(n: u128, parents: &[u128]) -> Principal {
    Principal {
        id: id(n),
        kind: PrincipalKind::User,
        parents: parents.iter().copied().map(id).collect(),
        active: true,
        credential_epoch: 0,
        grants: grants(),
    }
}
fn graph() -> Graph {
    let mut graph = Graph::bootstrap(Context {
        tenant: id(1),
        actor: id(2),
    })
    .unwrap()
    .graph;
    graph
        .principals
        .extend([person(3, &[1]), person(4, &[3]), person(5, &[1])]);
    graph
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/access-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn file(&self) -> PathBuf {
        self.0.join("test.redb")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn replace(store: &LocalStore, graph: Graph) -> Result<Value, Error> {
    let revision = store.access_graph(store.model().identity())?["revision"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    store.replace_access(&ReplaceGraph {
        model: store.model().identity().into(),
        if_revision: revision,
        graph,
    })
}
fn mutation(store: &LocalStore, operation: u128, commands: Value, returning: Value) -> Mutation {
    serde_json::from_value(json!({"model":store.model().identity(),"operation_id":id(operation),"commands":commands,"returning":returning})).unwrap()
}
fn page(
    store: &LocalStore,
    cursor: Option<String>,
    budget: u16,
) -> rebase_semantic_proof::query::Page {
    store
        .page(&PageRequest {
            model: store.model().identity().into(),
            query: RecordQuery::default(),
            limit: 32,
            visit_budget: budget,
            cursor,
        })
        .unwrap()
}

#[test]
fn prepared_scopes_match_independent_path_search_and_preserve_diamonds() {
    // Exhaust all 64 subgraphs of six optional forward edges. Expected access
    // uses a literal parent walk, not prepared descendants or the engine fold.
    let edges = [(3, 4), (3, 5), (3, 6), (4, 5), (4, 6), (5, 6)];
    for mask in 0..64 {
        let mut g = Graph::bootstrap(Context {
            tenant: id(1),
            actor: id(2),
        })
        .unwrap()
        .graph;
        let mut parents: BTreeMap<u128, Vec<u128>> = (3..=6).map(|n| (n, vec![1])).collect();
        for (bit, &(a, b)) in edges.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                parents.get_mut(&b).unwrap().push(a);
            }
        }
        g.principals
            .extend((3..=6).map(|n| person(n, &parents[&n])));
        let prepared = g.prepare().unwrap();
        for actor in 3..=6 {
            let expected: BTreeSet<_> = (3..=6)
                .filter(|&target| {
                    let mut pending = vec![target];
                    let mut visited = BTreeSet::new();
                    while let Some(next) = pending.pop() {
                        if next == actor {
                            return true;
                        }
                        if visited.insert(next) {
                            pending.extend(parents.get(&next).into_iter().flatten());
                        }
                    }
                    false
                })
                .map(id)
                .chain([id(1)])
                .collect();
            assert_eq!(
                prepared.scopes[&id(actor)].accessible,
                expected,
                "mask {mask}, actor {actor}"
            );
        }
    }
    let mut g = graph();
    g.principals.push(person(6, &[3]));
    g.principals
        .iter_mut()
        .find(|p| p.id == id(4))
        .unwrap()
        .parents
        .push(id(6));
    assert!(g.clone().prepare().unwrap().dominates(id(3), id(4)));
    g.principals
        .iter_mut()
        .find(|p| p.id == id(4))
        .unwrap()
        .parents
        .retain(|p| *p != id(3));
    assert!(g.clone().prepare().unwrap().dominates(id(3), id(4)));
    g.principals
        .iter_mut()
        .find(|p| p.id == id(6))
        .unwrap()
        .parents = vec![id(4)];
    assert_eq!(g.prepare().err().unwrap().code, "feedback");
}

#[test]
fn direct_group_access_inherits_grants_without_granting_siblings() {
    let mut g = graph();
    let group = Principal {
        kind: PrincipalKind::Group,
        ..person(6, &[1])
    };
    g.principals.push(group);
    for n in [4, 5] {
        let p = g.principals.iter_mut().find(|p| p.id == id(n)).unwrap();
        p.parents = vec![id(6)];
        p.grants = Grants::default();
    }
    let prepared = g.prepare().unwrap();
    let scope = &prepared.scopes[&id(4)];
    assert!(scope.accessible.contains(&id(6)));
    assert!(!scope.accessible.contains(&id(5)));
    assert!(scope.grants.allows(8, Action::Create));
    assert_eq!(prepared.reader(&[id(3), id(4)], id(2)), id(3)); // incomparable: retain first
    assert_eq!(prepared.reader(&[id(6), id(4)], id(2)), id(4)); // strict descendant replaces
}

#[test]
fn real_store_repairs_reader_indexes_revokes_credentials_and_redacts_receipts() {
    let dir = Directory::new();
    let model = Arc::new(PreparedModel::load().unwrap());
    let admin = LocalStore::create_secured(
        dir.file(),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    replace(&admin, graph()).unwrap();
    let manager = admin.session(id(3), 0).unwrap();
    let child = admin.session(id(4), 0).unwrap();
    let stranger = admin.session(id(5), 0).unwrap();
    let account = mutation(
        &child,
        100,
        json!([{"op":"create","id":id(10),"contract":4,"fields":{"native_unit":1}}]),
        json!([id(10)]),
    );
    child.mutate(&account).unwrap();
    let entry = mutation(
        &manager,
        101,
        json!([{"op":"create","id":id(11),"contract":8,"fields":{"account":id(10),"at":"0","amount":"10"}}]),
        json!([id(11)]),
    );
    let result = manager.mutate(&entry).unwrap();
    assert!(child.get(model.identity(), id(11)).unwrap().is_some());
    assert!(stranger.get(model.identity(), id(11)).unwrap().is_none());
    let basis = mutation(
        &manager,
        104,
        json!([
            {"op":"create","id":id(20),"contract":4,"fields":{"native_unit":1}},
            {"op":"create","id":id(22),"contract":4,"fields":{"native_unit":1}},
            {"op":"create","id":id(21),"contract":10,"fields":{"sources":[id(20),id(10)],"factor":"1","account":id(22),"at":"2","feedback":null}}
        ]),
        json!([id(21)]),
    );
    manager.mutate(&basis).unwrap();
    assert!(child.get(model.identity(), id(21)).unwrap().is_some());
    let readable = page(&child, None, 128);
    assert_eq!(
        readable.records.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![id(10), id(11), id(21)]
    );
    let first = page(&manager, None, 1);
    assert_eq!(first.records[0].id, id(10));
    assert!(first.cursor.is_some());
    let before = admin.observe_for_verification().unwrap();
    let denied = mutation(
        &child,
        102,
        json!([{"op":"update","id":id(11),"if_version":"0","set":{"amount":"-999"},"unset":[]}]),
        json!([]),
    );
    assert_eq!(child.mutate(&denied).unwrap_err().code, "forbidden"); // authority before version/error details
    assert_eq!(admin.observe_for_verification().unwrap(), before);
    let denied = mutation(
        &stranger,
        103,
        json!([{"op":"create","id":id(12),"contract":8,"fields":{"account":id(10),"at":"1","amount":"1"}}]),
        json!([]),
    );
    assert_eq!(stranger.mutate(&denied).unwrap_err().code, "forbidden");
    assert_eq!(admin.observe_for_verification().unwrap(), before);
    // A diamond edge change repairs the reader but does not grant union access.
    let mut g = graph();
    g.principals
        .iter_mut()
        .find(|p| p.id == id(4))
        .unwrap()
        .parents = vec![id(1)];
    replace(&admin, g.clone()).unwrap();
    assert!(manager.get(model.identity(), id(11)).unwrap().is_none());
    assert!(child.get(model.identity(), id(11)).unwrap().is_some());
    assert!(child.get(model.identity(), id(21)).unwrap().is_none());
    assert!(manager.get(model.identity(), id(21)).unwrap().is_some());
    let raw = admin.observe_for_verification().unwrap();
    let entries = raw["tables"]["reader_records"].as_array().unwrap();
    assert_eq!(entries.len(), 5); // private outputs never enter public candidates
    let entry_key = format!("{}{:04x}{}", id(4).simple(), 8, id(11).simple());
    let basis_key = format!("{}{:04x}{}", id(3).simple(), 10, id(21).simple());
    assert!(entries.iter().any(|r| r["key"] == entry_key));
    assert!(entries.iter().any(|r| r["key"] == basis_key));
    let replay = manager.mutate(&entry).unwrap();
    assert_eq!(replay["result"]["records"][0]["record"], Value::Null);
    assert_eq!(
        manager.operation_status(model.identity(), id(101)).unwrap()["result"]["records"][0]["record"],
        Value::Null
    );
    assert_eq!(
        stranger
            .operation_status(model.identity(), id(101))
            .unwrap()["status"],
        "not_observed"
    );
    assert_eq!(
        manager
            .page(&PageRequest {
                model: model.identity().into(),
                query: RecordQuery::default(),
                limit: 1,
                visit_budget: 1,
                cursor: first.cursor
            })
            .unwrap_err()
            .code,
        "query_changed"
    );
    g.principals
        .iter_mut()
        .find(|p| p.id == id(4))
        .unwrap()
        .credential_epoch = 1;
    replace(&admin, g).unwrap();
    assert_eq!(
        child.get(model.identity(), id(10)).unwrap_err().code,
        "forbidden"
    );
    let current = admin.session(id(4), 1).unwrap();
    assert!(current.get(model.identity(), id(10)).unwrap().is_some());
    assert_eq!(
        result["result"]["records"][0]["record"]["derived"],
        Value::Null
    );
    let snapshot = admin.observe_for_verification().unwrap();
    let mut bad = graph();
    bad.principals
        .iter_mut()
        .find(|p| p.id == id(3))
        .unwrap()
        .parents = vec![id(4)];
    assert_eq!(replace(&admin, bad).unwrap_err().code, "feedback");
    assert_eq!(admin.observe_for_verification().unwrap(), snapshot);
    drop((manager, child, stranger, current, admin));
    let reopened = LocalStore::open(dir.file(), model).unwrap();
    assert_eq!(reopened.observe_for_verification().unwrap(), snapshot);
    assert_eq!(
        page(&reopened.session(id(4), 1).unwrap(), None, 128)
            .records
            .len(),
        2
    );
}
