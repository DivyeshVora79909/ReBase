//! Source-literal acceptance for output-free published Issue consumers.
use rebase_semantic_proof::{
    binding::Binding,
    lifecycle,
    local::{Mutation, Store},
    model::Prepared,
    models::invoicing::Invoicing,
    native_codec::{self, Address, Key, StoredValue},
    native_slice::Context,
    routes::Route,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
use uuid::Uuid;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/issue-share-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn ratio(n: i128, d: i128) -> Value {
    json!({"numerator":n.to_string(),"denominator":d.to_string()})
}
fn request(store: &Store<Invoicing>, commands: Value) -> Mutation {
    serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":Uuid::new_v4(),"commands":commands,"returning":[]})).unwrap()
}
fn change(store: &Store<Invoicing>, record: Uuid, set: Value) -> Value {
    json!({"op":"update","id":record,"if_version":store.get(store.model().identity(),record).unwrap().unwrap().version.to_string(),"set":set,"unset":[]})
}
fn delete(store: &Store<Invoicing>, record: Uuid) -> Value {
    json!({"op":"delete","id":record,"if_version":store.get(store.model().identity(),record).unwrap().unwrap().version.to_string()})
}
fn commit(store: &Store<Invoicing>, commands: Value) -> (Mutation, Value) {
    let request = request(store, commands);
    let result = store.mutate(&request).unwrap();
    store.check_integrity().unwrap();
    (request, result)
}
fn publication(store: &Store<Invoicing>, share: Uuid, basis: i128, amount: i128) {
    assert_eq!(
        store
            .get(store.model().identity(), share)
            .unwrap()
            .unwrap()
            .derived,
        Some(json!({"basis_minor":basis.to_string(),"amount_minor":amount.to_string()}))
    );
}
fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn inventory(store: &Store<Invoicing>) -> BTreeMap<Key, StoredValue<Invoicing>> {
    store.observe_for_verification().unwrap()["tables"]["native_kv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let key = Key::decode(&unhex(row["key"].as_str().unwrap())).unwrap();
            let value =
                native_codec::decode_for::<Invoicing>(&key, &unhex(row["value"].as_str().unwrap()))
                    .unwrap();
            (key, value)
        })
        .collect()
}
fn registration(store: &Store<Invoicing>, share: Uuid, parent: Uuid) {
    let rows = inventory(store);
    let address = Address::new(share, 1);
    assert!(
        matches!(rows.get(&Key::DirectNode(address)),Some(StoredValue::RouteNode(node)) if node.route == Route::Direct(parent))
    );
    assert!(!rows.keys().any(|key| match key {
        Key::Root(a) | Key::Node(a) | Key::Query(a) | Key::Role(a) | Key::Subscribers(a) =>
            a.id == share,
        Key::Reserved(reserved) => *reserved == share,
        _ => false,
    }));
    assert_eq!(
        rows.keys()
            .filter(|key| matches!(key,Key::DirectNode(a) if a.id==share))
            .count(),
        1
    );
}

#[test]
fn issue_share_uses_fresh_ready_publications_without_outputs_or_queries() {
    let dir = Directory::new();
    let path = dir.0.join("app.redb");
    let model = Arc::new(Prepared::<Invoicing>::load().unwrap());
    let store = Store::<Invoicing>::create_secured(
        &path,
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let fixture = Invoicing::fixture_plan(&model, "issue-share", id(30)).unwrap();
    assert_eq!(
        fixture,
        Invoicing::fixture_plan(&model, "issue-share", id(30)).unwrap()
    );
    let ids = &fixture["fixture"]["ids"];
    let identity = |name: &str| Uuid::parse_str(ids[name].as_str().unwrap()).unwrap();
    let (issue, share) = (identity("Issue"), identity("Share"));
    let (seed, seeded) = commit(&store, fixture["commands"].clone());
    publication(&store, share, 15002, 5001);
    registration(&store, share, issue);
    assert_eq!(store.check_integrity().unwrap()["nodes"], 5);
    assert_eq!(store.check_integrity().unwrap()["records"], 8);
    assert_eq!(store.mutate(&seed).unwrap()["result"], seeded["result"]);

    commit(
        &store,
        json!([change(&store, issue, json!({"quantity":ratio(2,1)}))]),
    );
    publication(&store, share, 20002, 6667); // Capturing the old Issue during resolve gives 5001.
    commit(
        &store,
        json!([change(&store, issue, json!({"unit_price_minor":"10004"}))]),
    );
    publication(&store, share, 20008, 6669);
    commit(
        &store,
        json!([change(
            &store,
            issue,
            json!({"quantity":ratio(3,2),"unit_price_minor":"10001","rounding":"floor"})
        )]),
    );
    publication(&store, share, 15001, 5000);
    commit(
        &store,
        json!([change(&store, issue, json!({"rounding":"half_even"}))]),
    );
    publication(&store, share, 15002, 5001);
    commit(
        &store,
        json!([change(&store, share, json!({"ratio":ratio(1,2)}))]),
    );
    publication(&store, share, 15002, 7501);
    commit(
        &store,
        json!([change(
            &store,
            share,
            json!({"ratio":ratio(1,3),"rounding":"floor"})
        )]),
    );
    publication(&store, share, 15002, 5000);
    commit(
        &store,
        json!([change(&store, share, json!({"rounding":"ceiling"}))]),
    );
    publication(&store, share, 15002, 5001);
    commit(
        &store,
        json!([change(&store, share, json!({"ratio":ratio(0,1)}))]),
    );
    publication(&store, share, 15002, 0);
    registration(&store, share, issue);
    let version = store.get(model.identity(), share).unwrap().unwrap().version;
    commit(&store, json!([change(&store, issue, json!({"at":"1"}))]));
    publication(&store, share, 15002, 0);
    registration(&store, share, issue);
    assert_eq!(
        store.get(model.identity(), share).unwrap().unwrap().version,
        version
    );
    let (last, outcome) = commit(
        &store,
        json!([change(&store, issue, json!({"quantity":ratio(2,1)}))]),
    );
    publication(&store, share, 20002, 0);
    registration(&store, share, issue);
    let before = store.observe_for_verification().unwrap();
    let backup = dir.0.join("backup.json");
    store.backup(&backup).unwrap();
    let restored = dir.0.join("restored.redb");
    lifecycle::restore(&backup, &restored, model.clone()).unwrap();
    let restored = Store::<Invoicing>::open(&restored, model.clone()).unwrap();
    assert_eq!(restored.observe_for_verification().unwrap(), before);
    publication(&restored, share, 20002, 0);
    drop(restored);
    drop(store);
    let store = Store::<Invoicing>::open(&path, model.clone()).unwrap();
    assert_eq!(store.observe_for_verification().unwrap(), before);
    assert_eq!(store.mutate(&last).unwrap()["result"], outcome["result"]);
    publication(&store, share, 20002, 0);
    commit(
        &store,
        json!([delete(&store, share), delete(&store, issue)]),
    );
    assert!(!inventory(&store).contains_key(&Key::DirectNode(Address::new(share, 1))));
}

#[test]
fn issue_share_retarget_and_existing_parent_edits_use_final_references_in_both_orders() {
    for parent_first in [false, true] {
        let dir = Directory::new();
        let model = Arc::new(Prepared::<Invoicing>::load().unwrap());
        let store = Store::<Invoicing>::create(
            dir.0.join("app.redb"),
            model.clone(),
            Context {
                tenant: id(1),
                actor: id(2),
            },
        )
        .unwrap();
        let fixture = Invoicing::fixture_plan(&model, "issue-share", id(30)).unwrap();
        let ids = &fixture["fixture"]["ids"];
        let identity = |name: &str| Uuid::parse_str(ids[name].as_str().unwrap()).unwrap();
        let (issue, share, other) = (identity("Issue"), identity("Share"), id(400));
        commit(&store, fixture["commands"].clone());
        commit(
            &store,
            json!([{"op":"create","id":other,"contract":211,"fields":{"invoice":identity("Invoice"),"at":"0","quantity":ratio(1,1),"unit_price_minor":"300","rounding":"half_even"}}]),
        );
        let parent = change(&store, other, json!({"unit_price_minor":"600"}));
        let consumer = change(&store, share, json!({"issue":other}));
        commit(
            &store,
            json!(if parent_first {
                vec![parent, consumer]
            } else {
                vec![consumer, parent]
            }),
        );
        publication(&store, share, 600, 200);
        registration(&store, share, other);
        assert!(
            matches!(inventory(&store).get(&Key::Direct(issue)),Some(StoredValue::Direct(header)) if header.len==0)
        );
        let version = store.get(model.identity(), share).unwrap().unwrap().version;
        commit(
            &store,
            json!([change(&store, issue, json!({"unit_price_minor":"10009"}))]),
        );
        publication(&store, share, 600, 200);
        assert_eq!(
            store.get(model.identity(), share).unwrap().unwrap().version,
            version
        );
        commit(
            &store,
            json!([change(&store, other, json!({"unit_price_minor":"900"}))]),
        );
        publication(&store, share, 900, 300);
        // Final retarget removes the surviving reference and allows old parent deletion.
        let retarget = change(&store, share, json!({"issue":issue}));
        let retire = delete(&store, other);
        commit(
            &store,
            json!(if parent_first {
                vec![retire, retarget]
            } else {
                vec![retarget, retire]
            }),
        );
        publication(&store, share, 15014, 5005);
        registration(&store, share, issue);
    }
}

#[test]
fn issue_share_invalid_batches_preserve_all_tables_and_receipt_absence() {
    let dir = Directory::new();
    let model = Arc::new(Prepared::<Invoicing>::load().unwrap());
    let store = Store::<Invoicing>::create_secured(
        dir.0.join("app.redb"),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let fixture = Invoicing::fixture_plan(&model, "issue-share", id(30)).unwrap();
    let ids = &fixture["fixture"]["ids"];
    let identity = |name: &str| Uuid::parse_str(ids[name].as_str().unwrap()).unwrap();
    let (issue, share) = (identity("Issue"), identity("Share"));
    commit(&store, fixture["commands"].clone());
    let batches = [
        (
            "invalid_input",
            json!([change(&store, share, json!({"ratio":ratio(4,3)}))]),
        ),
        (
            "invalid_input",
            json!([change(&store, share, json!({"ratio":ratio(-1,3)}))]),
        ),
        (
            "inexact",
            json!([change(&store, share, json!({"rounding":"exact"}))]),
        ),
        (
            "unavailable_reference",
            json!([change(&store, share, json!({"issue":id(999)}))]),
        ),
        (
            "unavailable_reference",
            json!([change(&store, share, json!({"issue":identity("Invoice")}))]),
        ),
        ("unavailable_reference", json!([delete(&store, issue)])),
        (
            "inexact",
            json!([
                change(&store, issue, json!({"unit_price_minor":"10003"})),
                change(&store, share, json!({"rounding":"exact"}))
            ]),
        ),
    ];
    for (kind, commands) in batches {
        let before = store.observe_for_verification().unwrap();
        let bad = request(&store, commands);
        assert_eq!(store.mutate(&bad).unwrap_err().code, kind);
        assert_eq!(store.observe_for_verification().unwrap(), before);
        assert_eq!(
            store
                .operation_status(model.identity(), &bad.context, bad.operation_id)
                .unwrap()["status"],
            "not_observed"
        );
    }
    assert!(
        store
            .session(id(999), 0)
            .unwrap()
            .get(model.identity(), share)
            .is_err()
    );
    let c = model.contract(821).unwrap();
    assert!(
        c.roots.is_empty()
            && c.memberships.is_empty()
            && c.queries.is_empty()
            && c.outputs.is_empty()
    );
    assert_eq!(c.publication_inputs.len(), 1);
    assert_eq!(c.publication_inputs[0].field_code, 101);
    assert!(c.fields.iter().find(|f| f.name == "issue").unwrap().mutable);
    assert!(
        !model
            .contract(307)
            .unwrap()
            .fields
            .iter()
            .find(|f| f.name == "issue")
            .unwrap()
            .mutable
    );
    for fields in [
        json!({"issue":issue,"ratio":ratio(2,6),"rounding":"half_even"}),
        json!({"issue":issue,"ratio":ratio(1,3),"rounding":"half_even","basis_minor":"3"}),
        json!([issue, ratio(1, 3), "half_even"]),
    ] {
        assert!(model.validate(821, &fields).is_err());
    }
}

#[test]
fn issue_share_checker_rejects_stale_publications_and_missing_or_orphan_direct_routes() {
    use rebase_semantic_proof::{
        identity::IdentityConfig,
        models::invoicing::Derived,
        server::{self, ServerConfig},
    };
    use redb::{Database, TableDefinition};
    use sha2::{Digest, Sha256};
    let dir = Directory::new();
    let model = Arc::new(Prepared::<Invoicing>::load().unwrap());
    let store = Store::<Invoicing>::create_secured(
        dir.0.join("source.redb"),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let expected_store = store.inspect().unwrap()["store"].clone();
    let fixture = Invoicing::fixture_plan(&model, "issue-share", id(30)).unwrap();
    let ids = &fixture["fixture"]["ids"];
    let identity = |name: &str| Uuid::parse_str(ids[name].as_str().unwrap()).unwrap();
    let (issue, share) = (identity("Issue"), identity("Share"));
    commit(&store, fixture["commands"].clone());
    let backup = dir.0.join("valid.json");
    store.backup(&backup).unwrap();
    let image: Value = serde_json::from_slice(&std::fs::read(&backup).unwrap()).unwrap();
    let original = inventory(&store);
    let member = Address::new(share, 1);
    let mut stale = original[&Key::Record(share)].clone();
    let StoredValue::Record(record) = &mut stale else {
        panic!("share")
    };
    let Some(Derived::IssueShare { amount_minor, .. }) = &mut record.derived else {
        panic!("derived share")
    };
    *amount_minor += 1;
    let mut orphan = original[&Key::DirectNode(member)].clone();
    let StoredValue::RouteNode(node) = &mut orphan else {
        panic!("direct route")
    };
    let orphan_id = Address::new(id(900), 1);
    node.key.member = orphan_id;
    let mut misbound = original[&Key::DirectNode(member)].clone();
    let StoredValue::RouteNode(node) = &mut misbound else {
        panic!("direct route")
    };
    node.route = Route::Direct(id(901));
    let controls = [
        ("stale-derived", Key::Record(share), Some(stale)),
        ("missing-registration", Key::DirectNode(member), None),
        ("missing-header", Key::Direct(issue), None),
        (
            "orphan-registration",
            Key::DirectNode(orphan_id),
            Some(orphan),
        ),
        (
            "misbound-registration",
            Key::DirectNode(member),
            Some(misbound),
        ),
    ];
    let config = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        max_inflight: 1,
        request_timeout_seconds: 5,
        effects: None,
        identity: IdentityConfig {
            issuer: "issue-share-test".into(),
            audience: "rebase-test".into(),
            public_keys: [(
                "test".into(),
                include_str!("fixtures/test-ed25519-public.pem").into(),
            )]
            .into(),
            max_token_seconds: 600,
        },
    };
    for (label, key, value) in controls {
        let corrupt =
            value.map(|value| native_codec::encode_for::<Invoicing>(&key, &value).unwrap());
        let mut bad = image.clone();
        let rows = bad["payload"]["tables"]["native_kv"]
            .as_array_mut()
            .unwrap();
        let hexkey = native_codec::hex(&key.encode());
        rows.retain(|row| row["key"] != hexkey);
        if let Some(bytes) = &corrupt {
            rows.push(json!({"key":hexkey,"value":native_codec::hex(bytes)}));
        }
        rows.sort_by_key(|row| row["key"].as_str().unwrap().to_owned());
        bad["sha256"] = json!(native_codec::hex(&Sha256::digest(
            serde_json::to_vec(&bad["payload"]).unwrap()
        )));
        let source = dir.0.join(format!("bad-{label}.json"));
        std::fs::write(&source, serde_json::to_vec(&bad).unwrap()).unwrap();
        let rejected = dir.0.join(format!("rejected-{label}.redb"));
        assert!(
            lifecycle::restore(&source, &rejected, model.clone()).is_err(),
            "{label}"
        );
        assert!(!rejected.exists());
        let path = dir.0.join(format!("corrupt-{label}.redb"));
        lifecycle::restore(&backup, &path, model.clone()).unwrap();
        let db = Database::open(&path).unwrap();
        let tx = db.begin_write().unwrap();
        {
            let mut table = tx
                .open_table(TableDefinition::<&[u8], &[u8]>::new("native_kv"))
                .unwrap();
            if let Some(bytes) = &corrupt {
                table
                    .insert(key.encode().as_slice(), bytes.as_slice())
                    .unwrap();
            } else {
                table.remove(key.encode().as_slice()).unwrap();
            }
        }
        tx.commit().unwrap();
        drop(db);
        let damaged = Arc::new(Store::<Invoicing>::open(&path, model.clone()).unwrap());
        let before = damaged.observe_for_verification().unwrap();
        let integrity_error = damaged.check_integrity().unwrap_err();
        assert!(
            server::router(damaged.clone(), &config).is_err(),
            "startup {label}"
        );
        assert_eq!(damaged.observe_for_verification().unwrap(), before);
        drop(damaged);
        let startup = dir.0.join("corrupt-service.json");
        std::fs::write(&startup, serde_json::to_vec(&json!({
            "format":"rebase-service-1","model":"invoicing","backend":{"kind":"redb","cluster_file":null},
            "target":{"mode":"open","path":path,"expect_store":expected_store},"service":config
        })).unwrap()).unwrap();
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_rebase-next"))
            .arg("serve")
            .arg(&startup)
            .env("PATH", "")
            .output()
            .unwrap();
        assert!(!result.status.success(), "standalone startup {label}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains(integrity_error.code),
            "startup {label}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let reopened = Store::<Invoicing>::open(&path, model.clone()).unwrap();
        assert_eq!(
            reopened.observe_for_verification().unwrap(),
            before,
            "startup changed {label}"
        );
    }
}
