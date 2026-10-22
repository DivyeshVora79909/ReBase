use rebase_semantic_proof::{
    binding::Binding,
    lifecycle,
    local::{Mutation, Store},
    model::{Prepared, PreparedModel},
    models::equipment::Equipment,
    native_slice::Context,
};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};
use uuid::Uuid;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/equipment-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
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
fn request(store: &Store<Equipment>, operation: u128, commands: Value) -> Mutation {
    serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":id(operation),"commands":commands,"returning":[]})).unwrap()
}
fn update(store: &Store<Equipment>, operation: u128, record: Uuid, set: Value) {
    let version = store
        .get(store.model().identity(), record)
        .unwrap()
        .unwrap()
        .version;
    store.mutate(&request(store,operation,json!([{"op":"update","id":record,"if_version":version.to_string(),"set":set,"unset":[]}]))).unwrap();
    store.check_integrity().unwrap();
}
fn allocated(store: &Store<Equipment>, record: Uuid) -> Value {
    store
        .get(store.model().identity(), record)
        .unwrap()
        .unwrap()
        .derived
        .unwrap()["allocated"]
        .clone()
}
#[test]
fn independent_equipment_model_reuses_mutation_receipts_queries_and_storage() {
    let dir = Directory::new();
    let model = Arc::new(Prepared::<Equipment>::load().unwrap());
    let path = dir.0.join("equipment.redb");
    let store = Store::<Equipment>::create_secured(
        &path,
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let fixture = Equipment::fixture_plan(&model, "equipment", id(100)).unwrap();
    let ids = &fixture["fixture"]["ids"];
    let get_id = |key: &str| Uuid::parse_str(ids[key].as_str().unwrap()).unwrap();
    let a = get_id("a");
    let b = get_id("b");
    let delivery = get_id("delivery");
    let seed = request(&store, 1000, fixture["commands"].clone());
    let first = store.mutate(&seed).unwrap();
    let replay = store.mutate(&seed).unwrap();
    assert_eq!(replay["result"], first["result"]);
    assert_eq!(replay["replayed"], true);
    store.check_integrity().unwrap();
    assert_eq!(allocated(&store, a), "8");
    assert_eq!(allocated(&store, b), "2");
    for (at, expected) in [(1, "10"), (11, "2"), (21, "0"), (31, "8"), (41, "10")] {
        let query = serde_json::from_value(json!({"model":model.identity(),"owner":get_id("pool"),"slot":7,"read":{"kind":"before","at":at.to_string()}})).unwrap();
        assert_eq!(store.root_read(&query).unwrap()["value"]["sum"], expected);
    }

    update(&store, 1001, delivery, json!({"quantity":"12"}));
    assert_eq!(allocated(&store, b), "4");
    update(&store, 1002, a, json!({"ends":"15"}));
    assert_eq!(allocated(&store, b), "7");
    let role_inventory = store.observe_for_verification().unwrap();
    update(&store, 1003, a, json!({"active":false}));
    assert_eq!(allocated(&store, a), "0");
    assert_eq!(allocated(&store, b), "7");
    update(&store, 1004, a, json!({"active":true}));
    assert_eq!(allocated(&store, a), "8");
    assert_eq!(allocated(&store, b), "7");
    let role_rows = |observation: &Value| -> Vec<Value> {
        observation["tables"]["native_kv"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["key"].as_str().unwrap().starts_with("08"))
            .cloned()
            .collect()
    };
    assert_eq!(
        role_rows(&store.observe_for_verification().unwrap()),
        role_rows(&role_inventory)
    );
    let other = id(500);
    store.mutate(&request(&store,1005,json!([{"op":"create","id":other,"contract":101,"fields":{"unit":1}},{"op":"create","id":id(501),"contract":205,"fields":{"pool":other,"at":"0","quantity":"6"}}]))).unwrap();
    update(&store, 1006, a, json!({"pool":other}));
    assert_eq!(allocated(&store, a), "6");
    assert_eq!(allocated(&store, b), "7");
    update(&store, 1010, b, json!({"requested":"0"}));
    assert_eq!(allocated(&store, b), "0");
    update(&store, 1011, b, json!({"requested":"7"}));
    assert_eq!(allocated(&store, b), "7");
    let before = store.observe_for_verification().unwrap();
    let version = store.get(model.identity(), a).unwrap().unwrap().version;
    let invalid = request(
        &store,
        1007,
        json!([{"op":"update","id":a,"if_version":version.to_string(),"set":{"ends":"0"},"unset":[]}]),
    );
    assert!(store.mutate(&invalid).is_err());
    assert_eq!(store.observe_for_verification().unwrap(), before);
    let simultaneous = request(
        &store,
        1008,
        json!([{"op":"update","id":a,"if_version":version.to_string(),"set":{"pool":get_id("pool"),"starts":"20","ends":"30"},"unset":[]}]),
    );
    assert_eq!(store.mutate(&simultaneous).unwrap_err().code, "invariant");
    assert_eq!(store.observe_for_verification().unwrap(), before);
    let private = request(
        &store,
        1009,
        json!([{"op":"create","id":id(9999),"contract":900,"fields":{"producer":a,"role":11,"pool":other,"at":"10","quantity":"-1"}}]),
    );
    assert!(store.mutate(&private).is_err());
    assert_eq!(store.observe_for_verification().unwrap(), before);
    assert!(
        store
            .session(id(999), 0)
            .unwrap()
            .get(model.identity(), a)
            .is_err()
    );
    let backup = dir.0.join("backup.json");
    store.backup(&backup).unwrap();
    let restored_path = dir.0.join("restore.redb");
    lifecycle::restore(&backup, &restored_path, model.clone()).unwrap();
    let restored = Store::<Equipment>::open(&restored_path, model.clone()).unwrap();
    assert_eq!(restored.observe_for_verification().unwrap(), before);
    drop(restored);
    drop(store);
    assert!(Store::open(&path, Arc::new(PreparedModel::load().unwrap())).is_err());
    let reopened = Store::<Equipment>::open(&path, model.clone()).unwrap();
    assert_eq!(allocated(&reopened, a), "6");
    let store_id = Uuid::parse_str(
        reopened.check_integrity().unwrap()["store"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    reopened.reset(store_id).unwrap();
    assert_eq!(reopened.check_integrity().unwrap()["records"], 0);
}
#[test]
fn sparse_equipment_contracts_are_closed_and_native_bound() {
    let model = Prepared::<Equipment>::load().unwrap();
    assert!(model.contract(101).is_ok());
    assert!(model.contract(1).is_err());
    assert!(
        model
            .validate(205, &json!({"pool":id(1),"at":"0","quantity":"1000001"}))
            .is_err()
    );
    assert!(
        model
            .validate(205, &json!({"pool":id(1),"at":"00","quantity":"1"}))
            .is_err()
    );
    assert!(
        model
            .validate(
                410,
                &json!({"pool":id(1),"starts":"1","ends":"1","requested":"1","active":true})
            )
            .is_err()
    );
    assert_eq!(
        model.public_catalog()["contracts"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert!(model.public_contract(900).is_err());
}
