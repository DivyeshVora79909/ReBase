//! Bounded real-engine quantity exploration for the V1 workshop.
//!
//! The expected values below use only the authored source integer and literal
//! division/addition. Rejected edits must preserve every logical store table.

use rebase_semantic_proof::{
    local::{Mutation, Store},
    model::Prepared,
    models::quantity::{Derived, JOIN, Quantity, SCALE, SOURCE},
    native_slice::Context,
};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};
use uuid::Uuid;

const SOURCE_ID: u128 = 10;
const LEFT_ID: u128 = 11;
const RIGHT_ID: u128 = 12;
const JOIN_ID: u128 = 13;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/workshop-exhaustive")
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

fn id(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn request(store: &Store<Quantity>, commands: Value) -> Mutation {
    serde_json::from_value(json!({
        "model": store.model().identity(),
        "context": store.operation_context(store.model().identity()).unwrap(),
        "operation_id": Uuid::new_v4(),
        "commands": commands,
        "returning": []
    }))
    .unwrap()
}

fn current_input(store: &Store<Quantity>, record: Uuid) -> Value {
    serde_json::to_value(
        store
            .get(store.model().identity(), record)
            .unwrap()
            .unwrap()
            .input,
    )
    .unwrap()
}

fn update(store: &Store<Quantity>, record: Uuid, set: Value) -> Value {
    let old = store
        .get(store.model().identity(), record)
        .unwrap()
        .unwrap();
    json!({
        "op": "update",
        "id": record,
        "if_version": old.version.to_string(),
        "set": set,
        "unset": []
    })
}

fn derived(store: &Store<Quantity>, record: Uuid) -> i128 {
    serde_json::from_value::<Derived>(
        store
            .get(store.model().identity(), record)
            .unwrap()
            .unwrap()
            .derived
            .unwrap(),
    )
    .unwrap()
    .quantity
}

fn observe(store: &Store<Quantity>, source: i128) {
    assert_eq!(
        current_input(store, id(SOURCE_ID))["value"],
        source.to_string()
    );
    assert_eq!(derived(store, id(LEFT_ID)), source / 2);
    assert_eq!(derived(store, id(RIGHT_ID)), source / 3);
    assert_eq!(derived(store, id(JOIN_ID)), source / 2 + source / 3);
    store.check_integrity().unwrap();
}

fn seed(store: &Store<Quantity>) {
    let commands = json!([
        {"op": "create", "id": id(SOURCE_ID), "contract": SOURCE, "fields": {"value": "12"}},
        {"op": "create", "id": id(LEFT_ID), "contract": SCALE, "fields": {"parent": id(SOURCE_ID), "factor": {"numerator": "1", "denominator": "2"}, "rounding": "exact"}},
        {"op": "create", "id": id(RIGHT_ID), "contract": SCALE, "fields": {"parent": id(SOURCE_ID), "factor": {"numerator": "1", "denominator": "3"}, "rounding": "exact"}},
        {"op": "create", "id": id(JOIN_ID), "contract": JOIN, "fields": {"left": id(LEFT_ID), "right": id(RIGHT_ID)}}
    ]);
    store.mutate(&request(store, commands)).unwrap();
    observe(store, 12);
}

fn source_snapshot(store: &Store<Quantity>) -> Value {
    store.observe_for_verification().unwrap()
}

// There are six concrete commands and depth three: 6 + 36 + 216 = 258
// transition attempts, with every successful branch restored before its peer.
fn explore(store: &Store<Quantity>, source: i128, depth: usize) -> usize {
    if depth == 0 {
        return 0;
    }
    let mut attempts = 0;
    for action in 0..6 {
        attempts += 1;
        let before = source_snapshot(store);
        match action {
            0..=3 => {
                let next = [0_i128, 6, 12, 2][action];
                let command = update(store, id(SOURCE_ID), json!({"value": next.to_string()}));
                let result = store.mutate(&request(store, json!([command])));
                if action == 3 {
                    assert_eq!(result.unwrap_err().code, "inexact");
                    assert_eq!(source_snapshot(store), before);
                    observe(store, source);
                    attempts += explore(store, source, depth - 1);
                } else {
                    result.unwrap();
                    observe(store, next);
                    attempts += explore(store, next, depth - 1);
                    let restore =
                        update(store, id(SOURCE_ID), json!({"value": source.to_string()}));
                    store.mutate(&request(store, json!([restore]))).unwrap();
                    observe(store, source);
                }
            }
            4 => {
                let version = store
                    .get(store.model().identity(), id(SOURCE_ID))
                    .unwrap()
                    .unwrap()
                    .version;
                let command = json!({
                    "op": "delete",
                    "id": id(SOURCE_ID),
                    "if_version": version.to_string()
                });
                assert!(store.mutate(&request(store, json!([command]))).is_err());
                assert_eq!(source_snapshot(store), before);
                observe(store, source);
                attempts += explore(store, source, depth - 1);
            }
            5 => {
                let command = update(store, id(LEFT_ID), json!({"parent": id(JOIN_ID)}));
                assert_eq!(
                    store
                        .mutate(&request(store, json!([command])))
                        .unwrap_err()
                        .code,
                    "feedback"
                );
                assert_eq!(source_snapshot(store), before);
                observe(store, source);
                attempts += explore(store, source, depth - 1);
            }
            _ => unreachable!(),
        }
    }
    attempts
}

#[test]
fn six_authored_actions_match_literal_oracle_through_depth_three() {
    let directory = Directory::new();
    let model = Arc::new(Prepared::<Quantity>::load().unwrap());
    let context = Context {
        tenant: id(1),
        actor: id(2),
    };
    let store =
        Store::<Quantity>::create_secured(directory.0.join("workshop.redb"), model, context)
            .unwrap();
    seed(&store);
    assert_eq!(explore(&store, 12, 3), 258);
    observe(&store, 12);
    println!("WORKSHOP_EXHAUSTIVE transitions=258 depth=3 actions=6");
}
