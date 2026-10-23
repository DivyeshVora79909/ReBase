use rebase_semantic_proof::{
    binding::Binding,
    index::{NativeIndex, TimeKey},
    indexes::measurement::{Dimension, MAX_VALUE, Observation, STATISTICS, Statistics, Summary},
    lifecycle,
    local::{Mutation, Store},
    model::Prepared,
    models::measurement::Measurement,
    native_codec::{self, Address, Key, StoredValue},
    native_slice::Context,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc};
use uuid::Uuid;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/measurement-tests")
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
fn request(store: &Store<Measurement>, commands: Value) -> Mutation {
    serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":Uuid::new_v4(),"commands":commands,"returning":[]})).unwrap()
}
fn change(store: &Store<Measurement>, record: Uuid, set: Value) -> Value {
    json!({"op":"update","id":record,"if_version":store.get(store.model().identity(),record).unwrap().unwrap().version.to_string(),"set":set,"unset":[]})
}
fn delete(store: &Store<Measurement>, record: Uuid) -> Value {
    json!({"op":"delete","id":record,"if_version":store.get(store.model().identity(),record).unwrap().unwrap().version.to_string()})
}
fn run(store: &Store<Measurement>, commands: Value) {
    store.mutate(&request(store, commands)).unwrap();
    store.check_integrity().unwrap();
}
fn read(store: &Store<Measurement>, owner: Uuid, read: Value) -> Value {
    store
        .root_read(
            &serde_json::from_value(
                json!({"model":store.model().identity(),"owner":owner,"slot":7,"read":read}),
            )
            .unwrap(),
        )
        .unwrap()["value"]
        .clone()
}
fn stats(count: u64, sum: i128, min: Option<i128>, max: Option<i128>, unit: Option<u16>) -> Value {
    json!({"count":count,"sum":sum.to_string(),"min":min.map(|v|v.to_string()),"max":max.map(|v|v.to_string()),"unit":unit})
}
fn scan(leaves: &[Observation]) -> Summary {
    let values: Vec<_> = leaves.iter().map(|l| l.value).collect();
    let units: BTreeSet<_> = leaves.iter().map(|l| l.unit).collect();
    Summary {
        count: values.len() as u64,
        sum: values.iter().sum(),
        min: values.iter().copied().min(),
        max: values.iter().copied().max(),
        dimension: match units.len() {
            0 => Dimension::Empty,
            1 => Dimension::Unit {
                code: *units.first().unwrap(),
            },
            _ => Dimension::Mixed,
        },
    }
}
fn parenthesizations(leaves: &[Observation]) -> Vec<Summary> {
    if leaves.is_empty() {
        return vec![Statistics::empty(STATISTICS).unwrap()];
    }
    if leaves.len() == 1 {
        return vec![Statistics::singleton(STATISTICS, &TimeKey::new(0), &leaves[0]).unwrap()];
    }
    let mut result = vec![];
    for split in 1..leaves.len() {
        for a in parenthesizations(&leaves[..split]) {
            for b in parenthesizations(&leaves[split..]) {
                result.push(Statistics::combine(STATISTICS, &a, &b).unwrap());
            }
        }
    }
    result
}
#[test]
fn measurement_algebra_matches_literal_scan_for_every_short_parenthesization() {
    let atoms = [
        Observation { unit: 7, value: -2 },
        Observation { unit: 7, value: 0 },
        Observation { unit: 8, value: 3 },
    ];
    for length in 0..=5u32 {
        for mut number in 0..3usize.pow(length) {
            let leaves: Vec<_> = (0..length)
                .map(|_| {
                    let leaf = atoms[number % 3];
                    number /= 3;
                    leaf
                })
                .collect();
            let expected = scan(&leaves);
            for actual in parenthesizations(&leaves) {
                assert_eq!(actual, expected);
                assert_eq!(
                    Statistics::combine(STATISTICS, &Summary::default(), &actual).unwrap(),
                    expected
                );
                assert_eq!(
                    Statistics::combine(STATISTICS, &actual, &Summary::default()).unwrap(),
                    expected
                );
            }
        }
    }
    let leaves = vec![
        Observation {
            unit: 7,
            value: MAX_VALUE
        };
        64
    ];
    let total = leaves.iter().fold(Summary::default(), |a, leaf| {
        Statistics::combine(
            STATISTICS,
            &a,
            &Statistics::singleton(STATISTICS, &TimeKey::new(0), leaf).unwrap(),
        )
        .unwrap()
    });
    assert_eq!(total, scan(&leaves));
    assert!(
        Statistics::combine(
            STATISTICS,
            &total,
            &Statistics::singleton(STATISTICS, &TimeKey::new(0), &leaves[0]).unwrap()
        )
        .is_err()
    );
}

#[test]
fn measurements_use_native_members_windows_final_unit_repairs_replay_and_lifecycle() {
    let dir = Directory::new();
    let path = dir.0.join("app.redb");
    let model = Arc::new(Prepared::<Measurement>::load().unwrap());
    let store = Store::<Measurement>::create_secured(
        &path,
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let fixture = Measurement::fixture_plan(&model, "measurements", id(30)).unwrap();
    let ids = &fixture["fixture"]["ids"];
    let identity = |name: &str| Uuid::parse_str(ids[name].as_str().unwrap()).unwrap();
    let owner = identity("instrument");
    let other = identity("other");
    let (a, b, c) = (identity("a"), identity("b"), identity("c"));
    let seed = request(&store, fixture["commands"].clone());
    let committed = store.mutate(&seed).unwrap();
    assert_eq!(store.mutate(&seed).unwrap()["result"], committed["result"]);
    store.check_integrity().unwrap();
    assert_eq!(
        read(&store, owner, json!({"kind":"summary"})),
        stats(3, 12, Some(-2), Some(9), Some(7))
    );
    assert_eq!(
        read(
            &store,
            owner,
            json!({"kind":"range","range":{"lower":{"included":"10"},"upper":{"included":"10"}}})
        ),
        stats(2, 7, Some(-2), Some(9), Some(7))
    );
    assert_eq!(
        read(&store, owner, json!({"kind":"before","at":"10"})),
        stats(1, 5, Some(5), Some(5), Some(7))
    );
    for range in [
        json!({"lower":{"excluded":"10"},"upper":{"included":"10"}}),
        json!({"lower":{"included":"99"},"upper":null}),
    ] {
        assert_eq!(
            read(&store, owner, json!({"kind":"range","range":range})),
            stats(0, 0, None, None, None)
        );
    }
    assert_eq!(
        read(&store, other, json!({"kind":"summary"})),
        stats(0, 0, None, None, None)
    );
    for commands in [
        json!([change(&store, b, json!({"unit":8}))]),
        json!([change(&store, owner, json!({"unit":8}))]),
        json!([change(
            &store,
            a,
            json!({"value":(MAX_VALUE+1).to_string()})
        )]),
        json!([delete(&store, owner)]),
    ] {
        let before = store.observe_for_verification().unwrap();
        let bad = request(&store, commands);
        assert!(store.mutate(&bad).is_err());
        assert_eq!(store.observe_for_verification().unwrap(), before);
        assert_eq!(
            store
                .operation_status(model.identity(), &bad.context, bad.operation_id)
                .unwrap()["status"],
            "not_observed"
        );
    }
    // Each batch is valid only in its final state. Both parent-first and child-first
    // orders must allow the temporary mixed unit summaries during reconciliation.
    for (unit, parent_first) in [(8, true), (7, false)] {
        let parent = change(&store, owner, json!({"unit":unit}));
        let mut commands: Vec<_> = [a, b, c]
            .into_iter()
            .map(|r| change(&store, r, json!({"unit":unit})))
            .collect();
        if parent_first {
            commands.insert(0, parent);
        } else {
            commands.push(parent);
        }
        run(&store, json!(commands));
        assert_eq!(
            read(&store, owner, json!({"kind":"summary"})),
            stats(3, 12, Some(-2), Some(9), Some(unit))
        );
    }
    run(
        &store,
        json!([
            change(&store, b, json!({"instrument":other})),
            change(&store, c, json!({"at":"-5","value":"-9"}))
        ]),
    );
    assert_eq!(
        read(&store, owner, json!({"kind":"before","at":"0"})),
        stats(1, -9, Some(-9), Some(-9), Some(7))
    );
    assert_eq!(
        read(&store, other, json!({"kind":"summary"})),
        stats(1, -2, Some(-2), Some(-2), Some(7))
    );
    run(&store, json!([delete(&store, a), delete(&store, c)]));
    assert_eq!(
        read(&store, owner, json!({"kind":"summary"})),
        stats(0, 0, None, None, None)
    );
    run(&store, json!([change(&store, owner, json!({"unit":9}))]));
    let before = store.observe_for_verification().unwrap();
    let bad = request(
        &store,
        json!([change(&store, b, json!({"instrument":owner}))]),
    );
    assert_eq!(store.mutate(&bad).unwrap_err().code, "invariant");
    assert_eq!(store.observe_for_verification().unwrap(), before);
    let query = serde_json::from_value(
        json!({"model":model.identity(),"owner":other,"slot":7,"read":{"kind":"summary"}}),
    )
    .unwrap();
    assert!(
        store
            .session(id(999), 0)
            .unwrap()
            .root_read(&query)
            .is_err()
    );
    assert_eq!(store.observe_for_verification().unwrap(), before);
    let backup = dir.0.join("backup.json");
    store.backup(&backup).unwrap();
    let restored = dir.0.join("restored.redb");
    lifecycle::restore(&backup, &restored, model.clone()).unwrap();
    let restored = Store::<Measurement>::open(&restored, model.clone()).unwrap();
    assert_eq!(restored.observe_for_verification().unwrap(), before);
    drop(restored);
    drop(store);
    let store = Store::<Measurement>::open(&path, model.clone()).unwrap();
    assert_eq!(store.observe_for_verification().unwrap(), before);
    assert_eq!(store.mutate(&seed).unwrap()["result"], committed["result"]);
    run(
        &store,
        json!([
            delete(&store, b),
            delete(&store, other),
            delete(&store, owner)
        ]),
    );
    assert_eq!(store.check_integrity().unwrap()["records"], 0);
    let archive = dir.0.join("archive.json");
    store.archive_receipts(&archive).unwrap();
    assert!(store.mutate(&seed).is_err());
    let store_id =
        Uuid::parse_str(store.check_integrity().unwrap()["store"].as_str().unwrap()).unwrap();
    store.reset(store_id).unwrap();
    store.check_integrity().unwrap();
}

#[test]
fn measurement_schemas_and_native_objects_are_closed_and_exact() {
    let model = Prepared::<Measurement>::load().unwrap();
    for fields in [
        json!({"instrument":id(1),"at":"00","unit":7,"value":"1"}),
        json!({"instrument":id(1),"at":0,"unit":7,"value":"1"}),
        json!({"instrument":id(1),"at":"0","unit":0,"value":"1"}),
        json!({"instrument":id(1),"at":"0","unit":7,"value":1}),
        json!({"instrument":id(1),"at":"0","unit":7,"value":"-0"}),
        json!({"instrument":id(1),"at":"0","unit":7,"value":"1","sum":"1"}),
        json!([id(1), "0", 7, "1"]),
    ] {
        assert!(model.validate(211, &fields).is_err(), "{fields}");
    }
    assert!(serde_json::from_value::<Observation>(json!([7, "1"])).is_err());
    assert!(serde_json::from_value::<Summary>(json!([0,"0",null,null,{"kind":"empty"}])).is_err());
    for value in [
        json!({"count":0,"sum":"0","min":null,"dimension":{"kind":"empty"}}),
        json!({"count":0,"sum":"00","min":null,"max":null,"dimension":{"kind":"empty"}}),
    ] {
        assert!(serde_json::from_value::<Summary>(value).is_err());
    }
    assert!(
        Statistics::validate_summary(
            STATISTICS,
            &Summary {
                count: 1,
                sum: 1,
                min: Some(0),
                max: Some(2),
                dimension: Dimension::Unit { code: 7 }
            }
        )
        .is_err()
    );
    assert!(Statistics::financial_summary(STATISTICS, &Summary::default()).is_err());
    let catalog = model.public_catalog();
    assert_eq!(catalog["contracts"].as_array().unwrap().len(), 2);
}

#[test]
fn measurement_population_limit_and_alternate_avl_shapes_use_complete_source_checks() {
    let dir = Directory::new();
    let model = Arc::new(Prepared::<Measurement>::load().unwrap());
    let mut values = vec![];
    for reverse in [false, true] {
        let store = Store::<Measurement>::create(
            dir.0.join(format!("{reverse}.redb")),
            model.clone(),
            Context {
                tenant: id(1),
                actor: id(2),
            },
        )
        .unwrap();
        run(
            &store,
            json!([{"op":"create","id":id(10),"contract":101,"fields":{"unit":7}}]),
        );
        let mut times: Vec<i64> = (0..63).collect();
        if reverse {
            times.reverse();
        }
        for chunk in times.chunks(21) {
            let commands:Vec<_>=chunk.iter().map(|at|json!({"op":"create","id":id(100+*at as u128),"contract":211,"fields":{"instrument":id(10),"at":at.to_string(),"unit":7,"value":(*at-31).to_string()}})).collect();
            run(&store, json!(commands));
        }
        values.push(read(&store, id(10), json!({"kind":"summary"})));
        let before = store.observe_for_verification().unwrap();
        assert!(
            store
                .mutate(&request(
                    &store,
                    json!([{"op":"create","id":id(999),"contract":101,"fields":{"unit":7}}])
                ))
                .is_err()
        );
        assert_eq!(store.observe_for_verification().unwrap(), before);
    }
    assert_eq!(values[0], values[1]);
    assert_eq!(values[0], stats(63, 0, Some(-31), Some(31), Some(7)));
}

#[test]
fn full_population_replacement_accepts_both_command_orders() {
    let dir = Directory::new();
    let model = Arc::new(Prepared::<Measurement>::load().unwrap());
    let expected: Vec<i128> = (32..63).map(|n| n - 31).chain(50..82).collect();
    for create_first in [true, false] {
        let store = Store::<Measurement>::create_secured(
            dir.0.join(format!("replace-{create_first}.redb")),
            model.clone(),
            Context {
                tenant: id(1),
                actor: id(2),
            },
        )
        .unwrap();
        let mut seed = vec![json!({"op":"create","id":id(10),"contract":101,"fields":{"unit":7}})];
        seed.extend((0..63).map(|n| {
            json!({"op":"create","id":id(100+n),"contract":211,
                "fields":{"instrument":id(10),"at":n.to_string(),"unit":7,"value":(n as i128-31).to_string()}})
        }));
        run(&store, json!(seed));
        let creates = (0..32).map(|n| {
            json!({"op":"create","id":id(1000+n),"contract":211,
                "fields":{"instrument":id(10),"at":(100+n).to_string(),"unit":7,"value":(50+n).to_string()}})
        });
        let deletes = (0..32).map(|n| delete(&store, id(100 + n)));
        let commands: Vec<_> = if create_first {
            creates.chain(deletes).collect()
        } else {
            deletes.chain(creates).collect()
        };
        assert_eq!(commands.len(), 64);
        run(&store, json!(commands));
        assert_eq!(
            read(&store, id(10), json!({"kind":"summary"})),
            stats(
                expected.len() as u64,
                expected.iter().sum(),
                expected.iter().copied().min(),
                expected.iter().copied().max(),
                Some(7),
            )
        );
    }
}

#[test]
fn measurement_corrupted_native_values_fail_check_startup_and_verified_restore() {
    use rebase_semantic_proof::{
        identity::IdentityConfig,
        server::{self, ServerConfig},
    };
    use redb::{Database, TableDefinition};
    use sha2::{Digest, Sha256};
    let dir = Directory::new();
    let path = dir.0.join("source.redb");
    let model = Arc::new(Prepared::<Measurement>::load().unwrap());
    let store = Store::<Measurement>::create_secured(
        &path,
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let fixture = Measurement::fixture_plan(&model, "measurements", id(40)).unwrap();
    run(&store, fixture["commands"].clone());
    let backup = dir.0.join("valid.json");
    store.backup(&backup).unwrap();
    let image: Value = serde_json::from_slice(&std::fs::read(&backup).unwrap()).unwrap();
    let owner = Uuid::parse_str(fixture["fixture"]["ids"]["instrument"].as_str().unwrap()).unwrap();
    let member = Uuid::parse_str(fixture["fixture"]["ids"]["b"].as_str().unwrap()).unwrap();
    let root_key = Key::Root(Address::new(owner, 7));
    let node_key = Key::Node(Address::new(member, 17));
    let original = |key: &Key| {
        let hexkey = native_codec::hex(&key.encode());
        let row = image["payload"]["tables"]["native_kv"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["key"] == hexkey)
            .unwrap();
        unhex(row["value"].as_str().unwrap())
    };
    let config = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        max_inflight: 1,
        request_timeout_seconds: 5,
        identity: IdentityConfig {
            issuer: "measurement-test".into(),
            audience: "rebase-test".into(),
            public_keys: [(
                "test".into(),
                include_str!("fixtures/test-ed25519-public.pem").into(),
            )]
            .into(),
            max_token_seconds: 600,
        },
    };
    for label in [
        "index-code",
        "key-variant",
        "leaf-variant",
        "summary-variant",
        "span",
        "cache",
    ] {
        let key = if matches!(label, "key-variant" | "leaf-variant") {
            node_key.clone()
        } else {
            root_key.clone()
        };
        let bytes = original(&key);
        let mut stored = native_codec::decode_for::<Measurement>(&key, &bytes).unwrap();
        let corrupt = if matches!(label, "span" | "cache") {
            let StoredValue::Root(root) = &mut stored else {
                panic!("root")
            };
            if label == "span" {
                root.span.as_mut().unwrap().first = TimeKey::new(-1);
            } else {
                root.summary.sum += 1; // Native bounds hold; literal source arithmetic must reject.
            }
            native_codec::encode_for::<Measurement>(&key, &stored).unwrap()
        } else {
            let mut wire: Value = serde_json::from_slice(&bytes).unwrap();
            match label {
                "index-code" => wire["data"]["kind"] = json!(999),
                "key-variant" => wire["data"]["key"]["value"] = json!({"time":"10"}),
                "leaf-variant" => wire["data"]["leaf"] = json!({"kind":"financial","value":"1"}),
                "summary-variant" => {
                    wire["data"]["summary"] = json!({"kind":"quote","value":{"count":1}})
                }
                _ => unreachable!(),
            }
            serde_json::to_vec(&wire).unwrap()
        };
        let hexkey = native_codec::hex(&key.encode());
        let mut bad = image.clone();
        let row = bad["payload"]["tables"]["native_kv"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|row| row["key"] == hexkey)
            .unwrap();
        row["value"] = json!(native_codec::hex(&corrupt));
        bad["sha256"] = json!(native_codec::hex(&Sha256::digest(
            serde_json::to_vec(&bad["payload"]).unwrap()
        )));
        let invalid = dir.0.join(format!("invalid-{label}.json"));
        std::fs::write(&invalid, serde_json::to_vec(&bad).unwrap()).unwrap();
        let destination = dir.0.join(format!("failed-{label}.redb"));
        assert!(
            lifecycle::restore(&invalid, &destination, model.clone()).is_err(),
            "{label}"
        );
        assert!(!destination.exists());
        let corrupt_path = dir.0.join(format!("corrupt-{label}.redb"));
        lifecycle::restore(&backup, &corrupt_path, model.clone()).unwrap();
        let db = Database::open(&corrupt_path).unwrap();
        let tx = db.begin_write().unwrap();
        {
            let mut table = tx
                .open_table(TableDefinition::<&[u8], &[u8]>::new("native_kv"))
                .unwrap();
            table
                .insert(key.encode().as_slice(), corrupt.as_slice())
                .unwrap();
        }
        tx.commit().unwrap();
        drop(db);
        let opened = Store::<Measurement>::open(&corrupt_path, model.clone()).unwrap();
        let before = opened.observe_for_verification().unwrap();
        assert!(opened.check_integrity().is_err(), "{label}");
        let opened = Arc::new(opened);
        assert!(
            server::router(opened.clone(), &config).is_err(),
            "startup {label}"
        );
        assert_eq!(opened.observe_for_verification().unwrap(), before);
        drop(opened);
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_rebase-next"))
            .args(["--model", "measurement", "check"])
            .arg(&corrupt_path)
            .output()
            .unwrap();
        assert!(!result.status.success(), "CLI check {label}");
    }
}

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
