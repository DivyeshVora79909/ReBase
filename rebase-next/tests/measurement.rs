use rebase_semantic_proof::{
    binding::Binding,
    index::{NativeIndex, TimeKey},
    indexes::measurement::{Dimension, MAX_VALUE, Observation, STATISTICS, Statistics, Summary},
    lifecycle,
    local::{Mutation, Store},
    model::Prepared,
    models::measurement::{Measurement, REPORT, REPORT_QUERY},
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
    assert_eq!(catalog["contracts"].as_array().unwrap().len(), 3);
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
fn observation_report_and_native_corruptions_fail_check_startup_and_verified_restore() {
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
    let fixture = Measurement::fixture_plan(&model, "observation-report", id(40)).unwrap();
    run(&store, fixture["commands"].clone());
    let backup = dir.0.join("valid.json");
    store.backup(&backup).unwrap();
    let image: Value = serde_json::from_slice(&std::fs::read(&backup).unwrap()).unwrap();
    let owner = Uuid::parse_str(fixture["fixture"]["ids"]["instrument"].as_str().unwrap()).unwrap();
    let member = Uuid::parse_str(fixture["fixture"]["ids"]["b"].as_str().unwrap()).unwrap();
    let root_key = Key::Root(Address::new(owner, 7));
    let node_key = Key::Node(Address::new(member, 17));
    let report = Uuid::parse_str(fixture["fixture"]["ids"]["report"].as_str().unwrap()).unwrap();
    let query_key = Key::Query(Address::new(report, REPORT_QUERY));
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
        effects: None,
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
        "report-result",
        "report-binding",
        "report-bounds",
        "report-cache",
        "report-derived",
        "report-route",
        "report-direct",
        "missing-query",
        "missing-route",
        "missing-direct",
    ] {
        let key = match label {
            "key-variant" | "leaf-variant" => node_key.clone(),
            "report-result" | "report-binding" | "report-bounds" | "report-cache"
            | "missing-query" => query_key.clone(),
            "report-derived" => Key::Record(report),
            "report-route" | "missing-route" => {
                Key::SubscriberNode(Address::new(report, REPORT_QUERY))
            }
            "report-direct" | "missing-direct" => Key::DirectNode(Address::new(report, 1)),
            _ => root_key.clone(),
        };
        let bytes = original(&key);
        let mut stored = native_codec::decode_for::<Measurement>(&key, &bytes).unwrap();
        let corrupt = if label.starts_with("missing-") {
            None
        } else if matches!(
            label,
            "span"
                | "cache"
                | "report-bounds"
                | "report-cache"
                | "report-derived"
                | "report-route"
                | "report-direct"
        ) {
            match &mut stored {
                StoredValue::Root(root) if label == "span" => {
                    root.span.as_mut().unwrap().first = TimeKey::new(-1)
                }
                StoredValue::Root(root) => root.summary.sum += 1,
                StoredValue::Query(query) if label == "report-bounds" => {
                    query.range.lower = rebase_semantic_proof::time_range::TimeBound::Included(1)
                }
                StoredValue::Query(query) => query.result.sum += 1,
                StoredValue::Record(record) => record.derived.as_mut().unwrap().count += 1,
                StoredValue::RouteNode(node) => {
                    let other =
                        Uuid::parse_str(fixture["fixture"]["ids"]["other"].as_str().unwrap())
                            .unwrap();
                    node.route = if label == "report-direct" {
                        rebase_semantic_proof::routes::Route::Direct(other)
                    } else {
                        rebase_semantic_proof::routes::Route::Subscribers(Address::new(other, 7))
                    };
                }
                _ => panic!("unexpected corrupt type"),
            }
            // Native local bounds hold; source-derived inventories must reject.
            Some(native_codec::encode_for::<Measurement>(&key, &stored).unwrap())
        } else {
            let mut wire: Value = serde_json::from_slice(&bytes).unwrap();
            match label {
                "index-code" => wire["data"]["kind"] = json!(999),
                "key-variant" => wire["data"]["key"]["value"] = json!({"time":"10"}),
                "leaf-variant" => wire["data"]["leaf"] = json!({"kind":"financial","value":"1"}),
                "summary-variant" => {
                    wire["data"]["summary"] = json!({"kind":"quote","value":{"count":1}})
                }
                "report-result" => {
                    wire["data"]["result"] = json!({"kind":"financial","value":"17"})
                }
                "report-binding" => wire["data"]["channel"] = json!("amount"),
                _ => unreachable!(),
            }
            Some(serde_json::to_vec(&wire).unwrap())
        };
        let hexkey = native_codec::hex(&key.encode());
        let mut bad = image.clone();
        let rows = bad["payload"]["tables"]["native_kv"]
            .as_array_mut()
            .unwrap();
        if let Some(corrupt) = &corrupt {
            rows.iter_mut().find(|row| row["key"] == hexkey).unwrap()["value"] =
                json!(native_codec::hex(corrupt));
        } else {
            rows.retain(|row| row["key"] != hexkey);
        }
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
            if let Some(corrupt) = &corrupt {
                table
                    .insert(key.encode().as_slice(), corrupt.as_slice())
                    .unwrap();
            } else {
                table.remove(key.encode().as_slice()).unwrap();
            }
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

fn report_value(count: u64, min: Option<i128>, max: Option<i128>, unit: u16, pass: bool) -> Value {
    json!({"count":count,"min":min.map(|v|v.to_string()),"max":max.map(|v|v.to_string()),
        "unit":unit,"at_least_threshold":pass})
}
fn report(store: &Store<Measurement>, id: Uuid) -> Value {
    store
        .get(store.model().identity(), id)
        .unwrap()
        .unwrap()
        .derived
        .unwrap()
}
fn reject_report(store: &Store<Measurement>, commands: Value, code: &str) {
    let before = store.observe_for_verification().unwrap();
    let attempt = request(store, commands);
    assert_eq!(store.mutate(&attempt).unwrap_err().code, code);
    assert_eq!(store.observe_for_verification().unwrap(), before);
    assert_eq!(
        store
            .operation_status(
                store.model().identity(),
                &attempt.context,
                attempt.operation_id
            )
            .unwrap()["status"],
        "not_observed"
    );
}

#[test]
fn observation_reports_keep_exact_empty_and_equal_result_dependencies() {
    let dir = Directory::new();
    let model = Arc::new(Prepared::<Measurement>::load().unwrap());
    let store = Store::create_secured(
        dir.0.join("reports.redb"),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let fixture = Measurement::fixture_plan(&model, "observation-report", id(55)).unwrap();
    let ids = &fixture["fixture"]["ids"];
    let named = |name: &str| Uuid::parse_str(ids[name].as_str().unwrap()).unwrap();
    let (instrument, other, a, b, c, reader) = (
        named("instrument"),
        named("other"),
        named("a"),
        named("b"),
        named("c"),
        named("report"),
    );
    let seed = request(&store, fixture["commands"].clone());
    let accepted = store
        .mutate_with_ids(&seed, &mut || panic!("report allocated a private identity"))
        .unwrap();
    assert_eq!(report(&store, reader), fixture["fixture"]["expected"]);
    assert_eq!(store.mutate(&seed).unwrap()["result"], accepted["result"]);
    store.check_integrity().unwrap();

    // Literal values for nine distinct bound shapes; this table does not use
    // the tree, native summary or writer range predicate for expectations.
    for (lower, upper, expected) in [
        (
            Value::Null,
            Value::Null,
            report_value(3, Some(-2), Some(12), 7, false),
        ),
        (
            Value::Null,
            json!({"excluded":"0"}),
            report_value(0, None, None, 7, false),
        ),
        (
            Value::Null,
            json!({"included":"0"}),
            report_value(1, Some(5), Some(5), 7, true),
        ),
        (
            json!({"excluded":"0"}),
            json!({"included":"20"}),
            report_value(2, Some(-2), Some(12), 7, false),
        ),
        (
            json!({"included":"10"}),
            json!({"included":"10"}),
            report_value(1, Some(12), Some(12), 7, true),
        ),
        (
            json!({"included":"10"}),
            json!({"excluded":"10"}),
            report_value(0, None, None, 7, false),
        ),
        (
            json!({"included":"20"}),
            Value::Null,
            report_value(1, Some(-2), Some(-2), 7, false),
        ),
        (
            json!({"included":"21"}),
            Value::Null,
            report_value(0, None, None, 7, false),
        ),
        (
            json!({"included":"0"}),
            json!({"excluded":"20"}),
            report_value(2, Some(5), Some(12), 7, true),
        ),
    ] {
        let range = json!({"lower":lower,"upper":upper});
        run(
            &store,
            json!([change(&store, reader, json!({"range":range}))]),
        );
        assert_eq!(report(&store, reader), expected);
        let view = store.inspect().unwrap();
        assert_eq!(view["queries"].as_array().unwrap().len(), 1);
        assert_eq!(view["queries"][0]["descriptor"]["range"], range);
        assert_eq!(
            view["queries"][0]["query"],
            json!({"id":reader,"slot":REPORT_QUERY})
        );
        assert!(view["roles"].as_array().unwrap().is_empty());
    }
    let before = store.get(model.identity(), reader).unwrap().unwrap();
    run(&store, json!([change(&store, b, json!({"at":"11"}))]));
    assert_eq!(
        store.get(model.identity(), reader).unwrap().unwrap(),
        before
    );
    run(&store, json!([change(&store, c, json!({"at":"15"}))]));
    assert_eq!(
        report(&store, reader),
        report_value(3, Some(-2), Some(12), 7, false)
    );
    run(
        &store,
        json!([change(&store, c, json!({"instrument":other}))]),
    );
    assert_eq!(
        report(&store, reader),
        report_value(2, Some(5), Some(12), 7, true)
    );
    run(&store, json!([change(&store, b, json!({"value":"4"}))]));
    assert_eq!(
        report(&store, reader),
        report_value(2, Some(4), Some(5), 7, false)
    );
    run(&store, json!([delete(&store, a), delete(&store, b)]));
    assert_eq!(
        report(&store, reader),
        report_value(0, None, None, 7, false)
    );
    assert_eq!(
        store.inspect().unwrap()["queries"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Even an empty report depends on its owner's authored unit.
    reject_report(
        &store,
        json!([change(&store, instrument, json!({"unit":8}))]),
        "invariant",
    );
    reject_report(
        &store,
        json!([delete(&store, instrument)]),
        "unavailable_reference",
    );
    reject_report(
        &store,
        json!([change(&store, reader, json!({"instrument":id(999)}))]),
        "unavailable_reference",
    );
    reject_report(
        &store,
        json!([change(&store, reader, json!({"instrument":c}))]),
        "unavailable_reference",
    );
    run(
        &store,
        json!([
            change(&store, reader, json!({"unit":8})),
            change(&store, instrument, json!({"unit":8}))
        ]),
    );
    assert_eq!(
        report(&store, reader),
        report_value(0, None, None, 8, false)
    );
    run(
        &store,
        json!([{"op":"create","id":id(999),"contract":211,"fields":{"instrument":instrument,"at":"0","unit":8,"value":"5"}}]),
    );
    assert_eq!(
        report(&store, reader),
        report_value(1, Some(5), Some(5), 8, true)
    );
}

#[test]
fn observation_reports_retarget_and_repair_units_in_both_orders_with_complete_rollback() {
    let dir = Directory::new();
    let model = Arc::new(Prepared::<Measurement>::load().unwrap());
    for reverse in [false, true] {
        let path = dir.0.join(format!("report-{reverse}.redb"));
        let store = Store::create_secured(
            &path,
            model.clone(),
            Context {
                tenant: id(1),
                actor: id(2),
            },
        )
        .unwrap();
        run(
            &store,
            json!([
                {"op":"create","id":id(10),"contract":101,"fields":{"unit":7}},
                {"op":"create","id":id(11),"contract":101,"fields":{"unit":8}},
                {"op":"create","id":id(20),"contract":211,"fields":{"instrument":id(10),"at":"0","unit":7,"value":"5"}},
                {"op":"create","id":id(30),"contract":REPORT,"fields":{"instrument":id(10),"range":{"lower":null,"upper":null},"unit":7,"threshold":"5"}}
            ]),
        );
        let mut commands = vec![
            change(&store, id(11), json!({"unit":9})),
            change(&store, id(20), json!({"instrument":id(11),"unit":9})),
            change(&store, id(30), json!({"instrument":id(11),"unit":9})),
        ];
        if reverse {
            commands.reverse();
        }
        run(&store, json!(commands));
        assert_eq!(
            report(&store, id(30)),
            report_value(1, Some(5), Some(5), 9, true)
        );
        let settled = store.get(model.identity(), id(30)).unwrap().unwrap();
        run(&store, json!([change(&store, id(10), json!({"unit":10}))]));
        assert_eq!(
            store.get(model.identity(), id(30)).unwrap().unwrap(),
            settled
        );
        let bad = json!([
            change(&store, id(20), json!({"at":"10","value":"-10"})),
            change(&store, id(30), json!({"unit":8}))
        ]);
        reject_report(&store, bad, "invariant");
        let before = store.observe_for_verification().unwrap();
        let backup = dir.0.join(format!("report-{reverse}.json"));
        store.backup(&backup).unwrap();
        let restored = dir.0.join(format!("restored-{reverse}.redb"));
        lifecycle::restore(&backup, &restored, model.clone()).unwrap();
        let restored = Store::<Measurement>::open(&restored, model.clone()).unwrap();
        assert_eq!(restored.observe_for_verification().unwrap(), before);
        assert_eq!(report(&restored, id(30)), report(&store, id(30)));
        drop(store);
        let reopened = Store::<Measurement>::open(&path, model.clone()).unwrap();
        assert_eq!(reopened.observe_for_verification().unwrap(), before);
    }
}

#[test]
fn observation_report_budget_failure_discards_staged_queries_and_all_tables() {
    use rebase_semantic_proof::{mutation, native_slice::Attempt};
    use std::collections::BTreeMap;
    let dir = Directory::new();
    let model = Arc::new(Prepared::<Measurement>::load().unwrap());
    let context = Context {
        tenant: id(1),
        actor: id(2),
    };
    let store = Store::create_secured(dir.0.join("budget.redb"), model.clone(), context).unwrap();
    let fixture = Measurement::fixture_plan(&model, "observation-report", id(56)).unwrap();
    run(&store, fixture["commands"].clone());
    let member = Uuid::parse_str(fixture["fixture"]["ids"]["a"].as_str().unwrap()).unwrap();
    let attempt = request(
        &store,
        json!([change(&store, member, json!({"value":"-9"}))]),
    );
    let before = store.observe_for_verification().unwrap();
    let bytes: BTreeMap<_, _> = before["tables"]["native_kv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                unhex(row["key"].as_str().unwrap()),
                unhex(row["value"].as_str().unwrap()),
            )
        })
        .collect();
    let mut ws = Attempt::<_, Measurement>::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 200_000);
    mutation::settle_authorized(
        &mut ws,
        &model,
        context,
        &attempt.commands,
        &mut || panic!("report allocation"),
        false,
        &mut |_, _, _, _| Ok(()),
    )
    .unwrap();
    let needed = ws.work.work_units;
    assert_eq!(ws.work.causal_evaluations, 1);
    assert!(!ws.finish().unwrap().is_empty());
    let mut ws =
        Attempt::<_, Measurement>::new(|key: &[u8]| Ok(bytes.get(key).cloned()), needed - 1);
    let failure = mutation::settle_authorized(
        &mut ws,
        &model,
        context,
        &attempt.commands,
        &mut || panic!("report allocation"),
        false,
        &mut |_, _, _, _| Ok(()),
    );
    assert_eq!(failure.unwrap_err().code, "work_limit");
    assert!(ws.work.staged_patches > 0);
    drop(ws);
    assert_eq!(store.observe_for_verification().unwrap(), before);
    assert_eq!(
        store
            .operation_status(model.identity(), &attempt.context, attempt.operation_id)
            .unwrap()["status"],
        "not_observed"
    );
}

#[test]
fn observation_report_query_contract_and_native_result_are_checked() {
    use rebase_semantic_proof::{native_slice::Query, time_range::TimeRange};
    let key = Key::Query(Address::new(id(30), REPORT_QUERY));
    let query = Query::<Statistics> {
        source: Address::new(id(10), 7),
        operation: "summary".into(),
        phase: "calculate".into(),
        channel: "statistics".into(),
        range: TimeRange::ALL,
        selected: None,
        result: Summary::default(),
    };
    let value = StoredValue::<Measurement>::Query(query);
    let bytes = native_codec::encode_for::<Measurement>(&key, &value).unwrap();
    assert_eq!(
        native_codec::decode_for::<Measurement>(&key, &bytes).unwrap(),
        value
    );
    for replacement in [
        json!("0"),
        json!({"kind":"financial","value":"0"}),
        json!([0,"0",null,null,{"kind":"empty"}]),
    ] {
        let mut wire: Value = serde_json::from_slice(&bytes).unwrap();
        wire["data"]["result"] = replacement;
        assert!(
            native_codec::decode_for::<Measurement>(&key, &serde_json::to_vec(&wire).unwrap())
                .is_err()
        );
    }
    for part in ["operation", "channel", "phase"] {
        let mut declarations = Measurement::declarations().unwrap();
        let report = declarations
            .iter_mut()
            .find(|contract| contract.code == REPORT)
            .unwrap();
        match part {
            "operation" => report.queries[0].operation = "sum",
            "channel" => report.queries[0].channel = "amount",
            "phase" => report.queries[0].phase = "validate",
            _ => unreachable!(),
        }
        assert!(Prepared::<Measurement>::prepare(declarations).is_err());
    }
}
