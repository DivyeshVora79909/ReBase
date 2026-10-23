//! Focused G5a controls. Each failure compares every persisted application table.
use crate::{
    access::{Action, Grants, Graph, Principal, PrincipalKind},
    binding::Binding,
    effects::{self, Cancel},
    lifecycle,
    local::{self, Mutation, Store},
    model::Prepared,
    models::effect_demo::EffectDemo,
    native_codec,
    native_slice::{Context, Error},
    security::ReplaceGraph,
};
use redb::{ReadableDatabase, TableDefinition};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc};
use uuid::Uuid;

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/effect-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn store(&self) -> Store<EffectDemo> {
        Store::create_secured(
            self.0.join("source.redb"),
            Arc::new(Prepared::load().unwrap()),
            Context {
                tenant: id(1),
                actor: id(2),
            },
        )
        .unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn mutation(store: &Store<EffectDemo>, operation: u128, commands: Value) -> Mutation {
    serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":id(operation),"commands":commands,"returning":[]})).unwrap()
}
fn create_account(n: u128, balance: i128) -> Value {
    json!({"op":"create","id":id(n),"contract":101,"fields":{"balance":balance.to_string()}})
}
fn dispatch(n: u128, account: u128) -> Value {
    json!({"op":"create","id":id(n),"contract":205,"fields":{"account":id(account),"units":"3","execute_at":null,"not_after":null}})
}
fn update(store: &Store<EffectDemo>, n: u128, fields: Value) -> Value {
    let record = store.get(store.model().identity(), id(n)).unwrap().unwrap();
    json!({"op":"update","id":id(n),"if_version":record.version.to_string(),"set":fields,"unset":[]})
}
fn delete(store: &Store<EffectDemo>, n: u128) -> Value {
    let record = store.get(store.model().identity(), id(n)).unwrap().unwrap();
    json!({"op":"delete","id":id(n),"if_version":record.version.to_string()})
}
fn cancellation(store: &Store<EffectDemo>, operation: u128, execution: Uuid) -> Cancel {
    Cancel {
        model: store.model().identity().into(),
        context: store.operation_context(store.model().identity()).unwrap(),
        operation_id: id(operation),
        execution_id: execution,
        if_revision: 1,
    }
}
fn executions(result: &Value) -> Vec<Uuid> {
    result["result"]["executions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| Uuid::parse_str(r["execution_id"].as_str().unwrap()).unwrap())
        .collect()
}
fn rejected(store: &Store<EffectDemo>, request: &Mutation, code: &str) {
    let before = store.observe_for_verification().unwrap();
    assert_eq!(store.mutate(request).unwrap_err().code, code);
    assert_eq!(store.observe_for_verification().unwrap(), before);
    assert_eq!(
        store
            .operation_status(&request.model, &request.context, request.operation_id)
            .unwrap()["status"],
        "not_observed"
    );
}

#[test]
fn intent_and_cancel_roll_back_after_actual_writes_and_share_receipts() {
    let dir = Directory::new();
    let store = dir.store();
    store
        .mutate(&mutation(&store, 100, json!([create_account(10, 12)])))
        .unwrap();
    let request = mutation(
        &store,
        101,
        json!([
            update(&store, 10, json!({"balance":"10"})),
            dispatch(20, 10)
        ]),
    );
    let before = store.observe_for_verification().unwrap();
    assert_eq!(before["tables"].as_object().unwrap().len(), 11);
    let snapshot = store.db.begin_read().unwrap();
    for abort in [
        1,
        usize::MAX - 1,
        usize::MAX - 2,
        usize::MAX - 3,
        usize::MAX,
    ] {
        assert_eq!(
            store
                .mutate_inner(&request, &mut || Ok(id(500)), Some(abort))
                .unwrap_err()
                .code,
            "injected_abort"
        );
        assert_eq!(
            store.observe_for_verification().unwrap(),
            before,
            "abort {abort}"
        );
        assert_eq!(local::observe(&snapshot).unwrap(), before);
        assert_eq!(
            store
                .operation_status(&request.model, &request.context, request.operation_id)
                .unwrap()["status"],
            "not_observed"
        );
    }
    let mut invalid = request.clone();
    invalid.commands = serde_json::from_value(json!([
        update(&store, 10, json!({"balance":"-1"})),
        dispatch(20, 10)
    ]))
    .unwrap();
    let mut allocations = 0;
    assert_eq!(
        store
            .mutate_with_ids(&invalid, &mut || {
                allocations += 1;
                Ok(id(500))
            })
            .unwrap_err()
            .code,
        "invariant"
    );
    assert_eq!(allocations, 0);
    assert_eq!(store.observe_for_verification().unwrap(), before);
    for collision in [Uuid::nil(), id(10), id(20)] {
        assert_eq!(
            store
                .mutate_with_ids(&request, &mut || Ok(collision))
                .unwrap_err()
                .code,
            "allocation_collision"
        );
        assert_eq!(store.observe_for_verification().unwrap(), before);
    }
    let result = store
        .mutate_with_ids(&request, &mut || Ok(id(500)))
        .unwrap();
    assert_eq!(executions(&result), [id(500)]);
    assert_eq!(local::observe(&snapshot).unwrap(), before);
    drop(snapshot);
    let status = store.effect_status(&request.model, id(500)).unwrap();
    assert_eq!(status["phase"], "ready");
    assert_eq!(status["request"]["units"], "3");
    assert_eq!(status["worker_mode"], "disabled");
    assert_eq!(
        store.get(&request.model, id(10)).unwrap().unwrap().input,
        crate::models::effect_demo::Input::Account { balance: 10 }
    );
    let accepted = store.observe_for_verification().unwrap();
    let replay = store
        .mutate_with_ids(&request, &mut || panic!("replay allocated"))
        .unwrap();
    assert_eq!(replay["result"], result["result"]);
    assert_eq!(store.observe_for_verification().unwrap(), accepted);
    assert_eq!(
        store.mutate(&invalid).unwrap_err().code,
        "operation_conflict"
    );
    let cancel = cancellation(&store, 102, id(500));
    for abort in [usize::MAX - 1, usize::MAX - 2, usize::MAX - 3, usize::MAX] {
        assert_eq!(
            store
                .cancel_effect_inner(&cancel, Some(abort))
                .unwrap_err()
                .code,
            "injected_abort"
        );
        assert_eq!(store.observe_for_verification().unwrap(), accepted);
        assert_eq!(
            store
                .operation_status(&cancel.model, &cancel.context, cancel.operation_id)
                .unwrap()["status"],
            "not_observed"
        );
    }
    let cancelled = store.cancel_effect(&cancel).unwrap();
    assert_eq!(cancelled["result"]["phase"], "cancelled");
    assert_eq!(cancelled["result"]["execution_revision"], "2");
    assert_eq!(
        store.cancel_effect(&cancel).unwrap()["result"],
        cancelled["result"]
    );
    let mut conflict = cancel.clone();
    conflict.operation_id = request.operation_id;
    assert_eq!(
        store.cancel_effect(&conflict).unwrap_err().code,
        "operation_conflict"
    );
    let mut conflict = request.clone();
    conflict.operation_id = cancel.operation_id;
    assert_eq!(
        store.mutate(&conflict).unwrap_err().code,
        "operation_conflict"
    );
    let stale = cancellation(&store, 103, id(500));
    assert_eq!(
        store.cancel_effect(&stale).unwrap_err().code,
        "stale_version"
    );
    store
        .mutate(&mutation(&store, 104, json!([delete(&store, 20)])))
        .unwrap();
    rejected(
        &store,
        &mutation(&store, 105, json!([delete(&store, 10)])),
        "unavailable_reference",
    );
    let reused = store
        .mutate(&mutation(&store, 106, json!([dispatch(20, 10)])))
        .unwrap();
    assert_ne!(executions(&reused)[0], id(500));
    assert_eq!(
        store.effect_status(&request.model, id(500)).unwrap()["phase"],
        "cancelled"
    );
    store.check_integrity().unwrap();
}

#[test]
fn real_capacity_bounds_preserve_replay_reserved_bytes_restore_and_reset() {
    let dir = Directory::new();
    let store = dir.store();
    store
        .mutate(&mutation(&store, 100, json!([create_account(10, 12)])))
        .unwrap();
    let mut latest = None;
    for batch in 0..4u128 {
        let commands: Vec<_> = (0..64).map(|n| dispatch(1000 + n, 10)).collect();
        let request = mutation(&store, 200 + batch, json!(commands));
        let result = store.mutate(&request).unwrap();
        let rows = executions(&result);
        let before = store.observe_for_verification().unwrap();
        let overflow = mutation(&store, 300 + batch, json!([dispatch(2000, 10)]));
        rejected(&store, &overflow, "state_limit");
        assert_eq!(
            store
                .mutate_with_ids(&request, &mut || panic!("full-capacity replay allocated"))
                .unwrap()["result"],
            result["result"]
        );
        assert_eq!(store.observe_for_verification().unwrap(), before);
        let checked = store.check_integrity().unwrap();
        assert_eq!(checked["effects"]["retained"], ((batch + 1) * 64) as u64);
        assert_eq!(checked["effects"]["unresolved"], 64);
        assert_eq!(checked["effects"]["reserved_facts"], 64);
        if batch < 3 {
            for (n, execution) in rows.into_iter().enumerate() {
                store
                    .cancel_effect(&cancellation(
                        &store,
                        10000 + batch * 64 + n as u128,
                        execution,
                    ))
                    .unwrap();
            }
            let deletes: Vec<_> = (0..64).map(|n| delete(&store, 1000 + n)).collect();
            store
                .mutate(&mutation(&store, 400 + batch, json!(deletes)))
                .unwrap();
        } else {
            latest = Some((request, result, rows));
        }
    }
    let (request, result, rows) = latest.unwrap();
    let checked = store.check_integrity().unwrap();
    let backup = dir.0.join("full.json");
    let backed_up = store.backup(&backup).unwrap();
    assert!(backed_up["bytes"].as_u64().unwrap() < lifecycle::MAX_BACKUP_BYTES);
    let before = store.observe_for_verification().unwrap();
    let store_id = Uuid::parse_str(checked["store"].as_str().unwrap()).unwrap();
    assert_eq!(store.reset(store_id).unwrap_err().code, "invariant");
    assert_eq!(store.observe_for_verification().unwrap(), before);
    let restored_path = dir.0.join("restored.redb");
    let restored_result = lifecycle::restore(
        &backup,
        &restored_path,
        Arc::new(Prepared::<EffectDemo>::load().unwrap()),
    )
    .unwrap();
    assert_eq!(restored_result["integrity"]["effects"]["quarantined"], true);
    assert_eq!(restored_result["integrity"]["effects"]["unresolved"], 64);
    let restored =
        Store::<EffectDemo>::open(&restored_path, Arc::new(Prepared::load().unwrap())).unwrap();
    let after = restored.observe_for_verification().unwrap();
    for (name, rows) in before["tables"].as_object().unwrap() {
        if !["effect_runtime", "effect_executions", "effect_due"].contains(&name.as_str()) {
            assert_eq!(&after["tables"][name], rows);
        }
    }
    let runtime = |image: &Value| -> Value {
        serde_json::from_slice(
            &local::unhex(
                image["tables"]["effect_runtime"][0]["value"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    };
    assert_ne!(
        runtime(&before)["activation"],
        runtime(&after)["activation"]
    );
    assert_eq!(
        restored.mutate(&request).unwrap()["result"],
        result["result"]
    );
    drop(restored);
    // Free an unresolved slot: retained capacity must still reject a new request.
    store
        .cancel_effect(&cancellation(&store, 20000, rows[0]))
        .unwrap();
    rejected(
        &store,
        &mutation(&store, 20001, json!([dispatch(2000, 10)])),
        "state_limit",
    );
    let archive = dir.0.join("archive.json");
    let evidence = store.observe_for_verification().unwrap();
    store.archive_receipts(&archive).unwrap();
    let archived = store.observe_for_verification().unwrap();
    for table in [
        "effect_executions",
        "effect_due",
        "effect_facts",
        "effect_inbox",
        "effect_runtime",
    ] {
        assert_eq!(evidence["tables"][table], archived["tables"][table]);
    }
    assert_eq!(
        store.mutate(&request).unwrap_err().code,
        "operation_expired"
    );
    assert_eq!(
        store
            .operation_status(&request.model, &request.context, request.operation_id)
            .unwrap_err()
            .code,
        "operation_expired"
    );
    store.check_integrity().unwrap();
    for (n, execution) in rows.into_iter().enumerate().skip(1) {
        store
            .cancel_effect(&cancellation(&store, 21000 + n as u128, execution))
            .unwrap();
    }
    store.check_integrity().unwrap();
    let reset = store.reset(store_id).unwrap();
    assert_ne!(reset["store"], store_id.to_string());
    assert_eq!(store.check_integrity().unwrap()["effects"]["retained"], 0);
    assert_eq!(
        store
            .session(id(2), 0)
            .unwrap()
            .effect_status(store.model().identity(), id(500))
            .unwrap_err()
            .code,
        "forbidden"
    );
}

fn replace(store: &Store<EffectDemo>, graph: Graph) {
    let revision = store.access_graph(store.model().identity()).unwrap()["revision"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    store
        .replace_access(&ReplaceGraph {
            model: store.model().identity().into(),
            if_revision: revision,
            graph,
        })
        .unwrap();
}
#[test]
fn current_account_authority_controls_creation_cancel_status_and_receipt_disclosure() {
    let dir = Directory::new();
    let store = dir.store();
    let mut graph = Graph::bootstrap(store.context()).unwrap().graph;
    for n in [3, 4, 5] {
        graph.principals.push(Principal {
            id: id(n),
            kind: PrincipalKind::User,
            parents: vec![id(if n == 4 { 3 } else { 1 })],
            active: true,
            credential_epoch: 0,
            grants: Grants {
                admin: false,
                contracts: [101, 205]
                    .into_iter()
                    .map(|c| {
                        (
                            c,
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
    replace(&store, graph.clone());
    let requester = store.session(id(4), 0).unwrap();
    requester
        .mutate(&mutation(&requester, 100, json!([create_account(10, 12)])))
        .unwrap();
    let request = mutation(&requester, 101, json!([dispatch(20, 10)]));
    let result = requester.mutate(&request).unwrap();
    let execution = executions(&result)[0];
    let superior = store.session(id(3), 0).unwrap();
    assert!(
        superior
            .effect_status(&request.model, execution)
            .unwrap()
            .is_object()
    );
    let superior_cancel = cancellation(&superior, 102, execution);
    assert_eq!(
        superior.cancel_effect(&superior_cancel).unwrap_err().code,
        "forbidden"
    );
    let outsider = store.session(id(5), 0).unwrap();
    assert_eq!(
        outsider.effect_status(&request.model, execution).unwrap(),
        Value::Null
    );
    assert_eq!(
        outsider
            .cancel_effect(&cancellation(&outsider, 102, execution))
            .unwrap_err()
            .code,
        "forbidden"
    );
    graph
        .principals
        .iter_mut()
        .find(|p| p.id == id(4))
        .unwrap()
        .grants
        .contracts
        .get_mut(&101)
        .unwrap()
        .remove(&Action::Update);
    replace(&store, graph.clone());
    rejected(
        &requester,
        &mutation(&requester, 103, json!([dispatch(21, 10)])),
        "forbidden",
    );
    assert_eq!(
        requester
            .cancel_effect(&cancellation(&requester, 104, execution))
            .unwrap_err()
            .code,
        "forbidden"
    );
    let grants = graph
        .principals
        .iter_mut()
        .find(|p| p.id == id(4))
        .unwrap()
        .grants
        .contracts
        .get_mut(&101)
        .unwrap();
    grants.insert(Action::Update);
    grants.remove(&Action::Read);
    replace(&store, graph.clone());
    rejected(
        &requester,
        &mutation(&requester, 105, json!([dispatch(22, 10)])),
        "forbidden",
    );
    assert_eq!(
        requester.effect_status(&request.model, execution).unwrap(),
        Value::Null
    );
    assert!(
        requester.mutate(&request).unwrap()["result"]
            .get("executions")
            .is_none()
    );
    let cancel = cancellation(&requester, 106, execution);
    assert_eq!(
        requester.cancel_effect(&cancel).unwrap()["result"],
        Value::Null
    );
    assert_eq!(
        requester.cancel_effect(&cancel).unwrap()["result"],
        Value::Null
    );
    assert_eq!(
        requester
            .operation_status(&cancel.model, &cancel.context, cancel.operation_id)
            .unwrap()["result"],
        Value::Null
    );
    graph
        .principals
        .iter_mut()
        .find(|p| p.id == id(4))
        .unwrap()
        .grants
        .contracts
        .get_mut(&101)
        .unwrap()
        .insert(Action::Read);
    replace(&store, graph.clone());
    assert_eq!(
        requester.cancel_effect(&cancel).unwrap()["result"]["phase"],
        "cancelled"
    );
    let request2 = mutation(&requester, 107, json!([dispatch(23, 10)]));
    let execution2 = executions(&requester.mutate(&request2).unwrap())[0];
    store
        .cancel_effect(&cancellation(&store, 108, execution2))
        .unwrap();
    graph
        .principals
        .iter_mut()
        .find(|p| p.id == id(4))
        .unwrap()
        .credential_epoch = 1;
    replace(&store, graph);
    assert_eq!(
        requester
            .effect_status(&request.model, execution)
            .unwrap_err()
            .code,
        "forbidden"
    );
    assert_eq!(
        requester.cancel_effect(&cancel).unwrap_err().code,
        "forbidden"
    );
    store.check_integrity().unwrap();
}

#[test]
fn immutable_input_expiry_and_allocation_failures_leave_no_intent_or_receipt() {
    let dir = Directory::new();
    let store = dir.store();
    store
        .mutate(&mutation(&store, 100, json!([create_account(10, 12)])))
        .unwrap();
    for (n, at, end, units) in [
        (0, None, Some("0"), "3"),
        (1, Some(i64::MAX.to_string()), None, "3"),
        (2, None, None, "0"),
    ] {
        let mut command = dispatch(20, 10);
        command["fields"]["execute_at"] = json!(at);
        command["fields"]["not_after"] = json!(end);
        command["fields"]["units"] = json!(units);
        rejected(
            &store,
            &mutation(&store, 101 + n, json!([command])),
            "invalid_input",
        );
    }
    let result = store
        .mutate(&mutation(&store, 105, json!([dispatch(20, 10)])))
        .unwrap();
    rejected(
        &store,
        &mutation(
            &store,
            106,
            json!([update(&store, 20, json!({"units":"4"}))]),
        ),
        "invalid_input",
    );
    assert_eq!(
        store
            .effect_status(store.model().identity(), executions(&result)[0])
            .unwrap()["request"]["units"],
        "3"
    );
    let before = store.observe_for_verification().unwrap();
    let request = mutation(&store, 107, json!([dispatch(21, 10), dispatch(22, 10)]));
    assert_eq!(
        store
            .mutate_with_ids(&request, &mut || Ok(id(999)))
            .unwrap_err()
            .code,
        "allocation_collision"
    );
    assert_eq!(store.observe_for_verification().unwrap(), before);
    assert_eq!(
        store
            .mutate_with_ids(&request, &mut || Err(Error::new(
                "allocation_failed",
                "test allocation failed"
            )))
            .unwrap_err()
            .code,
        "allocation_failed"
    );
    assert_eq!(store.observe_for_verification().unwrap(), before);
    store.check_integrity().unwrap();
}

#[test]
fn corrupt_effect_inventory_rejects_complete_check_and_restore_without_publication() {
    let dir = Directory::new();
    let store = dir.store();
    store
        .mutate(&mutation(
            &store,
            100,
            json!([create_account(10, 12), dispatch(20, 10)]),
        ))
        .unwrap();
    let baseline = store.observe_for_verification().unwrap();
    let original = dir.0.join("source.redb");
    drop(store);
    for damage in 0..11 {
        let source = dir.0.join(format!("corrupt-{damage}.redb"));
        std::fs::copy(&original, &source).unwrap();
        let db = redb::Database::open(&source).unwrap();
        let write = db.begin_write().unwrap();
        let (name, remove, alter): (&str, bool, Option<(&str, Value)>) = match damage {
            0 => ("effect_due", true, None),
            1 => (
                "effect_executions",
                false,
                Some(("request_hash", json!("0".repeat(64)))),
            ),
            2 => (
                "effect_executions",
                false,
                Some(("action_version", json!("unknown-version"))),
            ),
            3 => ("effect_executions", false, Some(("target", json!(id(999))))),
            4 => (
                "effect_runtime",
                false,
                Some(("accounted_bytes", json!(4096))),
            ),
            5 => ("effect_runtime", false, Some(("next_class", json!(4)))),
            6 => ("effect_facts", false, None),
            7 => ("effect_inbox", false, None),
            8 => ("operations", false, Some(("kind", json!("cancel")))),
            9 => (
                "effect_executions",
                false,
                Some(("phase", json!("cancelled"))),
            ),
            _ => ("operations", false, None),
        };
        let definition = TableDefinition::<&[u8], &[u8]>::new(name);
        {
            let mut table = write.open_table(definition).unwrap();
            if name == "effect_facts" || name == "effect_inbox" {
                table
                    .insert(b"orphan".as_slice(), b"{}".as_slice())
                    .unwrap();
            } else {
                let row = &baseline["tables"][name][0];
                let key = local::unhex(row["key"].as_str().unwrap()).unwrap();
                if remove {
                    table.remove(key.as_slice()).unwrap();
                } else {
                    let mut value: Value = serde_json::from_slice(
                        &local::unhex(row["value"].as_str().unwrap()).unwrap(),
                    )
                    .unwrap();
                    if let Some((field, replacement)) = alter {
                        value[field] = replacement;
                    } else {
                        value["result"]["executions"] = json!([]);
                    }
                    let encoded = match name {
                        "effect_executions" => local::encode(
                            &serde_json::from_value::<effects::Execution<EffectDemo>>(value)
                                .unwrap(),
                        )
                        .unwrap(),
                        "effect_runtime" => local::encode(
                            &serde_json::from_value::<effects::Runtime>(value).unwrap(),
                        )
                        .unwrap(),
                        "operations" => local::encode(
                            &serde_json::from_value::<local::ReceiptValue<EffectDemo>>(value)
                                .unwrap(),
                        )
                        .unwrap(),
                        _ => unreachable!(),
                    };
                    table.insert(key.as_slice(), encoded.as_slice()).unwrap();
                }
            }
        }
        write.commit().unwrap();
        drop(db);
        let corrupt =
            Store::<EffectDemo>::open(&source, Arc::new(Prepared::load().unwrap())).unwrap();
        assert!(corrupt.check_integrity().is_err(), "damage {damage}");
        let payload = corrupt.observe_for_verification().unwrap();
        let corrupt = Arc::new(corrupt);
        let config = crate::server::ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            max_inflight: 2,
            request_timeout_seconds: 5,
            effects: None,
            identity: crate::identity::IdentityConfig {
                issuer: "effect-test".into(),
                audience: "effect-test".into(),
                max_token_seconds: 60,
                public_keys: std::collections::BTreeMap::from([(
                    "test".into(),
                    include_str!("../tests/fixtures/test-ed25519-public.pem").into(),
                )]),
            },
        };
        assert_eq!(
            crate::server::router(corrupt.clone(), &config)
                .err()
                .unwrap()
                .code,
            "corrupt_state",
            "startup damage {damage}"
        );
        drop(corrupt);
        let backup = dir.0.join(format!("corrupt-{damage}.json"));
        std::fs::write(&backup,local::encode(&json!({"format":"rebase-backup-1","sha256":native_codec::hex(&Sha256::digest(local::encode(&payload).unwrap())),"payload":payload})).unwrap()).unwrap();
        let destination = dir.0.join(format!("rejected-{damage}.redb"));
        assert!(
            lifecycle::restore(
                &backup,
                &destination,
                Arc::new(Prepared::<EffectDemo>::load().unwrap())
            )
            .is_err(),
            "damage {damage}"
        );
        assert!(!destination.exists());
    }
}

#[test]
fn action_metadata_is_checked_and_advertised_only_for_effect_models() {
    let model = Prepared::<EffectDemo>::load().unwrap();
    let catalog = model.public_catalog();
    assert_eq!(catalog["api"], "rebase-local-api-3");
    assert_eq!(
        catalog["capabilities"]["effects"]["limits"]["unresolved"],
        64
    );
    assert!(
        catalog["capabilities"]["methods"]
            .as_array()
            .unwrap()
            .contains(&json!("effects.cancel"))
    );
    let mut declarations = EffectDemo::declarations().unwrap();
    declarations
        .iter_mut()
        .find(|c| c.code == 205)
        .unwrap()
        .fields[0]
        .mutable = true;
    assert_eq!(
        Prepared::<EffectDemo>::prepare(declarations)
            .err()
            .unwrap()
            .code,
        "model"
    );
    let mut declarations = EffectDemo::declarations().unwrap();
    declarations
        .iter_mut()
        .find(|c| c.code == 205)
        .unwrap()
        .references[0]
        .optional = true;
    assert!(Prepared::<EffectDemo>::prepare(declarations).is_err());
    let unrelated = crate::model::PreparedModel::load()
        .unwrap()
        .public_catalog();
    assert!(unrelated["capabilities"].get("effects").is_none());
    assert!(
        !unrelated["capabilities"]["methods"]
            .as_array()
            .unwrap()
            .contains(&json!("effects.cancel"))
    );
    assert_eq!(effects::MAX_RETAINED, 256);
}
