use rebase_semantic_proof::{
    fixtures, lifecycle,
    local::{LocalStore, Mutation},
    model::PreparedModel,
    native_slice::Context,
    query::{RootRead, RootRequest},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};
use uuid::Uuid;
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/lifecycle-tests")
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
fn seed(store: &LocalStore) {
    let fixture: Value =
        serde_json::from_str(include_str!("../research/fixtures/causal-slice.json")).unwrap();
    let request:Mutation=serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":id(100),"commands":fixture["bases"]["baseline"],"returning":[]})).unwrap();
    store.mutate(&request).unwrap();
}
#[test]
fn verified_backup_restore_and_reset_preserve_or_atomically_replace_complete_state() {
    let dir = Directory::new();
    let model = Arc::new(PreparedModel::load().unwrap());
    let store = LocalStore::create_secured(
        dir.0.join("source.redb"),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    seed(&store);
    assert_eq!(store.check_integrity().unwrap()["status"], "valid");
    let before = store.observe_for_verification().unwrap();
    let backup = dir.0.join("backup.json");
    store.backup(&backup).unwrap();
    assert!(store.backup(&backup).is_err());
    let path = dir.0.join("restored.redb");
    lifecycle::restore(&backup, &path, model.clone()).unwrap();
    assert!(lifecycle::restore(&backup, &path, model.clone()).is_err());
    let restored = LocalStore::open(&path, model.clone()).unwrap();
    assert_eq!(restored.observe_for_verification().unwrap(), before);
    drop(restored);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(store.reset(id(999)).is_err());
    assert_eq!(store.observe_for_verification().unwrap(), before);
    let old_store =
        Uuid::parse_str(store.check_integrity().unwrap()["store"].as_str().unwrap()).unwrap();
    let result = store.reset(old_store).unwrap();
    assert_ne!(result["store"], old_store.to_string());
    assert_eq!(store.check_integrity().unwrap()["records"], 0);
    assert_eq!(
        store
            .session(id(2), 0)
            .unwrap()
            .get(model.identity(), id(10))
            .unwrap_err()
            .code,
        "forbidden"
    );
    assert!(
        store
            .session(id(2), 1)
            .unwrap()
            .get(model.identity(), id(10))
            .unwrap()
            .is_none()
    );
    seed(&store);
    store.check_integrity().unwrap();
    drop(store);
    let reopened = LocalStore::open(dir.0.join("source.redb"), model).unwrap();
    reopened.check_integrity().unwrap();
}
#[test]
fn damaged_or_incomplete_backups_never_publish_a_destination() {
    let dir = Directory::new();
    let model = Arc::new(PreparedModel::load().unwrap());
    let store = LocalStore::create_secured(
        dir.0.join("source.redb"),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    seed(&store);
    let backup = dir.0.join("backup.json");
    store.backup(&backup).unwrap();
    let original: Value = serde_json::from_slice(&std::fs::read(&backup).unwrap()).unwrap();
    for damage in 0..4 {
        let mut bad = original.clone();
        match damage {
            0 => bad["sha256"] = json!("0".repeat(64)),
            1 => bad["payload"]["tables"]["reader_records"] = json!([]),
            2 => bad["payload"]["complete"] = json!(false),
            _ => {
                let rows = bad["payload"]["tables"]["native_kv"]
                    .as_array_mut()
                    .unwrap();
                rows.push(rows[0].clone());
            }
        }
        if damage != 0 {
            bad["sha256"] = json!(format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&bad["payload"]).unwrap())
            ));
        }
        let source = dir.0.join(format!("bad-{damage}.json"));
        std::fs::write(&source, serde_json::to_vec(&bad).unwrap()).unwrap();
        let destination = dir.0.join(format!("rejected-{damage}.redb"));
        assert!(
            lifecycle::restore(&source, &destination, model.clone()).is_err(),
            "damage {damage}"
        );
        assert!(!destination.exists());
    }
    assert!(!std::fs::read_dir(&dir.0).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_str()
            .unwrap()
            .starts_with(".rebase-")
    }));
}

#[test]
fn archived_receipts_fence_old_uncertain_requests_and_remain_reconcilable() {
    let dir = Directory::new();
    let model = Arc::new(PreparedModel::load().unwrap());
    let store = LocalStore::create_secured(
        dir.0.join("store.redb"),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let context = store.operation_context(model.identity()).unwrap();
    let request:Mutation=serde_json::from_value(json!({"model":model.identity(),"context":context,"operation_id":id(100),"commands":[{"op":"create","id":id(10),"contract":7,"fields":{"at":"0"}}],"returning":[id(10)]})).unwrap();
    let original = store.mutate(&request).unwrap();
    let archive = dir.0.join("archive.json");
    let before = store.check_integrity().unwrap();
    store.archive_receipts(&archive).unwrap();
    let after = store.check_integrity().unwrap();
    assert_eq!(before["revision"], after["revision"]);
    assert_eq!(after["receipts"], 0);
    let snapshot = store.observe_for_verification().unwrap();
    assert_eq!(
        store.mutate(&request).unwrap_err().code,
        "operation_expired"
    );
    assert_eq!(
        store
            .operation_status(model.identity(), &context, id(100))
            .unwrap_err()
            .code,
        "operation_expired"
    );
    assert_eq!(store.observe_for_verification().unwrap(), snapshot);
    assert_ne!(store.operation_context(model.identity()).unwrap(), context);
    lifecycle::restore(&archive, dir.0.join("archive.redb"), model.clone()).unwrap();
    let archived = LocalStore::open(dir.0.join("archive.redb"), model.clone()).unwrap();
    assert_eq!(
        archived
            .operation_status(model.identity(), &context, id(100))
            .unwrap()["result"],
        original["result"]
    );
    let mut fresh = request.clone();
    fresh.context = store.operation_context(model.identity()).unwrap();
    fresh.operation_id = id(101);
    fresh.commands = serde_json::from_value(
        json!([{"op":"create","id":id(11),"contract":7,"fields":{"at":"1"}}]),
    )
    .unwrap();
    fresh.returning.clear();
    store.mutate(&fresh).unwrap();
    store.check_integrity().unwrap();
}

#[test]
fn mixed_causal_and_exchange_state_is_valid_across_rate_edits_restore_and_startup() {
    let dir = Directory::new();
    let model = Arc::new(PreparedModel::load().unwrap());
    let store = LocalStore::create_secured(
        dir.0.join("mixed.redb"),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let draft = fixtures::plan(&model, "causal-diamond", id(500)).unwrap();
    let mut commands = draft["commands"].as_array().unwrap().clone();
    commands.extend(json!([
        {"op":"create","id":id(1000),"contract":1,"fields":{"c":"2"}},
        {"op":"create","id":id(1001),"contract":2,"fields":{"native_unit":1,"reporting_unit":2}},
        {"op":"create","id":id(1002),"contract":4,"fields":{"native_unit":1}},
        {"op":"create","id":id(1003),"contract":5,"fields":{"reporting_unit":2}},
        {"op":"create","id":id(1004),"contract":3,"fields":{"curve":id(1001),"at":"0","rate":"3"}},
        {"op":"create","id":id(1005),"contract":3,"fields":{"curve":id(1001),"at":"10","rate":"4"}},
        {"op":"create","id":id(1006),"contract":6,"fields":{"units":"5","at":"5","rule":id(1000),"curve":id(1001),"account":id(1002),"subsidiary":id(1003)}},
        {"op":"create","id":id(1007),"contract":6,"fields":{"units":"3","at":"15","rule":id(1000),"curve":id(1001),"account":id(1002),"subsidiary":id(1003)}}
    ]).as_array().unwrap().clone());
    let contracts: std::collections::BTreeSet<_> = commands
        .iter()
        .map(|c| c["contract"].as_u64().unwrap())
        .collect();
    assert_eq!(contracts, (1..=10).collect());
    let request:Mutation=serde_json::from_value(json!({"model":model.identity(),"context":store.operation_context(model.identity()).unwrap(),"operation_id":id(600),"commands":commands,"returning":[]})).unwrap();
    store.mutate(&request).unwrap();
    // In the old checker, this valid committed state failed with "extra node":
    // quote memberships occupy slot 3, independently of the curve root slot 1.
    assert_eq!(store.check_integrity().unwrap()["records"], 27);
    let total = |store: &LocalStore, owner, slot| {
        store
            .root_read(&RootRequest {
                model: model.identity().into(),
                owner,
                slot,
                read: RootRead::Summary,
            })
            .unwrap()["value"]["sum"]
            .clone()
    };
    assert_eq!(total(&store, id(1002), 2), "16");
    assert_eq!(total(&store, id(1003), 3), "54");
    let early = store.get(model.identity(), id(1006)).unwrap().unwrap();
    let later = store.get(model.identity(), id(1007)).unwrap().unwrap();
    let version = store
        .get(model.identity(), id(1004))
        .unwrap()
        .unwrap()
        .version;
    let update:Mutation=serde_json::from_value(json!({"model":model.identity(),"context":store.operation_context(model.identity()).unwrap(),"operation_id":id(601),"commands":[{"op":"update","id":id(1004),"if_version":version.to_string(),"set":{"rate":"5"},"unset":[]}],"returning":[]})).unwrap();
    store.mutate(&update).unwrap();
    store.check_integrity().unwrap();
    assert_eq!(total(&store, id(1003), 3), "74");
    assert!(
        store
            .get(model.identity(), early.id)
            .unwrap()
            .unwrap()
            .version
            > early.version
    );
    assert_eq!(
        store
            .get(model.identity(), later.id)
            .unwrap()
            .unwrap()
            .version,
        later.version
    );
    let complete = store.observe_for_verification().unwrap();
    let backup = dir.0.join("mixed.json");
    store.backup(&backup).unwrap();
    lifecycle::restore(&backup, dir.0.join("restored.redb"), model.clone()).unwrap();
    let restored = Arc::new(LocalStore::open(dir.0.join("restored.redb"), model.clone()).unwrap());
    assert_eq!(restored.observe_for_verification().unwrap(), complete);
    let config = rebase_semantic_proof::server::ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        max_inflight: 1,
        request_timeout_seconds: 5,
        effects: None,
        identity: rebase_semantic_proof::identity::IdentityConfig {
            issuer: "https://review.example.test".into(),
            audience: "review".into(),
            max_token_seconds: 60,
            public_keys: std::collections::BTreeMap::from([(
                "test".into(),
                include_str!("fixtures/test-ed25519-public.pem").into(),
            )]),
        },
    };
    assert!(rebase_semantic_proof::server::router(restored, &config).is_ok());
}
