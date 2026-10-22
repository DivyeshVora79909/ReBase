use rebase_semantic_proof::{
    lifecycle,
    local::{LocalStore, Mutation},
    model::PreparedModel,
    native_slice::Context,
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
