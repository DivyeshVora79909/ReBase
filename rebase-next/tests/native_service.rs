use rebase_semantic_proof::host::{Host, PROTOCOL};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};
use uuid::Uuid;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/native-service-tests")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn call(host: &mut Host, method: &str, params: Value) -> Value {
    host.handle(
        &serde_json::to_vec(
            &json!({"protocol":PROTOCOL,"id":"test","method":method,"params":params}),
        )
        .unwrap(),
    )
}
fn ok(reply: Value) -> Value {
    assert!(reply.get("error").is_none(), "{reply}");
    reply["result"].clone()
}
fn identity() -> Value {
    json!({"issuer":"n2-test","audience":"n2-native","public_keys":{"test":include_str!("fixtures/test-ed25519-public.pem")},"max_token_seconds":600})
}
fn config() -> Value {
    json!({"listen":"127.0.0.1:0","identity":identity(),"max_inflight":2,"request_timeout_seconds":1,"effects":null})
}
fn create(host: &mut Host, path: &PathBuf) -> Value {
    let result = ok(call(
        host,
        "host.configure",
        json!({"model":"calculation","backend":{"kind":"redb","cluster_file":null},"target":{"mode":"create","path":path,"tenant":"11111111-1111-4111-8111-111111111111","actor":"22222222-2222-4222-8222-222222222222"},"operator_methods":["store.inspect","store.check","service.start","service.stop","identity.issue","store.backup","store.restore","store.archive","store.reset"]}),
    ));
    json!({"model":result["model"],"store":result["target"]["store"]})
}
fn issue(host: &mut Host, scope: &Value, epoch: u64) -> Value {
    call(
        host,
        "identity.issue",
        json!({"scope":scope,"identity":identity(),"request":{"tenant":"11111111-1111-4111-8111-111111111111","actor":"22222222-2222-4222-8222-222222222222","epoch":epoch,"ttl":300,"key_id":"test"},"private_key_pem":include_str!("fixtures/test-ed25519-private.pem")}),
    )
}
fn rpc(
    runtime: &tokio::runtime::Runtime,
    endpoint: &str,
    token: &str,
    method: &str,
    params: Value,
) -> Value {
    runtime.block_on(async {
        reqwest::Client::new()
            .post(endpoint)
            .bearer_auth(token)
            .json(&json!({"jsonrpc":"2.0","id":"public","method":method,"params":params}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    })
}

#[test]
fn owned_http_identity_mutation_inspection_and_lifecycle_preserve_fences() {
    let directory = Directory::new();
    let mut host = Host::default();
    let scope = create(&mut host, &directory.0.join("source.redb"));
    let token = ok(issue(&mut host, &scope, 0))["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(issue(&mut host, &scope, 1)["error"]["kind"], "forbidden");
    let started = ok(call(
        &mut host,
        "service.start",
        json!({"scope":scope,"config":config()}),
    ));
    let endpoint = started["endpoint"].as_str().unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let session = rpc(&runtime, endpoint, &token, "session.describe", json!({}))["result"].clone();
    assert_eq!(session["store"], scope["store"]);
    let fixture: Value =
        serde_json::from_str(include_str!("../research/fixtures/causal-slice.json")).unwrap();
    let mutation = json!({"model":scope["model"],"context":session["operation_context"],"operation_id":Uuid::new_v4(),"commands":fixture["bases"]["baseline"],"returning":[]});
    let committed = rpc(
        &runtime,
        endpoint,
        &token,
        "records.mutate",
        mutation.clone(),
    );
    assert!(committed.get("result").is_some(), "{committed}");
    let replay = rpc(
        &runtime,
        endpoint,
        &token,
        "records.mutate",
        mutation.clone(),
    );
    assert_eq!(committed["result"]["result"], replay["result"]["result"]);
    assert_eq!(replay["result"]["replayed"], true);
    assert_eq!(
        rpc(
            &runtime,
            endpoint,
            &token,
            "store.inspect",
            json!({"scope":scope})
        )["error"]["data"]["kind"],
        "method_not_found"
    );
    let inspected = ok(call(&mut host, "store.inspect", json!({"scope":scope})));
    assert!(!inspected["records"].as_array().unwrap().is_empty());
    let html = ok(call(
        &mut host,
        "model.render",
        json!({"scope":"store","target":scope}),
    ));
    assert!(html["html"].as_str().unwrap().contains("Settled snapshot"));
    let backup = directory.0.join("live-backup.json");
    ok(call(
        &mut host,
        "store.backup",
        json!({"scope":scope,"destination":backup}),
    ));
    let archive = directory.0.join("archive.json");
    assert_eq!(
        call(
            &mut host,
            "store.archive",
            json!({"scope":scope,"destination":archive})
        )["error"]["kind"],
        "service_running"
    );
    assert!(!archive.exists());
    assert_eq!(
        call(
            &mut host,
            "service.stop",
            json!({"scope":scope,"service":Uuid::new_v4()})
        )["error"]["kind"],
        "wrong_target"
    );
    ok(call(
        &mut host,
        "service.stop",
        json!({"scope":scope,"service":started["service"]}),
    ));
    assert!(std::net::TcpStream::connect(started["address"].as_str().unwrap()).is_err());
    ok(call(
        &mut host,
        "store.archive",
        json!({"scope":scope,"destination":archive}),
    ));
    let restarted = ok(call(
        &mut host,
        "service.start",
        json!({"scope":scope,"config":config()}),
    ));
    let next_endpoint = restarted["endpoint"].as_str().unwrap();
    assert_ne!(
        rpc(
            &runtime,
            next_endpoint,
            &token,
            "session.describe",
            json!({})
        )["result"]["operation_context"],
        mutation["context"]
    );
    assert_eq!(
        rpc(
            &runtime,
            next_endpoint,
            &token,
            "records.mutate",
            mutation.clone()
        )["error"]["data"]["kind"],
        "operation_expired"
    );
    ok(call(
        &mut host,
        "service.stop",
        json!({"scope":scope,"service":restarted["service"]}),
    ));
    let bad_destination = directory.0.join("must-not-exist.redb");
    let wrong_backup = call(
        &mut host,
        "store.restore",
        json!({"scope":scope,"backup":archive,"expect_backup_store":Uuid::new_v4(),"destination":{"backend":{"kind":"redb","cluster_file":null},"target":{"path":bad_destination}}}),
    );
    assert_eq!(wrong_backup["error"]["kind"], "wrong_target");
    assert!(!bad_destination.exists());
    let restored = directory.0.join("restored.redb");
    let restore = json!({"scope":scope,"backup":archive,"expect_backup_store":scope["store"],"destination":{"backend":{"kind":"redb","cluster_file":null},"target":{"path":restored}}});
    let result = ok(call(&mut host, "store.restore", restore.clone()));
    assert_eq!(result["status"], "restored");
    assert_eq!(
        call(&mut host, "store.restore", restore)["error"]["kind"],
        "invalid_destination"
    );
    let model = std::sync::Arc::new(rebase_semantic_proof::model::PreparedModel::load().unwrap());
    let clone = rebase_semantic_proof::local::LocalStore::open(&restored, model).unwrap();
    assert_eq!(
        clone
            .operation_status(
                scope["model"].as_str().unwrap(),
                mutation["context"].as_str().unwrap(),
                Uuid::parse_str(mutation["operation_id"].as_str().unwrap()).unwrap()
            )
            .unwrap()["status"],
        "committed"
    );
    drop(clone);
    let reset = ok(call(
        &mut host,
        "store.reset",
        json!({"scope":scope,"expect_store":scope["store"]}),
    ));
    assert_ne!(reset["store"], scope["store"]);
    assert_eq!(
        call(&mut host, "store.inspect", json!({"scope":scope}))["error"]["kind"],
        "wrong_target"
    );
    let new_scope = json!({"model":scope["model"],"store":reset["store"]});
    assert_eq!(
        issue(&mut host, &new_scope, 0)["error"]["kind"],
        "forbidden"
    );
    ok(issue(&mut host, &new_scope, 1));
    ok(call(&mut host, "host.close", json!({})));
}

#[test]
fn model_and_fixture_calls_reuse_native_values_without_store_creation() {
    let directory = Directory::new();
    let mut host = Host::default();
    ok(call(
        &mut host,
        "host.configure",
        json!({"model":"calculation","backend":{"kind":"redb","cluster_file":null},"target":null,"operator_methods":[]}),
    ));
    let explanation = ok(call(&mut host, "model.explain", json!({"selector":"7"})));
    assert_eq!(explanation["contract"]["code"], 7);
    assert_eq!(
        ok(call(
            &mut host,
            "model.validate",
            json!({"code":7,"input":{"at":"9007199254740993"}})
        ))["input"]["at"],
        "9007199254740993"
    );
    assert!(
        call(
            &mut host,
            "model.validate",
            json!({"code":7,"input":{"at":9007199254740993_u64}})
        )
        .get("error")
        .is_some()
    );
    assert!(
        ok(call(&mut host, "model.render", json!({"scope":"model"})))["html"]
            .as_str()
            .unwrap()
            .contains("Offline model")
    );
    let fixtures = ok(call(&mut host, "fixture.catalog", json!({})));
    assert!(fixtures.is_array());
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
}

#[test]
fn wrong_scopes_and_invalid_service_config_leave_the_owner_unchanged() {
    let directory = Directory::new();
    let mut host = Host::default();
    let scope = create(&mut host, &directory.0.join("source.redb"));
    let before = ok(call(&mut host, "store.inspect", json!({"scope":scope})));
    let wrong = json!({"model":scope["model"],"store":Uuid::new_v4()});
    let destination = directory.0.join("must-not-exist.json");
    for (method, params) in [
        (
            "store.backup",
            json!({"scope":wrong,"destination":destination}),
        ),
        (
            "store.archive",
            json!({"scope":wrong,"destination":destination}),
        ),
        (
            "store.reset",
            json!({"scope":wrong,"expect_store":scope["store"]}),
        ),
        (
            "store.restore",
            json!({"scope":wrong,"backup":destination,"expect_backup_store":scope["store"],"destination":{"backend":{"kind":"redb","cluster_file":null},"target":{"path":destination}}}),
        ),
        ("service.start", json!({"scope":wrong,"config":config()})),
        (
            "identity.issue",
            json!({"scope":wrong,"identity":identity(),"request":{"tenant":"11111111-1111-4111-8111-111111111111","actor":"22222222-2222-4222-8222-222222222222","epoch":0,"ttl":300,"key_id":"test"},"private_key_pem":include_str!("fixtures/test-ed25519-private.pem")}),
        ),
    ] {
        assert_eq!(
            call(&mut host, method, params)["error"]["kind"],
            "wrong_target",
            "{method}"
        );
    }
    assert!(!destination.exists());
    let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = bound.local_addr().unwrap();
    drop(bound);
    let mut invalid = config();
    invalid["listen"] = json!(address.to_string());
    invalid["identity"]["public_keys"]["test"] = json!("invalid public key");
    assert!(
        call(
            &mut host,
            "service.start",
            json!({"scope":scope,"config":invalid})
        )
        .get("error")
        .is_some()
    );
    assert!(std::net::TcpListener::bind(address).is_ok());
    assert_eq!(
        ok(call(&mut host, "store.inspect", json!({"scope":scope}))),
        before
    );
    // A failed start must not leave an owned service registered.
    let started = ok(call(
        &mut host,
        "service.start",
        json!({"scope":scope,"config":config()}),
    ));
    ok(call(
        &mut host,
        "service.stop",
        json!({"scope":scope,"service":started["service"]}),
    ));
}

#[test]
fn denied_operator_methods_reject_before_parsing_or_destination_disclosure() {
    let directory = Directory::new();
    let path = directory.0.join("source.redb");
    let mut host = Host::default();
    let mut configuration = json!({"model":"calculation","backend":{"kind":"redb","cluster_file":null},"target":{"mode":"create","path":path,"tenant":"11111111-1111-4111-8111-111111111111","actor":"22222222-2222-4222-8222-222222222222"},"operator_methods":[]});
    ok(call(&mut host, "host.configure", configuration.take()));
    for method in [
        "service.start",
        "service.stop",
        "identity.issue",
        "store.backup",
        "store.restore",
        "store.archive",
        "store.reset",
    ] {
        assert_eq!(
            call(&mut host, method, json!({"unknown":"private"}))["error"]["kind"],
            "forbidden",
            "{method}"
        );
    }
    assert_eq!(
        call(
            &mut host,
            "model.render",
            json!({"scope":"store","target":{"unknown":true}})
        )["error"]["kind"],
        "forbidden"
    );
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
}
