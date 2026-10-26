//! Standalone production serving has no Node/Python or legacy command parser.
use rebase_semantic_proof::{
    binding::{Binding, Calculation},
    identity::{self, IdentityConfig, TokenRequest},
    local::Store,
    model::Prepared,
    native_slice::Context,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};
use uuid::Uuid;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("rebase-bootstrap-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Process {
    child: Child,
    address: SocketAddr,
}
impl Process {
    fn start(configuration: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rebase-next"))
            .arg("serve")
            .arg(configuration)
            .env("PATH", "")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = 0;
            for line in BufReader::new(stderr).lines() {
                let line = line.unwrap();
                bytes += line.len();
                if bytes > 65_536 {
                    break;
                }
                let _ = send.send(line);
            }
        });
        // Own the child before waiting so every failed startup assertion kills it.
        let mut process = Self {
            child,
            address: "127.0.0.1:0".parse().unwrap(),
        };
        let line = receive
            .recv_timeout(Duration::from_secs(10))
            .expect("bounded standalone startup log");
        process.address = line
            .strip_prefix("ReBase Next listening on ")
            .and_then(|text| text.split_whitespace().next())
            .unwrap_or_else(|| panic!("standalone startup failed: {line}"))
            .parse()
            .unwrap();
        process
    }
    #[cfg(unix)]
    fn stop(mut self) {
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "bounded standalone shutdown");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(std::net::TcpStream::connect(self.address).is_err());
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn identity() -> IdentityConfig {
    serde_json::from_value(json!({"issuer":"bootstrap-test","audience":"bootstrap-test",
        "public_keys":{"test":include_str!("fixtures/test-ed25519-public.pem")},"max_token_seconds":300})).unwrap()
}
fn configuration(model: &str, path: &Path, store: &Value) -> Value {
    json!({"format":"rebase-service-1","model":model,"backend":{"kind":"redb","cluster_file":null},
        "target":{"mode":"open","path":path,"expect_store":store},
        "service":{"listen":"127.0.0.1:0","identity":identity(),"max_inflight":2,"request_timeout_seconds":5,"effects":null}})
}
fn token() -> String {
    identity::issue(
        &identity(),
        &TokenRequest {
            tenant: Uuid::from_u128(1),
            actor: Uuid::from_u128(2),
            epoch: 0,
            ttl: 300,
            key_id: "test".into(),
        },
        include_bytes!("fixtures/test-ed25519-private.pem"),
    )
    .unwrap()
}
fn rpc(address: SocketAddr, token: &str, method: &str, params: Value) -> Value {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            reqwest::Client::new()
                .post(format!("http://{address}/rpc"))
                .bearer_auth(token)
                .json(&json!({"jsonrpc":"2.0","id":"bootstrap","method":method,"params":params}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap()
        })
}

#[cfg(unix)]
fn model_workflow<B: Binding>(selector: &str) {
    let dir = Directory::new();
    let path = dir.0.join("store.redb");
    let model = Arc::new(Prepared::<B>::load().unwrap());
    let catalog = model.public_catalog();
    let store = Store::<B>::create_secured(
        &path,
        model.clone(),
        Context {
            tenant: Uuid::from_u128(1),
            actor: Uuid::from_u128(2),
        },
    )
    .unwrap();
    let store_id = store.inspect().unwrap()["store"].clone();
    let fixtures = B::fixture_catalog();
    let fixture = B::fixture_plan(
        &model,
        fixtures[0]["name"].as_str().unwrap(),
        Uuid::new_v4(),
    )
    .unwrap();
    drop(store);
    let config_path = dir.0.join("service.json");
    fs::write(
        &config_path,
        serde_json::to_vec(&configuration(selector, &path, &store_id)).unwrap(),
    )
    .unwrap();
    let process = Process::start(&config_path);
    let token = token();
    assert_eq!(
        rpc(process.address, &token, "model.describe", json!({}))["result"],
        catalog
    );
    let session = rpc(process.address, &token, "session.describe", json!({}))["result"].clone();
    assert_eq!(session["store"], store_id);
    let request = json!({"model":model.identity(),"context":session["operation_context"],"operation_id":Uuid::new_v4(),
        "commands":fixture["commands"],"returning":fixture["returning"]});
    let receipt = rpc(process.address, &token, "records.mutate", request.clone());
    assert_eq!(receipt["result"]["status"], "committed", "{receipt}");
    assert_eq!(
        rpc(process.address, &token, "store.inspect", json!({}))["error"]["data"]["kind"],
        "method_not_found"
    );
    process.stop();
    let reopened = Store::<B>::open(&path, model.clone()).unwrap();
    reopened.check_integrity().unwrap();
    drop(reopened);
    let process = Process::start(&config_path);
    let replay = rpc(process.address, &token, "records.mutate", request);
    assert_eq!(replay["result"]["replayed"], true);
    assert_eq!(replay["result"]["result"], receipt["result"]["result"]);
    process.stop();
}

#[cfg(unix)]
#[test]
fn standalone_rust_serves_all_six_catalogs_sources_and_original_receipts_without_tooling_on_path() {
    model_workflow::<Calculation>("calculation");
    model_workflow::<rebase_semantic_proof::models::equipment::Equipment>("equipment");
    model_workflow::<rebase_semantic_proof::models::invoicing::Invoicing>("invoicing");
    model_workflow::<rebase_semantic_proof::models::measurement::Measurement>("measurement");
    model_workflow::<rebase_semantic_proof::models::effect_demo::EffectDemo>("effect-demo");
    model_workflow::<rebase_semantic_proof::models::quantity::Quantity>("quantity");
}

#[test]
fn malformed_configuration_and_wrong_store_fail_without_changing_or_creating_stores() {
    let dir = Directory::new();
    let path = dir.0.join("store.redb");
    let store = Store::<Calculation>::create_secured(
        &path,
        Arc::new(Prepared::load().unwrap()),
        Context {
            tenant: Uuid::from_u128(1),
            actor: Uuid::from_u128(2),
        },
    )
    .unwrap();
    let id = store.inspect().unwrap()["store"].clone();
    drop(store);
    let valid = configuration("calculation", &path, &id);
    let before = fs::read(&path).unwrap();
    let config_path = dir.0.join("bad.json");
    let mut cases = Vec::new();
    let mut wrong = valid.clone();
    wrong["target"]["expect_store"] = json!(Uuid::new_v4());
    cases.push((wrong, "wrong_target"));
    let mut extra = valid.clone();
    extra["extra"] = json!(true);
    cases.push((extra, "invalid_config"));
    let mut create = valid.clone();
    create["target"] = json!({"mode":"create","path":dir.0.join("must-not-exist"),"tenant":Uuid::from_u128(1),"actor":Uuid::from_u128(2)});
    cases.push((create, "invalid_config"));
    let mut recover = valid.clone();
    recover["target"]["mode"] = json!("recover");
    cases.push((recover, "invalid_config"));
    let mut invalid = valid.clone();
    invalid["service"]["max_inflight"] = json!(0);
    invalid["target"]["path"] = json!(dir.0.join("must-not-exist"));
    cases.push((invalid, "invalid_input"));
    let mut invalid = valid.clone();
    invalid["service"]["identity"]["public_keys"]["test"] = json!("bad PEM");
    cases.push((invalid, "invalid_input"));
    let mut invalid = valid.clone();
    invalid["target"]["namespace"] = json!("alias");
    cases.push((invalid, "invalid_config"));
    for (value, kind) in cases {
        fs::write(&config_path, serde_json::to_vec(&value).unwrap()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_rebase-next"))
            .arg("serve")
            .arg(&config_path)
            .env("PATH", "")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(kind),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(!dir.0.join("must-not-exist").exists());
    }
    for bytes in [
        b"{\"format\":\"a\",\"format\":\"b\"}".to_vec(),
        vec![b' '; rebase_semantic_proof::json::MAX_REQUEST_BYTES + 1],
    ] {
        fs::write(&config_path, bytes).unwrap();
        assert!(
            !Command::new(env!("CARGO_BIN_EXE_rebase-next"))
                .arg("serve")
                .arg(&config_path)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    for args in [
        vec!["model", "public"],
        vec!["serve", "relative.json"],
        vec!["serve"],
        vec!["--model", "calculation", "check", "store"],
    ] {
        assert!(
            !Command::new(env!("CARGO_BIN_EXE_rebase-next"))
                .args(args)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
}
