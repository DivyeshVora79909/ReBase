use rebase_semantic_proof::{
    binding::Calculation,
    host::{self, Host},
    model::Prepared,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};
use uuid::Uuid;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/native-host-tests")
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
struct Process {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
}
impl Process {
    fn new() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rebase-next"))
            .arg("host")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            input,
            output,
        }
    }
    fn write(&mut self, bytes: &[u8]) {
        self.input.as_mut().unwrap().write_all(bytes).unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
    }
    fn read(&mut self) -> Value {
        let mut line = Vec::new();
        assert!(
            self.output.read_until(b'\n', &mut line).unwrap() > 0,
            "child omitted reply"
        );
        assert_eq!(line.last(), Some(&b'\n'));
        assert!(line.len() <= host::MAX_RESPONSE_BYTES + 1);
        serde_json::from_slice(&line).unwrap()
    }
    fn call(&mut self, id: &str, method: &str, params: Value) -> Value {
        let mut bytes = serde_json::to_vec(&request(id, method, params)).unwrap();
        bytes.push(b'\n');
        self.write(&bytes);
        self.read()
    }
    fn finish(&mut self) {
        self.input.take();
        assert!(self.child.wait().unwrap().success());
        let mut rest = vec![];
        self.output.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "non-protocol stdout: {rest:?}");
        let mut diagnostic = String::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut diagnostic)
            .unwrap();
        assert!(diagnostic.is_empty(), "unexpected diagnostic: {diagnostic}");
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn request(id: &str, method: &str, params: Value) -> Value {
    json!({"protocol":host::PROTOCOL,"id":id,"method":method,"params":params})
}
fn config(model: &str, target: Value, grants: Value) -> Value {
    json!({"model":model,"backend":{"kind":"redb","cluster_file":null},"target":target,"operator_methods":grants})
}
fn created(path: &PathBuf) -> Value {
    json!({"mode":"create","path":path,"tenant":"11111111-1111-4111-8111-111111111111","actor":"22222222-2222-4222-8222-222222222222"})
}
fn kind(reply: &Value) -> Option<&str> {
    reply["error"]["kind"].as_str()
}
fn digest(path: &PathBuf) -> Vec<u8> {
    Sha256::digest(fs::read(path).unwrap()).to_vec()
}

#[test]
fn frozen_sessions_run_against_real_process_and_authoritative_catalogs() {
    let fixture: Value =
        serde_json::from_str(include_str!("../research/fixtures/n0-native-protocol.json")).unwrap();
    let model = Prepared::<Calculation>::load().unwrap();
    for session in fixture["sessions"].as_array().unwrap() {
        let mut process = Process::new();
        for exchange in session["exchanges"].as_array().unwrap() {
            let mut bytes = serde_json::to_vec(&exchange["request"]).unwrap();
            bytes.push(b'\n');
            process.write(&bytes);
            let reply = process.read();
            if let Some(expected) = exchange.get("response") {
                assert_eq!(&reply, expected, "{}", session["name"]);
            } else {
                let expected = match exchange["request"]["params"]["scope"].as_str().unwrap() {
                    "public" => model.public_catalog(),
                    "developer" => model.developer_catalog(),
                    _ => unreachable!(),
                };
                assert_eq!(reply["result"], expected);
            }
        }
        process.finish();
    }
}

#[test]
fn frozen_malformed_frames_reject_and_oversize_resumes() {
    let fixture: Value =
        serde_json::from_str(include_str!("../research/fixtures/n0-native-protocol.json")).unwrap();
    for case in fixture["malformed_frames"].as_array().unwrap() {
        let mut process = Process::new();
        let bytes = if let Some(text) = case["raw_utf8"].as_str() {
            text.as_bytes().to_vec()
        } else if let Some(hex) = case["raw_hex"].as_str() {
            hex.as_bytes()
                .chunks(2)
                .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                .collect()
        } else {
            let generator = &case["generator"];
            let text = generator["prefix"]
                .as_str()
                .unwrap()
                .repeat(generator["repeat"].as_u64().unwrap() as usize)
                + generator["suffix"].as_str().unwrap();
            text.into_bytes()
        };
        process.write(&bytes);
        if case["eof"] == true {
            process.input.take();
        }
        if let Some(expected) = case.get("responses") {
            for expected in expected.as_array().unwrap() {
                assert_eq!(process.read(), *expected, "{}", case["name"]);
            }
        } else {
            assert_eq!(process.read(), case["response"], "{}", case["name"]);
        }
        process.finish();
    }
}

#[test]
fn exact_request_limit_fragmented_utf8_and_coalesced_frames_are_bounded() {
    let mut process = Process::new();
    let mut exact = serde_json::to_vec(&request("exact", "host.describe", json!({}))).unwrap();
    exact.resize(rebase_semantic_proof::json::MAX_REQUEST_BYTES, b' ');
    exact.push(b'\n');
    process.write(&exact);
    let description = process.read();
    assert_eq!(description["result"]["state"], "unconfigured");
    let framed = serde_json::to_vec(&request("unicode", "unknown.é", json!({}))).unwrap();
    let multibyte = framed.iter().position(|b| *b == 0xc3).unwrap();
    process.write(&framed[..multibyte + 1]);
    process.write(&framed[multibyte + 1..]);
    process.write(b"\n");
    assert_eq!(kind(&process.read()), Some("method_not_found"));
    let mut coalesced = serde_json::to_vec(&request("same", "host.describe", json!({}))).unwrap();
    coalesced.push(b'\n');
    coalesced.extend(serde_json::to_vec(&request("same", "host.close", json!({}))).unwrap());
    coalesced.push(b'\n');
    process.write(&coalesced);
    assert_eq!(process.read()["id"], "same");
    assert_eq!(process.read()["result"]["status"], "closed");
    process.finish();
}

#[test]
fn invalid_config_has_no_filesystem_effect_and_description_schema_validates() {
    let directory = Directory::new();
    let path = directory.0.join("untouched.redb");
    let mut process = Process::new();
    let description = process.call("describe", "host.describe", json!({}));
    let schema = description["result"]["configuration"]["schema"].clone();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let valid = config("calculation", created(&path), json!(["store.check"]));
    assert!(validator.is_valid(&valid));
    let mut bad = valid.clone();
    bad["operator_methods"] = json!(["store.raw"]);
    assert!(!validator.is_valid(&bad));
    assert_eq!(
        kind(&process.call("invalid-grant", "host.configure", bad)),
        Some("invalid_config")
    );
    let mut bad = valid.clone();
    bad["target"]["unexpected"] = json!(true);
    assert_eq!(
        kind(&process.call("invalid-target", "host.configure", bad)),
        Some("invalid_config")
    );
    let mut bad = valid.clone();
    bad["target"]["actor"] = json!("FFFFFFFF-FFFF-4FFF-8FFF-FFFFFFFFFFFF");
    assert_eq!(
        kind(&process.call("invalid-uuid", "host.configure", bad)),
        Some("invalid_config")
    );
    let mut bad = valid.clone();
    bad["backend"]["kind"] = json!("foundationdb");
    assert_eq!(
        kind(&process.call("implicit-fdb", "host.configure", bad.clone())),
        Some("invalid_config")
    );
    bad["backend"]["cluster_file"] = json!("/explicit/unused-fdb.cluster");
    assert_eq!(
        kind(&process.call("unsupported", "host.configure", bad)),
        Some(if cfg!(feature = "foundationdb") {
            "invalid_config"
        } else {
            "unsupported_backend"
        })
    );
    let mut bad = valid.clone();
    bad["model"] = json!("missing");
    assert_eq!(
        kind(&process.call("invalid-model", "host.configure", bad)),
        Some("invalid_config")
    );
    let mut bad = valid.clone();
    bad["target"]["actor"] = bad["target"]["tenant"].clone();
    assert_eq!(
        kind(&process.call("invalid-bootstrap", "host.configure", bad)),
        Some("invalid_config")
    );
    assert!(!path.exists());
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 0);
    assert_eq!(
        process.call(
            "recover",
            "host.configure",
            config("calculation", Value::Null, json!([]))
        )["result"]["status"],
        "configured"
    );
    process.call("close", "host.close", json!({}));
    process.finish();
}

#[test]
fn store_scope_grants_exclusivity_and_wrong_target_reject_before_writes() {
    let directory = Directory::new();
    let path = directory.0.join("owned.redb");
    let mut owner = Process::new();
    let configured = owner.call(
        "create",
        "host.configure",
        config(
            "equipment",
            created(&path),
            json!(["store.check", "store.inspect"]),
        ),
    );
    assert!(configured.get("error").is_none(), "{configured}");
    let model = configured["result"]["model"].clone();
    let store = configured["result"]["target"]["store"].clone();
    let scope = json!({"scope":{"model":model,"store":store}});
    assert!(
        owner
            .call("check", "store.check", scope.clone())
            .get("result")
            .is_some()
    );
    assert_eq!(
        owner.call("inspect", "store.inspect", scope.clone())["result"]["store"],
        store
    );
    let mut wrong = scope.clone();
    wrong["scope"]["model"] = json!("wrong");
    assert_eq!(
        kind(&owner.call("wrong-model", "store.inspect", wrong)),
        Some("wrong_target")
    );
    let mut wrong = scope.clone();
    wrong["scope"]["store"] = json!(Uuid::new_v4());
    assert_eq!(
        kind(&owner.call("wrong-store", "store.check", wrong)),
        Some("wrong_target")
    );
    let mut competitor = Process::new();
    let open = json!({"mode":"open","path":path,"expect_store":store});
    assert_eq!(
        kind(&competitor.call(
            "busy",
            "host.configure",
            config("equipment", open.clone(), json!(["store.inspect"]))
        )),
        Some("store_busy")
    );
    competitor.call("close", "host.close", json!({}));
    competitor.finish();
    owner.call("close", "host.close", json!({}));
    owner.finish();
    let before = digest(&path);
    let mut wrong_open = open.clone();
    wrong_open["expect_store"] = json!(Uuid::new_v4());
    let mut process = Process::new();
    assert_eq!(
        kind(&process.call(
            "wrong-store",
            "host.configure",
            config("equipment", wrong_open, json!(["store.inspect"]))
        )),
        Some("wrong_target")
    );
    assert_eq!(before, digest(&path));
    assert_eq!(
        kind(&process.call(
            "wrong-model",
            "host.configure",
            config("calculation", open.clone(), json!(["store.inspect"]))
        )),
        Some("wrong_target")
    );
    assert_eq!(before, digest(&path));
    assert!(
        process
            .call(
                "open",
                "host.configure",
                config("equipment", open.clone(), json!([]))
            )
            .get("result")
            .is_some()
    );
    assert_eq!(
        kind(&process.call("denied", "store.inspect", scope.clone())),
        Some("forbidden")
    );
    process.call("close", "host.close", json!({}));
    process.finish();
    let mut repeated = Process::new();
    assert!(
        repeated
            .call(
                "reopen",
                "host.configure",
                config("equipment", open, json!(["store.check"]))
            )
            .get("result")
            .is_some()
    );
    assert!(
        repeated
            .call("check", "store.check", scope)
            .get("result")
            .is_some()
    );
    repeated.call("close", "host.close", json!({}));
    repeated.finish();
}

#[test]
fn same_process_owners_contend_without_losing_the_first_handle() {
    let directory = Directory::new();
    let path = directory.0.join("shared.redb");
    let mut first = Host::default();
    let mut second = Host::default();
    let configured = first.handle(
        &serde_json::to_vec(&request(
            "create",
            "host.configure",
            config("calculation", created(&path), json!(["store.inspect"])),
        ))
        .unwrap(),
    );
    let store = configured["result"]["target"]["store"].clone();
    let model = configured["result"]["model"].clone();
    let open = config(
        "calculation",
        json!({"mode":"open","path":path,"expect_store":store}),
        json!([]),
    );
    assert_eq!(
        kind(&second.handle(
            &serde_json::to_vec(&request("busy", "host.configure", open.clone())).unwrap()
        )),
        Some("store_busy")
    );
    assert!(
        first
            .handle(
                &serde_json::to_vec(&request(
                    "inspect",
                    "store.inspect",
                    json!({"scope":{"model":model,"store":store}})
                ))
                .unwrap()
            )
            .get("result")
            .is_some()
    );
    first.handle(&serde_json::to_vec(&request("close", "host.close", json!({}))).unwrap());
    assert!(
        second
            .handle(&serde_json::to_vec(&request("open", "host.configure", open)).unwrap())
            .get("result")
            .is_some()
    );
}

#[test]
fn every_compiled_model_has_the_unchanged_catalog_on_both_scopes() {
    for model in [
        "calculation",
        "equipment",
        "invoicing",
        "measurement",
        "effect-demo",
        "quantity",
    ] {
        let mut process = Process::new();
        let configured = process.call(
            "configure",
            "host.configure",
            config(model, Value::Null, json!([])),
        );
        assert!(configured.get("result").is_some());
        for scope in ["public", "developer"] {
            let expected = Command::new(env!("CARGO_BIN_EXE_rebase-next"))
                .args(["--model", model, "model", scope])
                .output()
                .unwrap();
            assert!(expected.status.success());
            let expected: Value = serde_json::from_slice(&expected.stdout).unwrap();
            let actual = process.call(scope, "model.catalog", json!({"scope":scope}));
            assert_eq!(actual["result"], expected);
        }
        let description = process.call("describe", "host.describe", json!({}));
        assert_eq!(
            description["result"]["selection"]["model"],
            configured["result"]["model"]
        );
        assert_eq!(
            description["result"]["capabilities"]["framing"]["response_bytes"],
            host::MAX_RESPONSE_BYTES
        );
        process.call("close", "host.close", json!({}));
        process.finish();
    }
}

#[test]
fn exclusive_create_preserves_existing_destination_and_eof_releases_owner() {
    let directory = Directory::new();
    let path = directory.0.join("existing.redb");
    let mut owner = Process::new();
    let configured = owner.call(
        "create",
        "host.configure",
        config("calculation", created(&path), json!([])),
    );
    let store = configured["result"]["target"]["store"].clone();
    owner.finish();
    let before = digest(&path);
    let mut rejected = Process::new();
    assert!(
        rejected
            .call(
                "duplicate-create",
                "host.configure",
                config("calculation", created(&path), json!([]))
            )
            .get("error")
            .is_some()
    );
    rejected.finish();
    assert_eq!(digest(&path), before);
    let mut reopened = Process::new();
    assert!(
        reopened
            .call(
                "open",
                "host.configure",
                config(
                    "calculation",
                    json!({"mode":"open","path":path,"expect_store":store}),
                    json!([])
                )
            )
            .get("result")
            .is_some()
    );
    reopened.finish();
}

#[cfg(unix)]
#[test]
fn owned_sigterm_closes_native_store_cleanly_before_exit() {
    let directory = Directory::new();
    let path = directory.0.join("signal.redb");
    let mut owner = Process::new();
    let configured = owner.call(
        "create",
        "host.configure",
        config("calculation", created(&path), json!([])),
    );
    let store = configured["result"]["target"]["store"].clone();
    assert!(
        Command::new("kill")
            .args(["-TERM", &owner.child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    owner.finish();
    let mut reopened = Process::new();
    let reply = reopened.call(
        "open",
        "host.configure",
        config(
            "calculation",
            json!({"mode":"open","path":path,"expect_store":store}),
            json!(["store.check"]),
        ),
    );
    assert!(
        reply.get("result").is_some(),
        "signal left dirty/recovery-required store: {reply}"
    );
    reopened.finish();
}

#[cfg(unix)]
#[test]
fn killed_owner_requires_explicit_recovery_without_preview_writes() {
    let directory = Directory::new();
    let path = directory.0.join("crashed.redb");
    let mut owner = Process::new();
    let configured = owner.call(
        "create",
        "host.configure",
        config("calculation", created(&path), json!([])),
    );
    let store = configured["result"]["target"]["store"].clone();
    owner.child.kill().unwrap();
    assert!(!owner.child.wait().unwrap().success());
    owner.input.take();
    let before = digest(&path);
    let mut reopened = Process::new();
    let reply = reopened.call(
        "open",
        "host.configure",
        config(
            "calculation",
            json!({"mode":"open","path":path,"expect_store":store}),
            json!([]),
        ),
    );
    assert_eq!(kind(&reply), Some("recovery_required"));
    reopened.finish();
    assert_eq!(digest(&path), before);
    let mut recovered = Process::new();
    let configured = recovered.call(
        "recover",
        "host.configure",
        config(
            "calculation",
            json!({"mode":"recover","path":path,"expect_store":store}),
            json!(["store.recover", "store.check"]),
        ),
    );
    assert!(configured.get("result").is_some(), "{configured}");
    assert!(
        recovered
            .call(
                "check",
                "store.check",
                json!({"scope":{"model":configured["result"]["model"],"store":store}})
            )
            .get("result")
            .is_some()
    );
    recovered.finish();
}

#[test]
fn public_rpc_cannot_reach_the_operator_allowlist() {
    let directory = Directory::new();
    let path = directory.0.join("public.redb");
    let store = rebase_semantic_proof::local::Store::create_secured(
        &path,
        std::sync::Arc::new(Prepared::<Calculation>::load().unwrap()),
        rebase_semantic_proof::native_slice::Context {
            tenant: Uuid::new_v4(),
            actor: Uuid::new_v4(),
        },
    )
    .unwrap();
    for method in [
        "host.configure",
        "host.describe",
        "store.inspect",
        "store.check",
        "host.close",
        "model.render",
        "service.start",
        "service.stop",
        "identity.issue",
        "store.backup",
        "store.restore",
        "store.archive",
        "store.reset",
    ] {
        let reply = rebase_semantic_proof::rpc::handle(
            &store,
            &serde_json::to_vec(
                &json!({"jsonrpc":"2.0","id":"public","method":method,"params":{}}),
            )
            .unwrap(),
        );
        assert_eq!(reply["error"]["data"]["kind"], "method_not_found");
    }
}

#[test]
fn close_and_eof_join_owned_services_before_releasing_the_store() {
    for explicit_close in [true, false] {
        let directory = Directory::new();
        let path = directory.0.join("service.redb");
        let mut owner = Process::new();
        let configured = owner.call(
            "create",
            "host.configure",
            config("calculation", created(&path), json!(["service.start"])),
        );
        let scope = json!({"model":configured["result"]["model"],"store":configured["result"]["target"]["store"]});
        let started = owner.call("start", "service.start", json!({"scope":scope,"config":{"listen":"127.0.0.1:0","identity":{"issuer":"close-test","audience":"close-test","public_keys":{"test":include_str!("fixtures/test-ed25519-public.pem")},"max_token_seconds":600},"max_inflight":1,"request_timeout_seconds":1,"effects":null}}));
        assert!(started.get("result").is_some(), "{started}");
        let address = started["result"]["address"].as_str().unwrap();
        assert!(std::net::TcpStream::connect(address).is_ok());
        if explicit_close {
            assert_eq!(
                owner.call("close", "host.close", json!({}))["result"]["status"],
                "closed"
            );
        }
        owner.finish();
        assert!(std::net::TcpStream::connect(address).is_err());
        let mut reopened = Process::new();
        let reply = reopened.call(
            "open",
            "host.configure",
            config(
                "calculation",
                json!({"mode":"open","path":path,"expect_store":scope["store"]}),
                json!([]),
            ),
        );
        assert!(reply.get("result").is_some(), "{reply}");
        reopened.finish();
    }
}

#[cfg(feature = "foundationdb")]
#[test]
fn failed_fdb_configuration_keeps_the_process_network_for_retry() {
    let directory = Directory::new();
    let mut process = Process::new();
    let configuration = json!({"model":"calculation","backend":{"kind":"foundationdb","cluster_file":directory.0.join("missing.cluster")},"target":{"mode":"open","namespace":"n2-missing-cluster-retry","expect_store":Uuid::new_v4()},"operator_methods":[]});
    for id in ["first", "retry"] {
        assert!(
            process
                .call(id, "host.configure", configuration.clone())
                .get("error")
                .is_some()
        );
    }
    assert_eq!(
        process.call("describe", "host.describe", json!({}))["result"]["state"],
        "unconfigured"
    );
    process.call("close", "host.close", json!({}));
    process.finish();
}
