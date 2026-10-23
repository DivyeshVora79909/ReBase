//! Test keys are deliberately public fixtures, never deployment credentials.
use rebase_semantic_proof::{
    identity::{self, Claims, IdentityConfig, TokenRequest, Verifier},
    local::LocalStore,
    model::PreparedModel,
    native_slice::Context,
    server::{self, ServerConfig},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;
const PRIVATE: &[u8] = include_bytes!("fixtures/test-ed25519-private.pem");
const PUBLIC: &str = include_str!("fixtures/test-ed25519-public.pem");
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn config() -> ServerConfig {
    ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        identity: IdentityConfig {
            issuer: "https://identity.example.test".into(),
            audience: "rebase-test".into(),
            public_keys: BTreeMap::from([("test".into(), PUBLIC.into())]),
            max_token_seconds: 600,
        },
        max_inflight: 16,
        request_timeout_seconds: 5,
        effects: None,
    }
}
fn token(config: &ServerConfig, epoch: u64) -> String {
    identity::issue(
        &config.identity,
        &TokenRequest {
            tenant: id(1),
            actor: id(2),
            epoch,
            ttl: 300,
            key_id: "test".into(),
        },
        PRIVATE,
    )
    .unwrap()
}
fn sign(claims: &Claims, kid: &str) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some(kid.into());
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_ed_pem(PRIVATE).unwrap(),
    )
    .unwrap()
}
#[test]
fn standard_credential_profile_rejects_wrong_context_signature_time_and_key() {
    let cfg = config();
    let verifier = Verifier::new(cfg.identity.clone()).unwrap();
    let valid = token(&cfg, 0);
    let claims = verifier.verify(&valid, id(1)).unwrap();
    assert!(verifier.verify(&valid, id(3)).is_err());
    for change in 0..6 {
        let mut bad = claims.clone();
        match change {
            0 => bad.iss = "other".into(),
            1 => bad.aud = "other".into(),
            2 => {
                bad.iat = 1;
                bad.nbf = 1;
                bad.exp = 2;
            }
            3 => {
                bad.iat += 100;
                bad.nbf += 100;
                bad.exp += 100;
            }
            4 => bad.exp = bad.iat + 601,
            _ => bad.nbf = bad.iat - 1,
        }
        assert!(
            verifier.verify(&sign(&bad, "test"), id(1)).is_err(),
            "change {change}"
        );
    }
    assert!(verifier.verify(&sign(&claims, "unknown"), id(1)).is_err());
    let mut damaged = valid.into_bytes();
    let n = damaged.len() - 2;
    damaged[n] = if damaged[n] == b'A' { b'B' } else { b'A' };
    assert!(
        verifier
            .verify(std::str::from_utf8(&damaged).unwrap(), id(1))
            .is_err()
    );
    let hs = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(PUBLIC.as_bytes()),
    )
    .unwrap();
    assert!(verifier.verify(&hs, id(1)).is_err());
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/network-tests")
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
async fn http(addr: SocketAddr, token: Option<String>, body: Vec<u8>) -> (u16, Value) {
    tokio::task::spawn_blocking(move||{
        let mut tcp=TcpStream::connect_timeout(&addr,Duration::from_secs(5)).unwrap();tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let auth=token.map_or(String::new(),|t|format!("Authorization: Bearer {t}\r\n"));
        write!(tcp,"POST /rpc HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\n{auth}Content-Length: {}\r\n\r\n",body.len()).unwrap();tcp.write_all(&body).unwrap();
        let mut response=vec![];tcp.read_to_end(&mut response).unwrap();let boundary=response.windows(4).position(|b|b==b"\r\n\r\n").unwrap();
        let header=std::str::from_utf8(&response[..boundary]).unwrap();let status=header.split_whitespace().nth(1).unwrap().parse().unwrap();
        let body=&response[boundary+4..];let value=serde_json::from_slice(body).unwrap_or(Value::Null);(status,value)
    }).await.unwrap()
}
fn request(method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":"network-test","method":method,"params":params}),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_ranges_preserve_complete_times_exact_bounds_and_reopen() {
    let dir = Directory::new();
    let cfg = config();
    let model = Arc::new(PreparedModel::load().unwrap());
    let file = dir.0.join("ranges.redb");
    let store = Arc::new(
        LocalStore::create_secured(
            &file,
            model.clone(),
            Context {
                tenant: id(1),
                actor: id(2),
            },
        )
        .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = server::router(store.clone(), &cfg).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let credential = token(&cfg, 0);
    let mut commands =
        vec![json!({"op":"create","id":id(20),"contract":4,"fields":{"native_unit":1}})];
    for (n, at, amount) in [(30, 0, 10), (31, 10, 20), (32, 10, -5), (33, 20, 30)] {
        commands.push(json!({"op":"create","id":id(n),"contract":8,"fields":{"account":id(20),"at":at.to_string(),"amount":amount.to_string()}}));
    }
    let (_, result) = http(addr, Some(credential.clone()), request("records.mutate",json!({"model":model.identity(),"context":store.operation_context(model.identity()).unwrap(),"operation_id":id(200),"commands":commands,"returning":[]}))).await;
    assert_eq!(result["result"]["status"], "committed", "{result}");
    let read = |range: Value| json!({"model":model.identity(),"owner":id(20),"slot":2,"read":{"kind":"range","range":range}});
    for (range, count, sum) in [
        (json!({"lower":null,"upper":null}), 4, "55"),
        (
            json!({"lower":{"included":"10"},"upper":{"included":"10"}}),
            2,
            "15",
        ),
        (
            json!({"lower":{"included":"0"},"upper":{"excluded":"10"}}),
            1,
            "10",
        ),
        (json!({"lower":{"excluded":"10"},"upper":null}), 1, "30"),
        (
            json!({"lower":{"included":"20"},"upper":{"excluded":"0"}}),
            0,
            "0",
        ),
        (
            json!({"lower":null,"upper":{"excluded":i64::MIN.to_string()}}),
            0,
            "0",
        ),
    ] {
        let (_, response) = http(
            addr,
            Some(credential.clone()),
            request("roots.read", read(range)),
        )
        .await;
        assert_eq!(response["result"]["value"]["count"], count, "{response}");
        assert_eq!(response["result"]["value"]["sum"], sum, "{response}");
    }
    let range = json!({"lower":{"included":"10"},"upper":{"included":"10"}});
    assert_eq!(
        http(addr, None, request("roots.read", read(range.clone())))
            .await
            .0,
        401
    );
    let (_, missing) = http(addr,Some(credential.clone()),request("roots.read",json!({"model":model.identity(),"owner":id(999),"slot":2,"read":{"kind":"range","range":range}}))).await;
    assert_eq!(missing["error"]["data"]["kind"], "not_found");
    for range in [
        json!([null, null]),
        json!({"lower":{"included":0},"upper":null}),
        json!({"lower":null,"upper":null,"extra":true}),
    ] {
        let (_, malformed) = http(
            addr,
            Some(credential.clone()),
            request("roots.read", read(range)),
        )
        .await;
        assert_eq!(malformed["error"]["code"], -32602, "{malformed}");
    }
    store.check_integrity().unwrap();
    stop.send(()).unwrap();
    serving.await.unwrap();
    drop(store);
    let reopened = LocalStore::open(&file, model.clone()).unwrap();
    reopened.check_integrity().unwrap();
    let request = serde_json::from_value(read(
        json!({"lower":{"included":"10"},"upper":{"included":"10"}}),
    ))
    .unwrap();
    assert_eq!(
        reopened
            .session(id(2), 0)
            .unwrap()
            .root_read(&request)
            .unwrap()["value"]["sum"],
        "15"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_http_concurrency_receipts_revocation_and_reopen() {
    let dir = Directory::new();
    let cfg = config();
    let model = Arc::new(PreparedModel::load().unwrap());
    let store = Arc::new(
        LocalStore::create_secured(
            dir.0.join("test.redb"),
            model.clone(),
            Context {
                tenant: id(1),
                actor: id(2),
            },
        )
        .unwrap(),
    );
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = server::router(store.clone(), &cfg).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let credential = token(&cfg, 0);
    let operation_context = store.operation_context(model.identity()).unwrap();
    assert_eq!(
        http(addr, None, request("model.describe", json!({})))
            .await
            .0,
        401
    );
    assert_eq!(
        http(
            addr,
            Some("broken".into()),
            request("model.describe", json!({}))
        )
        .await
        .0,
        401
    );
    assert_eq!(
        http(addr, Some(credential.clone()), vec![b' '; 65537])
            .await
            .0,
        413
    );
    let create = request(
        "records.mutate",
        json!({"model":model.identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":id(100),"commands":[{"op":"create","id":id(10),"contract":7,"fields":{"at":"0"}}],"returning":[id(10)]}),
    );
    let mut tasks = vec![];
    for _ in 0..8 {
        tasks.push(tokio::spawn(http(
            addr,
            Some(credential.clone()),
            create.clone(),
        )));
    }
    let mut applied = 0;
    for task in tasks {
        let (status, value) = task.await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(value["result"]["status"], "committed");
        if value["result"]["replayed"] == false {
            applied += 1;
        }
    }
    assert_eq!(applied, 1);
    let version = store
        .get(model.identity(), id(10))
        .unwrap()
        .unwrap()
        .version
        .to_string();
    let mut tasks = vec![];
    for n in 0..8 {
        tasks.push(tokio::spawn(http(addr,Some(credential.clone()),request("records.mutate",json!({"model":model.identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":id(200+n),"commands":[{"op":"update","id":id(10),"if_version":version,"set":{"at":(n+1).to_string()},"unset":[]}],"returning":[]})))));
    }
    let mut committed = 0;
    let mut stale = 0;
    for task in tasks {
        let (_, value) = task.await.unwrap();
        if value.get("result").is_some() {
            committed += 1;
        } else {
            assert_eq!(value["error"]["data"]["kind"], "stale_version");
            stale += 1;
        }
    }
    assert_eq!((committed, stale), (1, 7));
    let (_, authority) = http(
        addr,
        Some(credential.clone()),
        request("access.describe", json!({"model":model.identity()})),
    )
    .await;
    let mut graph = authority["result"]["graph"].clone();
    let actor = graph["principals"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p["id"] == id(2).to_string())
        .unwrap();
    actor["credential_epoch"] = json!(1);
    let (_,updated)=http(addr,Some(credential.clone()),request("access.replace",json!({"model":model.identity(),"if_revision":authority["result"]["revision"],"graph":graph}))).await;
    assert!(updated.get("result").is_some(), "{updated}");
    let (_, denied) = http(addr, Some(credential), request("model.describe", json!({}))).await;
    assert_eq!(denied["error"]["data"]["kind"], "forbidden");
    let (_, allowed) = http(
        addr,
        Some(token(&cfg, 1)),
        request("records.get", json!({"model":model.identity(),"id":id(10)})),
    )
    .await;
    assert!(allowed["result"].is_object());
    assert_eq!(
        http(addr, Some(token(&cfg, 1)), request("inspect", json!({})))
            .await
            .1["error"]["code"],
        -32601
    );
    stop.send(()).unwrap();
    serving.await.unwrap();
    drop(store);
    let reopened = LocalStore::open(dir.0.join("test.redb"), model.clone()).unwrap();
    assert_eq!(
        reopened
            .session(id(2), 0)
            .unwrap()
            .get(model.identity(), id(10))
            .unwrap_err()
            .code,
        "forbidden"
    );
    assert_eq!(
        reopened
            .session(id(2), 1)
            .unwrap()
            .operation_status(model.identity(), &operation_context, id(100))
            .unwrap()["status"],
        "committed"
    );
}
