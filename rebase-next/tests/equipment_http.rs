//! Public fixture keys exercise the second compiled model through real HTTP.
use rebase_semantic_proof::{
    binding::Binding,
    identity::{self, IdentityConfig, TokenRequest},
    local::Store,
    model::Prepared,
    models::equipment::Equipment,
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
            audience: "rebase-equipment-test".into(),
            public_keys: BTreeMap::from([("test".into(), PUBLIC.into())]),
            max_token_seconds: 600,
        },
        max_inflight: 4,
        request_timeout_seconds: 5,
        effects: None,
    }
}
fn token(config: &ServerConfig, actor: Uuid) -> String {
    identity::issue(
        &config.identity,
        &TokenRequest {
            tenant: id(1),
            actor,
            epoch: 0,
            ttl: 300,
            key_id: "test".into(),
        },
        PRIVATE,
    )
    .unwrap()
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

async fn rpc(addr: SocketAddr, credential: &str, method: &str, params: Value) -> Value {
    let (status, response) = http(addr, Some(credential.into()), request(method, params)).await;
    assert_eq!(status, 200, "{response}");
    response
}
fn result(response: Value) -> Value {
    assert!(response.get("result").is_some(), "{response}");
    response["result"].clone()
}
fn forbidden(response: Value) {
    assert_eq!(response["error"]["data"]["kind"], "forbidden", "{response}");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn equipment_uses_shared_http_authority_receipts_and_sparse_queries() {
    let directory = Directory::new();
    let cfg = config();
    let model = Arc::new(Prepared::<Equipment>::load().unwrap());
    let store = Arc::new(
        Store::<Equipment>::create_secured(
            directory.0.join("equipment.redb"),
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
    let admin = token(&cfg, id(2));
    let session = result(rpc(addr, &admin, "session.describe", json!({})).await);
    assert_eq!(session["actor"], id(2).to_string());
    let catalog = result(rpc(addr, &admin, "model.describe", json!({})).await);
    let codes: Vec<_> = catalog["contracts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["code"].as_u64().unwrap())
        .collect();
    assert_eq!(codes, [101, 205, 410]);
    let draft = Equipment::fixture_plan(&model, "equipment", id(100)).unwrap();
    let pool = draft["fixture"]["ids"]["pool"].clone();
    let a = draft["fixture"]["ids"]["a"].clone();
    let mut seed = draft.clone();
    seed.as_object_mut().unwrap().remove("fixture");
    seed["context"] = session["operation_context"].clone();
    seed["operation_id"] = json!(id(1000));
    let committed = result(rpc(addr, &admin, "records.mutate", seed.clone()).await);
    assert_eq!(committed["replayed"], false);
    assert_eq!(
        committed["result"]["records"][0]["record"]["derived"]["allocated"],
        "8"
    );
    assert_eq!(
        committed["result"]["records"][1]["record"]["derived"]["allocated"],
        "2"
    );
    let replay = result(rpc(addr, &admin, "records.mutate", seed).await);
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["result"], committed["result"]);
    let root = result(rpc(addr, &admin, "roots.read", json!({"model":model.identity(),"owner":pool,"slot":7,"read":{"kind":"before","at":"21"}})).await);
    assert_eq!(root["value"]["sum"], "0");
    let query = json!({"path":"records.by_id","contract":410,"equals":null});
    let page = result(rpc(addr, &admin, "records.page", json!({"model":model.identity(),"query":query,"limit":32,"visit_budget":64,"cursor":null})).await);
    assert_eq!(page["records"].as_array().unwrap().len(), 2);
    assert_eq!(page["exhausted"], true);
    assert!(
        page["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["contract"] == 410)
    );
    let exists = result(
        rpc(
            addr,
            &admin,
            "records.exists",
            json!({"model":model.identity(),"query":query,"visit_budget":64,"cursor":null}),
        )
        .await,
    );
    assert_eq!(exists["answer"], "yes");
    let private = rpc(addr, &admin, "records.mutate", json!({"model":model.identity(),"context":session["operation_context"],"operation_id":id(1001),"commands":[{"op":"create","id":id(999),"contract":900,"fields":{"producer":a,"role":11,"pool":pool,"at":"10","quantity":"-1"}}],"returning":[]})).await;
    forbidden(private);

    // A real principal with limited grants cannot link to the administrator's
    // unreadable pool, even though reservation creation itself is granted.
    let authority = result(
        rpc(
            addr,
            &admin,
            "access.describe",
            json!({"model":model.identity()}),
        )
        .await,
    );
    let mut graph = authority["graph"].clone();
    graph["principals"].as_array_mut().unwrap().push(json!({"id":id(3),"kind":"user","parents":[id(1)],"active":true,"credential_epoch":0,"grants":{"admin":false,"contracts":{"101":["read"],"410":["read","create"]}}}));
    result(
        rpc(
            addr,
            &admin,
            "access.replace",
            json!({"model":model.identity(),"if_revision":authority["revision"],"graph":graph}),
        )
        .await,
    );
    let restricted = token(&cfg, id(3));
    let restricted_session = result(rpc(addr, &restricted, "session.describe", json!({})).await);
    assert!(
        result(
            rpc(
                addr,
                &restricted,
                "records.get",
                json!({"model":model.identity(),"id":pool})
            )
            .await
        )
        .is_null()
    );
    let mutate = |operation, commands| json!({"model":model.identity(),"context":restricted_session["operation_context"],"operation_id":id(operation),"commands":commands,"returning":[]});
    forbidden(rpc(addr, &restricted, "records.mutate", mutate(1002,json!([{"op":"create","id":id(1002),"contract":410,"fields":{"pool":pool,"starts":"50","ends":"60","requested":"1","active":true}}]))).await);
    forbidden(
        rpc(
            addr,
            &restricted,
            "records.mutate",
            mutate(
                1003,
                json!([{"op":"create","id":id(1003),"contract":101,"fields":{"unit":1}}]),
            ),
        )
        .await,
    );
    let authority = result(
        rpc(
            addr,
            &admin,
            "access.describe",
            json!({"model":model.identity()}),
        )
        .await,
    );
    let mut graph = authority["graph"].clone();
    graph["principals"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|p| p["id"] == id(3).to_string())
        .unwrap()["active"] = json!(false);
    result(
        rpc(
            addr,
            &admin,
            "access.replace",
            json!({"model":model.identity(),"if_revision":authority["revision"],"graph":graph}),
        )
        .await,
    );
    forbidden(rpc(addr, &restricted, "session.describe", json!({})).await);
    store.check_integrity().unwrap();
    stop.send(()).unwrap();
    serving.await.unwrap();
}
