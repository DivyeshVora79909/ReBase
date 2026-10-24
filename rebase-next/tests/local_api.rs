use rebase_semantic_proof::{
    json::MAX_REQUEST_BYTES,
    local::LocalStore,
    model::PreparedModel,
    native_slice::Context,
    query::{Equality, ExistsRequest, PageRequest, RecordQuery},
    rpc,
};
use serde_json::{Value, json};
use std::{fs, io::Cursor, path::PathBuf, sync::Arc};
use uuid::Uuid;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/local-tests")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn file(&self) -> PathBuf {
        self.0.join("demo.redb")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn store(dir: &Directory) -> LocalStore {
    LocalStore::create(
        dir.file(),
        Arc::new(PreparedModel::load().unwrap()),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap()
}
fn call(store: &LocalStore, method: &str, params: Value) -> Value {
    rpc::handle(
        store,
        &serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"test","method":method,"params":params}))
            .unwrap(),
    )
}
fn mutation(store: &LocalStore, op: u128, commands: Value, returning: Value) -> Value {
    json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":id(op),"commands":commands,"returning":returning})
}
fn seed(store: &LocalStore) -> (Value, Value) {
    let fixture: Value =
        serde_json::from_str(include_str!("../research/fixtures/causal-slice.json")).unwrap();
    let request = mutation(
        store,
        1000,
        fixture["bases"]["baseline"].clone(),
        json!([
            fixture["ids"]["P"],
            fixture["ids"]["Q"],
            fixture["ids"]["J"]
        ]),
    );
    let response = call(store, "records.mutate", request.clone());
    assert_eq!(response["result"]["status"], "committed", "{response}");
    (fixture, request)
}
fn page(store: &LocalStore) -> PageRequest {
    PageRequest {
        model: store.model().identity().into(),
        query: RecordQuery::default(),
        limit: 2,
        visit_budget: 3,
        cursor: None,
    }
}
fn kind(response: &Value) -> &str {
    response["error"]["data"]["kind"]
        .as_str()
        .unwrap_or("no error")
}
fn version(store: &LocalStore, id: &Value) -> String {
    store
        .get(
            store.model().identity(),
            Uuid::parse_str(id.as_str().unwrap()).unwrap(),
        )
        .unwrap()
        .unwrap()
        .version
        .to_string()
}

#[test]
fn exact_mutations_publish_settled_values_and_durable_replay_receipts() {
    let dir = Directory::new();
    let store = store(&dir);
    let (f, base) = seed(&store);
    let first = call(
        &store,
        "operations.status",
        json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":id(1000)}),
    );
    assert_eq!(
        first["result"]["result"]["records"][0]["record"]["derived"]["delta"],
        "10"
    );
    let replay = call(&store, "records.mutate", base.clone());
    assert_eq!(replay["result"]["replayed"], true);
    assert_eq!(replay["result"]["result"], first["result"]["result"]);
    let mut conflicting = base;
    conflicting["returning"] = json!([]);
    assert_eq!(
        kind(&call(&store, "records.mutate", conflicting)),
        "operation_conflict"
    );
    let old_mp = version(&store, &f["ids"]["MP"]);
    let update = mutation(
        &store,
        1001,
        json!([
            {"op":"update","id":f["ids"]["MP"],"if_version":old_mp,"set":{"at":"20"},"unset":[]},
            {"op":"update","id":f["ids"]["MQ"],"if_version":version(&store,&f["ids"]["MQ"]),"set":{"at":"10"},"unset":[]}
        ]),
        json!([f["ids"]["P"], f["ids"]["J"]]),
    );
    let response = call(&store, "records.mutate", update);
    assert_eq!(response["result"]["status"], "committed", "{response}");
    let revision =
        Uuid::parse_str(response["result"]["result"]["revision"].as_str().unwrap()).unwrap();
    assert!(!revision.is_nil());
    assert_ne!(
        response["result"]["result"]["revision"],
        first["result"]["result"]["revision"]
    );
    assert_eq!(
        response["result"]["result"]["records"][0]["record"]["derived"],
        json!({"at":"20","before":"30","delta":"-10"})
    );
    assert_eq!(
        response["result"]["result"]["records"][1]["record"]["derived"],
        json!({"value":"100"})
    );
    let stale = mutation(
        &store,
        1002,
        json!([{ "op":"update","id":f["ids"]["MP"],"if_version":old_mp,"set":{"at":"30"},"unset":[]}]),
        json!([]),
    );
    assert_eq!(
        kind(&call(&store, "records.mutate", stale)),
        "stale_version"
    );
    assert_eq!(
        call(
            &store,
            "operations.status",
            json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":id(1002)})
        )["result"]["status"],
        "not_observed"
    );
    let feedback = mutation(
        &store,
        1003,
        json!([{ "op":"update","id":f["ids"]["J"],"if_version":version(&store,&f["ids"]["J"]),"set":{"feedback":{"account":f["ids"]["A"],"at":"5"}},"unset":[]}]),
        json!([]),
    );
    assert_eq!(kind(&call(&store, "records.mutate", feedback)), "feedback");
    let root = call(
        &store,
        "roots.read",
        json!({"model":store.model().identity(),"owner":f["ids"]["A"],"slot":2,"read":{"kind":"before","at":"20"}}),
    );
    assert_eq!(root["result"]["value"]["sum"], "30");
    drop(store);
    let reopened = LocalStore::open(dir.file(), Arc::new(PreparedModel::load().unwrap())).unwrap();
    assert_eq!(
        call(
            &reopened,
            "operations.status",
            json!({"model":reopened.model().identity(),"context":reopened.operation_context(reopened.model().identity()).unwrap(),"operation_id":id(1000)})
        ),
        first
    );
}

#[test]
fn budgeted_reads_distinguish_empty_pages_unknown_and_exhaustion() {
    let dir = Directory::new();
    let store = store(&dir);
    let (f, _) = seed(&store);
    let mut request = page(&store);
    request.query.contract = Some(9);
    request.query.equals = Some(Equality {
        field: "target".into(),
        value: json!("20"),
    });
    request.visit_budget = 2;
    let empty = store.page(&request).unwrap();
    assert!(empty.records.is_empty() && !empty.exhausted && empty.cursor.is_some());
    assert_eq!(empty.visited, 2);
    let mut exists = ExistsRequest {
        model: request.model.clone(),
        query: request.query.clone(),
        visit_budget: 2,
        cursor: None,
    };
    assert_eq!(store.exists(&exists).unwrap()["answer"], "unknown");
    let mut answers = vec![];
    loop {
        let result = store.exists(&exists).unwrap();
        answers.push(result["answer"].as_str().unwrap().to_owned());
        if result["answer"] != "unknown" {
            break;
        }
        exists.cursor = Some(result["cursor"].as_str().unwrap().into());
        assert!(answers.len() < 20);
    }
    assert_eq!(answers.last().unwrap(), "yes");
    exists.cursor = None;
    exists.query.equals.as_mut().unwrap().value = json!("999");
    loop {
        let result = store.exists(&exists).unwrap();
        if result["answer"] != "unknown" {
            assert_eq!(result["answer"], "no");
            break;
        }
        exists.cursor = Some(result["cursor"].as_str().unwrap().into());
    }
    let mut all = page(&store);
    let mut ids = vec![];
    loop {
        let result = store.page(&all).unwrap();
        ids.extend(result.records.iter().map(|r| r.id.to_string()));
        if result.exhausted {
            break;
        }
        all.cursor = result.cursor;
    }
    assert_eq!(ids.len(), 14);
    assert!(ids.windows(2).all(|w| w[0] < w[1]));
    assert!(ids.contains(&f["ids"]["P"].as_str().unwrap().to_owned()));
    request.query.equals = Some(Equality {
        field: "derived".into(),
        value: json!({}),
    });
    assert_eq!(store.page(&request).unwrap_err().code, "invalid_input");
    request.query.contract = Some(12);
    request.query.equals = None;
    assert_eq!(store.page(&request).unwrap_err().code, "forbidden");
}

#[test]
fn cursors_bind_query_scope_and_survive_replay_noop_and_unchanged_reopen() {
    let dir = Directory::new();
    let first_store = store(&dir);
    let (f, base) = seed(&first_store);
    let mut request = page(&first_store);
    request.cursor = first_store.page(&request).unwrap().cursor;
    assert!(request.cursor.is_some());
    let expected = first_store.page(&request).unwrap().records;
    call(&first_store, "records.mutate", base);
    assert_eq!(first_store.page(&request).unwrap().records, expected);
    let other_dir = Directory::new();
    let other = store(&other_dir);
    assert_eq!(other.page(&request).unwrap_err().code, "invalid_cursor");
    let mut changed = request.clone();
    changed.query.contract = Some(9);
    assert_eq!(
        first_store.page(&changed).unwrap_err().code,
        "invalid_cursor"
    );
    let mut bad = request.clone();
    bad.cursor.as_mut().unwrap().push('0');
    assert_eq!(first_store.page(&bad).unwrap_err().code, "invalid_cursor");
    drop(first_store);
    let store = LocalStore::open(dir.file(), Arc::new(PreparedModel::load().unwrap())).unwrap();
    assert_eq!(store.page(&request).unwrap().records, expected);
    let before = version(&store, &f["ids"]["P"]);
    let noop = mutation(
        &store,
        1001,
        json!([{ "op":"update","id":f["ids"]["P"],"if_version":before,"set":{"target":"20"},"unset":[]}]),
        json!([f["ids"]["P"]]),
    );
    let result = call(&store, "records.mutate", noop);
    assert_eq!(
        result["result"]["result"]["records"][0]["record"]["version"],
        before
    );
    assert_eq!(store.page(&request).unwrap().records, expected);
    let field_edit = mutation(
        &store,
        1002,
        json!([{ "op":"update","id":f["ids"]["SeedA"],"if_version":version(&store,&f["ids"]["SeedA"]),"set":{"amount":"11"},"unset":[]}]),
        json!([]),
    );
    assert_eq!(
        call(&store, "records.mutate", field_edit)["result"]["status"],
        "committed"
    );
    assert_eq!(store.page(&request).unwrap_err().code, "query_changed");
}

#[test]
fn cursor_contract_scope_survives_unrelated_edits_and_covers_derived_only_changes() {
    let dir = Directory::new();
    let store = store(&dir);
    let (fixture, _) = seed(&store);
    let mut request = page(&store);
    request.query.contract = Some(9);
    request.limit = 1;
    request.visit_budget = 32;
    request.cursor = store.page(&request).unwrap().cursor;
    assert!(request.cursor.is_some());
    let expected = store.page(&request).unwrap().records;
    let unrelated = mutation(
        &store,
        3000,
        json!([{"op":"create","id":id(800),"contract":1,"fields":{"c":"2"}}]),
        json!([]),
    );
    assert_eq!(
        call(&store, "records.mutate", unrelated)["result"]["status"],
        "committed"
    );
    assert_eq!(store.page(&request).unwrap().records, expected);
    let source = &fixture["ids"]["SeedA"];
    let derived_change = mutation(
        &store,
        3001,
        json!([{"op":"update","id":source,"if_version":version(&store,source),"set":{"amount":"11"},"unset":[]}]),
        json!([]),
    );
    // The command targets an Entry (8). Its changed derived Prefix (9) must
    // invalidate the Prefix-only cursor even though no Prefix was authored.
    assert_eq!(
        call(&store, "records.mutate", derived_change)["result"]["status"],
        "committed"
    );
    assert_eq!(store.page(&request).unwrap_err().code, "query_changed");
    store.check_integrity().unwrap();
}

#[test]
fn private_identity_and_fixture_paths_are_not_public_operations() {
    let dir = Directory::new();
    let store = store(&dir);
    let (f, _) = seed(&store);
    let inspection = store.inspect().unwrap();
    assert!(inspection.get("cursor_key").is_none());
    let output = inspection["roles"][0]["binding"]["output"].clone();
    let get = call(
        &store,
        "records.get",
        json!({"model":store.model().identity(),"id":output}),
    );
    assert!(get["result"].is_null());
    for (n, command) in [
        json!({"op":"create","id":id(400),"contract":11,"fields":{"output":output}}),
        json!({"op":"create","id":id(401),"contract":12,"fields":{}}),
        json!({"op":"update","id":output,"if_version":id(1),"set":{"at":"99"},"unset":[]}),
        json!({"op":"delete","id":output,"if_version":id(1)}),
    ]
    .into_iter()
    .enumerate()
    {
        let response = call(
            &store,
            "records.mutate",
            mutation(&store, 2000 + n as u128, json!([command]), json!([])),
        );
        assert_eq!(kind(&response), "forbidden", "{response}");
        assert!(!response.to_string().contains(output.as_str().unwrap()));
    }
    let request = mutation(
        &store,
        2010,
        json!([{ "op":"update","id":f["ids"]["P"],"if_version":version(&store,&f["ids"]["P"]),"set":{},"unset":[]}]),
        json!([output]),
    );
    assert!(
        call(&store, "records.mutate", request.clone())["result"]["result"]["records"][0]["record"]
            .is_null()
    );
    let mut injected = request;
    injected["trusted"] = json!(true);
    assert_eq!(
        kind(&call(&store, "records.mutate", injected)),
        "invalid_input"
    );
    assert_eq!(
        kind(&call(&store, "model.developer", json!({}))),
        "method_not_found"
    );
    assert_eq!(
        call(&store, "model.describe", json!({}))["result"]["contracts"]
            .as_array()
            .unwrap()
            .len(),
        10
    );
}

#[test]
fn framing_and_request_rejections_cannot_execute_hidden_mutations() {
    let dir = Directory::new();
    let store = store(&dir);
    let request = json!({"jsonrpc":"2.0","method":"records.mutate","params":mutation(&store,1,
        json!([{ "op":"create","id":id(30),"contract":7,"fields":{"at":"1"}}]),json!([]))});
    assert_eq!(
        kind(&rpc::handle(&store, &serde_json::to_vec(&request).unwrap())),
        "invalid_request"
    );
    assert_eq!(
        kind(&rpc::handle(
            &store,
            &serde_json::to_vec(&json!([request])).unwrap()
        )),
        "invalid_request"
    );
    assert_eq!(kind(&rpc::handle(&store,br#"{"jsonrpc":"2.0","id":"x","method":"records.get","params":{"id":"first","id":"second"}}"#)),"parse_error");
    assert!(store.page(&page(&store)).unwrap().exhausted);
    let mut input = vec![b'x'; MAX_REQUEST_BYTES * 2];
    input.push(b'\n');
    input.extend_from_slice(
        br#"{"jsonrpc":"2.0","id":"next","method":"model.describe","params":{}}"#,
    );
    input.push(b'\n');
    let mut output = vec![];
    rpc::serve(&store, Cursor::new(input), &mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    let responses: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(responses.len(), 2);
    assert_eq!(kind(&responses[0]), "request_limit");
    assert_eq!(responses[1]["id"], "next");
    assert!(responses[1].get("result").is_some());
}
