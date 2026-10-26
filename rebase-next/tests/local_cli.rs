use serde_json::{Value, json};
use std::{fs, io::Write, path::PathBuf, sync::Arc};
use uuid::Uuid;

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn rpc(directory: &Directory, requests: &[Value]) -> Vec<Value> {
    let store = rebase_semantic_proof::local::LocalStore::open(
        directory.0.join("example/demo.redb"),
        Arc::new(rebase_semantic_proof::model::PreparedModel::load().unwrap()),
    )
    .unwrap();
    let mut input = Vec::new();
    for request in requests {
        writeln!(input, "{}", request).unwrap();
    }
    let mut output = Vec::new();
    rebase_semantic_proof::rpc::serve(&store, std::io::Cursor::new(input), &mut output).unwrap();
    String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn native_demo_offline_export_operation_api_and_reopen_are_usable_together() {
    let dir = Directory(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/local-cli-tests")
            .join(Uuid::new_v4().to_string()),
    );
    fs::create_dir_all(&dir.0).unwrap();
    let model = Arc::new(rebase_semantic_proof::model::PreparedModel::load().unwrap());
    let catalog = model.public_catalog();
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
    let result = rebase_semantic_proof::demo::run(&dir.0.join("example"), model.clone()).unwrap();
    assert_eq!(result["model"], catalog["model"]);
    assert_eq!(
        result["after_move"],
        json!({"A":"20","Left":"40","Right":"60","Final":"100"})
    );
    let html = fs::read_to_string(dir.0.join("example/inspect.html")).unwrap();
    assert!(
        html.contains("Settled snapshot") && html.contains("PRIVATE") && !html.contains("<script")
    );
    let before = fs::read(dir.0.join("example/demo.redb")).unwrap();
    assert!(rebase_semantic_proof::demo::run(&dir.0.join("example"), model).is_err());
    assert_eq!(fs::read(dir.0.join("example/demo.redb")).unwrap(), before);
    let source = "00000000-0000-4000-8000-000000000060";
    let account = "00000000-0000-4000-8000-000000000030";
    let operation = Uuid::new_v4();
    let current = rpc(
        &dir,
        &[
            json!({"jsonrpc":"2.0","id":"session","method":"session.describe","params":{}}),
            json!({"jsonrpc":"2.0","id":"record","method":"records.get","params":{"model":catalog["model"],"id":source}}),
        ],
    );
    let context = current[0]["result"]["operation_context"].clone();
    let version = current[1]["result"]["version"].clone();
    assert!(Uuid::parse_str(version.as_str().unwrap()).is_ok());
    let update = json!({"jsonrpc":"2.0","id":"edit","method":"records.mutate","params":{
        "model":catalog["model"],"context":context,"operation_id":operation,"commands":[{"op":"update","id":source,
        "if_version":version,"set":{"target":"25"},"unset":[]}],"returning":[source]}});
    let root = json!({"jsonrpc":"2.0","id":"root","method":"roots.read","params":{
        "model":catalog["model"],"owner":account,"slot":2,"read":{"kind":"summary"}}});
    let response = rpc(&dir, &[update.clone(), root.clone()]);
    assert_eq!(response.len(), 2);
    assert_eq!(response[0]["result"]["status"], "committed");
    assert_ne!(response[0]["result"]["result"]["revision"], version);
    assert_eq!(
        response[0]["result"]["result"]["revision"],
        response[0]["result"]["result"]["records"][0]["record"]["version"]
    );
    assert_eq!(
        response[0]["result"]["result"]["records"][0]["record"]["derived"]["delta"],
        "-5"
    );
    assert_eq!(response[1]["result"]["value"]["sum"], "25");
    let reopened = rpc(&dir, &[update, root]);
    assert_eq!(reopened[0]["result"]["replayed"], true);
    assert_eq!(
        reopened[0]["result"]["result"],
        response[0]["result"]["result"]
    );
    assert_eq!(reopened[1], response[1]);
}
