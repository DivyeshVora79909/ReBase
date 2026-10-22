use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};
use uuid::Uuid;

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn rpc(directory: &Directory, requests: &[Value]) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rebase-next"))
        .args(["rpc", "example/demo.redb"])
        .current_dir(&directory.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut input = child.stdin.take().unwrap();
        for request in requests {
            writeln!(input, "{}", request).unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn binary_demo_offline_export_process_api_and_restart_are_usable_together() {
    let dir = Directory(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/local-cli-tests")
            .join(Uuid::new_v4().to_string()),
    );
    fs::create_dir_all(&dir.0).unwrap();
    let offline = Command::new(env!("CARGO_BIN_EXE_rebase-next"))
        .args(["model", "public"])
        .current_dir(&dir.0)
        .output()
        .unwrap();
    assert!(offline.status.success());
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
    let catalog: Value = serde_json::from_slice(&offline.stdout).unwrap();
    let demo = Command::new(env!("CARGO_BIN_EXE_rebase-next"))
        .args(["demo", "example"])
        .current_dir(&dir.0)
        .output()
        .unwrap();
    assert!(
        demo.status.success(),
        "{}",
        String::from_utf8_lossy(&demo.stderr)
    );
    let result: Value = serde_json::from_slice(&demo.stdout).unwrap();
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
    let refused = Command::new(env!("CARGO_BIN_EXE_rebase-next"))
        .args(["demo", "example"])
        .current_dir(&dir.0)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert_eq!(fs::read(dir.0.join("example/demo.redb")).unwrap(), before);
    let source = "00000000-0000-4000-8000-000000000060";
    let account = "00000000-0000-4000-8000-000000000030";
    let operation = Uuid::new_v4();
    let update = json!({"jsonrpc":"2.0","id":"edit","method":"records.mutate","params":{
        "model":catalog["model"],"operation_id":operation,"commands":[{"op":"update","id":source,
        "if_version":"2","set":{"target":"25"},"unset":[]}],"returning":[source]}});
    let root = json!({"jsonrpc":"2.0","id":"root","method":"roots.read","params":{
        "model":catalog["model"],"owner":account,"slot":2,"read":{"kind":"summary"}}});
    let response = rpc(&dir, &[update.clone(), root.clone()]);
    assert_eq!(response.len(), 2);
    assert_eq!(response[0]["result"]["result"]["revision"], "3");
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
