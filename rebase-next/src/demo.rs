//! An ordinary client workflow over the same public operation adapter.

use crate::{
    inspector,
    local::LocalStore,
    model::PreparedModel,
    native_slice::{Context, Error, Result},
    rpc,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path, sync::Arc};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recipe {
    name: String,
    tenant: Uuid,
    actor: Uuid,
    ids: BTreeMap<String, Uuid>,
    commands: Value,
}

fn check(condition: bool, detail: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::new("demo_check", detail))
    }
}
fn io(error: impl std::fmt::Display) -> Error {
    Error::new("io", error.to_string())
}

fn call(
    store: &LocalStore,
    transcript: &mut Vec<Value>,
    label: &str,
    method: &str,
    params: Value,
) -> Result<Value> {
    let request = json!({"jsonrpc":"2.0","id":format!("step-{}",transcript.len()+1),"method":method,"params":params});
    let response = rpc::handle(store, &serde_json::to_vec(&request).map_err(io)?);
    transcript.push(json!({"label":label,"request":request,"response":response}));
    Ok(response)
}

fn values(
    store: &LocalStore,
    recipe: &Recipe,
    transcript: &mut Vec<Value>,
    label: &str,
) -> Result<Value> {
    let mut totals = serde_json::Map::new();
    for name in ["A", "Left", "Right", "Final"] {
        let response = call(
            store,
            transcript,
            &format!("{label}: {name} publication"),
            "roots.read",
            json!({"model":store.model().identity(),"owner":recipe.ids[name],"slot":2,"read":{"kind":"summary"}}),
        )?;
        check(response.get("error").is_none(), "root read failed")?;
        totals.insert(name.into(), response["result"]["value"]["sum"].clone());
    }
    Ok(Value::Object(totals))
}

pub fn run(directory: &Path, model: Arc<PreparedModel>) -> Result<Value> {
    let recipe: Recipe =
        serde_json::from_str(include_str!("../model/fixtures/causal-demo.json")).map_err(io)?;
    // This command owns a newly created directory only. Existing paths fail.
    fs::create_dir(directory).map_err(io)?;
    let path = directory.join("demo.redb");
    let store = LocalStore::create(
        &path,
        model.clone(),
        Context {
            tenant: recipe.tenant,
            actor: recipe.actor,
        },
    )?;
    let mut transcript = vec![];
    let seed_id = Uuid::from_u128(1000);
    let seed = json!({"model":model.identity(),"operation_id":seed_id,"commands":recipe.commands,
        "returning":[recipe.ids["P"],recipe.ids["Q"],recipe.ids["J"]]});
    let seeded = call(
        &store,
        &mut transcript,
        "Create the authored scenario",
        "records.mutate",
        seed.clone(),
    )?;
    check(seeded["result"]["status"] == "committed", "seed rejected")?;
    let initial = values(&store, &recipe, &mut transcript, "Initial")?;
    check(
        initial == json!({"A":"30","Left":"60","Right":"90","Final":"150"}),
        "initial publications",
    )?;
    let query =
        json!({"path":"records.by_id","contract":9,"equals":{"field":"target","value":"20"}});
    let budgeted = call(
        &store,
        &mut transcript,
        "A bounded search can remain unknown",
        "records.exists",
        json!({"model":model.identity(),"query":query,"visit_budget":2,"cursor":null}),
    )?;
    check(
        budgeted["result"]["answer"] == "unknown",
        "bounded existence",
    )?;
    let swap_id = Uuid::from_u128(1001);
    let swap = json!({"model":model.identity(),"operation_id":swap_id,"commands":[
        {"op":"update","id":recipe.ids["MP"],"if_version":"1","set":{"at":"20"},"unset":[]},
        {"op":"update","id":recipe.ids["MQ"],"if_version":"1","set":{"at":"10"},"unset":[]}
    ],"returning":[recipe.ids["P"],recipe.ids["Q"],recipe.ids["J"]]});
    let swapped = call(
        &store,
        &mut transcript,
        "Move both prefix readers atomically",
        "records.mutate",
        swap,
    )?;
    check(swapped["result"]["status"] == "committed", "swap rejected")?;
    check(
        swapped["result"]["result"]["records"][0]["record"]["derived"]
            == json!({"at":"20","before":"30","delta":"-10"}),
        "moved prefix result",
    )?;
    let after = values(&store, &recipe, &mut transcript, "After the move")?;
    check(
        after == json!({"A":"20","Left":"40","Right":"60","Final":"100"}),
        "moved publications",
    )?;
    let stale = call(
        &store,
        &mut transcript,
        "Reject a stale editor version",
        "records.mutate",
        json!({"model":model.identity(),
        "operation_id":Uuid::from_u128(1002),"commands":[{"op":"update","id":recipe.ids["MP"],"if_version":"1","set":{"at":"30"},"unset":[]}],"returning":[]}),
    )?;
    check(
        stale["error"]["data"]["kind"] == "stale_version",
        "stale-version rejection",
    )?;
    let feedback = call(
        &store,
        &mut transcript,
        "Reject zero-valued feedback",
        "records.mutate",
        json!({"model":model.identity(),
        "operation_id":Uuid::from_u128(1003),"commands":[{"op":"update","id":recipe.ids["J"],"if_version":"2",
            "set":{"feedback":{"account":recipe.ids["A"],"at":"5"}},"unset":[]}],"returning":[]}),
    )?;
    check(
        feedback["error"]["data"]["kind"] == "feedback",
        "feedback rejection",
    )?;
    let replay = call(
        &store,
        &mut transcript,
        "Reconcile the original operation without applying it again",
        "records.mutate",
        seed,
    )?;
    check(
        replay["result"]["replayed"] == true
            && replay["result"]["result"] == seeded["result"]["result"],
        "receipt replay",
    )?;
    let receipt = call(
        &store,
        &mut transcript,
        "Read the committed swap receipt",
        "operations.status",
        json!({"model":model.identity(),"operation_id":swap_id}),
    )?;
    check(
        receipt["result"]["result"] == swapped["result"]["result"],
        "operation status",
    )?;
    let before_reopen = store.inspect()?;
    check(
        before_reopen["revision"] == "2" && before_reopen["receipt_count"] == 2,
        "rejections/replay preserve revision and receipts",
    )?;
    drop(store);
    let reopened = LocalStore::open(&path, model.clone())?;
    let mut snapshot = reopened.inspect()?;
    check(snapshot == before_reopen, "reopened state differs")?;
    snapshot["labels"] = json!(recipe.ids);
    let after_reopen = values(&reopened, &recipe, &mut transcript, "After reopening")?;
    check(after_reopen == after, "reopened public results differ")?;
    let listed = call(
        &reopened,
        &mut transcript,
        "List the public sources",
        "records.page",
        json!({"model":model.identity(),
        "query":{"path":"records.by_id","contract":null,"equals":null},"limit":32,"visit_budget":128,"cursor":null}),
    )?;
    check(
        listed["result"]["records"]
            .as_array()
            .is_some_and(|r| r.len() == 14)
            && listed["result"]["exhausted"] == true,
        "public index result",
    )?;
    for (name, value) in [
        ("public-model.json", model.public_catalog()),
        ("developer-model.json", model.developer_catalog()),
        ("inspection.json", snapshot.clone()),
        ("transcript.json", json!(transcript)),
    ] {
        fs::write(
            directory.join(name),
            serde_json::to_vec_pretty(&value).map_err(io)?,
        )
        .map_err(io)?;
    }
    fs::write(
        directory.join("inspect.html"),
        inspector::render(&model, Some(&snapshot), &transcript)?,
    )
    .map_err(io)?;
    let report = json!({"status":"passed","demo":recipe.name,"model":model.identity(),"store":path,
        "initial":initial,"after_move":after,"reopened_equal":true,"revision":"2","public_sources":14,"private_outputs":5,
        "confirmed_receipts":2,"checks":["exact moved-prefix results","reporting diamond","budgeted existence",
            "stale-version rejection","zero-feedback rejection","receipt replay/status","unchanged rejections","restart","public index"],
        "artifacts":{"inspector":directory.join("inspect.html"),"transcript":directory.join("transcript.json"),
            "public_model":directory.join("public-model.json"),"developer_model":directory.join("developer-model.json")}});
    fs::write(
        directory.join("result.json"),
        serde_json::to_vec_pretty(&report).map_err(io)?,
    )
    .map_err(io)?;
    Ok(report)
}
