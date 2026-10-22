//! Observe the real local adapter using explicit allocator inputs. Semantic
//! expectations and complete-table acceptance live in the independent checker.

use rebase_semantic_proof::{
    local::{LocalStore, Mutation},
    model::PreparedModel,
    native_slice::{Command, Context, Error as NativeError},
};
use serde_json::{Value, json};
use std::{error::Error, fs, path::PathBuf, sync::Arc};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn mutate(
    store: &LocalStore,
    request: &Mutation,
    allocations: &Value,
) -> std::result::Result<Value, NativeError> {
    let mut ids: std::vec::IntoIter<Uuid> =
        serde_json::from_value::<Vec<Uuid>>(allocations.clone())
            .map_err(|e| NativeError::new("invalid_input", e.to_string()))?
            .into_iter();
    store.mutate_with_ids(request, &mut || {
        ids.next()
            .ok_or_else(|| NativeError::new("allocation_exhausted", "explicit check allocator"))
    })
}

fn run() -> Result<()> {
    let model = Arc::new(PreparedModel::load()?);
    let fixtures: Value =
        serde_json::from_str(include_str!("../research/fixtures/causal-slice.json"))?;
    let context = Context {
        tenant: serde_json::from_value(fixtures["tenant"].clone())?,
        actor: serde_json::from_value(fixtures["actor"].clone())?,
    };
    let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/local-prototype");
    fs::create_dir_all(&parent)?;
    let output = parent.join(format!(
        "run-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    fs::create_dir(&output)?;
    let selected = [
        "swap",
        "disable_reenable",
        "delete_and_new_lifetime",
        "noncyclic_zero_output",
        "historical_floor_after_settlement",
        "delete_account_and_move_whole_causal_role",
        "public_output_create_forbidden",
        "coincident_query_slots",
        "allocation_retries",
    ];
    let mut cases = vec![];
    for case in fixtures["cases"].as_array().ok_or("cases")? {
        let name = case["name"].as_str().ok_or("case name")?;
        if !selected.contains(&name) {
            continue;
        }
        let directory = output.join(name);
        fs::create_dir(&directory)?;
        let path = directory.join("check.redb");
        let store = LocalStore::create(&path, model.clone(), context)?;
        let base = case["base"].as_str().ok_or("base")?;
        let base_commands: Vec<Command> = serde_json::from_value(fixtures["bases"][base].clone())?;
        let request = Mutation {
            model: model.identity().into(),
            operation_id: Uuid::from_u128(5000),
            returning: base_commands.iter().map(Command::id).collect(),
            commands: base_commands,
        };
        let base_allocations = fixtures["base_allocations"]
            .get(base)
            .cloned()
            .unwrap_or(json!([]));
        let initial_result = mutate(&store, &request, &base_allocations)?;
        let initial = store.observe_for_verification()?;
        let mut operations = vec![];
        for (i, operation) in case["operations"]
            .as_array()
            .ok_or("operations")?
            .iter()
            .enumerate()
        {
            let request = Mutation {
                model: model.identity().into(),
                operation_id: Uuid::from_u128(5001 + i as u128),
                commands: serde_json::from_value(operation["commands"].clone())?,
                returning: ["P", "Q", "J", "A"]
                    .iter()
                    .map(|name| serde_json::from_value(fixtures["ids"][name].clone()))
                    .collect::<std::result::Result<_, _>>()?,
            };
            let allocations = operation.get("allocations").cloned().unwrap_or(json!([]));
            let result = mutate(&store, &request, &allocations);
            let after = store.observe_for_verification()?;
            let observed = match result {
                Ok(result) => {
                    let replay = mutate(&store, &request, &json!([]))?;
                    let replay_unchanged = store.observe_for_verification()? == after;
                    let status = store.operation_status(model.identity(), request.operation_id)?;
                    let mut changed = request.clone();
                    changed.returning.clear();
                    let conflict = mutate(&store, &changed, &json!([]))
                        .err()
                        .ok_or("expected operation conflict observation")?;
                    let conflict_unchanged = store.observe_for_verification()? == after;
                    json!({"request":request,"status":"committed","returned":result,"after":after,
                        "replay":replay,"replay_unchanged":replay_unchanged,"receipt":status,
                        "conflict_code":conflict.code,"conflict_unchanged":conflict_unchanged})
                }
                Err(error) => {
                    json!({"request":request,"status":"rejected","code":error.code,"returned":null,"after":after,
                    "receipt":store.operation_status(model.identity(),request.operation_id)?})
                }
            };
            operations.push(observed);
        }
        let final_image = store.observe_for_verification()?;
        drop(store);
        let reopened = LocalStore::open(&path, model.clone())?;
        let reopened_image = reopened.observe_for_verification()?;
        drop(reopened);
        fs::remove_dir_all(&directory)?;
        cases.push(json!({"name":name,"base_request":request,"base_result":initial_result,"initial":initial,
            "operations":operations,"reopened_equal":final_image==reopened_image}));
    }
    let path = output.join("local-observations.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&json!({"format":"rebase-local-adapter-run-1",
        "model":model.identity(),"developer_catalog":model.developer_catalog(),"cases":cases}))?,
    )?;
    println!(
        "Observed {} local adapter cases; independent acceptance still required.\n{}",
        cases.len(),
        path.display()
    );
    Ok(())
}

fn main() -> Result<()> {
    run()
}
