//! G7.5 scoped coordination and retention over actual adapter transactions.
use rebase_semantic_proof::{
    native_slice::{Error, Result},
    storage,
};
use serde_json::json;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err(Error::new(
            "invalid_input",
            "usage: g7_coordination redb|foundationdb|surrealkv <fresh directory|cluster file>",
        ));
    }
    let backend = args[1].clone();
    let location = args[2].clone();
    #[cfg(feature = "foundationdb")]
    let _network = if backend == "foundationdb" {
        Some(unsafe { foundationdb::boot() })
    } else {
        None
    };
    let namespace = format!("rebase-g75-{}", uuid::Uuid::new_v4());
    if backend != "foundationdb" {
        std::fs::create_dir(&location).map_err(|e| Error::new("storage", e.to_string()))?;
    }
    let output_backend = backend.clone();
    let output_namespace = namespace.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| Error::new("runtime", e.to_string()))?;
    let result = runtime.block_on(async move {
        tokio::task::spawn_blocking(move || {
            let factory = |family: &str| match backend.as_str() {
                "redb" => {
                    let path = std::path::Path::new(&location).join(format!("{family}.redb"));
                    if path.exists() {
                        storage::Database::open(path)
                    } else {
                        storage::Database::create(path)
                    }
                }
                #[cfg(feature = "foundationdb")]
                "foundationdb" => storage::foundationdb::connect(
                    Some(&location),
                    format!("{namespace}/{family}").as_bytes(),
                ),
                #[cfg(feature = "surrealkv")]
                "surrealkv" => {
                    storage::surrealkv::connect(std::path::Path::new(&location).join(family))
                }
                _ => Err(Error::new("invalid_input", "backend feature not compiled")),
            };
            let concurrent = backend != "redb";
            let coordination = storage::coordination_checks::run(factory, concurrent)?;
            let lifecycle = storage::lifecycle_checks::run(factory, concurrent)?;
            Ok::<_, Error>(json!({"coordination":coordination,"lifecycle":lifecycle}))
        })
        .await
        .map_err(|e| Error::new("runtime", e.to_string()))
    })??;
    println!(
        "{}",
        json!({"status":"passed","backend":output_backend,"namespace":output_namespace,"result":result})
    );
    Ok(())
}
