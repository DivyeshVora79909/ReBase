//! Real adapter application acceptance. Supply backend and an isolated location.
use rebase_semantic_proof::{
    native_slice::{Error, Result},
    storage,
};
use serde_json::json;

fn main() -> Result<()> {
    let backend = std::env::args().nth(1).expect("backend argument required");
    let location = std::env::args()
        .nth(2)
        .expect("cluster file or destination directory required");
    #[cfg(feature = "foundationdb")]
    let _network = if backend == "foundationdb" {
        Some(unsafe { foundationdb::boot() })
    } else {
        None
    };
    let namespace = format!("rebase-g7-application-{}", uuid::Uuid::new_v4());
    if backend != "foundationdb" {
        std::fs::create_dir_all(&location).map_err(|e| Error::new("storage", e.to_string()))?;
    }
    let concurrent = backend != "redb";
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
            let application = storage::application_checks::run(factory, concurrent)?;
            let effects = rebase_semantic_proof::effects::conformance::run(factory)?;
            let predicates = storage::concurrency_checks::run(factory, concurrent)?;
            Ok::<_, Error>(
                json!({"application":application,"effects":effects,"predicates":predicates}),
            )
        })
        .await
        .map_err(|e| Error::new("runtime", e.to_string()))
    })??;
    println!(
        "{}",
        json!({"backend":output_backend,"namespace":output_namespace,"result":result})
    );
    Ok(())
}
