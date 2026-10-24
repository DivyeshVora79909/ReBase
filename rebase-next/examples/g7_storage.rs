//! Real backend execution of the common byte-storage interleaving oracle.
use rebase_semantic_proof::{
    native_slice::{Error, Result},
    storage,
};
use serde_json::json;

fn connect(backend: &str, location: &str, _namespace: &[u8]) -> Result<storage::Database> {
    match backend {
        "redb" => Ok(storage::Database::from_redb(
            redb::Database::create(location)
                .map_err(|error| Error::new("storage", error.to_string()))?,
        )),
        #[cfg(feature = "foundationdb")]
        "foundationdb" => storage::foundationdb::connect(Some(location), _namespace),
        #[cfg(feature = "surrealkv")]
        "surrealkv" => storage::surrealkv::connect(location),
        _ => Err(Error::new(
            "invalid_input",
            format!("backend not compiled: {backend}"),
        )),
    }
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 && !(args.len() == 5 && args[3] == "--verify-namespace") {
        return Err(Error::new(
            "invalid_input",
            "usage: g7_storage redb|foundationdb|surrealkv <fresh path|cluster file>",
        ));
    }
    let backend = args[1].clone();
    let location = args[2].clone();
    let namespace = if args.len() == 5 {
        args[4].clone()
    } else {
        format!("rebase-g7-conformance-{}", uuid::Uuid::new_v4())
    };
    #[cfg(feature = "foundationdb")]
    let _network = if backend == "foundationdb" {
        Some(unsafe { foundationdb::boot() })
    } else {
        None
    };
    let db = connect(&backend, &location, namespace.as_bytes())?;
    if args.len() == 5 {
        let digest = storage::conformance::fingerprint(&db)?;
        drop(db);
        println!(
            "{}",
            json!({"status":"passed","backend":backend,"namespace":namespace,"image_sha256":digest})
        );
        return Ok(());
    }
    let optimistic = backend != "redb";
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| Error::new("runtime", error.to_string()))?;
    let result = runtime.block_on(async move {
        tokio::task::spawn_blocking(move || storage::conformance::run(&db, optimistic))
            .await
            .map_err(|error| Error::new("runtime", error.to_string()))?
    })?;
    // The first Store is dropped inside the blocking task before reopen. This
    // checks logical persistence, without inventing a database migration.
    let db = connect(&backend, &location, namespace.as_bytes())?;
    let digest = storage::conformance::fingerprint(&db)?;
    if result["final_image_sha256"] != digest {
        return Err(Error::new(
            "conformance_failed",
            "reopen changed complete logical tables",
        ));
    }
    drop(db);
    println!(
        "{}",
        json!({"status":"passed","backend":backend,"namespace":namespace,
        "conformance":result,"reopen":{"status":"passed","image_sha256":digest},
        "concurrency":if optimistic{"controlled optimistic interleavings; no automatic retry"}else{"serialized writer; optimistic conflict schedules do not apply"}})
    );
    Ok(())
}
