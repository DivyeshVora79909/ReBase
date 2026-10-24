use rebase_semantic_proof::{
    binding::{Binding, Calculation},
    demo, identity, inspector, json,
    model::{Prepared, PreparedModel},
    models::effect_demo::EffectDemo,
    models::equipment::Equipment,
    models::invoicing::Invoicing,
    models::measurement::Measurement,
    models::quantity::Quantity,
    native_slice::Context,
    rpc, server,
    storage::target::{BackendKind, BackendTarget},
};
use std::{
    error::Error,
    fs::File,
    io::{self, Read},
    path::Path,
    sync::Arc,
};
use uuid::Uuid;

fn identity(text: &str) -> Result<Uuid, Box<dyn Error>> {
    let id = Uuid::parse_str(text)?;
    if id.to_string() != text {
        return Err("canonical UUID required".into());
    }
    Ok(id)
}

fn read_json(path: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    let mut bytes = vec![];
    File::open(path)?
        .take((json::MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    Ok(json::parse(&bytes)?)
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut raw: Vec<_> = std::env::args().skip(1).collect();
    let mut target = BackendTarget::default();
    let mut selected = "calculation".to_owned();
    while !raw.is_empty() {
        match raw[0].as_str() {
            "--model" => {
                selected = raw
                    .get(1)
                    .ok_or("--model requires a compiled model name")?
                    .clone();
                raw.drain(0..=1);
            }
            "--backend" => {
                target.kind = match raw
                    .get(1)
                    .ok_or("--backend requires redb, foundationdb or surrealkv")?
                    .as_str()
                {
                    "redb" => BackendKind::Redb,
                    "foundationdb" => BackendKind::FoundationDb,
                    "surrealkv" => BackendKind::SurrealKv,
                    _ => return Err("--backend requires redb, foundationdb or surrealkv".into()),
                };
                raw.drain(0..=1);
            }
            "--cluster-file" => {
                target.cluster_file =
                    Some(raw.get(1).ok_or("--cluster-file requires a path")?.clone());
                raw.drain(0..=1);
            }
            _ => break,
        }
    }
    let args = raw;
    if args.is_empty()
        || args == ["--help"]
        || matches!(args.as_slice(), [option, _, help] if option == "--model" && help == "--help")
    {
        println!(
            "ReBase Next backend\nLeading options may be composed in any order: --model calculation|equipment|invoicing|measurement|effect-demo|quantity, --backend redb|foundationdb|surrealkv, --cluster-file <path>. Defaults: calculation and redb.\n\n  rebase-next version\n  rebase-next check <store>\n  rebase-next backup <store> <new-backup.json>\n  rebase-next receipts archive <store> <new-archive.json>\n  rebase-next restore <backup.json> <new-store>\n  rebase-next reset <store> --expect-store <uuid>\n  rebase-next model public\n  rebase-next model developer\n  rebase-next model view\n  rebase-next model explain <name|code>\n  rebase-next model validate <code> <input.json>\n  rebase-next fixture list\n  rebase-next fixture plan <name> --namespace <uuid>\n  rebase-next init <new-store> --tenant <uuid> --actor <uuid>\n  rebase-next rpc <store>\n  rebase-next serve <store> --config <server.json>\n  rebase-next auth issue <server.json> <token-request.json> <private-key.pem>\n  rebase-next inspect <store> [--html]\n  rebase-next demo <new-directory>"
        );
        return Ok(());
    }
    if target.kind != BackendKind::FoundationDb && target.cluster_file.is_some() {
        return Err("--cluster-file is only valid with --backend foundationdb".into());
    }
    target.ensure_available()?;
    let selected = selected.as_str();
    let arguments = args.as_slice();
    if let [command, directory] = arguments
        && command == "demo"
    {
        if selected != "calculation" || target.kind != BackendKind::Redb {
            return Err(
                "demo uses the calculation model and redb; use the ordinary client for other targets"
                    .into(),
            );
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&demo::run(
                Path::new(directory),
                Arc::new(PreparedModel::load()?)
            )?)?
        );
        return Ok(());
    }
    match selected {
        "calculation" => run_model::<Calculation>(arguments, &target),
        "equipment" => run_model::<Equipment>(arguments, &target),
        "invoicing" => run_model::<Invoicing>(arguments, &target),
        "measurement" => run_model::<Measurement>(arguments, &target),
        "effect-demo" => run_model::<EffectDemo>(arguments, &target),
        "quantity" => run_model::<Quantity>(arguments, &target),
        _ => Err(
            "unknown compiled model; choose calculation, equipment, invoicing, measurement, effect-demo or quantity"
                .into(),
        ),
    }
}

fn run_model<B: Binding>(args: &[String], target: &BackendTarget) -> Result<(), Box<dyn Error>> {
    let model = Arc::new(Prepared::<B>::load()?);
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["model", "public"] => model.public_catalog(),
        ["fixture", "list"] => B::fixture_catalog(),
        ["fixture", "plan", name, "--namespace", namespace] => {
            B::fixture_plan(&model, name, identity(namespace)?)?
        }
        ["version"] => {
            serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"model":model.identity(),"store_format":rebase_semantic_proof::local::STORE_FORMAT})
        }
        ["check", path] => target.open(path, model)?.check_integrity()?,
        ["backup", path, destination] => target.open(path, model)?.backup(destination)?,
        ["receipts", "archive", path, destination] => {
            target.open(path, model)?.archive_receipts(destination)?
        }
        ["restore", backup, destination] => target.restore(backup, destination, model)?,
        ["reset", path, "--expect-store", store] => {
            target.open(path, model)?.reset(identity(store)?)?
        }
        [
            "effects",
            "retry",
            path,
            execution,
            "--if-revision",
            revision,
        ] => {
            let store = target.open(path, model)?;
            store.check_integrity()?;
            store.retry_effect(identity(execution)?, revision.parse()?)?
        }
        ["model", "developer"] => model.developer_catalog(),
        ["model", "view"] => {
            println!("{}", inspector::render(&model, None, &[])?);
            return Ok(());
        }
        ["model", "explain", selector] => model.explain(selector)?,
        ["model", "validate", code, path] => {
            let mut bytes = vec![];
            File::open(path)?
                .take((json::MAX_REQUEST_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            let input = json::parse(&bytes)?;
            model.validate(code.parse()?, &input)?;
            serde_json::json!({"status":"valid","model":model.identity(),"input":input})
        }
        ["init", path, "--tenant", tenant, "--actor", actor] => {
            let store = target.create(
                path,
                model,
                Context {
                    tenant: identity(tenant)?,
                    actor: identity(actor)?,
                },
            )?;
            serde_json::json!({"status":"created","path":path,"model":store.model().identity(),"tenant":tenant,"actor":actor})
        }
        ["rpc", path] => {
            let store = target.open(path, model)?;
            rpc::serve(&store, io::stdin().lock(), io::stdout().lock())?;
            return Ok(());
        }
        ["serve", path, "--config", config] => {
            let config: server::ServerConfig = serde_json::from_value(read_json(config)?)?;
            let store = Arc::new(target.open(path, model)?);
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?
                .block_on(server::serve(store, config))?;
            return Ok(());
        }
        ["auth", "issue", config, request, private_key] => {
            let config: server::ServerConfig = serde_json::from_value(read_json(config)?)?;
            let request: identity::TokenRequest = serde_json::from_value(read_json(request)?)?;
            let mut pem = vec![];
            File::open(private_key)?.take(4097).read_to_end(&mut pem)?;
            if pem.len() > 4096 {
                return Err("private key byte limit".into());
            }
            let token = identity::issue(&config.identity, &request, &pem)?;
            println!("{token}");
            return Ok(());
        }
        ["inspect", path] => target.open(path, model)?.inspect()?,
        ["inspect", path, "--html"] => {
            let store = target.open(path, model.clone())?;
            println!(
                "{}",
                inspector::render(&model, Some(&store.inspect()?), &[])?
            );
            return Ok(());
        }
        _ => return Err("unsupported command; see --help".into()),
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn main() -> std::process::ExitCode {
    #[cfg(feature = "foundationdb")]
    let _fdb_network = if std::env::args()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| pair[0] == "--backend" && pair[1] == "foundationdb")
    {
        Some(unsafe { foundationdb::boot() })
    } else {
        None
    };
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
