use rebase_semantic_proof::{
    binding::{Binding, Calculation},
    demo, identity, inspector, json, lifecycle,
    local::Store,
    model::{Prepared, PreparedModel},
    models::equipment::Equipment,
    models::invoicing::Invoicing,
    models::measurement::Measurement,
    native_slice::Context,
    rpc, server,
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
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty()
        || args == ["--help"]
        || matches!(args.as_slice(), [option, _, help] if option == "--model" && help == "--help")
    {
        println!(
            "ReBase Next backend\nSelect a compiled model with --model calculation|equipment|invoicing|measurement before the command (default calculation).\n\n  rebase-next version\n  rebase-next check <store.redb>\n  rebase-next backup <store.redb> <new-backup.json>\n  rebase-next receipts archive <store.redb> <new-archive.json>\n  rebase-next restore <backup.json> <new-store.redb>\n  rebase-next reset <store.redb> --expect-store <uuid>\n  rebase-next model public\n  rebase-next model developer\n  rebase-next model view\n  rebase-next model explain <name|code>\n  rebase-next model validate <code> <input.json>\n  rebase-next fixture list\n  rebase-next fixture plan <name> --namespace <uuid>\n  rebase-next init <new.redb> --tenant <uuid> --actor <uuid>\n  rebase-next rpc <store.redb>\n  rebase-next serve <store.redb> --config <server.json>\n  rebase-next auth issue <server.json> <token-request.json> <private-key.pem>\n  rebase-next inspect <store.redb> [--html]\n  rebase-next demo <new-directory>"
        );
        return Ok(());
    }
    let (selected, arguments) = if args.first().is_some_and(|s| s == "--model") {
        (
            args.get(1)
                .ok_or("--model requires a compiled model name")?
                .as_str(),
            &args[2..],
        )
    } else {
        ("calculation", args.as_slice())
    };
    if let [command, directory] = arguments
        && command == "demo"
    {
        if selected != "calculation" {
            return Err("use the selected model's fixture plan with the ordinary client".into());
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
        "calculation" => run_model::<Calculation>(arguments),
        "equipment" => run_model::<Equipment>(arguments),
        "invoicing" => run_model::<Invoicing>(arguments),
        "measurement" => run_model::<Measurement>(arguments),
        _ => Err(
            "unknown compiled model; choose calculation, equipment, invoicing or measurement"
                .into(),
        ),
    }
}

fn run_model<B: Binding>(args: &[String]) -> Result<(), Box<dyn Error>> {
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
        ["check", path] => Store::<B>::open(path, model)?.check_integrity()?,
        ["backup", path, destination] => Store::<B>::open(path, model)?.backup(destination)?,
        ["receipts", "archive", path, destination] => {
            Store::<B>::open(path, model)?.archive_receipts(destination)?
        }
        ["restore", backup, destination] => lifecycle::restore(backup, destination, model)?,
        ["reset", path, "--expect-store", store] => {
            Store::<B>::open(path, model)?.reset(identity(store)?)?
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
            let store = Store::<B>::create_secured(
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
            let store = Store::<B>::open(path, model)?;
            rpc::serve(&store, io::stdin().lock(), io::stdout().lock())?;
            return Ok(());
        }
        ["serve", path, "--config", config] => {
            let config: server::ServerConfig = serde_json::from_value(read_json(config)?)?;
            let store = Arc::new(Store::<B>::open(path, model)?);
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
        ["inspect", path] => Store::<B>::open(path, model)?.inspect()?,
        ["inspect", path, "--html"] => {
            let store = Store::<B>::open(path, model.clone())?;
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

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
