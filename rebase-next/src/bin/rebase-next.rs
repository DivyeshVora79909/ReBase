use std::{error::Error, path::Path};

fn run() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [mode] if mode == "host" => rebase_semantic_proof::host::run_stdio()?,
        [mode, configuration] if mode == "serve" => {
            rebase_semantic_proof::host::run_service_file(Path::new(configuration))?;
        }
        _ => {
            return Err(
                "usage: rebase-next host | rebase-next serve <absolute-service.json>".into(),
            );
        }
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
