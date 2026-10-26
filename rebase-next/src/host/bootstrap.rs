//! Minimal standalone service startup over the same typed native preparation.
use super::*;
use std::{fs::File, io::Read};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceConfiguration {
    format: String,
    model: String,
    backend: BackendConfig,
    target: Value,
    service: crate::server::ServerConfig,
}

/// Open one explicitly identified existing store and serve without Node/Python.
/// The FDB network owner outlives the selected store and the drained service.
pub fn run_service_file(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error::new(
            "invalid_config",
            "absolute service configuration path required",
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(local::storage)?
        .take((json::MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(local::storage)?;
    let config: ServiceConfiguration = bind(json::parse(&bytes)?, "invalid_config")?;
    if config.format != "rebase-service-1"
        || !MODELS.contains(&config.model.as_str())
        || config.target["mode"] != "open"
    {
        return Err(Error::new(
            "invalid_config",
            "explicit service format, model and open target required",
        ));
    }
    backend::validate(&config.backend)?;
    backend::validate_target(&config.backend, &config.target, &BTreeSet::new())?;
    let target: Target = bind(config.target, "invalid_config")?;
    let Target::Open { expect_store, .. } = &target else {
        return Err(Error::new("invalid_config", "service target must be open"));
    };
    let expected = *expect_store;
    #[cfg(feature = "foundationdb")]
    let network = Arc::new(std::sync::Mutex::new(None));
    let selected = prepare_selected(
        &config.model,
        Some(target),
        config.backend,
        Some(&config.service),
        #[cfg(feature = "foundationdb")]
        network.clone(),
    )?;
    selected.serve(config.service, expected)
}
