//! Explicit backend targets and process-owned optional adapter lifetime.
use super::*;
use crate::storage::target::{BackendKind, BackendTarget};
pub(super) fn validate(backend: &BackendConfig) -> Result<()> {
    if backend.kind == "foundationdb" && backend.cluster_file.is_null() {
        return Err(Error::new(
            "invalid_config",
            "explicit FDB cluster file required",
        ));
    }
    let available = match backend.kind.as_str() {
        "redb" => true,
        "surrealkv" => cfg!(feature = "surrealkv"),
        "foundationdb" => cfg!(feature = "foundationdb"),
        _ => return Err(Error::new("invalid_config", "unknown backend")),
    };
    if backend.kind != "foundationdb" && !backend.cluster_file.is_null() {
        return Err(Error::new(
            "invalid_config",
            "cluster file only valid for FDB",
        ));
    }
    if !backend.cluster_file.is_null() {
        let path = backend
            .cluster_file
            .as_str()
            .ok_or_else(|| Error::new("invalid_config", "cluster path"))?;
        super::operations::absolute(path)
            .map_err(|_| Error::new("invalid_config", "cluster path"))?;
    }
    if !available {
        return Err(Error::new(
            "unsupported_backend",
            "backend feature not compiled",
        ));
    }
    Ok(())
}
pub(super) fn validate_target(
    backend: &BackendConfig,
    target: &Value,
    grants: &BTreeSet<String>,
) -> Result<()> {
    if target.is_null() {
        return Ok(());
    }
    let mode = target["mode"]
        .as_str()
        .ok_or_else(|| Error::new("invalid_config", "target mode"))?;
    let address = if backend.kind == "foundationdb" {
        "namespace"
    } else {
        "path"
    };
    let expected = match mode {
        "create" => vec!["mode", address, "tenant", "actor"],
        "open" | "recover" => vec!["mode", address, "expect_store"],
        _ => return Err(Error::new("invalid_config", "target mode")),
    };
    let object = target
        .as_object()
        .ok_or_else(|| Error::new("invalid_config", "target object"))?;
    if object.len() != expected.len() || expected.iter().any(|k| !object.contains_key(*k)) {
        return Err(Error::new("invalid_config", "target fields"));
    }
    if mode == "recover" && (backend.kind != "redb" || !grants.contains("store.recover")) {
        return Err(Error::new(
            "invalid_config",
            "explicit redb recovery grant required",
        ));
    }
    let text = target[address]
        .as_str()
        .ok_or_else(|| Error::new("invalid_config", "target address"))?;
    if address == "path" {
        super::operations::absolute(text)
            .map_err(|_| Error::new("invalid_config", "target path"))?;
    } else if text.is_empty() || text.len() > 1024 || text.contains('\0') {
        return Err(Error::new("invalid_config", "namespace bounds"));
    }
    Ok(())
}
pub(super) fn failure(error: Box<dyn std::error::Error>) -> Error {
    if let Some(native) = error.downcast_ref::<Error>() {
        if native.code == "storage" && native.detail.to_ascii_lowercase().contains("lock") {
            Error::new("store_busy", "embedded store lock held")
        } else {
            native.clone()
        }
    } else {
        Error::new("internal", "backend operation failed")
    }
}
impl BackendConfig {
    pub(super) fn native(&self) -> BackendTarget {
        BackendTarget {
            kind: match self.kind.as_str() {
                "redb" => BackendKind::Redb,
                "foundationdb" => BackendKind::FoundationDb,
                "surrealkv" => BackendKind::SurrealKv,
                _ => unreachable!("validated backend"),
            },
            cluster_file: self.cluster_file.as_str().map(str::to_owned),
        }
    }
}
impl<B: Binding> SelectedModel<B> {
    pub(super) fn ensure_network(&mut self, kind: &str) -> Result<()> {
        if kind == "foundationdb" {
            #[cfg(feature = "foundationdb")]
            {
                let mut network = self
                    .network
                    .lock()
                    .map_err(|_| Error::new("internal", "FDB owner lock"))?;
                if network.is_none() {
                    *network = Some(unsafe { foundationdb::boot() });
                }
            }
            #[cfg(not(feature = "foundationdb"))]
            return Err(Error::new(
                "unsupported_backend",
                "FDB feature not compiled",
            ));
        }
        Ok(())
    }
    pub(super) fn open_target(&mut self, target: Target) -> Result<()> {
        if let Target::Create { tenant, actor, .. } = &target {
            crate::access::Graph::bootstrap(Context {
                tenant: *tenant,
                actor: *actor,
            })
            .map_err(|_| Error::new("invalid_config", "authority bootstrap"))?;
        }
        let kind = self.backend.kind.clone();
        self.ensure_network(&kind)?;
        let path = target.path().map(PathBuf::from);
        let location = if let Some(path) = path {
            let canonical = if matches!(target, Target::Create { .. }) {
                path.parent()
                    .and_then(|p| p.canonicalize().ok())
                    .and_then(|p| path.file_name().map(|name| p.join(name)))
                    .ok_or_else(|| Error::new("invalid_config", "target parent"))?
            } else {
                path.canonicalize().map_err(local::storage)?
            };
            self.path = Some(canonical.clone());
            canonical
                .to_str()
                .ok_or_else(|| Error::new("invalid_config", "UTF8 path"))?
                .to_owned()
        } else {
            let namespace = target.namespace().expect("validated namespace").to_owned();
            self.namespace = Some(namespace.clone());
            namespace
        };
        let native = self.backend.native();
        let store = match target {
            Target::Create { tenant, actor, .. } => {
                if kind == "surrealkv" {
                    std::fs::create_dir(&location).map_err(local::storage)?;
                }
                native
                    .create(&location, self.model.clone(), Context { tenant, actor })
                    .map_err(failure)?
            }
            Target::Open { expect_store, .. } | Target::Recover { expect_store, .. } => {
                if kind == "redb" {
                    if matches!(target, Target::Recover { .. }) {
                        crate::storage::recover_host_redb(
                            Path::new(&location),
                            self.model.clone(),
                            expect_store,
                        )?
                    } else {
                        crate::storage::open_host_redb(
                            Path::new(&location),
                            self.model.clone(),
                            expect_store,
                        )?
                    }
                } else {
                    let db = native.database(&location).map_err(failure)?;
                    let read = db.begin_read()?;
                    let meta = local::read_meta(&read)?;
                    let header = local::read_header(&read)?;
                    if meta.model != self.model.identity()
                        || meta.codec != crate::native_codec::CODEC
                        || header.store_id != expect_store
                    {
                        return Err(Error::new("wrong_target", "backend identity differs"));
                    }
                    drop(read);
                    let store = local::Store::open_backend(db, self.model.clone())?;
                    let (_, _, current) = store.read(self.model.identity())?;
                    if current.store_id != expect_store {
                        return Err(Error::new("wrong_target", "store changed during open"));
                    }
                    if !store.secured {
                        return Err(Error::new("invalid_config", "secured host store required"));
                    }
                    store
                }
            }
        };
        self.store = Some(Arc::new(store));
        Ok(())
    }
}
