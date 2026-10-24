//! Ordinary CLI selection of one transactional backend.
use std::{error::Error, path::Path, sync::Arc};

use crate::{binding::Binding, lifecycle, local::Store, model::Prepared, native_slice::Context};

use super::Database;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BackendKind {
    #[default]
    Redb,
    FoundationDb,
    SurrealKv,
}

#[derive(Clone, Debug, Default)]
pub struct BackendTarget {
    pub kind: BackendKind,
    pub cluster_file: Option<String>,
}

impl BackendTarget {
    pub fn ensure_available(&self) -> Result<(), Box<dyn Error>> {
        match self.kind {
            BackendKind::FoundationDb => {
                #[cfg(not(feature = "foundationdb"))]
                return Err(
                    "FoundationDB support is missing; rebuild with --features foundationdb".into(),
                );
            }
            BackendKind::SurrealKv => {
                #[cfg(not(feature = "surrealkv"))]
                return Err(
                    "SurrealKV support is missing; rebuild with --features surrealkv".into(),
                );
            }
            BackendKind::Redb => {}
        }
        Ok(())
    }

    pub fn database(&self, location: &str) -> Result<Database, Box<dyn Error>> {
        self.ensure_available()?;
        match self.kind {
            BackendKind::Redb => Ok(Database::open(location)?),
            BackendKind::FoundationDb => {
                #[cfg(feature = "foundationdb")]
                {
                    use sha2::{Digest, Sha256};
                    // The CLI's store argument is its stable logical namespace label.
                    let namespace = Sha256::digest(location.as_bytes());
                    Ok(super::foundationdb::connect(
                        self.cluster_file.as_deref(),
                        &namespace,
                    )?)
                }
                #[cfg(not(feature = "foundationdb"))]
                {
                    let _ = location;
                    Err(
                        "FoundationDB support is missing; rebuild with --features foundationdb"
                            .into(),
                    )
                }
            }
            BackendKind::SurrealKv => {
                #[cfg(feature = "surrealkv")]
                {
                    Ok(super::surrealkv::connect(location)?)
                }
                #[cfg(not(feature = "surrealkv"))]
                {
                    Err("SurrealKV support is missing; rebuild with --features surrealkv".into())
                }
            }
        }
    }

    pub fn open<B: Binding>(
        &self,
        location: &str,
        model: Arc<Prepared<B>>,
    ) -> Result<Store<B>, Box<dyn Error>> {
        self.ensure_available()?;
        if self.kind == BackendKind::SurrealKv && !Path::new(location).is_dir() {
            return Err(format!("SurrealKV database directory does not exist: {location}").into());
        }
        if self.kind == BackendKind::Redb {
            return Ok(Store::open(location, model)?);
        }
        Ok(Store::open_backend(self.database(location)?, model)?)
    }

    pub fn create<B: Binding>(
        &self,
        location: &str,
        model: Arc<Prepared<B>>,
        context: Context,
    ) -> Result<Store<B>, Box<dyn Error>> {
        self.ensure_available()?;
        if self.kind == BackendKind::Redb {
            return Ok(Store::create_secured(location, model, context)?);
        }
        Ok(Store::create_backend_secured(
            self.database(location)?,
            model,
            context,
        )?)
    }

    pub fn restore<B: Binding>(
        &self,
        backup: &str,
        destination: &str,
        model: Arc<Prepared<B>>,
    ) -> Result<serde_json::Value, Box<dyn Error>> {
        self.ensure_available()?;
        if self.kind == BackendKind::Redb {
            return Ok(lifecycle::restore(backup, destination, model)?);
        }
        Ok(lifecycle::restore_to_backend(
            backup,
            self.database(destination)?,
            model,
        )?)
    }
}
