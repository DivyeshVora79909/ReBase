//! Typed developer/operator operations over the existing prepared native owner.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Explain {
    selector: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Validate {
    code: u16,
    input: Value,
}
#[derive(Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
enum Render {
    Model,
    Store { target: Scope },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    name: String,
    #[serde(with = "uuid_text")]
    namespace: Uuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    scope: Scope,
    config: crate::server::ServerConfig,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stop {
    scope: Scope,
    #[serde(with = "uuid_text")]
    service: Uuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issue {
    scope: Scope,
    identity: crate::identity::IdentityConfig,
    request: crate::identity::TokenRequest,
    private_key_pem: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Destination {
    scope: Scope,
    destination: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reset {
    scope: Scope,
    #[serde(with = "uuid_text")]
    expect_store: Uuid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Restore {
    scope: Scope,
    backup: String,
    #[serde(with = "uuid_text")]
    expect_backup_store: Uuid,
    destination: RestoreDestination,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreDestination {
    backend: BackendConfig,
    target: Value,
}

pub(super) fn absolute(path: &str) -> Result<PathBuf> {
    if path.is_empty() || path.len() > 4096 || path.contains('\0') || !Path::new(path).is_absolute()
    {
        return Err(Error::new("invalid_destination", "absolute path required"));
    }
    Ok(PathBuf::from(path))
}

fn authorize_identity<B: Binding>(
    store: &local::Store<B>,
    scope: &Scope,
    request: &crate::identity::TokenRequest,
) -> Result<()> {
    let session = store.session(request.actor, request.epoch)?;
    let (read, _, header) = session.read(store.model().identity())?;
    if header.store_id != scope.store {
        return Err(Error::new("wrong_target", "identity store scope changed"));
    }
    session.authority(&read)?;
    Ok(())
}

impl<B: Binding> SelectedModel<B> {
    fn scoped(&self, scope: &Scope) -> Result<Arc<local::Store<B>>> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| Error::new("wrong_target", "no store"))?;
        let (_, _, header) = store.read(self.model.identity())?;
        if scope.model != self.model.identity() || scope.store != header.store_id {
            return Err(Error::new("wrong_target", "scope differs"));
        }
        Ok(store.clone())
    }
    fn offline(&self) -> Result<()> {
        if self.service.is_some() {
            Err(Error::new("service_running", "stop owned service first"))
        } else {
            Ok(())
        }
    }
    pub(super) fn dispatch_extended(
        &mut self,
        method: &str,
        params: Value,
        runtime: Option<&tokio::runtime::Handle>,
    ) -> Result<Value> {
        match method {
            "model.explain" => {
                let p: Explain = bind(params, "invalid_request")?;
                self.model.explain(&p.selector)
            }
            "model.validate" => {
                let p: Validate = bind(params, "invalid_request")?;
                self.model.validate(p.code, &p.input)?;
                Ok(json!({"status":"valid","model":self.model.identity(),"input":p.input}))
            }
            "model.render" => {
                let p: Render = bind(params, "invalid_request")?;
                match p {
                    Render::Model => Ok(
                        json!({"model":self.model.identity(),"html":crate::inspector::render(&self.model,None,&[])?}),
                    ),
                    Render::Store { target } => {
                        let store = self.scoped(&target)?;
                        let snapshot = store.inspect()?;
                        if snapshot["store"] != target.store.to_string() {
                            return Err(Error::new(
                                "wrong_target",
                                "store changed during inspection",
                            ));
                        }
                        Ok(
                            json!({"model":self.model.identity(),"store":target.store,"html":crate::inspector::render(&self.model,Some(&snapshot),&[])?}),
                        )
                    }
                }
            }
            "fixture.catalog" => {
                let _: Empty = bind(params, "invalid_request")?;
                Ok(B::fixture_catalog())
            }
            "fixture.plan" => {
                let p: Fixture = bind(params, "invalid_request")?;
                B::fixture_plan(&self.model, &p.name, p.namespace)
            }
            "service.start" => {
                let p: Start = bind(params, "invalid_request")?;
                let store = self.scoped(&p.scope)?;
                self.offline()?;
                let runtime =
                    runtime.ok_or_else(|| Error::new("internal", "service runtime unavailable"))?;
                let service = runtime.block_on(crate::server::start_scoped(
                    store,
                    p.config,
                    Some(p.scope.store),
                ))?;
                let id = Uuid::new_v4();
                let address = service.address;
                self.service = Some((id, service));
                Ok(
                    json!({"status":"started","service":id,"address":address.to_string(),"endpoint":format!("http://{address}/rpc"),"scope":{"model":p.scope.model,"store":p.scope.store}}),
                )
            }
            "service.stop" => {
                let p: Stop = bind(params, "invalid_request")?;
                self.scoped(&p.scope)?;
                match &self.service {
                    None => return Err(Error::new("service_not_running", "no owned service")),
                    Some((id, _)) if *id != p.service => {
                        return Err(Error::new("wrong_target", "service UUID differs"));
                    }
                    _ => {}
                }
                self.shutdown(runtime)?;
                Ok(json!({"status":"stopped","service":p.service}))
            }
            "identity.issue" => {
                let p: Issue = bind(params, "invalid_request")?;
                let store = self.scoped(&p.scope)?;
                if p.request.tenant != store.context().tenant {
                    return Err(Error::new("wrong_target", "token tenant differs"));
                }
                if p.private_key_pem.len() > 4096 {
                    return Err(Error::new("invalid_input", "private key byte limit"));
                }
                authorize_identity(&store, &p.scope, &p.request)?;
                Ok(
                    json!({"token":crate::identity::issue(&p.identity,&p.request,p.private_key_pem.as_bytes())?}),
                )
            }
            "store.backup" | "store.archive" => {
                let p: Destination = bind(params, "invalid_request")?;
                let store = self.scoped(&p.scope)?;
                let destination = absolute(&p.destination)?;
                if method == "store.archive" {
                    self.offline()?;
                    store.archive_receipts_scoped(destination, Some(p.scope.store))
                } else {
                    store.backup_scoped(destination, Some(p.scope.store))
                }
            }
            "store.reset" => {
                let p: Reset = bind(params, "invalid_request")?;
                let store = self.scoped(&p.scope)?;
                self.offline()?;
                if p.expect_store != p.scope.store {
                    return Err(Error::new("wrong_target", "reset expected UUID differs"));
                }
                store.reset(p.expect_store)
            }
            "store.restore" => {
                let p: Restore = bind(params, "invalid_request")?;
                self.scoped(&p.scope)?;
                self.offline()?;
                let backup = absolute(&p.backup)?;
                if crate::lifecycle::backup_store(&backup)? != p.expect_backup_store {
                    return Err(Error::new("wrong_target", "backup store differs"));
                }
                super::backend::validate(&p.destination.backend)?;
                let is_fdb = p.destination.backend.kind == "foundationdb";
                let key = if is_fdb { "namespace" } else { "path" };
                let object = p
                    .destination
                    .target
                    .as_object()
                    .ok_or_else(|| Error::new("invalid_destination", "destination target"))?;
                if object.len() != 1 || !object.contains_key(key) {
                    return Err(Error::new(
                        "invalid_destination",
                        "destination address fields",
                    ));
                }
                let requested = object[key]
                    .as_str()
                    .ok_or_else(|| Error::new("invalid_destination", "destination address"))?;
                let location = if is_fdb {
                    if requested.is_empty()
                        || requested.len() > 1024
                        || requested.contains('\0')
                        || self.namespace.as_deref() == Some(requested)
                    {
                        return Err(Error::new("invalid_destination", "new namespace required"));
                    }
                    requested.to_owned()
                } else {
                    let path = absolute(requested)?;
                    let canonical = path
                        .parent()
                        .and_then(|p| p.canonicalize().ok())
                        .and_then(|p| path.file_name().map(|n| p.join(n)))
                        .ok_or_else(|| Error::new("invalid_destination", "destination parent"))?;
                    if self.path.as_ref() == Some(&canonical)
                        || std::fs::symlink_metadata(&canonical).is_ok()
                    {
                        return Err(Error::new("invalid_destination", "destination must be new"));
                    }
                    canonical
                        .to_str()
                        .ok_or_else(|| Error::new("invalid_destination", "UTF8 destination"))?
                        .to_owned()
                };
                if p.destination.backend.kind == "redb" {
                    crate::lifecycle::restore(backup, &location, self.model.clone())
                } else {
                    self.ensure_network(&p.destination.backend.kind)?;
                    let native = p.destination.backend.native();
                    let kind = p.destination.backend.kind;
                    crate::lifecycle::restore_backend_after_validation(
                        backup,
                        self.model.clone(),
                        || {
                            if kind == "surrealkv" {
                                std::fs::create_dir(&location).map_err(local::storage)?;
                            }
                            native.database(&location).map_err(super::backend::failure)
                        },
                    )
                }
            }
            _ => Err(Error::new("method_not_found", "unknown extended method")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_old_scope_cannot_authorize_the_post_reset_credential_epoch() {
        let directory =
            std::env::temp_dir().join(format!("rebase-identity-scope-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let store = local::LocalStore::create_secured(
            directory.join("store.redb"),
            Arc::new(crate::model::PreparedModel::load().unwrap()),
            Context {
                tenant: Uuid::from_u128(1),
                actor: Uuid::from_u128(2),
            },
        )
        .unwrap();
        let (_, _, header) = store.read(store.model().identity()).unwrap();
        let mut scope = Scope {
            model: store.model().identity().to_owned(),
            store: header.store_id,
        };
        let mut request = crate::identity::TokenRequest {
            tenant: Uuid::from_u128(1),
            actor: Uuid::from_u128(2),
            epoch: 1,
            ttl: 300,
            key_id: "test".into(),
        };
        // The outer host scope check observed the old UUID; a competing reset
        // happens before issuance's own authorization snapshot.
        store.reset(scope.store).unwrap();
        assert_eq!(
            authorize_identity(&store, &scope, &request)
                .unwrap_err()
                .code,
            "wrong_target"
        );
        let (_, _, header) = store.read(store.model().identity()).unwrap();
        scope.store = header.store_id;
        authorize_identity(&store, &scope, &request).unwrap();
        request.epoch = 0;
        assert_eq!(
            authorize_identity(&store, &scope, &request)
                .unwrap_err()
                .code,
            "forbidden"
        );
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
