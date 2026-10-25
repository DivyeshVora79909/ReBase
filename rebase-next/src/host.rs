//! Private, bounded local control host. Native model and store functions remain
//! authoritative; this module owns only configuration, guards and transport.
use crate::{
    binding::{Binding, Calculation},
    json, local,
    model::Prepared,
    models::{
        effect_demo::EffectDemo, equipment::Equipment, invoicing::Invoicing,
        measurement::Measurement, quantity::Quantity,
    },
    native_codec::uuid_text,
    native_slice::{Context, Error, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

mod backend;
mod operations;

pub const PROTOCOL: &str = "rebase-native-host-1";
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MODELS: [&str; 6] = [
    "calculation",
    "equipment",
    "invoicing",
    "measurement",
    "effect-demo",
    "quantity",
];
const METHODS: [&str; 18] = [
    "host.describe",
    "host.configure",
    "model.catalog",
    "store.check",
    "store.inspect",
    "host.close",
    "model.explain",
    "model.validate",
    "model.render",
    "fixture.catalog",
    "fixture.plan",
    "service.start",
    "service.stop",
    "identity.issue",
    "store.backup",
    "store.restore",
    "store.archive",
    "store.reset",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    id: String,
    method: String,
    params: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendConfig {
    kind: String,
    cluster_file: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    model: String,
    backend: BackendConfig,
    target: Value,
    operator_methods: Vec<String>,
}
#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum Target {
    Create {
        path: Option<String>,
        namespace: Option<String>,
        #[serde(with = "uuid_text")]
        tenant: Uuid,
        #[serde(with = "uuid_text")]
        actor: Uuid,
    },
    Open {
        path: Option<String>,
        namespace: Option<String>,
        #[serde(with = "uuid_text")]
        expect_store: Uuid,
    },
    Recover {
        path: Option<String>,
        namespace: Option<String>,
        #[serde(with = "uuid_text")]
        expect_store: Uuid,
    },
}
impl Target {
    fn path(&self) -> Option<&str> {
        match self {
            Self::Create { path, .. } | Self::Open { path, .. } | Self::Recover { path, .. } => {
                path.as_deref()
            }
        }
    }
    fn namespace(&self) -> Option<&str> {
        match self {
            Self::Create { namespace, .. }
            | Self::Open { namespace, .. }
            | Self::Recover { namespace, .. } => namespace.as_deref(),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    scope: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scoped {
    scope: Scope,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    model: String,
    #[serde(with = "uuid_text")]
    store: Uuid,
}

fn bind<T: for<'de> Deserialize<'de>>(value: Value, kind: &'static str) -> Result<T> {
    serde_json::from_value(value).map_err(|_| Error::new(kind, "invalid typed host parameters"))
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
fn failure(id: Value, kind: &str) -> Value {
    let message = match kind {
        "parse_error" => "Invalid JSON frame",
        "invalid_request" => "Invalid host request",
        "protocol_mismatch" => "Unsupported host protocol",
        "request_limit" => "Host request byte limit",
        "response_limit" => "Host response byte limit",
        "method_not_found" => "Unknown host method",
        "not_configured" => "Host is not configured",
        "already_configured" => "Host is already configured",
        "invalid_config" => "Invalid host configuration",
        "unsupported_backend" => "Backend is not supported by this host",
        "wrong_target" => "Host target identity differs",
        "forbidden" => "Host operation is not granted",
        "store_busy" => "Store is already owned",
        "recovery_required" => "Store requires explicit recovery",
        "service_running" => "Service must be stopped",
        "service_not_running" => "Service is not running",
        "invalid_destination" => "Invalid restore destination",
        "internal" => "Host operation failed",
        _ => {
            let public = crate::rpc::failure(id.clone(), kind);
            if public["error"]["data"]["kind"] == "internal" {
                return failure(id, "internal");
            }
            return json!({"protocol":PROTOCOL,"id":id,"error":{
                "kind":public["error"]["data"]["kind"],"message":public["error"]["message"]}});
        }
    };
    json!({"protocol":PROTOCOL,"id":id,"error":{"kind":kind,"message":message}})
}

trait Selected {
    fn identity(&self) -> &str;
    fn backend(&self) -> Value;
    fn catalog(&self, developer: bool) -> Value;
    fn target(&self) -> Result<Value>;
    fn operate(&self, method: &str, scope: &Scope) -> Result<Value>;
    fn extended(
        &mut self,
        method: &str,
        params: Value,
        runtime: Option<&tokio::runtime::Handle>,
    ) -> Result<Value>;
    fn shutdown(&mut self, runtime: Option<&tokio::runtime::Handle>) -> Result<()>;
}
struct SelectedModel<B: Binding> {
    model: Arc<Prepared<B>>,
    store: Option<Arc<local::Store<B>>>,
    service: Option<(Uuid, crate::server::OwnedService)>,
    path: Option<PathBuf>,
    namespace: Option<String>,
    backend: BackendConfig,
    #[cfg(feature = "foundationdb")]
    network: Arc<std::sync::Mutex<Option<foundationdb::api::NetworkAutoStop>>>,
}
impl<B: Binding> Selected for SelectedModel<B> {
    fn backend(&self) -> Value {
        serde_json::to_value(&self.backend).expect("backend config serializes")
    }
    fn identity(&self) -> &str {
        self.model.identity()
    }
    fn catalog(&self, developer: bool) -> Value {
        if developer {
            self.model.developer_catalog()
        } else {
            self.model.public_catalog()
        }
    }
    fn target(&self) -> Result<Value> {
        match &self.store {
            Some(store) => {
                let (_, _, header) = store.read(self.model.identity())?;
                Ok(if let Some(namespace) = &self.namespace {
                    json!({"namespace":namespace,"store":header.store_id})
                } else {
                    json!({"path":self.path,"store":header.store_id})
                })
            }
            None => Ok(Value::Null),
        }
    }
    fn extended(
        &mut self,
        method: &str,
        params: Value,
        runtime: Option<&tokio::runtime::Handle>,
    ) -> Result<Value> {
        self.dispatch_extended(method, params, runtime)
    }
    fn shutdown(&mut self, runtime: Option<&tokio::runtime::Handle>) -> Result<()> {
        if let Some((_, service)) = self.service.take() {
            runtime
                .ok_or_else(|| Error::new("internal", "service runtime unavailable"))?
                .block_on(service.stop())?;
        }
        Ok(())
    }
    fn operate(&self, method: &str, scope: &Scope) -> Result<Value> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| Error::new("wrong_target", "no configured store"))?;
        let (_, _, header) = store.read(self.model.identity())?;
        if scope.model != self.model.identity() || scope.store != header.store_id {
            return Err(Error::new("wrong_target", "scope differs"));
        }
        let result = match method {
            "store.check" => store.check_integrity(),
            "store.inspect" => store.inspect(),
            _ => unreachable!("closed operator allowlist"),
        }?;
        if result["store"] != scope.store.to_string() {
            return Err(Error::new(
                "wrong_target",
                "store changed during inspection",
            ));
        }
        Ok(result)
    }
}

fn prepare<B: Binding>(
    target: Option<Target>,
    backend: BackendConfig,
    #[cfg(feature = "foundationdb")] network: Arc<
        std::sync::Mutex<Option<foundationdb::api::NetworkAutoStop>>,
    >,
) -> Result<Box<dyn Selected>> {
    let model = Arc::new(Prepared::<B>::load()?);
    let mut selected = SelectedModel {
        model,
        store: None,
        path: None,
        namespace: None,
        backend,
        service: None,
        #[cfg(feature = "foundationdb")]
        network,
    };
    if let Some(target) = target {
        selected.open_target(target)?;
    }
    Ok(Box::new(selected))
}

/// One control owner, with no retained request history or hidden process state.
/// FDB supports the executable's single Host owner per process; its SDK network
/// cannot be restarted by creating another independent Host after this one drops.
#[derive(Default)]
pub struct Host {
    selected: Option<Box<dyn Selected>>,
    selector: Option<String>,
    grants: BTreeSet<String>,
    closed: bool,
    runtime: Option<tokio::runtime::Runtime>,
    // Keep the SDK network across failed configuration, and drop it only after
    // selected stores and service/runtime work have been released.
    #[cfg(feature = "foundationdb")]
    network: Arc<std::sync::Mutex<Option<foundationdb::api::NetworkAutoStop>>>,
}
impl Drop for Host {
    fn drop(&mut self) {
        if let Some(selected) = &mut self.selected {
            let _ = selected.shutdown(self.runtime.as_ref().map(|r| r.handle()));
        }
    }
}

impl Host {
    fn configure(&mut self, params: Value) -> Result<Value> {
        if self.selected.is_some() {
            return Err(Error::new("already_configured", "immutable configuration"));
        }
        let config: Config = bind(params, "invalid_config")?;
        if !MODELS.contains(&config.model.as_str()) {
            return Err(Error::new("invalid_config", "unknown model"));
        }
        backend::validate(&config.backend)?;
        let grants: BTreeSet<_> = config.operator_methods.iter().cloned().collect();
        if grants.len() != config.operator_methods.len()
            || grants.iter().any(|g| {
                !matches!(
                    g.as_str(),
                    "store.check"
                        | "store.inspect"
                        | "service.start"
                        | "service.stop"
                        | "identity.issue"
                        | "store.backup"
                        | "store.restore"
                        | "store.archive"
                        | "store.reset"
                        | "store.recover"
                )
            })
            || (config.target.is_null() && !grants.is_empty())
        {
            return Err(Error::new("invalid_config", "invalid operator grants"));
        }
        backend::validate_target(&config.backend, &config.target, &grants)?;
        let target: Option<Target> = if config.target.is_null() {
            None
        } else {
            Some(bind(config.target, "invalid_config")?)
        };
        // All parameter/grant validation precedes model preparation and every
        // store side effect. Selection only becomes visible on full success.
        macro_rules! prepare_selected {
            ($binding:ty) => {
                prepare::<$binding>(
                    target,
                    config.backend,
                    #[cfg(feature = "foundationdb")]
                    self.network.clone(),
                )?
            };
        }
        let selected = match config.model.as_str() {
            "calculation" => prepare_selected!(Calculation),
            "equipment" => prepare_selected!(Equipment),
            "invoicing" => prepare_selected!(Invoicing),
            "measurement" => prepare_selected!(Measurement),
            "effect-demo" => prepare_selected!(EffectDemo),
            "quantity" => prepare_selected!(Quantity),
            _ => unreachable!("validated compiled selector"),
        };
        let response = json!({"status":"configured","model":selected.identity(),"target":selected.target()?,"operator_methods":grants});
        self.selector = Some(config.model);
        self.grants = grants;
        self.selected = Some(selected);
        Ok(response)
    }
    fn describe(&self) -> Result<Value> {
        let mut compiled_backends = vec!["redb"];
        if cfg!(feature = "foundationdb") {
            compiled_backends.push("foundationdb");
        }
        if cfg!(feature = "surrealkv") {
            compiled_backends.push("surrealkv");
        }
        let (selection, ownership, capabilities) = match &self.selected {
            None => (Value::Null, Value::Null, Value::Null),
            Some(selected) => {
                let target = selected.target()?;
                let ownership = if target.is_null() {
                    Value::Null
                } else {
                    json!({"store":target["store"],"mode":if selected.backend()["kind"] == "foundationdb" {"shared_transactional"} else {"exclusive"}})
                };
                (
                    json!({"selector":self.selector,"model":selected.identity(),"backend":selected.backend(),"target":target}),
                    ownership,
                    selected.catalog(false)["capabilities"].clone(),
                )
            }
        };
        Ok(
            json!({"protocol":PROTOCOL,"state":if self.selected.is_some(){"configured"}else{"unconfigured"},
            "engine":{"version":env!("CARGO_PKG_VERSION"),"api":crate::model::API_VERSION,"store_format":local::STORE_FORMAT,
                "native_codec":crate::native_codec::CODEC,"effect_codec":crate::effects::CODEC,"compiled_models":MODELS,"compiled_backends":compiled_backends},
            "configuration":{"schema":configuration_schema(),"defaults":{},"sources":{
                "configuration":"src/host.rs::configuration_schema","request_bytes":"src/json.rs::MAX_REQUEST_BYTES",
                "response_bytes":"src/host.rs::MAX_RESPONSE_BYTES","model":"src/model.rs::Prepared::public_catalog",
                "mutation_work_limit":"src/local.rs::MUTATION_WORK_LIMIT","backup_bytes":"src/lifecycle.rs::MAX_BACKUP_BYTES"}},
            "capabilities":{"framing":{"request_bytes":json::MAX_REQUEST_BYTES,"response_bytes":MAX_RESPONSE_BYTES,"max_outstanding":1,"bytes_exclude_lf":true},
                "host_methods":METHODS,"host_backends":compiled_backends,"model":capabilities,
                "mutation_work_limit":local::MUTATION_WORK_LIMIT,"backup_bytes":crate::lifecycle::MAX_BACKUP_BYTES},
            "selection":selection,"ownership":ownership}),
        )
    }
    fn dispatch(&mut self, method: &str, params: Value) -> Result<Value> {
        match method {
            "host.describe" => {
                let _: Empty = bind(params, "invalid_request")?;
                self.describe()
            }
            "host.configure" => self.configure(params),
            "host.close" => {
                let _: Empty = bind(params, "invalid_request")?;
                if let Some(selected) = &mut self.selected {
                    selected.shutdown(self.runtime.as_ref().map(|r| r.handle()))?;
                }
                self.selected.take();
                self.closed = true;
                Ok(json!({"status":"closed"}))
            }
            "model.catalog" => {
                let selected = self
                    .selected
                    .as_ref()
                    .ok_or_else(|| Error::new("not_configured", "model unavailable"))?;
                let p: Catalog = bind(params, "invalid_request")?;
                match p.scope.as_str() {
                    "public" => Ok(selected.catalog(false)),
                    "developer" => Ok(selected.catalog(true)),
                    _ => Err(Error::new("invalid_request", "catalog scope")),
                }
            }
            "store.check" | "store.inspect" => {
                let selected = self
                    .selected
                    .as_ref()
                    .ok_or_else(|| Error::new("not_configured", "store unavailable"))?;
                if !self.grants.contains(method) {
                    return Err(Error::new("forbidden", "operator grant absent"));
                }
                let p: Scoped = bind(params, "invalid_request")?;
                selected.operate(method, &p.scope)
            }
            "model.explain" | "model.validate" | "model.render" | "fixture.catalog"
            | "fixture.plan" | "service.start" | "service.stop" | "identity.issue"
            | "store.backup" | "store.restore" | "store.archive" | "store.reset" => {
                if self.selected.is_none() {
                    return Err(Error::new("not_configured", "model/store unavailable"));
                }
                let privileged = method.starts_with("service.")
                    || method.starts_with("identity.")
                    || method.starts_with("store.");
                if privileged && !self.grants.contains(method) {
                    return Err(Error::new("forbidden", "operator grant absent"));
                }
                if method == "model.render"
                    && params["scope"] == "store"
                    && !self.grants.contains("store.inspect")
                {
                    return Err(Error::new("forbidden", "inspection grant absent"));
                }
                if method == "service.start" && self.runtime.is_none() {
                    self.runtime = Some(
                        tokio::runtime::Builder::new_multi_thread()
                            .worker_threads(2)
                            .enable_all()
                            .build()
                            .map_err(local::storage)?,
                    );
                }
                self.selected.as_mut().expect("checked selection").extended(
                    method,
                    params,
                    self.runtime.as_ref().map(|r| r.handle()),
                )
            }
            _ => Err(Error::new("method_not_found", "closed host allowlist")),
        }
    }
    /// Decode one bounded frame. Transport IDs are never operation identities.
    pub fn handle(&mut self, bytes: &[u8]) -> Value {
        let value = match json::parse(bytes) {
            Ok(v) => v,
            Err(e) => return failure(Value::Null, e.code),
        };
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| valid_id(id))
            .map_or(Value::Null, |id| json!(id));
        let request: Request = match serde_json::from_value(value) {
            Ok(r) => r,
            Err(_) => return failure(id, "invalid_request"),
        };
        if !valid_id(&request.id) || !request.params.is_object() {
            return failure(id, "invalid_request");
        }
        if request.protocol != PROTOCOL {
            return failure(id, "protocol_mismatch");
        }
        match self.dispatch(&request.method, request.params) {
            Ok(result) => json!({"protocol":PROTOCOL,"id":request.id,"result":result}),
            Err(e) => failure(id, e.code),
        }
    }
}

/// Native schema for the exact configuration accepted above. Capability bounds
/// stay Rust-owned; there is no environment or JavaScript default lookup here.
pub fn configuration_schema() -> Value {
    let uuid = json!({"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"});
    let path = json!({"type":"string","minLength":1,"maxLength":4096,"x-maxUtf8Bytes":4096,"pattern":"^/[^\\u0000]*$"});
    let namespace = json!({"type":"string","minLength":1,"maxLength":1024,"x-maxUtf8Bytes":1024});
    let mut backends = vec!["redb"];
    if cfg!(feature = "foundationdb") {
        backends.push("foundationdb");
    }
    if cfg!(feature = "surrealkv") {
        backends.push("surrealkv");
    }
    let target = |address: &str, value: Value| {
        json!({"oneOf":[{"type":"null"},{"type":"object","additionalProperties":false,"required":["mode",address,"tenant","actor"],"properties":{"mode":{"const":"create"},(address):value,"tenant":uuid,"actor":uuid}},
        {"type":"object","additionalProperties":false,"required":["mode",address,"expect_store"],"properties":{"mode":{"enum":["open","recover"]},(address):value,"expect_store":uuid}}]})
    };
    json!({"$schema":crate::model::SCHEMA_DIALECT,"type":"object","additionalProperties":false,"required":["model","backend","target","operator_methods"],"properties":{
        "model":{"enum":MODELS},"backend":{"type":"object","additionalProperties":false,"required":["kind","cluster_file"],"properties":{"kind":{"enum":backends},"cluster_file":{"oneOf":[{"type":"null"},path]}}},
        "target":{},"operator_methods":{"type":"array","uniqueItems":true,"maxItems":10,"items":{"enum":["store.check","store.inspect","service.start","service.stop","identity.issue","store.backup","store.restore","store.archive","store.reset","store.recover"]}}},
        "allOf":[{"if":{"properties":{"target":{"type":"null"}}},"then":{"properties":{"operator_methods":{"maxItems":0}}}},
        {"if":{"properties":{"backend":{"properties":{"kind":{"const":"foundationdb"}}}}},"then":{"properties":{"target":target("namespace",namespace),"backend":{"properties":{"cluster_file":path}}}},"else":{"properties":{"target":target("path",path),"backend":{"properties":{"cluster_file":{"type":"null"}}}}}},
        {"if":{"properties":{"target":{"type":"object","properties":{"mode":{"const":"recover"}},"required":["mode"]}}},"then":{"properties":{"backend":{"properties":{"kind":{"const":"redb"}}},"operator_methods":{"contains":{"const":"store.recover"}}}}}]})
}

enum Frame {
    Complete(Vec<u8>),
    Oversize,
    Truncated,
}
fn read_frame(input: &mut impl BufRead) -> io::Result<Option<Frame>> {
    let mut bytes = Vec::new();
    let mut oversize = false;
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return Ok(if oversize {
                Some(Frame::Oversize)
            } else if bytes.is_empty() {
                None
            } else {
                Some(Frame::Truncated)
            });
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let size = newline.unwrap_or(available.len());
        if !oversize {
            let copy = size.min(json::MAX_REQUEST_BYTES + 1 - bytes.len());
            bytes.extend_from_slice(&available[..copy]);
            oversize = bytes.len() > json::MAX_REQUEST_BYTES;
        }
        input.consume(size + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(if oversize {
                Frame::Oversize
            } else {
                Frame::Complete(bytes)
            }));
        }
    }
}
struct Bounded {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(io::Error::other("response byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encoded(value: &Value) -> Vec<u8> {
    let mut writer = Bounded {
        bytes: Vec::new(),
        limit: MAX_RESPONSE_BYTES,
    };
    if serde_json::to_writer(&mut writer, value).is_ok() {
        writer.bytes
    } else {
        serde_json::to_vec(&failure(value["id"].clone(), "response_limit"))
            .expect("fixed bounded failure")
    }
}

fn respond(host: &mut Host, frame: Frame, output: &mut impl Write) -> io::Result<bool> {
    let truncated = matches!(frame, Frame::Truncated);
    let reply = match frame {
        Frame::Complete(bytes) => host.handle(&bytes),
        Frame::Oversize => failure(Value::Null, "request_limit"),
        Frame::Truncated => failure(Value::Null, "parse_error"),
    };
    output.write_all(&encoded(&reply))?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(host.closed || truncated)
}

async fn shutdown_signal() -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result, _ = terminate.recv() => Ok(()) }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

/// Process bootstrap. A bounded reader owns only stdin, never a store. Signals
/// are admitted between completed synchronous operations, and drop the owner
/// before process exit. This keeps a blocked stdin read off the signal executor.
pub fn run_stdio() -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    std::thread::Builder::new()
        .name("native-host-input".into())
        .spawn(move || {
            let mut input = io::stdin().lock();
            loop {
                let frame = read_frame(&mut input);
                let last = matches!(frame, Ok(None) | Err(_));
                if sender.blocking_send(frame).is_err() || last {
                    break;
                }
            }
        })?;
    let mut host = Host::default();
    let mut output = io::stdout().lock();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        // The runtime only waits for input/signals. Native synchronous work is
        // dispatched after block_on returns, never while holding an async task.
        let frame = runtime.block_on(async {
            tokio::select! {
                result = &mut shutdown => { result?; Ok(None) },
                frame = receiver.recv() => frame.unwrap_or(Ok(None)),
            }
        })?;
        match frame {
            Some(frame) => {
                if respond(&mut host, frame, &mut output)? {
                    break;
                }
            }
            None => break,
        }
    }
    drop(host);
    Ok(())
}

/// The process owns this synchronous loop in N1; no async executor is blocked.
pub fn serve(mut input: impl BufRead, mut output: impl Write) -> io::Result<()> {
    let mut host = Host::default();
    while let Some(frame) = read_frame(&mut input)? {
        if respond(&mut host, frame, &mut output)? {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serialization_never_publishes_a_partial_oversized_result() {
        let value =
            json!({"protocol":PROTOCOL,"id":"bound","result":"x".repeat(MAX_RESPONSE_BYTES)});
        let bytes = encoded(&value);
        assert!(bytes.len() < MAX_RESPONSE_BYTES);
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            failure(json!("bound"), "response_limit")
        );
    }
}
