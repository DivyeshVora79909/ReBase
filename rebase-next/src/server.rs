//! Bounded HTTP transport over the ordinary operation API. Blocking database
//! work owns its admission permit until completion, including after a timeout.
use crate::binding::Binding;
use crate::{
    identity::{IdentityConfig, Verifier},
    json::MAX_REQUEST_BYTES,
    local::Store,
    native_slice::{Error, Result},
    rpc,
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    pub identity: IdentityConfig,
    pub max_inflight: u16,
    pub request_timeout_seconds: u16,
    #[serde(default)]
    pub effects: Option<crate::effects::fake::Config>,
}
#[derive(Clone)]
struct App<B: Binding> {
    store: Arc<Store<B>>,
    verifier: Arc<Verifier>,
    permits: Arc<Semaphore>,
    timeout: Duration,
    ingress: Option<Arc<crate::effects::inbox::Secret>>,
    effect_probe_directory: Option<std::path::PathBuf>,
}
fn response(status: StatusCode, value: Value) -> Response {
    let bytes = serde_json::to_vec(&value).expect("JSON value serializes");
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(bytes))
        .expect("static response headers")
}
async fn health() -> Response {
    response(StatusCode::OK, json!({"status":"up"}))
}
async fn call<B: Binding>(State(app): State<App<B>>, headers: HeaderMap, body: Bytes) -> Response {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_none_or(|h| h.split(';').next().unwrap_or("").trim() != "application/json")
    {
        return response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            json!({"error":"application/json required"}),
        );
    }
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));
    let token = match token.filter(|t| t.len() <= crate::identity::MAX_TOKEN_BYTES) {
        Some(token) => token.to_owned(),
        None => return response(StatusCode::UNAUTHORIZED, json!({"error":"unauthenticated"})),
    };
    let permit = match app.permits.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return response(StatusCode::TOO_MANY_REQUESTS, json!({"error":"busy"})),
    };
    let id = crate::json::parse(&body)
        .ok()
        .and_then(|v| v.get("id").cloned())
        .filter(Value::is_string)
        .unwrap_or(Value::Null);
    let work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let claims = app.verifier.verify(&token, app.store.context().tenant)?;
        let session = app.store.session(claims.sub, claims.epoch)?;
        Ok::<_, Error>(rpc::handle(&session, &body))
    });
    match tokio::time::timeout(app.timeout, work).await {
        Ok(Ok(Ok(value))) => response(StatusCode::OK, value),
        Ok(Ok(Err(_))) => response(StatusCode::UNAUTHORIZED, json!({"error":"unauthenticated"})),
        // A dropped/failed response cannot certify rollback. The client retains
        // its operation UUID and reconciles, even if a blocking worker continues.
        _ => response(
            StatusCode::GATEWAY_TIMEOUT,
            rpc::failure(id, "outcome_unknown"),
        ),
    }
}

async fn webhook<B: Binding>(State(app): State<App<B>>, request: Request) -> Response {
    let Some(secret) = &app.ingress else {
        return response(StatusCode::NOT_FOUND, json!({"error":"unavailable"}));
    };
    let (parts, body) = request.into_parts();
    if parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_none_or(|h| h.split(';').next().unwrap_or("").trim() != "application/json")
    {
        return response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            json!({"error":"application/json required"}),
        );
    }
    let permit = match app.permits.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return response(StatusCode::TOO_MANY_REQUESTS, json!({"error":"busy"})),
    };
    let body = match tokio::time::timeout(
        Duration::from_secs(2),
        axum::body::to_bytes(body, crate::effects::MAX_WEBHOOK),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            return response(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"error":"webhook body limit"}),
            );
        }
        Err(_) => {
            return response(
                StatusCode::REQUEST_TIMEOUT,
                json!({"error":"webhook body deadline"}),
            );
        }
    };
    let verified = (|| {
        let header = |name| {
            let mut values = parts.headers.get_all(name).iter();
            let value = values.next().and_then(|h| h.to_str().ok());
            value
                .filter(|_| values.next().is_none())
                .ok_or_else(|| Error::new("unauthenticated", "webhook headers"))
        };
        secret.verify::<B>(
            header("x-fake-account")?,
            header("x-fake-event")?,
            header("x-fake-timestamp")?,
            header("x-fake-signature")?,
            &body,
            crate::effects::now_millis()?,
        )
    })();
    let event = match verified {
        Ok(event) => event,
        Err(error) => return webhook_error(error),
    };
    let abort = app
        .effect_probe_directory
        .as_ref()
        .is_some_and(|path| path.join("inbox.abort").exists())
        .then_some(usize::MAX - 6);
    let work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        app.store.accept_effect_event(event, abort)
    });
    match tokio::time::timeout(app.timeout, work).await {
        Ok(Ok(Ok(value))) => response(StatusCode::OK, value),
        Ok(Ok(Err(error))) => webhook_error(error),
        _ => response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"outcome_unknown"}),
        ),
    }
}
fn webhook_error(error: Error) -> Response {
    let status = match error.code {
        "unauthenticated" => StatusCode::UNAUTHORIZED,
        "invalid_input" | "parse_error" => StatusCode::BAD_REQUEST,
        "request_limit" => StatusCode::PAYLOAD_TOO_LARGE,
        "not_found" => StatusCode::NOT_FOUND,
        "content_conflict" => StatusCode::CONFLICT,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    response(status, json!({"error":error.code}))
}

fn router_with_admission<B: Binding>(
    store: Arc<Store<B>>,
    config: &ServerConfig,
    expected_store: Option<uuid::Uuid>,
) -> Result<(Router, Arc<Semaphore>)> {
    if !store.secured {
        return Err(Error::new(
            "invalid_input",
            "network API requires a secured store",
        ));
    }
    let checked = store.check_integrity()?;
    if expected_store.is_some_and(|expected| checked["store"] != expected.to_string()) {
        return Err(Error::new("wrong_target", "service store scope changed"));
    }
    if let Some(effects) = &config.effects {
        effects.validate::<B>()?;
    }
    if !(1..=64).contains(&config.max_inflight)
        || !(1..=120).contains(&config.request_timeout_seconds)
    {
        return Err(Error::new(
            "invalid_input",
            "network concurrency/deadline limits",
        ));
    }
    let permits = Arc::new(Semaphore::new(usize::from(config.max_inflight)));
    let app = App {
        store,
        verifier: Arc::new(Verifier::new(config.identity.clone())?),
        permits: permits.clone(),
        timeout: Duration::from_secs(u64::from(config.request_timeout_seconds)),
        ingress: config
            .effects
            .as_ref()
            .and_then(|effects| effects.ingress_secret_file.as_ref())
            .map(|path| crate::effects::inbox::Secret::load(path).map(Arc::new))
            .transpose()?,
        effect_probe_directory: config
            .effects
            .as_ref()
            .and_then(|effects| effects.probe_directory.clone()),
    };
    Ok((
        Router::new()
            .route("/health", get(health))
            .route("/rpc", post(call::<B>))
            .route("/effects/fake", post(webhook::<B>))
            .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
            .with_state(app),
        permits,
    ))
}

pub fn router<B: Binding>(store: Arc<Store<B>>, config: &ServerConfig) -> Result<Router> {
    Ok(router_with_admission(store, config, None)?.0)
}

/// One bound native service. Explicit stop joins HTTP, all admitted blocking
/// operations (including those whose HTTP wait timed out), and effect workers.
pub struct OwnedService {
    pub address: SocketAddr,
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<()>>,
}
impl OwnedService {
    pub async fn stop(self) -> Result<()> {
        let _ = self.stop.send(true);
        self.task
            .await
            .map_err(|_| Error::new("internal", "service task"))?
    }
}

pub async fn start<B: Binding>(store: Arc<Store<B>>, config: ServerConfig) -> Result<OwnedService> {
    start_scoped(store, config, None).await
}

pub(crate) async fn start_scoped<B: Binding>(
    store: Arc<Store<B>>,
    config: ServerConfig,
    expected_store: Option<uuid::Uuid>,
) -> Result<OwnedService> {
    let checked = config.clone();
    let owner = store.clone();
    let (routes, admission) =
        tokio::task::spawn_blocking(move || router_with_admission(owner, &checked, expected_store))
            .await
            .map_err(|_| Error::new("internal", "service validation task"))??;
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|e| Error::new("transport", e.to_string()))?;
    let address = listener
        .local_addr()
        .map_err(|e| Error::new("transport", e.to_string()))?;
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    let worker = if B::effect_action().is_some() {
        let owner = store.clone();
        let mode = config
            .effects
            .as_ref()
            .map_or(crate::effects::WorkerMode::Disabled, |effects| effects.mode);
        let activation = tokio::task::spawn_blocking(move || owner.activate_effect_worker(mode))
            .await
            .map_err(|_| Error::new("internal", "worker activation task"))??;
        config
            .effects
            .filter(|effects| effects.mode.active())
            .map(|effects| {
                let owner = store.clone();
                let receiver = stop.subscribe();
                let failed = stop.clone();
                tokio::spawn(async move {
                    let result =
                        crate::effects::fake::run(owner, effects, activation, receiver).await;
                    if result.is_err() {
                        let _ = failed.send(true);
                    }
                    result
                })
            })
    } else {
        None
    };
    let finished = stop.clone();
    let task = tokio::spawn(async move {
        let served = axum::serve(listener, routes)
            .with_graceful_shutdown(async move {
                while !*stopped.borrow() {
                    if stopped.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await
            .map_err(|e| Error::new("transport", e.to_string()));
        let _ = finished.send(true);
        // HTTP timeouts do not stop spawn_blocking work. Every admitted operation
        // retains its permit until it actually finishes, so drain all permits.
        let _drained = admission
            .acquire_many_owned(u32::from(config.max_inflight))
            .await
            .map_err(|_| Error::new("internal", "service admission closed"))?;
        let worker_result = match worker {
            Some(worker) => worker
                .await
                .map_err(|_| Error::new("internal", "effect worker task"))?,
            None => Ok(()),
        };
        if B::effect_action().is_some() {
            tokio::task::spawn_blocking(move || {
                store.activate_effect_worker(crate::effects::WorkerMode::Disabled)
            })
            .await
            .map_err(|_| Error::new("internal", "worker shutdown task"))??;
        }
        served.and(worker_result)
    });
    Ok(OwnedService {
        address,
        stop,
        task,
    })
}

pub async fn serve<B: Binding>(store: Arc<Store<B>>, config: ServerConfig) -> Result<()> {
    let mut service = start(store, config).await?;
    eprintln!(
        "ReBase Next listening on {} (TLS belongs at the ingress proxy)",
        service.address
    );
    tokio::select! {
        result = &mut service.task => result.map_err(|_|Error::new("internal","service task"))?,
        _ = shutdown() => service.stop().await,
    }
}
async fn shutdown() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM registration");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalStore;
    use crate::{
        identity::{self, TokenRequest},
        model::PreparedModel,
        native_slice::Context,
    };
    use std::collections::BTreeMap;
    use uuid::Uuid;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scoped_start_rejects_reset_before_native_validation() {
        let dir = std::env::temp_dir().join(format!("rebase-service-scope-{}", Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let store = Arc::new(
            LocalStore::create_secured(
                dir.join("store.redb"),
                Arc::new(PreparedModel::load().unwrap()),
                Context {
                    tenant: Uuid::from_u128(1),
                    actor: Uuid::from_u128(2),
                },
            )
            .unwrap(),
        );
        let (_, _, header) = store.read(store.model().identity()).unwrap();
        store.reset(header.store_id).unwrap();
        let config = ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            identity: IdentityConfig {
                issuer: "scope".into(),
                audience: "scope".into(),
                public_keys: BTreeMap::from([(
                    "test".into(),
                    include_str!("../tests/fixtures/test-ed25519-public.pem").into(),
                )]),
                max_token_seconds: 600,
            },
            max_inflight: 1,
            request_timeout_seconds: 1,
            effects: None,
        };
        let result = start_scoped(store.clone(), config, Some(header.store_id)).await;
        assert!(matches!(result, Err(error) if error.code == "wrong_target"));
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deadline_keeps_admission_until_the_real_transaction_finishes() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/deadline-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(
            LocalStore::create_secured(
                dir.join("store.redb"),
                Arc::new(PreparedModel::load().unwrap()),
                Context {
                    tenant: Uuid::from_u128(1),
                    actor: Uuid::from_u128(2),
                },
            )
            .unwrap(),
        );
        let config = IdentityConfig {
            issuer: "test".into(),
            audience: "test".into(),
            public_keys: BTreeMap::from([(
                "test".into(),
                include_str!("../tests/fixtures/test-ed25519-public.pem").into(),
            )]),
            max_token_seconds: 600,
        };
        let token = identity::issue(
            &config,
            &TokenRequest {
                tenant: store.context().tenant,
                actor: store.context().actor,
                epoch: 0,
                ttl: 300,
                key_id: "test".into(),
            },
            include_bytes!("../tests/fixtures/test-ed25519-private.pem"),
        )
        .unwrap();
        let app = App {
            store: store.clone(),
            verifier: Arc::new(Verifier::new(config).unwrap()),
            permits: Arc::new(Semaphore::new(1)),
            timeout: Duration::from_millis(2),
            ingress: None,
            effect_probe_directory: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        let operation = Uuid::from_u128(100);
        let body=Bytes::from(serde_json::to_vec(&json!({"jsonrpc":"2.0","id":"deadline","method":"records.mutate","params":{"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":operation,"commands":[{"op":"create","id":Uuid::from_u128(10),"contract":7,"fields":{"at":"0"}}],"returning":[]}})).unwrap());
        let held = store.db.begin_write().unwrap();
        let timed = call(State(app.clone()), headers.clone(), body.clone()).await;
        assert_eq!(timed.status(), StatusCode::GATEWAY_TIMEOUT);
        let value: Value =
            serde_json::from_slice(&axum::body::to_bytes(timed.into_body(), 4096).await.unwrap())
                .unwrap();
        assert_eq!(value["error"]["data"]["kind"], "outcome_unknown");
        assert_eq!(app.permits.available_permits(), 0);
        assert_eq!(
            call(State(app.clone()), headers, body).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        drop(held);
        let permit = tokio::time::timeout(Duration::from_secs(5), app.permits.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        assert_eq!(
            store
                .operation_status(
                    store.model().identity(),
                    &store.operation_context(store.model().identity()).unwrap(),
                    operation
                )
                .unwrap()["status"],
            "committed"
        );
        drop(app);
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn owned_stop_waits_for_timed_out_blocking_attempt() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/owned-stop-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(
            LocalStore::create_secured(
                dir.join("store.redb"),
                Arc::new(PreparedModel::load().unwrap()),
                Context {
                    tenant: Uuid::from_u128(1),
                    actor: Uuid::from_u128(2),
                },
            )
            .unwrap(),
        );
        let identity = IdentityConfig {
            issuer: "owned-stop".into(),
            audience: "owned-stop".into(),
            public_keys: BTreeMap::from([(
                "test".into(),
                include_str!("../tests/fixtures/test-ed25519-public.pem").into(),
            )]),
            max_token_seconds: 600,
        };
        let token = identity::issue(
            &identity,
            &TokenRequest {
                tenant: store.context().tenant,
                actor: store.context().actor,
                epoch: 0,
                ttl: 300,
                key_id: "test".into(),
            },
            include_bytes!("../tests/fixtures/test-ed25519-private.pem"),
        )
        .unwrap();
        let service = start(
            store.clone(),
            ServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                identity,
                max_inflight: 1,
                request_timeout_seconds: 1,
                effects: None,
            },
        )
        .await
        .unwrap();
        let operation = Uuid::new_v4();
        let context = store.operation_context(store.model().identity()).unwrap();
        let request = json!({"jsonrpc":"2.0","id":"timed","method":"records.mutate","params":{"model":store.model().identity(),"context":context,"operation_id":operation,"commands":[{"op":"create","id":Uuid::new_v4(),"contract":7,"fields":{"at":"0"}}],"returning":[]}});
        let held = store.db.begin_write().unwrap();
        let response = reqwest::Client::new()
            .post(format!("http://{}/rpc", service.address))
            .bearer_auth(token)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);
        let stopped = tokio::spawn(service.stop());
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !stopped.is_finished(),
            "service released ownership while blocking attempt still ran"
        );
        drop(held);
        tokio::time::timeout(Duration::from_secs(5), stopped)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            store
                .operation_status(store.model().identity(), &context, operation)
                .unwrap()["status"],
            "committed"
        );
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
