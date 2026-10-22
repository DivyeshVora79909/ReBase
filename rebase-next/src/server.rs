//! Bounded HTTP transport over the ordinary operation API. Blocking database
//! work owns its admission permit until completion, including after a timeout.
use crate::{
    identity::{IdentityConfig, Verifier},
    json::MAX_REQUEST_BYTES,
    local::LocalStore,
    native_slice::{Error, Result},
    rpc,
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, State},
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
}
#[derive(Clone)]
struct App {
    store: Arc<LocalStore>,
    verifier: Arc<Verifier>,
    permits: Arc<Semaphore>,
    timeout: Duration,
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
async fn call(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Response {
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

pub fn router(store: Arc<LocalStore>, config: &ServerConfig) -> Result<Router> {
    if !store.secured {
        return Err(Error::new(
            "invalid_input",
            "network API requires a secured store",
        ));
    }
    store.check_integrity()?;
    if !(1..=64).contains(&config.max_inflight)
        || !(1..=120).contains(&config.request_timeout_seconds)
    {
        return Err(Error::new(
            "invalid_input",
            "network concurrency/deadline limits",
        ));
    }
    let app = App {
        store,
        verifier: Arc::new(Verifier::new(config.identity.clone())?),
        permits: Arc::new(Semaphore::new(usize::from(config.max_inflight))),
        timeout: Duration::from_secs(u64::from(config.request_timeout_seconds)),
    };
    Ok(Router::new()
        .route("/health", get(health))
        .route("/rpc", post(call))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(app))
}

pub async fn serve(store: Arc<LocalStore>, config: ServerConfig) -> Result<()> {
    let routes = router(store, &config)?;
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|e| Error::new("transport", e.to_string()))?;
    eprintln!(
        "ReBase Next listening on {} (TLS belongs at the ingress proxy)",
        listener
            .local_addr()
            .map_err(|e| Error::new("transport", e.to_string()))?
    );
    axum::serve(listener, routes)
        .with_graceful_shutdown(shutdown())
        .await
        .map_err(|e| Error::new("transport", e.to_string()))
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
    use crate::{
        identity::{self, TokenRequest},
        model::PreparedModel,
        native_slice::Context,
    };
    use std::collections::BTreeMap;
    use uuid::Uuid;

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
}
