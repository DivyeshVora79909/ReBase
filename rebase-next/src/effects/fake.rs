//! The one experimental provider transport. Endpoints are operator configuration;
//! model inputs cannot choose a transport, URL, credential or arbitrary result.
use super::*;
use state::{Claim, Mode, WorkClass};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{sync::watch, task::JoinSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub endpoint: String,
    /// Deterministic acceptance pauses, only for the experimental fake adapter.
    /// The directory must already exist. No request can select it.
    #[serde(default)]
    pub probe_directory: Option<PathBuf>,
}
impl Config {
    pub(crate) fn validate<B: Binding>(&self) -> Result<()> {
        let action = B::effect_action()
            .ok_or_else(|| Error::new("invalid_input", "model has no fake provider"))?;
        let url = reqwest::Url::parse(&self.endpoint)
            .map_err(|_| Error::new("invalid_input", "fake provider endpoint"))?;
        let loopback = url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if B::NAME != "effect-demo"
            || action.provider_account != "fake-account-1"
            || action.version != "fake-units-1"
            || url.scheme() != "http"
            || !loopback
            || url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || self
                .probe_directory
                .as_ref()
                .is_some_and(|path| !path.is_absolute() || !path.is_dir())
        {
            return Err(Error::new(
                "invalid_input",
                "fake provider requires a loopback origin and matching action",
            ));
        }
        Ok(())
    }
}
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| Error::new("internal", "effect transaction task"))?
}
async fn probe(
    config: &Config,
    point: &str,
    id: Uuid,
    stop: &mut watch::Receiver<bool>,
) -> Result<bool> {
    let Some(directory) = &config.probe_directory else {
        return Ok(!*stop.borrow());
    };
    std::fs::write(
        directory.join(format!("{id}.{point}.json")),
        local::encode(&json!({"execution_id":id,"boundary":point}))?,
    )
    .map_err(local::storage)?;
    while (directory.join(format!("{point}.hold")).exists()
        || directory.join(format!("{id}.{point}.hold")).exists())
        && !*stop.borrow()
    {
        tokio::select! {
            _=tokio::time::sleep(Duration::from_millis(25))=>{},
            _=stop.changed()=>{break;},
        }
    }
    Ok(!*stop.borrow())
}

async fn call<B: Binding>(
    client: reqwest::Client,
    endpoint: String,
    row: Execution<B>,
    mode: Mode,
) -> Option<B::Outcome> {
    let url = format!(
        "{}/executions/{}/{}",
        endpoint.trim_end_matches('/'),
        row.id,
        row.action
    );
    let request=match mode {
        Mode::Submit=>client.post(url).json(&json!({"execution_id":row.id,"account":row.provider_account,"action":row.action,"request":row.request})),
        Mode::Reconcile=>client.get(url),
    };
    let mut response = request.send().await.ok()?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|len| len > MAX_OUTCOME as u64)
    {
        return None;
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if bytes.len().checked_add(chunk.len())? > MAX_OUTCOME {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    let outcome: B::Outcome = serde_json::from_value(crate::json::parse(&bytes).ok()?).ok()?;
    B::effect_outcome(&row.request, row.id, &outcome).ok()?;
    Some(outcome)
}

struct Completed<B: Binding> {
    claim: Claim,
    outcome: Option<B::Outcome>,
}

async fn finish<B: Binding>(
    store: Arc<Store<B>>,
    config: &Config,
    completed: Completed<B>,
    stop: &mut watch::Receiver<bool>,
) -> Result<()> {
    probe(config, "after_provider", completed.claim.execution, stop).await?;
    let id = completed.claim.execution;
    let result =
        blocking(move || store.finish_effect(&completed.claim, completed.outcome.as_ref())).await;
    match result {
        Ok(()) => {
            probe(config, "after_fact", id, stop).await?;
            Ok(())
        }
        // Cancellation, activation and expiry can supersede a real remote call.
        // Its durable start remains discoverable for read-only reconciliation.
        Err(error) if error.code == "stale_version" => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) async fn run<B: Binding>(
    store: Arc<Store<B>>,
    config: Config,
    activation: Uuid,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    config.validate::<B>()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(2))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .pool_max_idle_per_host(2)
        .build()
        .map_err(|_| Error::new("transport", "fake HTTP client"))?;
    let mut calls: JoinSet<Completed<B>> = JoinSet::new();
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let result:Result<()>=async {
        loop {
            if *stop.borrow() {break;}
            tokio::select! {
                _=stop.changed()=>{break;},
                completed=calls.join_next(),if !calls.is_empty()=> {
                    let completed=completed.ok_or_else(||Error::new("internal","missing effect task"))?
                        .map_err(|_|Error::new("internal","provider task"))?;
                    finish(store.clone(),&config,completed,&mut stop).await?;
                }
                _=interval.tick()=> {
                    let owner=store.clone();
                    let candidates=blocking(move ||owner.scan_effects(activation)).await?;
                    for candidate in candidates {
                        if *stop.borrow() {break;}
                        if candidate.class==WorkClass::Apply {
                            let owner=store.clone();blocking(move ||owner.apply_effect(&candidate)).await?;
                            continue;
                        }
                        if candidate.class!=WorkClass::Expiry && calls.len()>=2 {continue;}
                        let owner=store.clone();
                        let Some(claim)=blocking(move ||owner.claim_effect(&candidate)).await? else {continue;};
                        let (claim,row)=if claim.mode==Mode::Submit {
                            if !probe(&config,"before_start",claim.execution,&mut stop).await? {break;}
                            let owner=store.clone();
                            let started=match blocking(move ||owner.start_effect(&claim)).await {
                                Ok(Some(started))=>started, Ok(None)=>continue,
                                Err(error) if error.code=="stale_version"=>continue,
                                Err(error)=>return Err(error),
                            };
                            if !probe(&config,"after_start",started.execution,&mut stop).await? {break;}
                            let owner=store.clone();let copy=started.clone();
                            // Also recheck after any controlled pause/unknown start ACK.
                            let row=match blocking(move ||owner.confirm_effect_start(&copy)).await {
                                Ok(row)=>row,Err(e) if e.code=="stale_version"=>continue,Err(e)=>return Err(e),
                            };
                            (started,row)
                        } else {
                            let owner=store.clone();let id=claim.execution;
                            let row=blocking(move || {
                                let write=owner.db.begin_write().map_err(local::storage)?;
                                load_execution::<B>(&write,id)
                            }).await?;
                            (claim,row)
                        };
                        let client=client.clone();let endpoint=config.endpoint.clone();
                        calls.spawn(async move {
                            let outcome=call(client,endpoint,row,claim.mode).await;
                            Completed {claim,outcome}
                        });
                    }
                }
            }
        }
        Ok(())
    }.await;
    // Calls retain their slots through timeout/completion and shutdown. No
    // detached retries or newly claimed work enter this drain.
    while let Some(completed) = calls.join_next().await {
        if let Ok(completed) = completed
            && let Err(error) = finish(store.clone(), &config, completed, &mut stop).await
        {
            eprintln!(
                "{}",
                json!({"event":"effect_finish_deferred","kind":error.code})
            );
        }
    }
    result
}
