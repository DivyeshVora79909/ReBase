//! G5b obligations at real storage boundaries; clocks are explicit, no sleeps.
use super::*;
use crate::{
    access::{Grants, Graph, Principal, PrincipalKind},
    local::Mutation,
    models::effect_demo::{EffectDemo, Input, Outcome, ProviderPhase},
    native_slice::Context,
    security::ReplaceGraph,
};
use state::{Candidate, Claim, MAX_OBSERVATIONS, Mode, WorkClass};
use std::{path::PathBuf, sync::Arc};

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
struct Fixture {
    store: Store<EffectDemo>,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/effect-worker-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&path).unwrap();
        let store = Store::create_secured(
            path.join("store.redb"),
            Arc::new(Prepared::load().unwrap()),
            Context {
                tenant: id(1),
                actor: id(2),
            },
        )
        .unwrap();
        Self { store, path }
    }
    fn seed(&self, balance: i128) -> Uuid {
        self.seed_as(&self.store, balance)
    }
    fn seed_as(&self, session: &Store<EffectDemo>, balance: i128) -> Uuid {
        mutate(
            session,
            json!([
                {"op":"create","id":id(10),"contract":101,"fields":{"balance":balance.to_string()}},
                dispatch(20,None)
            ]),
        )["result"]["executions"][0]["execution_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap()
    }
    fn begin(&self, e: Uuid) -> (Claim, i64) {
        self.store
            .activate_effect_worker(WorkerMode::Delivery)
            .unwrap();
        let now = row(&self.store, e).created_at + 1;
        let claimed = self
            .store
            .claim_effect_at(&candidate(&self.store, e, WorkClass::Submit), Some(now))
            .unwrap()
            .unwrap();
        let started = self
            .store
            .start_effect_at(&claimed, Some(now))
            .unwrap()
            .unwrap();
        (started, now)
    }
    fn balance(&self) -> i128 {
        let Input::Account { balance } = self
            .store
            .get(self.store.model().identity(), id(10))
            .unwrap()
            .unwrap()
            .input
        else {
            panic!("account")
        };
        balance
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
fn mutate(store: &Store<EffectDemo>, commands: Value) -> Value {
    let request:Mutation=serde_json::from_value(json!({"model":store.model().identity(),
        "context":store.operation_context(store.model().identity()).unwrap(),"operation_id":Uuid::new_v4(),"commands":commands,"returning":[]})).unwrap();
    store.mutate(&request).unwrap()
}
fn dispatch(n: u128, at: Option<i64>) -> Value {
    json!({"op":"create","id":id(n),"contract":205,"fields":{"account":id(10),"units":"3","execute_at":at.map(|n|n.to_string()),"not_after":null}})
}
fn set_balance(store: &Store<EffectDemo>, balance: i128) {
    let target = store
        .get(store.model().identity(), id(10))
        .unwrap()
        .unwrap();
    mutate(
        store,
        json!([{"op":"update","id":id(10),"if_version":target.version.to_string(),"set":{"balance":balance.to_string()},"unset":[]} ]),
    );
}
fn row(store: &Store<EffectDemo>, e: Uuid) -> Execution<EffectDemo> {
    let write = store.db.begin_write().unwrap();
    load_execution(&write, e).unwrap()
}
fn candidate(store: &Store<EffectDemo>, e: Uuid, class: WorkClass) -> Candidate {
    let write = store.db.begin_write().unwrap();
    let runtime = runtime_write(&write).unwrap();
    let row = load_execution::<EffectDemo>(&write, e).unwrap();
    Candidate {
        store: row.store,
        activation: runtime.activation,
        execution: e,
        revision: row.revision,
        class,
    }
}
fn outcome(e: Uuid, phase: ProviderPhase) -> Outcome {
    Outcome {
        execution_id: e,
        account: "fake-account-1".into(),
        action: 1,
        units: 3,
        phase,
        receipt: matches!(phase, ProviderPhase::Succeeded | ProviderPhase::Waiting)
            .then(|| id(999).to_string()),
    }
}
fn cancel(store: &Store<EffectDemo>, e: Uuid) {
    store
        .cancel_effect(&Cancel {
            model: store.model().identity().into(),
            context: store.operation_context(store.model().identity()).unwrap(),
            operation_id: Uuid::new_v4(),
            execution_id: e,
            if_revision: row(store, e).revision,
        })
        .unwrap();
}
fn replace_graph(store: &Store<EffectDemo>, graph: Graph) {
    let revision = store.access_graph(store.model().identity()).unwrap()["revision"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    store
        .replace_access(&ReplaceGraph {
            model: store.model().identity().into(),
            if_revision: revision,
            graph,
        })
        .unwrap();
}
fn requester(store: &Store<EffectDemo>) -> (Store<EffectDemo>, Graph) {
    let mut graph = Graph::bootstrap(store.context()).unwrap().graph;
    graph.principals.push(Principal {
        id: id(3),
        kind: PrincipalKind::User,
        parents: vec![id(1)],
        active: true,
        credential_epoch: 0,
        grants: Grants {
            admin: false,
            contracts: [101, 205]
                .into_iter()
                .map(|c| {
                    (
                        c,
                        BTreeSet::from([Action::Read, Action::Create, Action::Update]),
                    )
                })
                .collect(),
        },
    });
    replace_graph(store, graph.clone());
    (store.session(id(3), 0).unwrap(), graph)
}

#[test]
fn success_applies_once_and_blocked_fact_survives_repair_without_resubmission() {
    let f = Fixture::new();
    let e = f.seed(12);
    set_balance(&f.store, 10);
    let (claim, now) = f.begin(e);
    f.store
        .finish_effect_at(
            &claim,
            Some(&outcome(e, ProviderPhase::Succeeded)),
            Some(now + 1),
            None,
        )
        .unwrap();
    assert_eq!(f.balance(), 10);
    let apply = candidate(&f.store, e, WorkClass::Apply);
    assert!(f.store.apply_effect(&apply).unwrap());
    assert_eq!(f.balance(), 7);
    let applied = f.store.observe_for_verification().unwrap();
    assert!(!f.store.apply_effect(&apply).unwrap());
    assert_eq!(f.store.observe_for_verification().unwrap(), applied);
    f.store.check_integrity().unwrap();

    let f = Fixture::new();
    let e = f.seed(12);
    let (claim, now) = f.begin(e);
    set_balance(&f.store, 2);
    f.store
        .finish_effect_at(
            &claim,
            Some(&outcome(e, ProviderPhase::Succeeded)),
            Some(now + 1),
            None,
        )
        .unwrap();
    assert!(
        !f.store
            .apply_effect(&candidate(&f.store, e, WorkClass::Apply))
            .unwrap()
    );
    assert_eq!(f.balance(), 2);
    assert_eq!(row(&f.store, e).application, Application::Blocked);
    assert_eq!(f.store.check_integrity().unwrap()["effects"]["facts"], 1);
    set_balance(&f.store, 5);
    f.store
        .activate_effect_worker(WorkerMode::Disabled)
        .unwrap();
    f.store.retry_effect(e, row(&f.store, e).revision).unwrap();
    f.store
        .activate_effect_worker(WorkerMode::Delivery)
        .unwrap();
    assert!(
        f.store
            .apply_effect(&candidate(&f.store, e, WorkClass::Apply))
            .unwrap()
    );
    assert_eq!(f.balance(), 2);
    assert_eq!(row(&f.store, e).attempts, 1);
    assert!(
        f.store
            .claim_effect_at(&candidate(&f.store, e, WorkClass::Submit), Some(now + 2))
            .unwrap()
            .is_none()
    );
    f.store.check_integrity().unwrap();
}

#[test]
fn scoped_retry_rechecks_current_authority_revision_worker_and_phase_without_partial_writes() {
    let f = Fixture::new();
    let (requesting, mut graph) = requester(&f.store);
    let e = f.seed_as(&requesting, 12);
    let (claim, now) = f.begin(e);
    set_balance(&f.store, 2);
    f.store
        .finish_effect_at(
            &claim,
            Some(&outcome(e, ProviderPhase::Succeeded)),
            Some(now + 1),
            None,
        )
        .unwrap();
    assert!(
        !f.store
            .apply_effect(&candidate(&f.store, e, WorkClass::Apply))
            .unwrap()
    );
    let (_, _, header) = f.store.read(f.store.model().identity()).unwrap();
    let revision = row(&f.store, e).revision;
    let before = f.store.observe_for_verification().unwrap();
    assert_eq!(
        requesting
            .retry_effect_scoped(header.store_id, e, revision)
            .unwrap_err()
            .code,
        "invalid_input"
    );
    assert_eq!(f.store.observe_for_verification().unwrap(), before);
    f.store
        .activate_effect_worker(WorkerMode::Disabled)
        .unwrap();
    graph
        .principals
        .iter_mut()
        .find(|p| p.id == id(3))
        .unwrap()
        .grants
        .contracts
        .get_mut(&101)
        .unwrap()
        .remove(&Action::Update);
    replace_graph(&f.store, graph.clone());
    let before = f.store.observe_for_verification().unwrap();
    assert_eq!(
        requesting
            .retry_effect_scoped(header.store_id, e, revision)
            .unwrap_err()
            .code,
        "forbidden"
    );
    assert_eq!(f.store.observe_for_verification().unwrap(), before);
    graph
        .principals
        .iter_mut()
        .find(|p| p.id == id(3))
        .unwrap()
        .grants
        .contracts
        .get_mut(&101)
        .unwrap()
        .insert(Action::Update);
    replace_graph(&f.store, graph);
    let before = f.store.observe_for_verification().unwrap();
    assert_eq!(
        requesting
            .retry_effect_scoped(header.store_id, e, revision - 1)
            .unwrap_err()
            .code,
        "stale_version"
    );
    assert_eq!(f.store.observe_for_verification().unwrap(), before);
    assert_eq!(
        requesting
            .retry_effect_scoped(Uuid::new_v4(), e, revision)
            .unwrap_err()
            .code,
        "wrong_target"
    );
    assert_eq!(f.store.observe_for_verification().unwrap(), before);
    let retried = requesting
        .retry_effect_scoped(header.store_id, e, revision)
        .unwrap();
    assert_eq!(retried["application"], "pending");
    assert_eq!(retried["revision"], (revision + 1).to_string());
    assert_eq!(row(&f.store, e).attempts, 1);
    let before = f.store.observe_for_verification().unwrap();
    assert_eq!(
        requesting
            .retry_effect_scoped(header.store_id, e, revision + 1)
            .unwrap_err()
            .code,
        "invalid_input"
    );
    assert_eq!(f.store.observe_for_verification().unwrap(), before);
    f.store.check_integrity().unwrap();
}

#[test]
fn private_host_retry_requires_grant_and_stopped_service_then_retries_a_blocked_fact() {
    use crate::host::{Host, PROTOCOL};
    fn call(host: &mut Host, method: &str, params: Value) -> Value {
        host.handle(
            &serde_json::to_vec(
                &json!({"protocol":PROTOCOL,"id":"retry-test","method":method,"params":params}),
            )
            .unwrap(),
        )
    }
    fn image(host: &mut Host, scope: &Value, directory: &std::path::Path) -> Value {
        let destination = directory.join(format!("image-{}.json", Uuid::new_v4()));
        let reply = call(
            host,
            "store.backup",
            json!({"scope":scope,"destination":destination}),
        );
        assert!(reply.get("error").is_none(), "{reply}");
        let backup: Value = serde_json::from_slice(&std::fs::read(destination).unwrap()).unwrap();
        backup["payload"].clone()
    }
    let directory = std::env::temp_dir().join(format!("rebase-host-retry-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("store.redb");
    let store = Store::<EffectDemo>::create_secured(
        &path,
        Arc::new(Prepared::load().unwrap()),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    let e: Uuid = mutate(
        &store,
        json!([
            {"op":"create","id":id(10),"contract":101,"fields":{"balance":"12"}}, dispatch(20, None)
        ]),
    )["result"]["executions"][0]["execution_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    store.activate_effect_worker(WorkerMode::Delivery).unwrap();
    let now = row(&store, e).created_at + 1;
    let claim = store
        .claim_effect_at(&candidate(&store, e, WorkClass::Submit), Some(now))
        .unwrap()
        .unwrap();
    let claim = store.start_effect_at(&claim, Some(now)).unwrap().unwrap();
    set_balance(&store, 2);
    store
        .finish_effect_at(
            &claim,
            Some(&outcome(e, ProviderPhase::Succeeded)),
            Some(now + 1),
            None,
        )
        .unwrap();
    assert!(
        !store
            .apply_effect(&candidate(&store, e, WorkClass::Apply))
            .unwrap()
    );
    store.activate_effect_worker(WorkerMode::Disabled).unwrap();
    let revision = row(&store, e).revision;
    let (_, _, header) = store.read(store.model().identity()).unwrap();
    let scope = json!({"model":store.model().identity(),"store":header.store_id});
    let public = crate::rpc::handle(
        &store,
        &serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":"public","method":"effects.retry","params":{}}),
        )
        .unwrap(),
    );
    assert_eq!(public["error"]["data"]["kind"], "method_not_found");
    drop(store);
    let config = |granted: bool| {
        json!({"model":"effect-demo","backend":{"kind":"redb","cluster_file":null},
        "target":{"mode":"open","path":path,"expect_store":header.store_id},
        "operator_methods":if granted { vec!["effects.retry","store.backup","service.start","service.stop"] } else { vec![] }})
    };
    let params = json!({"scope":scope,"execution_id":e,"if_revision":revision.to_string()});
    let mut host = Host::default();
    assert!(
        call(&mut host, "host.configure", config(false))
            .get("error")
            .is_none()
    );
    assert_eq!(
        call(&mut host, "effects.retry", params.clone())["error"]["kind"],
        "forbidden"
    );
    call(&mut host, "host.close", json!({}));
    drop(host);
    let mut host = Host::default();
    assert!(
        call(&mut host, "host.configure", config(true))
            .get("error")
            .is_none()
    );
    for invalid in [
        json!(revision),
        json!("01"),
        json!("-1"),
        json!("18446744073709551616"),
    ] {
        let mut request = params.clone();
        request["if_revision"] = invalid;
        assert_eq!(
            call(&mut host, "effects.retry", request)["error"]["kind"],
            "invalid_request"
        );
    }
    let service = call(
        &mut host,
        "service.start",
        json!({"scope":scope,"config":{
            "listen":"127.0.0.1:0","identity":{"issuer":"retry","audience":"retry","public_keys":{"test":include_str!("../../tests/fixtures/test-ed25519-public.pem")},"max_token_seconds":300},
            "max_inflight":1,"request_timeout_seconds":1,"effects":null
        }}),
    );
    assert!(service.get("error").is_none(), "{service}");
    let before = image(&mut host, &scope, &directory);
    assert_eq!(
        call(&mut host, "effects.retry", params.clone())["error"]["kind"],
        "service_running"
    );
    assert_eq!(image(&mut host, &scope, &directory), before);
    assert!(
        call(
            &mut host,
            "service.stop",
            json!({"scope":scope,"service":service["result"]["service"]})
        )
        .get("error")
        .is_none()
    );
    let before = image(&mut host, &scope, &directory);
    let mut wrong = params.clone();
    wrong["scope"]["store"] = json!(Uuid::new_v4());
    assert_eq!(
        call(&mut host, "effects.retry", wrong)["error"]["kind"],
        "wrong_target"
    );
    let mut stale = params.clone();
    stale["if_revision"] = json!((revision - 1).to_string());
    assert_eq!(
        call(&mut host, "effects.retry", stale)["error"]["kind"],
        "stale_version"
    );
    assert_eq!(image(&mut host, &scope, &directory), before);
    let retried = call(&mut host, "effects.retry", params);
    assert_eq!(retried["result"]["application"], "pending", "{retried}");
    assert_eq!(retried["result"]["revision"], (revision + 1).to_string());
    call(&mut host, "host.close", json!({}));
    drop(host);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn fact_and_application_abort_after_real_writes_preserve_every_table() {
    let f = Fixture::new();
    let e = f.seed(12);
    let (claim, now) = f.begin(e);
    let before = f.store.observe_for_verification().unwrap();
    for point in [
        usize::MAX - 4,
        usize::MAX - 2,
        usize::MAX - 1,
        usize::MAX - 3,
    ] {
        assert_eq!(
            f.store
                .finish_effect_at(
                    &claim,
                    Some(&outcome(e, ProviderPhase::Succeeded)),
                    Some(now + 1),
                    Some(point)
                )
                .unwrap_err()
                .code,
            "injected_abort"
        );
        assert_eq!(f.store.observe_for_verification().unwrap(), before);
    }
    f.store
        .finish_effect_at(
            &claim,
            Some(&outcome(e, ProviderPhase::Succeeded)),
            Some(now + 1),
            None,
        )
        .unwrap();
    let apply = candidate(&f.store, e, WorkClass::Apply);
    let before = f.store.observe_for_verification().unwrap();
    for point in [
        1,
        usize::MAX - 5,
        usize::MAX - 4,
        usize::MAX - 2,
        usize::MAX - 1,
        usize::MAX - 3,
    ] {
        assert_eq!(
            f.store
                .apply_effect_inner(&apply, Some(point))
                .unwrap_err()
                .code,
            "injected_abort"
        );
        assert_eq!(f.store.observe_for_verification().unwrap(), before);
    }
    assert!(f.store.apply_effect(&apply).unwrap());
    assert_eq!(f.balance(), 9);
    f.store.check_integrity().unwrap();
}

#[test]
fn duplicate_claims_revisions_activation_and_finite_renewal_fence_writers() {
    let f = Fixture::new();
    let e = f.seed(12);
    f.store
        .activate_effect_worker(WorkerMode::Delivery)
        .unwrap();
    let now = row(&f.store, e).created_at + 1;
    let selected = candidate(&f.store, e, WorkClass::Submit);
    let claim = f
        .store
        .claim_effect_at(&selected, Some(now))
        .unwrap()
        .unwrap();
    assert!(
        f.store
            .claim_effect_at(&selected, Some(now))
            .unwrap()
            .is_none()
    );
    let started = f.store.start_effect_at(&claim, Some(now)).unwrap().unwrap();
    assert_eq!(
        f.store.start_effect_at(&claim, Some(now)).unwrap_err().code,
        "stale_version"
    );
    let renewed = f.store.renew_effect_at(&started, Some(now + 9000)).unwrap();
    assert_eq!(
        f.store
            .finish_effect_at(&started, None, Some(now + 9001), None)
            .unwrap_err()
            .code,
        "stale_version"
    );
    let renewed = f
        .store
        .renew_effect_at(&renewed, Some(now + 18000))
        .unwrap();
    assert!(
        f.store
            .renew_effect_at(&renewed, Some(now + 27000))
            .is_err()
    );
    assert!(
        f.store
            .finish_effect_at(&renewed, None, Some(now + 28000), None)
            .is_err()
    );
    f.store
        .claim_effect_at(
            &candidate(&f.store, e, WorkClass::Expiry),
            Some(now + 28000),
        )
        .unwrap();
    assert_eq!(row(&f.store, e).phase, Phase::Uncertain);
    assert!(
        f.store
            .claim_effect_at(
                &candidate(&f.store, e, WorkClass::Submit),
                Some(now + 30000)
            )
            .unwrap()
            .is_none()
    );
    let reconcile = f
        .store
        .claim_effect_at(
            &candidate(&f.store, e, WorkClass::Reconcile),
            Some(now + 30000),
        )
        .unwrap()
        .unwrap();
    f.store
        .activate_effect_worker(WorkerMode::Delivery)
        .unwrap();
    assert!(
        f.store
            .finish_effect_at(
                &reconcile,
                Some(&outcome(e, ProviderPhase::Succeeded)),
                Some(now + 30001),
                None
            )
            .is_err()
    );
    f.store.check_integrity().unwrap();
}

#[test]
fn captured_epoch_is_rechecked_at_claim_and_start_but_cannot_erase_later_facts() {
    for stage in 0..3 {
        let f = Fixture::new();
        let (session, mut graph) = requester(&f.store);
        let e = f.seed_as(&session, 12);
        f.store
            .activate_effect_worker(WorkerMode::Delivery)
            .unwrap();
        let now = row(&f.store, e).created_at + 1;
        let claim = (stage > 0).then(|| {
            f.store
                .claim_effect_at(&candidate(&f.store, e, WorkClass::Submit), Some(now))
                .unwrap()
                .unwrap()
        });
        let started = (stage == 2).then(|| {
            f.store
                .start_effect_at(claim.as_ref().unwrap(), Some(now))
                .unwrap()
                .unwrap()
        });
        graph
            .principals
            .iter_mut()
            .find(|p| p.id == id(3))
            .unwrap()
            .credential_epoch = 1;
        replace_graph(&f.store, graph);
        match stage {
            0 => assert!(
                f.store
                    .claim_effect_at(&candidate(&f.store, e, WorkClass::Submit), Some(now))
                    .unwrap()
                    .is_none()
            ),
            1 => assert!(
                f.store
                    .start_effect_at(claim.as_ref().unwrap(), Some(now + 1))
                    .unwrap()
                    .is_none()
            ),
            _ => {
                f.store
                    .finish_effect_at(
                        started.as_ref().unwrap(),
                        Some(&outcome(e, ProviderPhase::Succeeded)),
                        Some(now + 1),
                        None,
                    )
                    .unwrap();
                assert!(
                    f.store
                        .apply_effect(&candidate(&f.store, e, WorkClass::Apply))
                        .unwrap()
                );
                assert_eq!(f.balance(), 9);
            }
        }
        if stage < 2 {
            assert_eq!(row(&f.store, e).cancellation, Some(Cancellation::Revoked));
        }
        f.store.check_integrity().unwrap();
    }
}

#[test]
fn cancellation_before_start_suppresses_it_and_after_start_forces_reconciliation() {
    for after in [false, true] {
        let f = Fixture::new();
        let e = f.seed(12);
        f.store
            .activate_effect_worker(WorkerMode::Delivery)
            .unwrap();
        let now = row(&f.store, e).created_at + 1;
        let claim = f
            .store
            .claim_effect_at(&candidate(&f.store, e, WorkClass::Submit), Some(now))
            .unwrap()
            .unwrap();
        let claim = if after {
            f.store.start_effect_at(&claim, Some(now)).unwrap().unwrap()
        } else {
            claim
        };
        cancel(&f.store, e);
        assert!(f.store.start_effect_at(&claim, Some(now + 1)).is_err());
        assert!(
            f.store
                .finish_effect_at(
                    &claim,
                    Some(&outcome(e, ProviderPhase::Succeeded)),
                    Some(now + 1),
                    None
                )
                .is_err()
        );
        if after {
            assert_eq!(row(&f.store, e).phase, Phase::Uncertain);
            let now = row(&f.store, e).next_at.max(now + 1);
            let claim = f
                .store
                .claim_effect_at(&candidate(&f.store, e, WorkClass::Reconcile), Some(now))
                .unwrap()
                .unwrap();
            assert_eq!(claim.mode, Mode::Reconcile);
            f.store
                .finish_effect_at(
                    &claim,
                    Some(&outcome(e, ProviderPhase::Succeeded)),
                    Some(now + 1),
                    None,
                )
                .unwrap();
            f.store
                .apply_effect(&candidate(&f.store, e, WorkClass::Apply))
                .unwrap();
            assert_eq!(f.balance(), 9);
        } else {
            assert_eq!(row(&f.store, e).phase, Phase::Cancelled);
            assert_eq!(f.balance(), 12);
        }
        f.store.check_integrity().unwrap();
    }
}

#[test]
fn only_definitive_nonacceptance_retries_and_all_automatic_budgets_terminate() {
    let f = Fixture::new();
    let e = f.seed(12);
    f.store
        .activate_effect_worker(WorkerMode::Delivery)
        .unwrap();
    for attempt in 1..=3 {
        let now = row(&f.store, e).next_at.max(row(&f.store, e).created_at) + 1;
        let claim = f
            .store
            .claim_effect_at(&candidate(&f.store, e, WorkClass::Submit), Some(now))
            .unwrap()
            .unwrap();
        let claim = f.store.start_effect_at(&claim, Some(now)).unwrap().unwrap();
        f.store
            .finish_effect_at(
                &claim,
                Some(&outcome(e, ProviderPhase::NotAccepted)),
                Some(now + 1),
                None,
            )
            .unwrap();
        assert_eq!(row(&f.store, e).attempts, attempt);
    }
    assert_eq!(row(&f.store, e).phase, Phase::Failed);
    assert!(!row(&f.store, e).unresolved());
    f.store.check_integrity().unwrap();
    let f = Fixture::new();
    let e = f.seed(12);
    let (claim, now) = f.begin(e);
    f.store
        .finish_effect_at(&claim, None, Some(now + 1), None)
        .unwrap();
    for _ in 0..MAX_OBSERVATIONS {
        let now = row(&f.store, e).next_at + 1;
        let claim = f
            .store
            .claim_effect_at(&candidate(&f.store, e, WorkClass::Reconcile), Some(now))
            .unwrap()
            .unwrap();
        f.store
            .finish_effect_at(&claim, None, Some(now + 1), None)
            .unwrap();
    }
    let final_row = row(&f.store, e);
    assert_eq!(final_row.phase, Phase::Uncertain);
    assert_eq!(final_row.attempts, 1);
    assert!(final_row.due().is_none());
    f.store.check_integrity().unwrap();
}

#[test]
fn expired_unstarted_claims_and_submission_deadlines_do_not_call_the_provider() {
    let f = Fixture::new();
    let e = f.seed(12);
    f.store
        .activate_effect_worker(WorkerMode::Delivery)
        .unwrap();
    for _ in 0..3 {
        let now = row(&f.store, e).next_at.max(row(&f.store, e).created_at) + 1;
        let claim = f
            .store
            .claim_effect_at(&candidate(&f.store, e, WorkClass::Submit), Some(now))
            .unwrap()
            .unwrap();
        f.store
            .claim_effect_at(
                &candidate(&f.store, e, WorkClass::Expiry),
                Some(now + 10_000),
            )
            .unwrap();
        assert!(f.store.start_effect_at(&claim, Some(now + 10_000)).is_err());
    }
    let now = row(&f.store, e).next_at + 1;
    assert!(
        f.store
            .claim_effect_at(&candidate(&f.store, e, WorkClass::Submit), Some(now))
            .unwrap()
            .is_none()
    );
    assert_eq!(row(&f.store, e).phase, Phase::Failed);
    f.store.check_integrity().unwrap();
    for start in [false, true] {
        let f = Fixture::new();
        let e = f.seed(12);
        f.store
            .activate_effect_worker(WorkerMode::Delivery)
            .unwrap();
        let end = row(&f.store, e).not_after;
        if start {
            let claim = f
                .store
                .claim_effect_at(&candidate(&f.store, e, WorkClass::Submit), Some(end - 1))
                .unwrap()
                .unwrap();
            assert!(
                f.store
                    .start_effect_at(&claim, Some(end))
                    .unwrap()
                    .is_none()
            );
        } else {
            assert!(
                f.store
                    .claim_effect_at(&candidate(&f.store, e, WorkClass::Submit), Some(end))
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(row(&f.store, e).cancellation, Some(Cancellation::Expired));
        f.store.check_integrity().unwrap();
    }
}

#[test]
fn bounded_sweeps_advance_past_unclaimed_rows_wrap_backdated_inserts_and_restart() {
    let f = Fixture::new();
    let first = f.seed(12);
    let at = row(&f.store, first).created_at;
    mutate(
        &f.store,
        Value::Array((21..39).map(|n| dispatch(n, Some(at))).collect()),
    );
    let activation = f
        .store
        .activate_effect_worker(WorkerMode::Delivery)
        .unwrap();
    let now = at + 1000;
    let mut seen = BTreeSet::new();
    for _ in 0..8 {
        let rows = f.store.scan_effects_at(activation, Some(now)).unwrap();
        assert!(rows.len() <= 16);
        seen.extend(rows.into_iter().map(|r| r.execution));
    }
    assert_eq!(seen.len(), 19);
    let new=mutate(&f.store,json!([dispatch(39,Some(at-1000))]))["result"]["executions"][0]["execution_id"].as_str().unwrap().parse::<Uuid>().unwrap();
    for _ in 0..8 {
        seen.extend(
            f.store
                .scan_effects_at(activation, Some(now))
                .unwrap()
                .into_iter()
                .map(|r| r.execution),
        );
    }
    assert!(seen.contains(&new));
    let activation = f
        .store
        .activate_effect_worker(WorkerMode::Delivery)
        .unwrap();
    let mut restarted = BTreeSet::new();
    for _ in 0..8 {
        restarted.extend(
            f.store
                .scan_effects_at(activation, Some(now))
                .unwrap()
                .into_iter()
                .map(|r| r.execution),
        );
    }
    assert_eq!(seen, restarted);
    f.store.check_integrity().unwrap();
}

#[test]
fn typed_outcome_binding_and_fact_inventory_reject_corruption() {
    let f = Fixture::new();
    let e = f.seed(12);
    let (claim, now) = f.begin(e);
    let before = f.store.observe_for_verification().unwrap();
    let mut bad = outcome(e, ProviderPhase::Succeeded);
    bad.units = 4;
    assert!(
        f.store
            .finish_effect_at(&claim, Some(&bad), Some(now + 1), None)
            .is_err()
    );
    bad = outcome(id(1234), ProviderPhase::Succeeded);
    assert!(
        f.store
            .finish_effect_at(&claim, Some(&bad), Some(now + 1), None)
            .is_err()
    );
    bad = outcome(e, ProviderPhase::Succeeded);
    bad.account = "x".repeat(MAX_OUTCOME);
    assert_eq!(
        f.store
            .finish_effect_at(&claim, Some(&bad), Some(now + 1), None)
            .unwrap_err()
            .code,
        "request_limit"
    );
    assert_eq!(f.store.observe_for_verification().unwrap(), before);
    f.store
        .finish_effect_at(
            &claim,
            Some(&outcome(e, ProviderPhase::Succeeded)),
            Some(now + 1),
            None,
        )
        .unwrap();
    let write = f.store.db.begin_write().unwrap();
    let original: Fact<EffectDemo> = {
        let t = write.open_table(FACTS).unwrap();
        local::decode(t.iter().unwrap().next().unwrap().unwrap().1.value()).unwrap()
    };
    drop(write);
    for changed in 0..3 {
        let mut fact = original.clone();
        match changed {
            0 => fact.request_hash = "0".repeat(64),
            1 => fact.applied_revision = Some(Uuid::nil()),
            _ => fact.disposition = Disposition::Waiting,
        }
        let key = state::fact_key(e, &original.digest).unwrap();
        let write = f.store.db.begin_write().unwrap();
        write
            .open_table(FACTS)
            .unwrap()
            .insert(key.as_slice(), local::encode(&fact).unwrap().as_slice())
            .unwrap();
        write.commit().unwrap();
        assert!(f.store.check_integrity().is_err());
        let write = f.store.db.begin_write().unwrap();
        write
            .open_table(FACTS)
            .unwrap()
            .insert(key.as_slice(), local::encode(&original).unwrap().as_slice())
            .unwrap();
        write.commit().unwrap();
    }
    f.store.check_integrity().unwrap();
}

#[test]
fn terminal_reservation_survives_the_actual_fact_ceiling_and_duplicates() {
    let f = Fixture::new();
    let e = f.seed(12);
    let (claim, now) = f.begin(e);
    f.store
        .finish_effect_at(
            &claim,
            Some(&outcome(e, ProviderPhase::Waiting)),
            Some(now + 1),
            None,
        )
        .unwrap();
    // Fill discretionary evidence in a single transaction, retaining the one
    // promised result slot. Distinct immutable receipts are distinct evidence.
    let write = f.store.db.begin_write().unwrap();
    let mut runtime = runtime_write(&write).unwrap();
    for n in 1..MAX_FACTS - 1 {
        let before = load_execution::<EffectDemo>(&write, e).unwrap();
        let mut row = before.clone();
        let mut next = outcome(e, ProviderPhase::Waiting);
        next.receipt = Some(id(10_000 + n as u128).to_string());
        worker::record_fact(&write, &mut runtime, &mut row, &next, now + 2, false).unwrap();
        row.advance().unwrap();
        replace_execution(&write, &mut runtime, &before, &row, None).unwrap();
    }
    write.commit().unwrap();
    let before = f.store.observe_for_verification().unwrap();
    let discretionary = || -> Result<()> {
        let write = f.store.db.begin_write().map_err(local::storage)?;
        let mut runtime = runtime_write(&write)?;
        let before = load_execution::<EffectDemo>(&write, e)?;
        let mut row = before.clone();
        let mut next = outcome(e, ProviderPhase::Waiting);
        next.receipt = Some(id(999_999).to_string());
        worker::record_fact(&write, &mut runtime, &mut row, &next, now + 2, false)?;
        row.advance()?;
        replace_execution(&write, &mut runtime, &before, &row, None)
    };
    assert_eq!(discretionary().unwrap_err().code, "state_limit");
    assert_eq!(f.store.observe_for_verification().unwrap(), before);
    let claim = f
        .store
        .claim_effect_at(
            &candidate(&f.store, e, WorkClass::Reconcile),
            Some(now + 5000),
        )
        .unwrap()
        .unwrap();
    f.store
        .finish_effect_at(
            &claim,
            Some(&outcome(e, ProviderPhase::Succeeded)),
            Some(now + 5001),
            None,
        )
        .unwrap();
    let checked = f.store.check_integrity().unwrap();
    assert_eq!(checked["effects"]["facts"], MAX_FACTS);
    assert_eq!(checked["effects"]["reserved_facts"], 0);
    assert!(
        f.store
            .apply_effect(&candidate(&f.store, e, WorkClass::Apply))
            .unwrap()
    );
    assert_eq!(f.balance(), 9);
    assert!(
        f.store.backup(f.path.join("full.backup.json")).unwrap()["bytes"]
            .as_u64()
            .unwrap()
            < crate::lifecycle::MAX_BACKUP_BYTES
    );
}

#[test]
fn duplicate_and_older_facts_do_not_regress_success_and_conflicts_remain_evidence() {
    let f = Fixture::new();
    let e = f.seed(12);
    let (claim, now) = f.begin(e);
    f.store
        .finish_effect_at(
            &claim,
            Some(&outcome(e, ProviderPhase::Succeeded)),
            Some(now + 1),
            None,
        )
        .unwrap();
    f.store
        .apply_effect(&candidate(&f.store, e, WorkClass::Apply))
        .unwrap();
    for (phase, count, conflict) in [
        (ProviderPhase::Succeeded, 1, false),
        (ProviderPhase::Waiting, 2, false),
        (ProviderPhase::Failed, 3, true),
    ] {
        let write = f.store.db.begin_write().unwrap();
        let mut runtime = runtime_write(&write).unwrap();
        let before = load_execution::<EffectDemo>(&write, e).unwrap();
        let mut changed = before.clone();
        worker::record_fact(
            &write,
            &mut runtime,
            &mut changed,
            &outcome(e, phase),
            now + 2,
            false,
        )
        .unwrap();
        changed.advance().unwrap();
        replace_execution(&write, &mut runtime, &before, &changed, None).unwrap();
        write.commit().unwrap();
        let current = row(&f.store, e);
        assert_eq!(current.phase, Phase::Succeeded);
        assert_eq!(current.application, Application::Applied);
        assert_eq!(current.conflict, conflict);
        assert_eq!(f.balance(), 9);
        assert_eq!(
            f.store.check_integrity().unwrap()["effects"]["facts"],
            count
        );
    }
}

#[test]
fn persisted_sweep_and_lease_bounds_and_unsupported_failure_states_are_checked() {
    let f = Fixture::new();
    let e = f.seed(12);
    let (claim, now) = f.begin(e);
    let write = f.store.db.begin_write().unwrap();
    let runtime = runtime_write(&write).unwrap();
    let baseline = load_execution::<EffectDemo>(&write, e).unwrap();
    drop(write);
    let mut bad = baseline.clone();
    bad.lease.as_mut().unwrap().expires_at = now + 10_001;
    assert!(bad.validate_state(&runtime).is_err());
    bad = baseline.clone();
    bad.started.as_mut().unwrap().at = now - 1;
    assert!(bad.validate_state(&runtime).is_err());
    bad = baseline;
    bad.phase = Phase::Failed;
    bad.started = None;
    bad.lease = None;
    bad.reservation = false;
    bad.diagnostic = Some("unproved failure".into());
    assert!(bad.validate_state(&runtime).is_err());
    let future = state::work_key(WorkClass::Submit, now + 1, e);
    let sweep = Sweep {
        cutoff: now,
        end: Some(native_codec::hex(&future)),
        cursor: None,
    };
    assert!(sweep.validate(WorkClass::Submit as u8).is_err());
    assert_eq!(claim.mode, Mode::Submit);
    f.store.check_integrity().unwrap();
}

#[path = "inbox_tests.rs"]
mod ingress;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scoped_live_worker_and_signed_ingress_cannot_adopt_reset_store() {
    use crate::{
        identity::IdentityConfig,
        server::{ServerConfig, start_scoped},
    };
    use hmac::{Hmac, Mac};
    let f = Fixture::new();
    let execution = f.seed(12);
    let store = Arc::new(f.store.session(id(2), 0).unwrap());
    let (_, _, header) = store.read(store.model().identity()).unwrap();
    let scoped = store.scoped_to(header.store_id);
    let secret = b"n6-disposable-secret-for-runtime-scope";
    let secret_path = f.path.join("ingress.secret");
    std::fs::write(&secret_path, secret).unwrap();
    let hold = f.path.join("before_start.hold");
    std::fs::write(&hold, b"").unwrap();
    let identity: IdentityConfig = serde_json::from_value(json!({
        "issuer":"worker-scope", "audience":"worker-scope",
        "public_keys":{"test":include_str!("../../tests/fixtures/test-ed25519-public.pem")},
        "max_token_seconds":300,
    }))
    .unwrap();
    let service = start_scoped(
        store.clone(),
        ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            identity,
            max_inflight: 2,
            request_timeout_seconds: 2,
            effects: Some(fake::Config {
                endpoint: "http://127.0.0.1:1/".into(),
                mode: WorkerMode::Delivery,
                ingress_secret_file: Some(secret_path),
                probe_directory: Some(f.path.clone()),
            }),
        },
        Some(header.store_id),
    )
    .await
    .unwrap();
    let paused = f.path.join(format!("{execution}.before_start.json"));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !paused.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // The real worker is paused after claim and before native start/provider I/O.
    // A retained unscoped owner cancels work and disables its activation before
    // a legal reset. The service and worker remain alive with the old UUID.
    cancel(&store, execution);
    store.activate_effect_worker(WorkerMode::Disabled).unwrap();
    store.reset(header.store_id).unwrap();
    let replacement = store.observe_for_verification().unwrap();
    let event = Uuid::new_v4().to_string();
    let timestamp = now_millis().unwrap().to_string();
    let bytes = local::encode(&json!({
        "execution_id":execution, "outcome":outcome(execution, ProviderPhase::Succeeded),
    }))
    .unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(format!("fake-account-1\n{event}\n{timestamp}\n").as_bytes());
    mac.update(&bytes);
    let response = reqwest::Client::new()
        .post(format!("http://{}/effects/fake", service.address))
        .header("content-type", "application/json")
        .header("x-fake-account", "fake-account-1")
        .header("x-fake-event", event)
        .header("x-fake-timestamp", timestamp)
        .header(
            "x-fake-signature",
            native_codec::hex(&mac.finalize().into_bytes()),
        )
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        "wrong_target"
    );
    for mode in [WorkerMode::Delivery, WorkerMode::Disabled] {
        assert_eq!(
            scoped.activate_effect_worker(mode).unwrap_err().code,
            "wrong_target"
        );
    }
    assert_eq!(
        scoped.scan_effects(Uuid::new_v4()).unwrap_err().code,
        "wrong_target"
    );
    assert_eq!(store.observe_for_verification().unwrap(), replacement);
    // Releasing the real worker forces its next transaction to reject the new
    // UUID. Its failure stops admission; stop joins the worker and HTTP drain.
    std::fs::remove_file(&hold).unwrap();
    let address = service.address;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while tokio::net::TcpStream::connect(address).await.is_ok() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(service.stop().await.unwrap_err().code, "wrong_target");
    assert_eq!(store.observe_for_verification().unwrap(), replacement);
    drop((scoped, store));
    std::fs::remove_dir_all(&f.path).unwrap();
}
