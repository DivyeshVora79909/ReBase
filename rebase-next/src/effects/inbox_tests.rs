//! G5c controls reuse the G5b store fixture; explicit clocks avoid timed polling.
use super::*;
use hmac::{Hmac, Mac};

const SECRET: &[u8] = b"g5c-disposable-test-secret-32-bytes";
fn body(e: Uuid, phase: ProviderPhase) -> Vec<u8> {
    local::encode(&json!({"execution_id":e,"outcome":outcome(e,phase)})).unwrap()
}
fn signature(event: &str, at: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
    mac.update(format!("fake-account-1\n{event}\n{at}\n").as_bytes());
    mac.update(body);
    native_codec::hex(&mac.finalize().into_bytes())
}
fn verified(event: Uuid, bytes: &[u8], now: i64) -> inbox::Verified<EffectDemo> {
    let (event, at) = (event.to_string(), now.to_string());
    inbox::Secret::new(SECRET.to_vec())
        .unwrap()
        .verify(
            inbox::ACCOUNT,
            &event,
            &at,
            &signature(&event, &at, bytes),
            bytes,
            now,
        )
        .unwrap()
}
fn event_key(event: Uuid) -> Vec<u8> {
    [b"fake-account-1\0".as_slice(), event.as_bytes()].concat()
}
fn receive(store: &Store<EffectDemo>, event: Uuid, bytes: &[u8], now: i64) -> Value {
    store
        .accept_effect_event(verified(event, bytes, now), None)
        .unwrap()
}
fn consume(store: &Store<EffectDemo>, event: Uuid, now: i64) -> Result<bool> {
    let activation = {
        let write = store.db.begin_write().unwrap();
        runtime_write(&write).unwrap().activation
    };
    store.consume_effect_event(activation, &event_key(event), Some(now), None)
}

#[test]
fn authentication_covers_exact_bytes_identity_skew_and_bounded_typed_json() {
    let secret = inbox::Secret::new(SECRET.to_vec()).unwrap();
    let now = 1_700_000_000_000i64;
    let event = id(1).to_string();
    let mut bytes = body(id(2), ProviderPhase::Succeeded);
    for offset in [-300_001, -300_000, 0, 300_000, 300_001] {
        let at = (now + offset).to_string();
        let result = secret.verify::<EffectDemo>(
            inbox::ACCOUNT,
            &event,
            &at,
            &signature(&event, &at, &bytes),
            &bytes,
            now,
        );
        assert_eq!(result.is_ok(), (-300_000..=300_000).contains(&offset));
    }
    let at = now.to_string();
    let sig = signature(&event, &at, &bytes);
    let mut changed = bytes.clone();
    changed.push(b' ');
    assert!(
        secret
            .verify::<EffectDemo>(inbox::ACCOUNT, &event, &at, &sig, &changed, now)
            .is_err()
    );
    for (account, event, at) in [
        ("wrong-account".to_owned(), event.clone(), at.clone()),
        (inbox::ACCOUNT.to_owned(), id(3).to_string(), at.clone()),
        (
            inbox::ACCOUNT.to_owned(),
            Uuid::nil().to_string(),
            at.clone(),
        ),
        (inbox::ACCOUNT.to_owned(), event.clone(), format!("0{at}")),
    ] {
        assert!(
            secret
                .verify::<EffectDemo>(&account, &event, &at, &sig, &bytes, now)
                .is_err()
        );
    }
    assert!(
        secret
            .verify::<EffectDemo>(
                inbox::ACCOUNT,
                &event,
                &at,
                &"0".repeat(64),
                b"invalid JSON",
                now
            )
            .is_err()
    );
    bytes.resize(MAX_WEBHOOK, b' ');
    assert!(
        secret
            .verify::<EffectDemo>(
                inbox::ACCOUNT,
                &event,
                &at,
                &signature(&event, &at, &bytes),
                &bytes,
                now
            )
            .is_ok()
    );
    bytes.push(b' ');
    assert!(matches!(
        secret.verify::<EffectDemo>(inbox::ACCOUNT, &event, &at, &sig, &bytes, now),
        Err(Error {
            code: "request_limit",
            ..
        })
    ));
    for bytes in [
        b"{\"execution_id\":null,\"execution_id\":null}".as_slice(),
        b"{} {}",
        b"{}",
    ] {
        assert!(
            secret
                .verify::<EffectDemo>(
                    inbox::ACCOUNT,
                    &event,
                    &at,
                    &signature(&event, &at, bytes),
                    bytes,
                    now
                )
                .is_err()
        );
    }
    for len in [0, 31, 129] {
        assert!(inbox::Secret::new(vec![1; len]).is_err());
    }
    let cfg: fake::Config =
        serde_json::from_value(json!({"endpoint":"http://127.0.0.1:9999"})).unwrap();
    assert_eq!(cfg.mode, WorkerMode::Disabled);
}

#[test]
fn durable_ack_dedup_and_consumed_fact_rollback_cover_actual_writes() {
    let f = Fixture::new();
    let e = f.seed(12);
    let (old_claim, now) = f.begin(e);
    let event = id(500);
    let bytes = body(e, ProviderPhase::Succeeded);
    let before = f.store.observe_for_verification().unwrap();
    for abort in [usize::MAX - 6, usize::MAX - 7] {
        assert!(
            f.store
                .accept_effect_event(verified(event, &bytes, now + 1), Some(abort))
                .is_err()
        );
        assert_eq!(f.store.observe_for_verification().unwrap(), before);
    }
    assert_eq!(
        receive(&f.store, event, &bytes, now + 1)["duplicate"],
        false
    );
    let received = f.store.observe_for_verification().unwrap();
    assert_eq!(receive(&f.store, event, &bytes, now + 2)["duplicate"], true);
    assert_eq!(f.store.observe_for_verification().unwrap(), received);
    let mut conflict = bytes.clone();
    conflict.push(b' ');
    assert_eq!(
        f.store
            .accept_effect_event(verified(event, &conflict, now + 1), None)
            .unwrap_err()
            .code,
        "content_conflict"
    );
    assert_eq!(
        f.store
            .accept_effect_event(
                verified(id(501), &body(id(999), ProviderPhase::Succeeded), now + 1),
                None
            )
            .unwrap_err()
            .code,
        "not_found"
    );
    let activation = old_claim.activation;
    for abort in [
        usize::MAX - 4,
        usize::MAX - 6,
        usize::MAX - 2,
        usize::MAX - 1,
        usize::MAX - 3,
    ] {
        assert!(
            f.store
                .consume_effect_event(activation, &event_key(event), Some(now + 3), Some(abort))
                .is_err()
        );
        assert_eq!(f.store.observe_for_verification().unwrap(), received);
    }
    assert!(consume(&f.store, event, now + 3).unwrap());
    assert!(!consume(&f.store, event, now + 3).unwrap());
    assert_eq!(f.balance(), 12);
    assert_eq!(
        f.store
            .finish_effect_at(
                &old_claim,
                Some(&outcome(e, ProviderPhase::Succeeded)),
                Some(now + 3),
                None
            )
            .unwrap_err()
            .code,
        "stale_version"
    );
    let checked = f.store.check_integrity().unwrap();
    assert_eq!(checked["effects"]["facts"], 1);
    assert_eq!(checked["effects"]["inbox_pending"], 0);
    assert!(
        f.store
            .apply_effect(&candidate(&f.store, e, WorkClass::Apply))
            .unwrap()
    );
    assert_eq!(f.balance(), 9);
    f.store.check_integrity().unwrap();
}

#[test]
fn delayed_events_preserve_blocked_diagnostics_and_applied_revisions() {
    let f = Fixture::new();
    let e = f.seed(2);
    let (_, now) = f.begin(e);
    for (event, phase) in [
        (501, ProviderPhase::Succeeded),
        (502, ProviderPhase::Waiting),
        (503, ProviderPhase::Succeeded),
    ] {
        receive(&f.store, id(event), &body(e, phase), now + 1);
        consume(&f.store, id(event), now + 2).unwrap();
        f.store
            .apply_effect(&candidate(&f.store, e, WorkClass::Apply))
            .unwrap();
        let row = row(&f.store, e);
        assert_eq!(row.phase, Phase::Succeeded);
        assert_eq!(row.application, Application::Blocked);
        assert_eq!(row.diagnostic.as_deref(), Some("invariant"));
        assert_eq!(f.balance(), 2);
        f.store.check_integrity().unwrap();
    }
    set_balance(&f.store, 5);
    f.store
        .activate_effect_worker(WorkerMode::Disabled)
        .unwrap();
    f.store.retry_effect(e, row(&f.store, e).revision).unwrap();
    f.store
        .activate_effect_worker(WorkerMode::Reconcile)
        .unwrap();
    assert!(
        f.store
            .apply_effect(&candidate(&f.store, e, WorkClass::Apply))
            .unwrap()
    );
    let fact_before = f.store.observe_for_verification().unwrap()["tables"]["effect_facts"].clone();
    receive(&f.store, id(504), &body(e, ProviderPhase::Waiting), now + 2);
    consume(&f.store, id(504), now + 3).unwrap();
    assert_eq!(
        f.store.observe_for_verification().unwrap()["tables"]["effect_facts"],
        fact_before
    );
    assert_eq!(f.balance(), 2);
    receive(&f.store, id(505), &body(e, ProviderPhase::Failed), now + 2);
    consume(&f.store, id(505), now + 3).unwrap();
    assert!(row(&f.store, e).conflict);
    assert_eq!(row(&f.store, e).application, Application::Applied);
    f.store.check_integrity().unwrap();
}

#[test]
fn prestart_restore_only_reconciles_and_empty_lookup_never_authorizes_submission() {
    let f = Fixture::new();
    let e = f.seed(12);
    let backup = f.path.join("prestart.backup.json");
    f.store.backup(&backup).unwrap();
    let (old_claim, now) = f.begin(e);
    f.store
        .finish_effect_at(
            &old_claim,
            Some(&outcome(e, ProviderPhase::Succeeded)),
            Some(now + 1),
            None,
        )
        .unwrap();
    f.store
        .activate_effect_worker(WorkerMode::Disabled)
        .unwrap();
    let restored_path = f.path.join("restored.redb");
    crate::lifecycle::restore(
        &backup,
        &restored_path,
        Arc::new(Prepared::<EffectDemo>::load().unwrap()),
    )
    .unwrap();
    let restored =
        Store::<EffectDemo>::open(&restored_path, Arc::new(Prepared::load().unwrap())).unwrap();
    assert!(
        restored
            .activate_effect_worker(WorkerMode::Delivery)
            .is_err()
    );
    let activation = restored
        .activate_effect_worker(WorkerMode::Reconcile)
        .unwrap();
    assert_ne!(activation, old_claim.activation);
    // Repeated ownership loss before a reconciliation response leaves the
    // predating row ready/quarantined. An operator can renew observations, but
    // must never recover a submission capability or clear quarantine.
    for _ in 0..MAX_OBSERVATIONS {
        let now = row(&restored, e).next_at;
        assert!(
            restored
                .claim_effect_at(&candidate(&restored, e, WorkClass::Reconcile), Some(now))
                .unwrap()
                .is_some()
        );
        restored
            .activate_effect_worker(WorkerMode::Reconcile)
            .unwrap();
    }
    assert_eq!(row(&restored, e).phase, Phase::Ready);
    assert!(row(&restored, e).due().is_none());
    restored
        .activate_effect_worker(WorkerMode::Disabled)
        .unwrap();
    restored
        .retry_effect(e, row(&restored, e).revision)
        .unwrap();
    assert!(row(&restored, e).quarantined);
    assert_eq!(row(&restored, e).observations, 0);
    restored
        .activate_effect_worker(WorkerMode::Reconcile)
        .unwrap();
    let now = row(&restored, e).next_at.max(now + 2);
    assert!(
        restored
            .claim_effect_at(&candidate(&restored, e, WorkClass::Submit), Some(now))
            .unwrap()
            .is_none()
    );
    let before = restored.observe_for_verification().unwrap();
    let request: Mutation = serde_json::from_value(json!({"model":restored.model().identity(),
        "context":restored.operation_context(restored.model().identity()).unwrap(),"operation_id":Uuid::new_v4(),"commands":[dispatch(21,None)],"returning":[]})).unwrap();
    assert_eq!(restored.mutate(&request).unwrap_err().code, "invalid_input");
    assert_eq!(restored.observe_for_verification().unwrap(), before);
    let claim = restored
        .claim_effect_at(&candidate(&restored, e, WorkClass::Reconcile), Some(now))
        .unwrap()
        .unwrap();
    restored
        .finish_effect_at(&claim, None, Some(now + 1), None)
        .unwrap();
    assert_eq!(row(&restored, e).phase, Phase::Uncertain);
    assert!(row(&restored, e).quarantined);
    assert_eq!(row(&restored, e).attempts, 0);
    assert!(restored.start_effect_at(&old_claim, Some(now + 1)).is_err());
    assert!(restored.scan_effect_inbox(old_claim.activation).is_err());
    let now = row(&restored, e).next_at;
    let claim = restored
        .claim_effect_at(&candidate(&restored, e, WorkClass::Reconcile), Some(now))
        .unwrap()
        .unwrap();
    restored
        .finish_effect_at(
            &claim,
            Some(&outcome(e, ProviderPhase::Succeeded)),
            Some(now + 1),
            None,
        )
        .unwrap();
    assert!(
        restored
            .apply_effect(&candidate(&restored, e, WorkClass::Apply))
            .unwrap()
    );
    assert_eq!(
        restored
            .get(restored.model().identity(), id(10))
            .unwrap()
            .unwrap()
            .input,
        Input::Account { balance: 9 }
    );
    assert_eq!(row(&restored, e).attempts, 0);
    assert!(
        restored.check_integrity().unwrap()["effects"]["quarantined"]
            .as_bool()
            .unwrap()
    );
    assert!(
        restored
            .activate_effect_worker(WorkerMode::Delivery)
            .is_err()
    );
}

#[test]
fn complete_capacity_retains_a_blocked_event_advances_sweeps_and_fits_backup() {
    let f = Fixture::new();
    let e = f.seed(12);
    // Fill the real retained boundary before fact capacity consumes new-intent
    // reservations. Public Dispatch sources may be deleted; executions remain.
    for size in [63u128, 63, 63, 63, 3] {
        let result = mutate(
            &f.store,
            json!(
                (0..size)
                    .map(|n| dispatch(1000 + n, None))
                    .collect::<Vec<_>>()
            ),
        );
        for created in result["result"]["executions"].as_array().unwrap() {
            cancel(
                &f.store,
                created["execution_id"].as_str().unwrap().parse().unwrap(),
            );
        }
        let commands = (0..size)
            .map(|n| {
                let source = f
                    .store
                    .get(f.store.model().identity(), id(1000 + n))
                    .unwrap()
                    .unwrap();
                json!({"op":"delete","id":source.id,"if_version":source.version.to_string()})
            })
            .collect::<Vec<_>>();
        mutate(&f.store, json!(commands));
    }
    let (_, now) = f.begin(e);
    let write = f.store.db.begin_write().unwrap();
    let mut runtime = runtime_write(&write).unwrap();
    for n in 0..MAX_FACTS - 1 {
        let before = load_execution::<EffectDemo>(&write, e).unwrap();
        let mut row = before.clone();
        row.lease = None;
        let mut next = outcome(e, ProviderPhase::Waiting);
        if n > 0 {
            next.receipt = Some(id(10_000 + n as u128).to_string());
        }
        worker::record_fact(&write, &mut runtime, &mut row, &next, now + 1, false).unwrap();
        row.advance().unwrap();
        replace_execution(&write, &mut runtime, &before, &row, None).unwrap();
    }
    write.commit().unwrap();
    let mut blocked = outcome(e, ProviderPhase::Waiting);
    blocked.receipt = Some(id(999_999).to_string());
    let mut first = local::encode(&json!({"execution_id":e,"outcome":blocked})).unwrap();
    first.resize(MAX_WEBHOOK, b' ');
    let mut success = body(e, ProviderPhase::Succeeded);
    success.resize(MAX_WEBHOOK, b' ');
    let mut waiting = body(e, ProviderPhase::Waiting);
    waiting.resize(MAX_WEBHOOK, b' ');
    for event in 1..=MAX_INBOX as u128 {
        receive(
            &f.store,
            id(event),
            match event {
                1 => &first,
                2 => &success,
                _ => &waiting,
            },
            now + 2,
        );
    }
    let before = f.store.observe_for_verification().unwrap();
    assert_eq!(
        f.store
            .accept_effect_event(verified(id(1000), &waiting, now + 2), None)
            .unwrap_err()
            .code,
        "state_limit"
    );
    assert_eq!(
        receive(&f.store, id(2), &success, now + 2)["duplicate"],
        true
    );
    assert_eq!(f.store.observe_for_verification().unwrap(), before);
    let activation = candidate(&f.store, e, WorkClass::Reconcile).activation;
    let mut seen = BTreeSet::new();
    for _ in 0..16 {
        let keys = f.store.scan_effect_inbox(activation).unwrap();
        assert_eq!(keys.len(), 16);
        for key in keys {
            seen.insert(key.clone());
            let result = f
                .store
                .consume_effect_event(activation, &key, Some(now + 3), None);
            if key == event_key(id(1)) {
                assert_eq!(result.unwrap_err().code, "state_limit");
            } else {
                assert!(result.unwrap());
            }
        }
    }
    assert_eq!(seen.len(), MAX_INBOX);
    assert!(
        f.store
            .apply_effect(&candidate(&f.store, e, WorkClass::Apply))
            .unwrap()
    );
    assert_eq!(f.balance(), 9);
    // Restart wraps discovery to the retained blocked first row.
    let activation = f
        .store
        .activate_effect_worker(WorkerMode::Reconcile)
        .unwrap();
    assert_eq!(
        f.store.scan_effect_inbox(activation).unwrap()[0],
        event_key(id(1))
    );
    let checked = f.store.check_integrity().unwrap();
    assert_eq!(checked["effects"]["retained"], MAX_RETAINED);
    assert_eq!(checked["effects"]["facts"], MAX_FACTS);
    assert_eq!(checked["effects"]["inbox"], MAX_INBOX);
    assert_eq!(checked["effects"]["inbox_pending"], 1);
    f.store
        .activate_effect_worker(WorkerMode::Disabled)
        .unwrap();
    assert_eq!(
        f.store.reset(row(&f.store, e).store).unwrap_err().code,
        "invariant"
    );
    let backup = f.path.join("all-bounds.backup.json");
    let backed = f.store.backup(&backup).unwrap();
    assert!(backed["bytes"].as_u64().unwrap() < crate::lifecycle::MAX_BACKUP_BYTES);
    let restored = crate::lifecycle::restore(
        &backup,
        f.path.join("all-bounds.redb"),
        Arc::new(Prepared::<EffectDemo>::load().unwrap()),
    )
    .unwrap();
    assert_eq!(restored["integrity"]["effects"]["inbox_pending"], 1);
    std::fs::write(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/g5c-bounds.json"),
        serde_json::to_vec_pretty(&json!({"integrity":checked,"backup_bytes":backed["bytes"],"backup_sha256":backed["sha256"],"restored_integrity":restored["integrity"],"raw_bytes_per_event":MAX_WEBHOOK,"visited":seen.len()})).unwrap()).unwrap();
}

#[test]
fn archive_retains_inbox_and_clean_reset_rejects_old_receipts_claims_and_hints() {
    let f = Fixture::new();
    let e = f.seed(12);
    let context = f
        .store
        .operation_context(f.store.model().identity())
        .unwrap();
    let store_id = row(&f.store, e).store;
    let (old_claim, now) = f.begin(e);
    receive(
        &f.store,
        id(501),
        &body(e, ProviderPhase::Succeeded),
        now + 1,
    );
    assert_eq!(f.store.reset(store_id).unwrap_err().code, "invariant");
    consume(&f.store, id(501), now + 2).unwrap();
    f.store
        .activate_effect_worker(WorkerMode::Disabled)
        .unwrap();
    assert_eq!(f.store.reset(store_id).unwrap_err().code, "invariant");
    f.store
        .activate_effect_worker(WorkerMode::Reconcile)
        .unwrap();
    f.store
        .apply_effect(&candidate(&f.store, e, WorkClass::Apply))
        .unwrap();
    assert_eq!(f.store.reset(store_id).unwrap_err().code, "invariant");
    f.store
        .activate_effect_worker(WorkerMode::Disabled)
        .unwrap();
    let before = f.store.observe_for_verification().unwrap();
    f.store
        .archive_receipts(f.path.join("archive.json"))
        .unwrap();
    let archived = f.store.observe_for_verification().unwrap();
    for table in [
        "effect_inbox",
        "effect_executions",
        "effect_facts",
        "effect_due",
        "effect_runtime",
    ] {
        assert_eq!(before["tables"][table], archived["tables"][table]);
    }
    let reset = f.store.reset(store_id).unwrap();
    assert_ne!(reset["store"], store_id.to_string());
    assert_eq!(f.store.check_integrity().unwrap()["effects"]["inbox"], 0);
    assert!(
        f.store
            .finish_effect_at(&old_claim, None, Some(now + 3), None)
            .is_err()
    );
    assert!(f.store.scan_effect_inbox(old_claim.activation).is_err());
    let session = f.store.session(id(2), 1).unwrap();
    assert!(
        session
            .operation_status(session.model().identity(), &context, id(999))
            .is_err()
    );
    // Source ID reuse does not make an old execution valid in the fresh store.
    mutate(
        &session,
        json!([{"op":"create","id":id(10),"contract":101,"fields":{"balance":"12"}},dispatch(20,None)]),
    );
    assert_eq!(
        f.store
            .accept_effect_event(
                verified(id(501), &body(e, ProviderPhase::Succeeded), now + 3),
                None
            )
            .unwrap_err()
            .code,
        "not_found"
    );
    f.store.check_integrity().unwrap();
}

#[test]
fn inbox_inventory_and_compiled_action_mismatch_reject_check_and_restore() {
    let f = Fixture::new();
    let e = f.seed(12);
    let (_, now) = f.begin(e);
    receive(
        &f.store,
        id(501),
        &body(e, ProviderPhase::Succeeded),
        now + 1,
    );
    consume(&f.store, id(501), now + 2).unwrap();
    f.store
        .apply_effect(&candidate(&f.store, e, WorkClass::Apply))
        .unwrap();
    for variant in 0..8 {
        let (table, key) = match variant {
            5 => (EXECUTIONS, e.as_bytes().to_vec()),
            6 | 7 => (EFFECT_RUNTIME, HEADER.to_vec()),
            _ => (INBOX, event_key(id(501))),
        };
        let write = f.store.db.begin_write().unwrap();
        let original = write
            .open_table(table)
            .unwrap()
            .get(key.as_slice())
            .unwrap()
            .unwrap()
            .value()
            .to_vec();
        let mut changed: Value = local::decode(&original).unwrap();
        match variant {
            0 => changed["body_hash"] = json!("0".repeat(64)),
            1 => changed["event"] = json!(id(502)),
            2 => changed["store"] = json!(id(700)),
            3 => changed["payload"]["outcome"]["units"] = json!("4"),
            4 => changed["consumed_revision"] = json!(u64::MAX.to_string()),
            5 => changed["action_version"] = json!("fake-units-unsupported"),
            6 => changed["inbox_pending"] = json!(1),
            _ => {
                changed["inbox_end"] = json!("00");
            }
        }
        let changed = local::encode(&changed).unwrap();
        let canonical = match variant {
            5 => local::encode(&local::decode::<Execution<EffectDemo>>(&changed).unwrap()).unwrap(),
            6 | 7 => local::encode(&local::decode::<Runtime>(&changed).unwrap()).unwrap(),
            _ => {
                local::encode(&local::decode::<inbox::Row<EffectDemo>>(&changed).unwrap()).unwrap()
            }
        };
        write
            .open_table(table)
            .unwrap()
            .insert(key.as_slice(), canonical.as_slice())
            .unwrap();
        write.commit().unwrap();
        assert!(f.store.check_integrity().is_err(), "variant {variant}");
        let payload = f.store.observe_for_verification().unwrap();
        let hash = native_codec::hex(&Sha256::digest(local::encode(&payload).unwrap()));
        let backup = f.path.join(format!("corrupt-{variant}.json"));
        std::fs::write(
            &backup,
            local::encode(&json!({"format":"rebase-backup-1","sha256":hash,"payload":payload}))
                .unwrap(),
        )
        .unwrap();
        let destination = f.path.join(format!("corrupt-{variant}.redb"));
        assert!(
            crate::lifecycle::restore(
                &backup,
                &destination,
                Arc::new(Prepared::<EffectDemo>::load().unwrap())
            )
            .is_err(),
            "variant {variant}"
        );
        assert!(!destination.exists());
        let write = f.store.db.begin_write().unwrap();
        write
            .open_table(table)
            .unwrap()
            .insert(key.as_slice(), original.as_slice())
            .unwrap();
        write.commit().unwrap();
    }
    f.store.check_integrity().unwrap();
}
