//! Short durable lifecycle transactions. Only the transport module performs I/O.
use super::*;
use state::{
    Candidate, Claim, LEASE_MS, MAX_ATTEMPTS, MAX_LEASE_MS, MAX_OBSERVATIONS, Mode, WorkClass,
    backoff, fact_key, outcome_digest, work_key,
};
use std::ops::Bound;

fn clock(supplied: Option<i64>) -> Result<i64> {
    supplied.map_or_else(now_millis, Ok)
}
fn commit(write: WriteTransaction) -> Result<()> {
    write
        .commit()
        .map_err(|e| Error::new("outcome_unknown", e.to_string()))
}
fn stale() -> Error {
    Error::new("stale_version", "worker ownership changed or expired")
}

impl<B: Binding> Store<B> {
    /// Called only by the single server owner, before any provider tasks exist.
    pub(crate) fn activate_effect_worker(&self, enabled: bool) -> Result<Uuid> {
        let write = self.db.begin_write().map_err(local::storage)?;
        let now = now_millis()?;
        let mut runtime = runtime_write(&write)?;
        if enabled && (B::effect_action().is_none() || runtime.quarantined) {
            return Err(Error::new(
                "invalid_input",
                "worker activation unavailable for this store",
            ));
        }
        runtime.activation = Uuid::new_v4();
        runtime.dispatch_enabled = enabled;
        runtime.sweeps = Default::default();
        runtime.next_class = 0;
        let rows = write
            .open_table(EXECUTIONS)
            .map_err(local::storage)?
            .iter()
            .map_err(local::storage)?
            .map(|item| {
                let (_, value) = item.map_err(local::storage)?;
                local::decode::<Execution<B>>(value.value())
            })
            .collect::<Result<Vec<_>>>()?;
        for before in rows {
            if before.lease.is_none() {
                continue;
            }
            let mut row = before.clone();
            row.lease = None;
            if row.phase == Phase::Ready && row.started.is_some() {
                row.phase = Phase::Uncertain;
            }
            row.next_at = now;
            row.advance()?;
            replace_execution(&write, &mut runtime, &before, &row, None)?;
        }
        write_runtime(&write, &runtime)?;
        commit(write)?;
        Ok(runtime.activation)
    }

    /// A bounded full-key sweep. Cursor publication can precede processing:
    /// unprocessed rows remain indexed and are rediscovered on the next wrap.
    pub(crate) fn scan_effects(&self, activation: Uuid) -> Result<Vec<Candidate>> {
        self.scan_effects_at(activation, None)
    }
    pub(super) fn scan_effects_at(
        &self,
        activation: Uuid,
        supplied: Option<i64>,
    ) -> Result<Vec<Candidate>> {
        let write = self.db.begin_write().map_err(local::storage)?;
        let now = clock(supplied)?;
        let mut runtime = runtime_write(&write)?;
        if runtime.activation != activation || !runtime.dispatch_enabled {
            return Err(stale());
        }
        let class = WorkClass::from_byte(runtime.next_class)?;
        runtime.next_class = (runtime.next_class + 1) % 4;
        let sweep = &mut runtime.sweeps[class as usize];
        let start = work_key(class, 0, Uuid::nil());
        let upper = work_key(class, now, Uuid::from_u128(u128::MAX));
        let mut candidates = vec![];
        {
            let due = write.open_table(DUE).map_err(local::storage)?;
            if sweep.end.is_none() {
                sweep.cutoff = now;
                sweep.cursor = None;
                sweep.end = due
                    .range(start.as_slice()..=upper.as_slice())
                    .map_err(local::storage)?
                    .next_back()
                    .transpose()
                    .map_err(local::storage)?
                    .map(|(k, _)| native_codec::hex(k.value()));
            }
            if let Some(end) = &sweep.end {
                let end = local::unhex(end)?;
                let cursor = sweep.cursor.as_ref().map(|s| local::unhex(s)).transpose()?;
                let low = cursor
                    .as_deref()
                    .map_or(Bound::Included(start.as_slice()), Bound::Excluded);
                let plan_started = std::time::Instant::now();
                for item in due
                    .range::<&[u8]>((low, Bound::Included(end.as_slice())))
                    .map_err(local::storage)?
                {
                    let (key, _) = item.map_err(local::storage)?;
                    let key = key.value();
                    ensure(
                        key.len() == 25 && key[0] == class as u8,
                        "due discovery key",
                    )?;
                    let id = Uuid::from_slice(&key[9..]).map_err(local::storage)?;
                    let row = load_execution::<B>(&write, id)?;
                    ensure(row.due().as_deref() == Some(key), "due discovery row")?;
                    candidates.push(Candidate {
                        store: row.store,
                        activation,
                        execution: id,
                        revision: row.revision,
                        class,
                    });
                    sweep.cursor = Some(native_codec::hex(key));
                    if candidates.len() == 16 || plan_started.elapsed().as_millis() >= 100 {
                        break;
                    }
                }
                if candidates.is_empty() || sweep.cursor.as_ref() == sweep.end.as_ref() {
                    *sweep = Sweep::default();
                }
            }
        }
        write_runtime(&write, &runtime)?;
        commit(write)?;
        Ok(candidates)
    }

    fn effect_submit_authority(&self, write: &WriteTransaction, row: &Execution<B>) -> Result<()> {
        let scope = if self.secured {
            self.session(row.requester, row.credential_epoch)?
                .write_authority(write)?
        } else {
            if row.requester != self.context.actor || row.credential_epoch != 0 {
                return Err(crate::access::denied());
            }
            self.write_authority(write)?
        };
        let action = B::effect_action().ok_or_else(crate::access::denied)?;
        let table = write.open_table(KV).map_err(local::storage)?;
        let mut ws = Attempt::<_, B>::new(
            |key: &[u8]| {
                table
                    .get(key)
                    .map(|v| v.map(|v| v.value().to_vec()))
                    .map_err(local::storage)
            },
            1000,
        );
        let target = ws.record(row.target)?.ok_or_else(crate::access::denied)?;
        if scope.tenant != row.tenant
            || !scope.grants.allows(action.source_contract, Action::Create)
            || !scope.can_write(&target, Action::Update)
        {
            return Err(crate::access::denied());
        }
        Ok(())
    }

    pub(crate) fn claim_effect(&self, candidate: &Candidate) -> Result<Option<Claim>> {
        self.claim_effect_at(candidate, None)
    }
    pub(super) fn claim_effect_at(
        &self,
        candidate: &Candidate,
        supplied: Option<i64>,
    ) -> Result<Option<Claim>> {
        let write = self.db.begin_write().map_err(local::storage)?;
        let now = clock(supplied)?;
        let mut runtime = runtime_write(&write)?;
        let before = load_execution::<B>(&write, candidate.execution)?;
        if !runtime.dispatch_enabled
            || runtime.activation != candidate.activation
            || before.store != candidate.store
            || before.revision != candidate.revision
        {
            return Ok(None);
        }
        let Some(due) = before.due() else {
            return Ok(None);
        };
        if due[0] != candidate.class as u8
            || due > work_key(candidate.class, now, Uuid::from_u128(u128::MAX))
        {
            return Ok(None);
        }
        let mut row = before.clone();
        if candidate.class == WorkClass::Expiry {
            row.lease = None;
            if row.phase == Phase::Ready && row.started.is_some() {
                row.phase = Phase::Uncertain;
            }
            row.next_at = backoff(now, row.attempts.max(row.observations))?;
        } else if candidate.class == WorkClass::Submit {
            if row.started.is_some() || row.quarantined || row.cancellation.is_some() {
                return Err(local::corrupt("unsafe submission candidate"));
            }
            if now >= row.not_after {
                row.phase = Phase::Cancelled;
                row.cancellation = Some(Cancellation::Expired);
                row.reservation = false;
            } else if row.attempts >= MAX_ATTEMPTS {
                row.phase = Phase::Failed;
                row.diagnostic = Some("submission_budget_exhausted".into());
                row.reservation = false;
            } else {
                match self.effect_submit_authority(&write, &row) {
                    Ok(()) => {
                        row.attempts += 1;
                        row.lease = Some(new_lease(runtime.activation, Mode::Submit, now)?);
                    }
                    Err(error) if error.code == "forbidden" => {
                        row.phase = Phase::Cancelled;
                        row.cancellation = Some(Cancellation::Revoked);
                        row.reservation = false;
                    }
                    Err(error) => return Err(error),
                }
            }
        } else if candidate.class == WorkClass::Reconcile {
            if row.observations >= MAX_OBSERVATIONS {
                return Ok(None);
            }
            row.observations += 1;
            row.lease = Some(new_lease(runtime.activation, Mode::Reconcile, now)?);
        } else {
            return Ok(None);
        }
        row.advance()?;
        replace_execution(&write, &mut runtime, &before, &row, None)?;
        let claim = row
            .lease
            .as_ref()
            .map(|_| row.claim(runtime.activation))
            .transpose()?;
        commit(write)?;
        Ok(claim)
    }

    pub(crate) fn start_effect(&self, claim: &Claim) -> Result<Option<Claim>> {
        self.start_effect_at(claim, None)
    }
    pub(super) fn start_effect_at(
        &self,
        claim: &Claim,
        supplied: Option<i64>,
    ) -> Result<Option<Claim>> {
        let write = self.db.begin_write().map_err(local::storage)?;
        let now = clock(supplied)?;
        let mut runtime = runtime_write(&write)?;
        let before = load_execution::<B>(&write, claim.execution)?;
        if !before.matches_claim(&runtime, claim, now)
            || claim.mode != Mode::Submit
            || before.phase != Phase::Ready
            || before.started.is_some()
        {
            return Err(stale());
        }
        let mut row = before.clone();
        let cancellation = if now >= row.not_after {
            Some(Cancellation::Expired)
        } else {
            match self.effect_submit_authority(&write, &row) {
                Ok(()) => None,
                Err(e) if e.code == "forbidden" => Some(Cancellation::Revoked),
                Err(e) => return Err(e),
            }
        };
        if let Some(reason) = cancellation {
            row.phase = Phase::Cancelled;
            row.cancellation = Some(reason);
            row.reservation = false;
            row.lease = None;
        } else {
            if now < row.execute_at {
                return Err(stale());
            }
            row.started = Some(Start {
                activation: claim.activation,
                token: claim.token,
                at: now,
                attempt: row.attempts,
            });
        }
        row.advance()?;
        replace_execution(&write, &mut runtime, &before, &row, None)?;
        let started = row
            .lease
            .as_ref()
            .map(|_| row.claim(runtime.activation))
            .transpose()?;
        if let Err(error) = commit(write) {
            // A failed acknowledgement never itself authorizes a remote call.
            if let Some(claim) = &started
                && self.confirm_effect_start(claim).is_ok()
            {
                return Ok(started);
            }
            return Err(error);
        }
        Ok(started)
    }

    pub(crate) fn confirm_effect_start(&self, claim: &Claim) -> Result<Execution<B>> {
        let read = self.db.begin_read().map_err(local::storage)?;
        let runtime = runtime_read(&read)?;
        let table = read.open_table(EXECUTIONS).map_err(local::storage)?;
        let value = table
            .get(claim.execution.as_bytes().as_slice())
            .map_err(local::storage)?
            .ok_or_else(stale)?;
        let row: Execution<B> = local::decode(value.value())?;
        if !row.matches_claim(&runtime, claim, now_millis()?)
            || claim.mode != Mode::Submit
            || row
                .started
                .as_ref()
                .is_none_or(|s| s.token != claim.token || s.activation != claim.activation)
            || row.phase != Phase::Ready
        {
            return Err(stale());
        }
        Ok(row)
    }

    // The normal transport finishes within five seconds. Retained for adapters
    // that renew bounded ownership; controls exercise the real transaction path.
    #[allow(dead_code)]
    pub(super) fn renew_effect_at(&self, claim: &Claim, supplied: Option<i64>) -> Result<Claim> {
        let write = self.db.begin_write().map_err(local::storage)?;
        let now = clock(supplied)?;
        let mut runtime = runtime_write(&write)?;
        let before = load_execution::<B>(&write, claim.execution)?;
        if !before.matches_claim(&runtime, claim, now) {
            return Err(stale());
        }
        let mut row = before.clone();
        let lease = row.lease.as_mut().ok_or_else(stale)?;
        if lease.renewals >= 2 {
            return Err(stale());
        }
        let expires = now.checked_add(LEASE_MS).ok_or_else(stale)?.min(
            lease
                .claimed_at
                .checked_add(MAX_LEASE_MS)
                .ok_or_else(stale)?,
        );
        if expires <= lease.expires_at {
            return Err(stale());
        }
        lease.expires_at = expires;
        lease.renewals += 1;
        row.advance()?;
        replace_execution(&write, &mut runtime, &before, &row, None)?;
        let renewed = row.claim(runtime.activation)?;
        commit(write)?;
        Ok(renewed)
    }

    pub(crate) fn finish_effect(&self, claim: &Claim, outcome: Option<&B::Outcome>) -> Result<()> {
        self.finish_effect_at(claim, outcome, None, None)
    }
    pub(super) fn finish_effect_at(
        &self,
        claim: &Claim,
        outcome: Option<&B::Outcome>,
        supplied: Option<i64>,
        abort: Option<usize>,
    ) -> Result<()> {
        let write = self.db.begin_write().map_err(local::storage)?;
        let now = clock(supplied)?;
        let mut runtime = runtime_write(&write)?;
        let before = load_execution::<B>(&write, claim.execution)?;
        if !before.matches_claim(&runtime, claim, now)
            || claim.mode == Mode::Submit && before.started.is_none()
        {
            return Err(stale());
        }
        let mut row = before.clone();
        row.lease = None;
        if let Some(outcome) = outcome {
            record_fact(
                &write,
                &mut runtime,
                &mut row,
                outcome,
                now,
                claim.mode == Mode::Submit,
            )?;
            injected(abort, usize::MAX - 4)?;
        } else {
            if row.phase == Phase::Ready {
                row.phase = Phase::Uncertain;
            }
            row.next_at = backoff(now, row.observations)?;
            row.diagnostic = Some(
                if row.observations >= MAX_OBSERVATIONS {
                    "observation_budget_exhausted"
                } else {
                    "provider_outcome_unknown"
                }
                .into(),
            );
        }
        row.advance()?;
        replace_execution(&write, &mut runtime, &before, &row, abort)?;
        if let Err(error) = commit(write) {
            // Inspect the committed row; never repeat provider I/O for a local
            // finish acknowledgement failure, even when no fact was available.
            let read = self.db.begin_read().map_err(local::storage)?;
            let executions = read.open_table(EXECUTIONS).map_err(local::storage)?;
            if let Some(value) = executions
                .get(row.id.as_bytes().as_slice())
                .map_err(local::storage)?
            {
                let found: Execution<B> = local::decode(value.value())?;
                if local::encode(&found)? == local::encode(&row)? {
                    return Ok(());
                }
            }
            return Err(error);
        }
        Ok(())
    }
}

fn new_lease(activation: Uuid, mode: Mode, now: i64) -> Result<Lease> {
    Ok(Lease {
        activation,
        mode,
        token: Uuid::new_v4(),
        claimed_at: now,
        expires_at: now
            .checked_add(LEASE_MS)
            .ok_or_else(|| Error::new("overflow", "lease expiry"))?,
        renewals: 0,
    })
}

/// Persist a typed observation and its monotone state change. Submission may be
/// retried only for definitive nonacceptance of the currently started call.
pub(super) fn record_fact<B: Binding>(
    write: &WriteTransaction,
    runtime: &mut Runtime,
    row: &mut Execution<B>,
    outcome: &B::Outcome,
    now: i64,
    may_resubmit: bool,
) -> Result<()> {
    if local::encode(outcome)?.len() > MAX_OUTCOME {
        return Err(Error::new("request_limit", "provider outcome bytes"));
    }
    let disposition = B::effect_outcome(&row.request, row.id, outcome)?;
    let digest = outcome_digest::<B>(outcome)?;
    let key = fact_key(row.id, &digest)?;
    let mut facts = write.open_table(FACTS).map_err(local::storage)?;
    let exists = if let Some(value) = facts.get(key.as_slice()).map_err(local::storage)? {
        let fact: Fact<B> = local::decode(value.value())?;
        ensure(
            fact.outcome == *outcome && fact.request_hash == row.request_hash,
            "fact identity conflict",
        )?;
        true
    } else {
        false
    };
    if !exists {
        let fact = Fact::<B> {
            codec: CODEC.into(),
            execution: row.id,
            request_hash: row.request_hash.clone(),
            digest: digest.clone(),
            disposition,
            outcome: outcome.clone(),
            observed_at: now,
            applied_revision: None,
        };
        let bytes = local::encode(&fact)?;
        ensure(
            (key.len() + bytes.len()) as u64 <= RESULT_RESERVE,
            "reserved terminal fact envelope",
        )?;
        runtime.facts = runtime
            .facts
            .checked_add(1)
            .ok_or_else(|| Error::new("state_limit", "provider fact capacity"))?;
        runtime.accounted_bytes = runtime
            .accounted_bytes
            .checked_add((key.len() + bytes.len()) as u64)
            .ok_or_else(|| Error::new("state_limit", "provider fact byte capacity"))?;
        facts
            .insert(key.as_slice(), bytes.as_slice())
            .map_err(local::storage)?;
    }
    row.last_fact = Some(digest.clone());
    row.diagnostic = None;
    let terminal = matches!(
        row.phase,
        Phase::Succeeded | Phase::Failed | Phase::Cancelled
    );
    if terminal {
        if matches!(
            disposition,
            Disposition::Succeeded | Disposition::Failed | Disposition::NotAccepted
        ) && row.terminal_fact.as_ref() != Some(&digest)
        {
            row.conflict = true;
        }
    } else {
        match disposition {
            Disposition::Succeeded => {
                row.phase = Phase::Succeeded;
                row.application = Application::Pending;
                row.terminal_fact = Some(digest);
                row.reservation = false;
                row.quarantined = false;
            }
            Disposition::Failed => {
                row.phase = Phase::Failed;
                row.terminal_fact = Some(digest);
                row.reservation = false;
                row.quarantined = false;
            }
            Disposition::Waiting => {
                row.phase = Phase::Waiting;
            }
            Disposition::NotAccepted => {
                if may_resubmit
                    && row.phase == Phase::Ready
                    && row.started.is_some()
                    && !row.quarantined
                    && row.cancellation.is_none()
                {
                    row.started = None;
                    if row.attempts < MAX_ATTEMPTS && now < row.not_after {
                        row.phase = Phase::Ready;
                    } else {
                        row.phase = Phase::Failed;
                        row.terminal_fact = Some(digest);
                        row.reservation = false;
                        row.diagnostic = Some("submission_budget_exhausted_or_expired".into());
                    }
                } else {
                    row.phase = Phase::Uncertain;
                    row.conflict = true;
                }
            }
        }
    }
    row.next_at = if row.application == Application::Pending {
        now
    } else {
        backoff(now, row.attempts.max(row.observations))?
    };
    Ok(())
}
