//! Durable facts enter business state through the ordinary bounded engine.
use super::*;
use state::{Candidate, WorkClass, fact_key};

impl<B: Binding> Store<B> {
    pub(crate) fn apply_effect(&self, candidate: &Candidate) -> Result<bool> {
        match self.apply_effect_inner(candidate, None) {
            Ok(applied) => Ok(applied),
            Err(error)
                if matches!(
                    error.code,
                    "invariant"
                        | "unavailable_reference"
                        | "work_limit"
                        | "state_limit"
                        | "overflow"
                        | "invalid_input"
                        | "inexact"
                ) =>
            {
                // The failed domain transaction has already dropped. Its fact
                // predates it and remains durable; blocked is a separate write.
                let write = self.db.begin_write().map_err(local::storage)?;
                let mut runtime = runtime_write(&write)?;
                let before = load_execution::<B>(&write, candidate.execution)?;
                if runtime.activation == candidate.activation
                    && before.revision == candidate.revision
                    && before.store == candidate.store
                    && before.application == Application::Pending
                {
                    let mut row = before.clone();
                    row.application = Application::Blocked;
                    row.diagnostic = Some(error.code.into());
                    row.advance()?;
                    replace_execution(&write, &mut runtime, &before, &row, None)?;
                    write
                        .commit()
                        .map_err(|e| Error::new("outcome_unknown", e.to_string()))?;
                }
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn apply_effect_inner(
        &self,
        candidate: &Candidate,
        abort: Option<usize>,
    ) -> Result<bool> {
        let write = self.db.begin_write().map_err(local::storage)?;
        let mut runtime = runtime_write(&write)?;
        let before = load_execution::<B>(&write, candidate.execution)?;
        if candidate.class != WorkClass::Apply
            || runtime.activation != candidate.activation
            || !runtime.mode.active()
            || before.store != candidate.store
            || before.revision != candidate.revision
            || before.application != Application::Pending
            || before.conflict
        {
            return Ok(false);
        }
        let action = B::effect_action()
            .ok_or_else(|| local::corrupt("effect application without action"))?;
        let key = fact_key(
            before.id,
            before
                .terminal_fact
                .as_deref()
                .ok_or_else(|| local::corrupt("missing success fact"))?,
        )?;
        let mut fact: Fact<B> = {
            let table = write.open_table(FACTS).map_err(local::storage)?;
            local::decode(
                table
                    .get(key.as_slice())
                    .map_err(local::storage)?
                    .ok_or_else(|| local::corrupt("missing success fact"))?
                    .value(),
            )?
        };
        ensure(
            fact.applied_revision.is_none()
                && fact.disposition == Disposition::Succeeded
                && B::effect_outcome(&before.request, before.id, &fact.outcome)?
                    == Disposition::Succeeded,
            "effect application fact",
        )?;
        let (batch, revision) = {
            let table = write.open_table(KV).map_err(local::storage)?;
            let mut ws = Attempt::<_, B>::new(
                |key: &[u8]| {
                    table
                        .get(key)
                        .map(|v| v.map(|v| v.value().to_vec()))
                        .map_err(local::storage)
                },
                local::MUTATION_WORK_LIMIT,
            );
            let target = ws
                .record(before.target)?
                .ok_or_else(|| Error::new("unavailable_reference", "effect application target"))?;
            let command =
                B::effect_application(&before.request, &fact.outcome, &target, before.target)?;
            let settled = crate::mutation::settle_authorized(
                &mut ws,
                self.model(),
                crate::native_slice::Context {
                    tenant: before.tenant,
                    actor: before.requester,
                },
                &[command],
                &mut || Ok(Uuid::new_v4()),
                false,
                &mut |_ws, command, old, new| {
                    let Command::Update { id, set, unset, .. } = command else {
                        return Err(crate::access::denied());
                    };
                    let Some(old) = old else {
                        return Err(crate::access::denied());
                    };
                    if *id != before.target
                        || old.tenant != before.tenant
                        || old.contract != action.target_contract
                        || !unset.is_empty()
                        || set.is_empty()
                        || set
                            .keys()
                            .any(|field| !action.application_fields.contains(&field.as_str()))
                    {
                        return Err(crate::access::denied());
                    }
                    // The shared engine authorizes before binding, then again
                    // with the proposed record. Restrict both invocations.
                    if let Some(new) = new {
                        if new.tenant != before.tenant
                            || new.contract != action.target_contract
                            || old.input.references() != new.input.references()
                        {
                            return Err(crate::access::denied());
                        }
                        self.model().validate(
                            new.contract,
                            &serde_json::to_value(&new.input).map_err(local::storage)?,
                        )?;
                    }
                    Ok(())
                },
            )?;
            if self.secured {
                let ids = ws.changed_records();
                let mut dominance = BTreeMap::new();
                crate::security::repair_readers(
                    &mut ws,
                    self.model(),
                    ids,
                    settled.revision,
                    &mut |owners, fallback| {
                        crate::security::stored_reader(&write, owners, fallback, &mut dominance)
                    },
                )?;
            }
            (ws.finish()?, settled.revision)
        };
        self.publish_native(&write, &batch, abort)?;
        injected(abort, usize::MAX - 5)?;
        let old_len = local::encode(&fact)?.len();
        fact.applied_revision = Some(revision);
        let bytes = local::encode(&fact)?;
        runtime.accounted_bytes = runtime
            .accounted_bytes
            .checked_sub(old_len as u64)
            .and_then(|n| n.checked_add(bytes.len() as u64))
            .ok_or_else(|| local::corrupt("applied fact bytes"))?;
        write
            .open_table(FACTS)
            .map_err(local::storage)?
            .insert(key.as_slice(), bytes.as_slice())
            .map_err(local::storage)?;
        injected(abort, usize::MAX - 4)?;
        let mut row = before.clone();
        row.application = Application::Applied;
        row.diagnostic = None;
        row.quarantined = false;
        row.advance()?;
        replace_execution(&write, &mut runtime, &before, &row, abort)?;
        if let Err(error) = write.commit() {
            let read = self.db.begin_read().map_err(local::storage)?;
            let table = read.open_table(FACTS).map_err(local::storage)?;
            if let Some(value) = table.get(key.as_slice()).map_err(local::storage)? {
                let fact: Fact<B> = local::decode(value.value())?;
                if fact.applied_revision == Some(revision) {
                    return Ok(true);
                }
            }
            return Err(Error::new("outcome_unknown", error.to_string()));
        }
        Ok(true)
    }

    /// Offline operator command; never an arbitrary patch or a new submission.
    /// The caller must own the stopped store's file lock, as other CLI tools do.
    pub fn retry_effect(&self, id: Uuid, revision: u64) -> Result<Value> {
        let write = self.db.begin_write().map_err(local::storage)?;
        let now = now_millis()?;
        let scope = self.write_authority(&write)?;
        let mut runtime = runtime_write(&write)?;
        if runtime.mode.active() {
            return Err(Error::new(
                "invalid_input",
                "stop the effect worker before operator retry",
            ));
        }
        let before = load_execution::<B>(&write, id)?;
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
        let target = ws
            .record(before.target)?
            .ok_or_else(crate::access::denied)?;
        if !scope.can_write(&target, Action::Update)
            || scope.actor != before.requester && !scope.grants.admin
        {
            return Err(crate::access::denied());
        }
        drop(ws);
        drop(table);
        if before.revision != revision {
            return Err(Error::new("stale_version", "execution revision differs"));
        }
        let mut row = before.clone();
        if row.application == Application::Blocked && !row.conflict {
            row.application = Application::Pending;
        } else if matches!(row.phase, Phase::Waiting | Phase::Uncertain)
            || row.phase == Phase::Ready && row.quarantined
            || row.conflict
        {
            row.observations = 0;
        } else {
            return Err(Error::new(
                "invalid_input",
                "no blocked application or reconciliation to retry",
            ));
        }
        row.next_at = now;
        row.diagnostic = None;
        row.advance()?;
        replace_execution(&write, &mut runtime, &before, &row, None)?;
        write
            .commit()
            .map_err(|e| Error::new("outcome_unknown", e.to_string()))?;
        Ok(
            json!({"execution_id":id,"revision":row.revision.to_string(),"phase":row.phase,"application":row.application}),
        )
    }
}
