//! Checked persisted worker state. The transaction writer and checker use these
//! same row types; provider I/O is outside this module.
use super::*;
use crate::native_codec::optional_uuid_text;

pub(crate) const LEASE_MS: i64 = 10_000;
pub(crate) const MAX_LEASE_MS: i64 = 30_000;
pub(crate) const MAX_ATTEMPTS: u8 = 3;
pub(crate) const MAX_OBSERVATIONS: u8 = 6;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkerMode {
    #[default]
    Disabled,
    Delivery,
    Reconcile,
}
impl WorkerMode {
    pub(crate) fn active(self) -> bool {
        self != Self::Disabled
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Waiting,
    Succeeded,
    NotAccepted,
    Failed,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Application {
    None,
    Pending,
    Blocked,
    Applied,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mode {
    Submit,
    Reconcile,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lease {
    #[serde(with = "uuid_text")]
    pub activation: Uuid,
    #[serde(with = "uuid_text")]
    pub token: Uuid,
    pub mode: Mode,
    #[serde(with = "decimal")]
    pub claimed_at: i64,
    #[serde(with = "decimal")]
    pub expires_at: i64,
    pub renewals: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Start {
    #[serde(with = "uuid_text")]
    pub activation: Uuid,
    #[serde(with = "uuid_text")]
    pub token: Uuid,
    #[serde(with = "decimal")]
    pub at: i64,
    pub attempt: u8,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Sweep {
    #[serde(with = "decimal")]
    pub cutoff: i64,
    pub end: Option<String>,
    pub cursor: Option<String>,
}
impl Sweep {
    pub(crate) fn validate(&self, class: u8) -> Result<()> {
        ensure(
            self.cutoff >= 0 && (self.cursor.is_none() || self.end.is_some()),
            "effect sweep cursor",
        )?;
        for key in self.end.iter().chain(self.cursor.iter()) {
            let bytes = local::unhex(key).map_err(|_| local::corrupt("effect sweep key"))?;
            ensure(
                bytes.len() == 25
                    && bytes[0] == class
                    && bytes
                        <= work_key(
                            WorkClass::from_byte(class)?,
                            self.cutoff,
                            Uuid::from_u128(u128::MAX),
                        ),
                "effect sweep class/key",
            )?;
        }
        ensure(
            self.cursor
                .as_ref()
                .zip(self.end.as_ref())
                .is_none_or(|(cursor, end)| cursor <= end),
            "effect sweep order",
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(serialize = "", deserialize = ""))]
pub(crate) struct Fact<B: Binding> {
    pub codec: String,
    #[serde(with = "uuid_text")]
    pub execution: Uuid,
    pub request_hash: String,
    pub digest: String,
    pub disposition: Disposition,
    pub outcome: B::Outcome,
    #[serde(with = "decimal")]
    pub observed_at: i64,
    #[serde(with = "optional_uuid_text")]
    pub applied_revision: Option<Uuid>,
}

/// A capability passed only between trusted worker functions. Never an RPC DTO.
#[derive(Clone, Debug)]
pub(crate) struct Claim {
    pub store: Uuid,
    pub activation: Uuid,
    pub execution: Uuid,
    pub revision: u64,
    pub token: Uuid,
    pub mode: Mode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum WorkClass {
    Expiry = 0,
    Submit = 1,
    Reconcile = 2,
    Apply = 3,
}
impl WorkClass {
    pub fn from_byte(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Expiry),
            1 => Ok(Self::Submit),
            2 => Ok(Self::Reconcile),
            3 => Ok(Self::Apply),
            _ => Err(local::corrupt("effect work class")),
        }
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Candidate {
    pub store: Uuid,
    pub activation: Uuid,
    pub execution: Uuid,
    pub revision: u64,
    pub class: WorkClass,
}

pub(crate) fn work_key(class: WorkClass, at: i64, id: Uuid) -> Vec<u8> {
    [vec![class as u8], due_key(at, id)].concat()
}
pub(crate) fn fact_key(id: Uuid, digest: &str) -> Result<Vec<u8>> {
    let hash = local::unhex(digest)?;
    ensure(hash.len() == 32, "effect fact digest")?;
    Ok([id.as_bytes().as_slice(), hash.as_slice()].concat())
}
pub(crate) fn outcome_digest<B: Binding>(outcome: &B::Outcome) -> Result<String> {
    Ok(native_codec::hex(&Sha256::digest(local::encode(outcome)?)))
}
pub(crate) fn backoff(now: i64, observation: u8) -> Result<i64> {
    now.checked_add(1000i64 << observation.saturating_sub(1).min(5))
        .ok_or_else(|| Error::new("overflow", "effect backoff"))
}

impl<B: Binding> Execution<B> {
    pub(crate) fn same_intent(&self, other: &Self) -> bool {
        self.id == other.id
            && self.codec == other.codec
            && self.model == other.model
            && self.store == other.store
            && self.tenant == other.tenant
            && self.requester == other.requester
            && self.credential_epoch == other.credential_epoch
            && self.operation_id == other.operation_id
            && self.operation_epoch == other.operation_epoch
            && self.source == other.source
            && self.action == other.action
            && self.action_version == other.action_version
            && self.provider_account == other.provider_account
            && self.target == other.target
            && self.request == other.request
            && self.request_hash == other.request_hash
            && self.created_at == other.created_at
            && self.execute_at == other.execute_at
            && self.not_after == other.not_after
    }
    pub(crate) fn unresolved(&self) -> bool {
        self.conflict
            || matches!(self.phase, Phase::Ready | Phase::Waiting | Phase::Uncertain)
            || matches!(
                self.application,
                Application::Pending | Application::Blocked
            )
    }
    pub(crate) fn due(&self) -> Option<Vec<u8>> {
        let (class, at) = if let Some(lease) = &self.lease {
            (WorkClass::Expiry, lease.expires_at)
        } else if self.application == Application::Pending && !self.conflict {
            (WorkClass::Apply, self.next_at)
        } else if (matches!(self.phase, Phase::Waiting | Phase::Uncertain)
            || self.conflict
            || self.phase == Phase::Ready && self.quarantined)
            && self.observations < MAX_OBSERVATIONS
        {
            (WorkClass::Reconcile, self.next_at)
        } else if self.phase == Phase::Ready && !self.quarantined {
            (
                WorkClass::Submit,
                self.next_at.max(self.execute_at).min(self.not_after),
            )
        } else {
            return None;
        };
        Some(work_key(class, at, self.id))
    }
    pub(crate) fn accounted_bytes(&self) -> Result<u64> {
        Ok(row_bytes(self)?
            + self.due().map_or(0, |key| key.len() as u64)
            + if self.reservation { RESULT_RESERVE } else { 0 })
    }
    pub(crate) fn advance(&mut self) -> Result<()> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| Error::new("revision_exhausted", "execution revision"))?;
        Ok(())
    }
    pub(crate) fn claim(&self, activation: Uuid) -> Result<Claim> {
        let lease = self
            .lease
            .as_ref()
            .ok_or_else(|| local::corrupt("missing worker lease"))?;
        Ok(Claim {
            store: self.store,
            activation,
            execution: self.id,
            revision: self.revision,
            token: lease.token,
            mode: lease.mode,
        })
    }
    pub(crate) fn matches_claim(&self, runtime: &Runtime, claim: &Claim, now: i64) -> bool {
        self.store == claim.store
            && self.id == claim.execution
            && self.revision == claim.revision
            && runtime.activation == claim.activation
            && runtime.mode.active()
            && (claim.mode == Mode::Reconcile || runtime.mode == WorkerMode::Delivery)
            && self.lease.as_ref().is_some_and(|l| {
                l.activation == claim.activation
                    && l.token == claim.token
                    && l.mode == claim.mode
                    && now >= l.claimed_at
                    && now < l.expires_at
            })
    }
    pub(crate) fn validate_state(&self, runtime: &Runtime) -> Result<()> {
        ensure(
            self.revision > 0
                && self.attempts <= MAX_ATTEMPTS
                && self.observations <= MAX_OBSERVATIONS
                && self.next_at >= 0
                && self.diagnostic.as_ref().is_none_or(|d| d.len() <= 256),
            "effect state bounds",
        )?;
        ensure(
            self.reservation
                == matches!(self.phase, Phase::Ready | Phase::Waiting | Phase::Uncertain),
            "effect result reservation",
        )?;
        ensure(
            !runtime.quarantined || !self.reservation || self.quarantined,
            "restore execution quarantine",
        )?;
        if let Some(lease) = &self.lease {
            ensure(
                lease.activation == runtime.activation
                    && !lease.token.is_nil()
                    && lease.claimed_at >= self.created_at
                    && lease.expires_at > lease.claimed_at
                    && lease.expires_at.saturating_sub(lease.claimed_at) <= MAX_LEASE_MS
                    && lease.renewals <= 2
                    && (lease.renewals != 0
                        || lease.expires_at.saturating_sub(lease.claimed_at) == LEASE_MS)
                    && runtime.mode.active()
                    && match lease.mode {
                        Mode::Submit => {
                            runtime.mode == WorkerMode::Delivery
                                && self.phase == Phase::Ready
                                && !self.quarantined
                                && self.cancellation.is_none()
                                && self.attempts > 0
                        }
                        Mode::Reconcile => {
                            self.observations > 0
                                && (matches!(self.phase, Phase::Waiting | Phase::Uncertain)
                                    || self.conflict
                                    || self.quarantined)
                        }
                    },
                "effect lease",
            )?;
        }
        if let Some(start) = &self.started {
            ensure(
                !start.activation.is_nil()
                    && !start.token.is_nil()
                    && start.at >= self.created_at
                    && start.at >= self.execute_at
                    && start.at < self.not_after
                    && start.attempt > 0
                    && start.attempt <= self.attempts,
                "provider start marker",
            )?;
            if self.phase == Phase::Ready {
                ensure(
                    self.lease.as_ref().is_some_and(|l| {
                        l.mode == Mode::Submit
                            && l.token == start.token
                            && l.activation == start.activation
                            && start.at >= l.claimed_at
                            && start.at < l.expires_at
                    }),
                    "ready started ownership",
                )?;
            }
        }
        if self.phase == Phase::Cancelled {
            ensure(
                self.cancellation.is_some() && self.started.is_none() && self.lease.is_none(),
                "prestart cancellation",
            )?;
        }
        if self.phase == Phase::Ready {
            ensure(
                self.cancellation.is_none() && self.application == Application::None,
                "ready application/cancellation",
            )?;
        }
        ensure(
            (self.phase == Phase::Succeeded) == (self.application != Application::None),
            "remote/application phase",
        )?;
        if self.phase == Phase::Succeeded {
            ensure(self.terminal_fact.is_some(), "success without fact")?;
        }
        if self.phase == Phase::Failed {
            ensure(
                self.terminal_fact.is_some()
                    || (self.started.is_none()
                        && self.attempts == MAX_ATTEMPTS
                        && self.diagnostic.as_deref() == Some("submission_budget_exhausted")),
                "failure without evidence",
            )?;
        }
        ensure(
            self.phase != Phase::Ready || self.terminal_fact.is_none(),
            "ready terminal evidence",
        )?;
        ensure(
            self.phase != Phase::Ready || self.started.is_none() || self.lease.is_some(),
            "started submission lost lease",
        )?;
        for digest in self.last_fact.iter().chain(self.terminal_fact.iter()) {
            fact_key(self.id, digest)?;
        }
        Ok(())
    }
}
