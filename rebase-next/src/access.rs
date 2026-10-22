//! Tenant-local authority, independent of transport, tokens and storage.
//!
//! Preparation is control-plane work. Requests consume a precomputed scope and
//! current grants; they do not scan the principal graph or trust client scopes.

use crate::binding::Binding;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    native_codec::uuid_text,
    native_slice::{Context, Error, ModelRecord, Result},
    plan::choose_reader,
};

pub const MAX_PRINCIPALS: usize = 128;
pub const MAX_PARENTS: usize = 8;
pub const MAX_READER_STREAMS: usize = 1280;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Tenant,
    Group,
    User,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Read,
    Create,
    Update,
    Delete,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grants {
    pub admin: bool,
    pub contracts: BTreeMap<u16, BTreeSet<Action>>,
}

impl Grants {
    fn extend(&mut self, other: &Self) {
        self.admin |= other.admin;
        for (&code, actions) in &other.contracts {
            self.contracts.entry(code).or_default().extend(actions);
        }
    }

    pub fn allows(&self, code: u16, action: Action) -> bool {
        self.admin
            || self
                .contracts
                .get(&code)
                .is_some_and(|a| a.contains(&action))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    #[serde(with = "uuid_text")]
    pub id: Uuid,
    pub kind: PrincipalKind,
    pub parents: Vec<Uuid>,
    pub active: bool,
    /// Increment to revoke all previously issued credentials for this principal.
    pub credential_epoch: u64,
    pub grants: Grants,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Graph {
    #[serde(with = "uuid_text")]
    pub tenant: Uuid,
    pub principals: Vec<Principal>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    #[serde(with = "uuid_text")]
    pub tenant: Uuid,
    #[serde(with = "uuid_text")]
    pub actor: Uuid,
    pub active: bool,
    pub credential_epoch: u64,
    pub grants: Grants,
    pub accessible: BTreeSet<Uuid>,
    pub descendants: BTreeSet<Uuid>,
}

impl Scope {
    pub fn local(context: Context) -> Self {
        Self {
            tenant: context.tenant,
            actor: context.actor,
            active: true,
            credential_epoch: 0,
            grants: Grants {
                admin: true,
                contracts: BTreeMap::new(),
            },
            accessible: BTreeSet::from([context.actor]),
            descendants: BTreeSet::new(),
        }
    }

    pub fn require_active(&self) -> Result<()> {
        if self.active { Ok(()) } else { Err(denied()) }
    }

    pub fn can_read<B: Binding>(&self, record: &ModelRecord<B>) -> bool {
        self.active
            && record.tenant == self.tenant
            && self.grants.allows(record.contract, Action::Read)
            && self.accessible.contains(&record.reader)
    }

    pub fn can_write<B: Binding>(&self, record: &ModelRecord<B>, action: Action) -> bool {
        self.active
            && record.tenant == self.tenant
            && self.grants.allows(record.contract, action)
            && self.accessible.contains(&record.owner)
    }
}

pub fn denied() -> Error {
    Error::new("forbidden", "operation is not permitted")
}

pub struct PreparedGraph {
    pub graph: Graph,
    pub scopes: BTreeMap<Uuid, Scope>,
    descendants: BTreeMap<Uuid, BTreeSet<Uuid>>,
}

impl Graph {
    pub fn bootstrap(context: Context) -> Result<PreparedGraph> {
        if context.tenant == context.actor {
            return Err(Error::new("invalid_input", "tenant and actor must differ"));
        }
        Self {
            tenant: context.tenant,
            principals: vec![
                Principal {
                    id: context.tenant,
                    kind: PrincipalKind::Tenant,
                    parents: vec![],
                    active: true,
                    credential_epoch: 0,
                    grants: Grants::default(),
                },
                Principal {
                    id: context.actor,
                    kind: PrincipalKind::User,
                    parents: vec![context.tenant],
                    active: true,
                    credential_epoch: 0,
                    grants: Grants {
                        admin: true,
                        contracts: BTreeMap::new(),
                    },
                },
            ],
        }
        .prepare()
    }

    pub fn prepare(mut self) -> Result<PreparedGraph> {
        let bad = |message| Error::new("invalid_input", message);
        if self.principals.is_empty() || self.principals.len() > MAX_PRINCIPALS {
            return Err(Error::new("work_limit", "principal population limit"));
        }
        self.principals.sort_by_key(|p| p.id);
        let nodes: BTreeMap<_, _> = self.principals.iter().map(|p| (p.id, p)).collect();
        if nodes.len() != self.principals.len()
            || !nodes.get(&self.tenant).is_some_and(|p| {
                p.kind == PrincipalKind::Tenant && p.parents.is_empty() && p.active
            })
        {
            return Err(bad(
                "one active tenant root and unique principal IDs required",
            ));
        }
        let mut children = BTreeMap::<Uuid, BTreeSet<Uuid>>::new();
        let mut pending = BTreeMap::new();
        for p in nodes.values() {
            if p.id != self.tenant && (p.kind == PrincipalKind::Tenant || p.parents.is_empty())
                || p.parents.len() > MAX_PARENTS
                || p.parents.iter().collect::<BTreeSet<_>>().len() != p.parents.len()
                || p.parents.iter().any(|id| !nodes.contains_key(id))
            {
                return Err(bad("principal parent/kind obligations"));
            }
            pending.insert(p.id, p.parents.len());
            for &parent in &p.parents {
                children.entry(parent).or_default().insert(p.id);
            }
        }
        let mut ready = BTreeSet::from([self.tenant]);
        let mut order = vec![];
        while let Some(id) = ready.pop_first() {
            order.push(id);
            for child in children.get(&id).into_iter().flatten() {
                let count = pending.get_mut(child).expect("known child");
                *count -= 1;
                if *count == 0 {
                    ready.insert(*child);
                }
            }
        }
        if order.len() != nodes.len() {
            return Err(Error::new("feedback", "principal cycle"));
        }
        let mut descendants = BTreeMap::<Uuid, BTreeSet<Uuid>>::new();
        for &id in order.iter().rev() {
            let mut below = BTreeSet::new();
            for child in children.get(&id).into_iter().flatten() {
                below.insert(*child);
                below.extend(&descendants[child]);
            }
            descendants.insert(id, below);
        }
        let mut scopes = BTreeMap::new();
        for p in nodes.values() {
            let mut grants = p.grants.clone();
            let mut accessible = descendants[&p.id].clone();
            accessible.insert(p.id);
            for &parent in &p.parents {
                let node = nodes[&parent];
                if matches!(node.kind, PrincipalKind::Group | PrincipalKind::Tenant) {
                    accessible.insert(parent);
                    if node.active && p.kind == PrincipalKind::User {
                        grants.extend(&node.grants);
                    }
                }
            }
            if grants.admin {
                accessible.extend(nodes.keys());
            }
            scopes.insert(
                p.id,
                Scope {
                    tenant: self.tenant,
                    actor: p.id,
                    active: p.active,
                    credential_epoch: p.credential_epoch,
                    grants,
                    accessible,
                    descendants: descendants[&p.id].clone(),
                },
            );
        }
        if !scopes
            .values()
            .any(|s| s.active && s.grants.admin && nodes[&s.actor].kind == PrincipalKind::User)
        {
            return Err(bad("retain at least one active user administrator"));
        }
        Ok(PreparedGraph {
            graph: self,
            scopes,
            descendants,
        })
    }
}

impl PreparedGraph {
    pub fn dominates(&self, ancestor: Uuid, descendant: Uuid) -> bool {
        self.descendants
            .get(&ancestor)
            .is_some_and(|d| d.contains(&descendant))
    }

    pub fn reader(&self, owners: &[Uuid], fallback: Uuid) -> Uuid {
        choose_reader(owners, fallback, |a, b| self.dominates(a, b))
    }
}
