//! Fixed authored-key M1/M2/M4 experiment; not a public or distributed engine.

use crate::binding::{Binding, Calculation};
use crate::index::{NativeIndex, TimeKey};
use crate::native_codec::StoredValue;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

use crate::{
    native_codec::{self, Address, Key, Stored, decimal, uuid_text},
    plan::{Field, evaluation_order},
    routes::{self, Endpoint},
    staging::Batch,
    time_range::TimeRange,
};

pub const BEHAVIOR_CONTRACT: &str = "rebase-calculation-contract-6";

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Serialize)]
pub struct Error {
    pub code: &'static str,
    pub detail: String,
}
impl Error {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    pub model: String,
    pub codec: String,
    #[serde(with = "uuid_text")]
    pub tenant: Uuid,
    #[serde(with = "uuid_text")]
    pub actor: Uuid,
    #[serde(with = "decimal")]
    pub revision: u64,
    pub counts: BTreeMap<u16, u16>,
    pub reserved: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct Context {
    pub tenant: Uuid,
    pub actor: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Input {
    Rule {
        #[serde(with = "decimal")]
        c: u16,
    },
    Curve {
        native_unit: u16,
        reporting_unit: u16,
    },
    Quote {
        #[serde(with = "uuid_text")]
        curve: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        rate: u16,
    },
    Account {
        native_unit: u16,
    },
    Subsidiary {
        reporting_unit: u16,
    },
    Posting {
        #[serde(with = "decimal")]
        units: i128,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "uuid_text")]
        rule: Uuid,
        #[serde(with = "uuid_text")]
        curve: Uuid,
        #[serde(with = "uuid_text")]
        account: Uuid,
        #[serde(with = "uuid_text")]
        subsidiary: Uuid,
    },
    Moment {
        #[serde(with = "decimal")]
        at: i64,
    },
    Entry {
        #[serde(with = "uuid_text")]
        account: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        amount: i128,
    },
    Adjustment {
        #[serde(with = "uuid_text")]
        account: Uuid,
        #[serde(with = "uuid_text")]
        moment: Uuid,
        #[serde(with = "decimal")]
        offset: i64,
        #[serde(with = "decimal")]
        target: i128,
        post: bool,
    },
    Basis {
        sources: Vec<Uuid>,
        #[serde(with = "decimal")]
        factor: u16,
        #[serde(with = "uuid_text")]
        account: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        feedback: Option<Feedback>,
    },
    Pin {
        #[serde(with = "uuid_text")]
        output: Uuid,
    },
    Output {
        #[serde(with = "uuid_text")]
        producer: Uuid,
        role: u16,
        #[serde(with = "uuid_text")]
        account: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        amount: i128,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Feedback {
    #[serde(with = "uuid_text")]
    pub account: Uuid,
    #[serde(with = "decimal")]
    pub at: i64,
}

impl Input {
    pub fn contract(&self) -> u16 {
        match self {
            Self::Rule { .. } => 1,
            Self::Curve { .. } => 2,
            Self::Quote { .. } => 3,
            Self::Account { .. } => 4,
            Self::Subsidiary { .. } => 5,
            Self::Posting { .. } => 6,
            Self::Moment { .. } => 7,
            Self::Entry { .. } => 8,
            Self::Adjustment { .. } => 9,
            Self::Basis { .. } => 10,
            Self::Pin { .. } => 11,
            Self::Output { .. } => 12,
        }
    }
    pub fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::Rule { c } => (1..=1000).contains(c),
            Self::Curve {
                native_unit,
                reporting_unit,
            } => *native_unit > 0 && *reporting_unit > 0,
            Self::Quote { rate, .. } => (1..=1000).contains(rate),
            Self::Account { native_unit } => *native_unit > 0,
            Self::Subsidiary { reporting_unit } => *reporting_unit > 0,
            Self::Posting { units, .. } => (-1000..=1000).contains(units),
            Self::Moment { .. } => true,
            Self::Entry { amount, .. } => (-1000..=1000).contains(amount),
            Self::Adjustment { offset, target, .. } => {
                (-1000..=1000).contains(offset) && (-1000..=1000).contains(target)
            }
            Self::Basis {
                sources, factor, ..
            } => (1..=2).contains(&sources.len()) && (1..=3).contains(factor),
            Self::Pin { .. } => true,
            Self::Output { role, .. } => (1..=2).contains(role),
        };
        if valid {
            Ok(())
        } else {
            Err(Error::new(
                "invalid_input",
                "authored value outside fixture bounds",
            ))
        }
    }
    pub fn bind(code: u16, value: serde_json::Value) -> Result<Self> {
        let input: Self = serde_json::from_value(value.clone())
            .map_err(|e| Error::new("invalid_input", e.to_string()))?;
        if input.contract() != code {
            return Err(Error::new("invalid_input", "contract/input mismatch"));
        }
        input.validate()?;
        if serde_json::to_value(&input).map_err(|e| Error::new("codec", e.to_string()))? != value {
            return Err(Error::new(
                "invalid_input",
                "complete canonical input required",
            ));
        }
        Ok(input)
    }
    pub fn references(&self) -> Vec<(Uuid, u16, u16)> {
        match self {
            Self::Quote { curve, .. } => vec![(*curve, 2, 1)],
            Self::Posting {
                rule,
                curve,
                account,
                subsidiary,
                ..
            } => vec![
                (*rule, 1, 3),
                (*curve, 2, 4),
                (*account, 4, 5),
                (*subsidiary, 5, 6),
            ],
            Self::Entry { account, .. } => vec![(*account, 4, 1)],
            Self::Adjustment {
                account, moment, ..
            } => vec![(*account, 4, 1), (*moment, 7, 2)],
            Self::Basis {
                sources,
                account,
                feedback,
                ..
            } => {
                let mut refs: Vec<_> = sources
                    .iter()
                    .enumerate()
                    .map(|(i, id)| (*id, 4, i as u16 + 1))
                    .collect();
                refs.push((*account, 4, 3));
                if let Some(feedback) = feedback {
                    refs.push((feedback.account, 4, 4));
                }
                refs
            }
            Self::Pin { output } => vec![(*output, 12, 1)],
            Self::Output {
                producer, account, ..
            } => vec![(*producer, 0, 1), (*account, 4, 2)],
            _ => vec![],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Derived {
    #[serde(with = "decimal")]
    pub native_minor: i128,
    #[serde(with = "decimal")]
    pub reporting_minor: i128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Calculated {
    Posting(Derived),
    Adjustment {
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        before: i128,
        #[serde(with = "decimal")]
        delta: i128,
    },
    Basis {
        #[serde(with = "decimal")]
        value: i128,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(bound(
    serialize = "B::Input: Serialize, B::Derived: Serialize",
    deserialize = "B::Input: serde::de::DeserializeOwned, B::Derived: serde::de::DeserializeOwned"
))]
pub struct ModelRecord<B: Binding> {
    pub contract: u16,
    #[serde(with = "uuid_text")]
    pub tenant: Uuid,
    #[serde(with = "uuid_text")]
    pub owner: Uuid,
    #[serde(with = "uuid_text")]
    pub reader: Uuid,
    #[serde(with = "decimal")]
    pub version: u64,
    pub input: B::Input,
    pub derived: Option<B::Derived>,
}

pub type Record = ModelRecord<Calculation>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub source: Address,
    pub operation: String,
    pub phase: String,
    pub channel: String,
    pub range: TimeRange,
    pub selected: Option<Uuid>,
    #[serde(with = "decimal")]
    pub result: i128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
pub enum Command {
    Create {
        #[serde(with = "uuid_text")]
        id: Uuid,
        contract: u16,
        fields: serde_json::Value,
    },
    Update {
        #[serde(with = "uuid_text")]
        id: Uuid,
        #[serde(with = "decimal")]
        if_version: u64,
        set: BTreeMap<String, serde_json::Value>,
        unset: Vec<String>,
    },
    Delete {
        #[serde(with = "uuid_text")]
        id: Uuid,
        #[serde(with = "decimal")]
        if_version: u64,
    },
}

impl Command {
    pub fn id(&self) -> Uuid {
        match *self {
            Self::Create { id, .. } | Self::Update { id, .. } | Self::Delete { id, .. } => id,
        }
    }
}

#[derive(Clone)]
pub struct Model {
    pub identity: String,
    pub codec: String,
    pub order: Vec<usize>,
}

impl Model {
    pub fn prepare() -> Result<Self> {
        let fields = [
            ("a_reporting", vec!["z_native", "rate"]),
            ("z_native", vec!["units", "c"]),
            ("units", vec![]),
            ("c", vec![]),
            ("rate", vec![]),
        ]
        .into_iter()
        .map(|(name, inputs)| Field {
            name: name.into(),
            inputs: inputs.into_iter().map(str::to_owned).collect(),
        })
        .collect::<Vec<_>>();
        let order = evaluation_order(&fields).map_err(|e| Error::new("model", e))?;
        // Maintainers bump this contract revision for changes to formulas,
        // binding, settlement or invariants. Build/dependency bytes are not a
        // data model: patching transport must not strand an unchanged store.
        let identity = native_codec::hex(&Sha256::digest(BEHAVIOR_CONTRACT.as_bytes()));
        Ok(Self {
            identity,
            codec: native_codec::CODEC.into(),
            order,
        })
    }

    pub fn from_behavior(name: &str, behavior: &str) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"rebase-native-model-3\0");
        for part in [name.as_bytes(), behavior.as_bytes()] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        Self {
            identity: native_codec::hex(&hash.finalize()),
            codec: native_codec::CODEC.into(),
            order: vec![],
        }
    }

    pub fn calculate(&self, units: i128, c: u16, rate: u16) -> Result<Derived> {
        let mut values = [None; 5];
        for &index in &self.order {
            let input =
                |i: usize| values[i].ok_or_else(|| Error::new("model", "unsettled declared input"));
            let multiply = |a: i128, b: i128| {
                a.checked_mul(b)
                    .ok_or_else(|| Error::new("overflow", "exact product"))
            };
            values[index] = Some(match index {
                0 => multiply(input(1)?, input(4)?)?,
                1 => multiply(input(2)?, input(3)?)?,
                2 => units,
                3 => i128::from(c),
                4 => i128::from(rate),
                _ => return Err(Error::new("model", "unknown field")),
            });
        }
        Ok(Derived {
            native_minor: values[1].ok_or_else(|| Error::new("model", "missing native"))?,
            reporting_minor: values[0].ok_or_else(|| Error::new("model", "missing reporting"))?,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Work {
    pub work_units: u64,
    pub command_visits: u64,
    pub route_entries: u64,
    pub selector_visits: u64,
    pub node_visits: u64,
    pub key_loads: u64,
    pub loaded_bytes: u64,
    pub staged_patches: u64,
    pub candidates: u64,
    pub evaluations: u64,
    pub rotations: u64,
    pub causal_candidates: u64,
    pub causal_evaluations: u64,
    pub dependency_edges: u64,
    pub dependency_checks: u64,
    pub graph_nodes: u64,
    pub scheduler_visits: u64,
    pub reader_checks: u64,
    pub inventory_visits: u64,
    pub allocations: u64,
    pub detached_outputs: u64,
    pub final_dirty_keys: u64,
    pub encoded_bytes: u64,
}

#[derive(Clone)]
struct Entry<B: Binding> {
    before: Option<Vec<u8>>,
    original: Option<StoredValue<B>>,
    current: Option<StoredValue<B>>,
}

/// A synchronous point loader for this experiment, not a distributed driver API.
pub struct Attempt<L, B: Binding> {
    load: L,
    entries: BTreeMap<Key, Entry<B>>,
    pub work: Work,
    limit: u64,
}

impl<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding> Attempt<L, B> {
    pub fn new(load: L, limit: u64) -> Self {
        Self {
            load,
            entries: BTreeMap::new(),
            work: Work::default(),
            limit,
        }
    }
    pub fn charge(&mut self, kind: &str, count: u64) -> Result<()> {
        match kind {
            "command" => self.work.command_visits += count,
            "route" => self.work.route_entries += count,
            "select" => self.work.selector_visits += count,
            "node" => self.work.node_visits += count,
            "load" => self.work.key_loads += count,
            "patch" => self.work.staged_patches += count,
            "edge" => self.work.dependency_edges += count,
            "dependency" => self.work.dependency_checks += count,
            "graph" => self.work.graph_nodes += count,
            "schedule" => self.work.scheduler_visits += count,
            "reader" => self.work.reader_checks += count,
            "inventory" => self.work.inventory_visits += count,
            "allocate" => self.work.allocations += count,
            _ => return Err(Error::new("internal", "unknown work counter")),
        }
        self.work.work_units = self
            .work
            .work_units
            .checked_add(count)
            .ok_or_else(|| Error::new("work_limit", "counter overflow"))?;
        if self.work.work_units > self.limit {
            return Err(Error::new("work_limit", "attempt work budget"));
        }
        Ok(())
    }
    fn ensure(&mut self, key: &Key) -> Result<()> {
        if !self.entries.contains_key(key) {
            self.charge("load", 1)?;
            let before = (self.load)(&key.encode())?;
            self.work.loaded_bytes += before.as_ref().map_or(0, |bytes| bytes.len() as u64);
            let original = before
                .as_deref()
                .map(|bytes| native_codec::decode_for::<B>(key, bytes))
                .transpose()?;
            self.entries.insert(
                key.clone(),
                Entry {
                    before,
                    current: original.clone(),
                    original,
                },
            );
        }
        Ok(())
    }
    pub fn get(&mut self, key: &Key) -> Result<Option<StoredValue<B>>> {
        self.ensure(key)?;
        Ok(self.entries[key].current.clone())
    }
    pub fn original(&mut self, key: &Key) -> Result<Option<StoredValue<B>>> {
        self.ensure(key)?;
        Ok(self.entries[key].original.clone())
    }
    pub fn put(&mut self, key: Key, value: Option<StoredValue<B>>) -> Result<()> {
        self.ensure(&key)?;
        if self.entries[&key].current != value {
            self.charge("patch", 1)?;
            self.entries.get_mut(&key).expect("ensured entry").current = value;
        }
        Ok(())
    }
    pub fn finish(&mut self) -> Result<Batch> {
        let mut batch = Batch::new();
        for (key, entry) in &self.entries {
            if entry.current == entry.original {
                continue;
            }
            let value = entry
                .current
                .as_ref()
                .map(|v| native_codec::encode_for::<B>(key, v))
                .transpose()?;
            if value != entry.before {
                self.work.encoded_bytes += value.as_ref().map_or(0, |b| b.len() as u64);
                batch.insert(key.encode(), value);
            }
        }
        self.work.final_dirty_keys = batch.len() as u64;
        Ok(batch)
    }
    pub fn record(&mut self, id: Uuid) -> Result<Option<ModelRecord<B>>> {
        match self.get(&Key::Record(id))? {
            Some(StoredValue::Record(r)) => Ok(Some(r)),
            None => Ok(None),
            _ => Err(Error::new("corrupt_state", "record type")),
        }
    }
    pub(crate) fn changed_records(&self) -> BTreeSet<Uuid> {
        self.entries
            .iter()
            .filter_map(|(key, entry)| match key {
                Key::Record(id) if entry.current != entry.original => Some(*id),
                _ => None,
            })
            .collect()
    }
    pub(crate) fn changed_roots(&self) -> BTreeSet<Address> {
        let mut roots = BTreeSet::new();
        for (key, entry) in &self.entries {
            if let Key::Root(root) = key
                && entry.original.is_none()
                && entry.current.is_some()
            {
                roots.insert(*root);
            }
            if let Key::Node(_) = key {
                let logical = |value: &Option<StoredValue<B>>| match value {
                    Some(StoredValue::Node(n)) => Some((n.root, n.key.clone(), n.leaf.clone())),
                    _ => None,
                };
                let old = logical(&entry.original);
                let new = logical(&entry.current);
                if old != new {
                    roots.extend([old, new].into_iter().flatten().map(|n| n.0));
                }
            }
        }
        roots
    }
    pub(crate) fn financial_impacts(&self) -> BTreeMap<Address, BTreeSet<i64>> {
        let mut impacts = BTreeMap::<Address, BTreeSet<i64>>::new();
        for (key, entry) in &self.entries {
            if !matches!(key, Key::Node(_)) {
                continue;
            }
            let logical = |v: &Option<StoredValue<B>>| match v {
                Some(StoredValue::Node(n)) if B::Index::financial_leaf(n.kind, &n.leaf).is_ok() => {
                    B::Index::time(n.kind, &n.key.value)
                        .ok()
                        .map(|at| (n.root, at, n.leaf.clone()))
                }
                _ => None,
            };
            let old = logical(&entry.original);
            let new = logical(&entry.current);
            if old != new {
                for (root, at, _) in [old, new].into_iter().flatten() {
                    impacts.entry(root).or_default().insert(at);
                }
            }
        }
        impacts
    }
}

#[derive(Clone)]
pub struct ModelChange<B: Binding> {
    pub id: Uuid,
    pub old: Option<ModelRecord<B>>,
    pub new: Option<ModelRecord<B>>,
}

pub type Workspace<L> = Attempt<L, Calculation>;
pub(crate) type Change = ModelChange<Calculation>;

#[derive(Clone, Debug, Serialize)]
pub struct Settled {
    #[serde(with = "decimal")]
    pub revision: u64,
}

pub(crate) fn required<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    id: Uuid,
    code: u16,
    context: Context,
) -> Result<Record> {
    ws.record(id)?
        .filter(|r| {
            (r.contract == code || (code == 0 && matches!(r.contract, 9 | 10)))
                && r.tenant == context.tenant
        })
        .ok_or_else(|| Error::new("unavailable_reference", "reference target unavailable"))
}

pub(crate) fn validate_references<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    input: &Input,
    context: Context,
) -> Result<()> {
    for (id, code, _) in input.references() {
        required(ws, id, code, context)?;
    }
    if let Input::Posting {
        curve,
        account,
        subsidiary,
        ..
    } = *input
    {
        let Input::Curve {
            native_unit,
            reporting_unit,
        } = required(ws, curve, 2, context)?.input
        else {
            unreachable!()
        };
        let Input::Account {
            native_unit: account_unit,
        } = required(ws, account, 4, context)?.input
        else {
            unreachable!()
        };
        let Input::Subsidiary {
            reporting_unit: subsidiary_unit,
        } = required(ws, subsidiary, 5, context)?.input
        else {
            unreachable!()
        };
        if native_unit != account_unit || reporting_unit != subsidiary_unit {
            return Err(Error::new("unavailable_reference", "unit mismatch"));
        }
    }
    if let Input::Basis {
        sources,
        account,
        feedback,
        ..
    } = input
    {
        let Input::Account { native_unit } = required(ws, *account, 4, context)?.input else {
            unreachable!()
        };
        for id in sources
            .iter()
            .copied()
            .chain(feedback.iter().map(|f| f.account))
        {
            if required(ws, id, 4, context)?.input != (Input::Account { native_unit }) {
                return Err(Error::new("unavailable_reference", "basis unit mismatch"));
            }
        }
    }
    Ok(())
}

pub(crate) fn registrations(
    id: Uuid,
    input: Option<&Input>,
) -> BTreeMap<(Key, Address), TimeRange> {
    let mut entries = BTreeMap::new();
    if let Some(input) = input {
        for (target, _, field) in input.references() {
            entries.insert(
                (Key::Incoming(target), Address::new(id, field)),
                TimeRange::ALL,
            );
        }
        if let Input::Posting {
            rule, curve, at, ..
        } = input
        {
            entries.insert((Key::Direct(*rule), Address::new(id, 7)), TimeRange::ALL);
            entries.insert(
                (
                    Key::Subscribers(Address::new(*curve, 1)),
                    Address::new(id, 1),
                ),
                TimeRange::through(*at),
            );
        }
        if let Input::Adjustment { moment, .. } = input {
            entries.insert((Key::Direct(*moment), Address::new(id, 6)), TimeRange::ALL);
        }
    }
    entries
}

fn quote_successor<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    id: Uuid,
    original: bool,
) -> Result<Option<i64>> {
    let key = Key::Node(Address::new(id, 3));
    let value = if original {
        ws.original(&key)?
    } else {
        ws.get(&key)?
    };
    let Some(Stored::Node(n)) = value else {
        return Err(Error::new("corrupt_state", "missing quote membership"));
    };
    let Some(next) = n.next else {
        return Ok(None);
    };
    let key = Key::Node(next);
    let value = if original {
        ws.original(&key)?
    } else {
        ws.get(&key)?
    };
    match value {
        Some(Stored::Node(v)) if v.root == n.root && v.key.value.get() > n.key.value.get() => {
            Ok(Some(v.key.value.get()))
        }
        _ => Err(Error::new("corrupt_state", "quote successor")),
    }
}

fn quote(input: Option<&Input>) -> Option<(Uuid, i64, u16)> {
    match input {
        Some(Input::Quote { curve, at, rate }) => Some((*curve, *at, *rate)),
        _ => None,
    }
}

pub(crate) fn financial(
    record: Option<&Record>,
    slot: u16,
) -> Result<Option<(Address, i64, crate::indexes::standard::Leaf)>> {
    let Some(record) = record else {
        return Ok(None);
    };
    if let Input::Entry {
        account,
        at,
        amount,
    }
    | Input::Output {
        account,
        at,
        amount,
        ..
    } = record.input
    {
        return Ok((slot == 1).then_some((
            Address::new(account, 2),
            at,
            crate::indexes::standard::Leaf::Financial(amount),
        )));
    }
    let Input::Posting {
        at,
        account,
        subsidiary,
        ..
    } = record.input
    else {
        return Err(Error::new("internal", "not a posting"));
    };
    let derived = record
        .derived
        .ok_or_else(|| Error::new("corrupt_state", "unsettled posting"))?;
    let Calculated::Posting(derived) = derived else {
        return Err(Error::new("corrupt_state", "posting calculation type"));
    };
    Ok(Some(if slot == 1 {
        (
            Address::new(account, 2),
            at,
            crate::indexes::standard::Leaf::Financial(derived.native_minor),
        )
    } else {
        (
            Address::new(subsidiary, 3),
            at,
            crate::indexes::standard::Leaf::Financial(derived.reporting_minor),
        )
    }))
}

pub(crate) fn reconcile_member<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    id: Address,
    old: Option<(Address, i64, crate::indexes::standard::Leaf)>,
    new: Option<(Address, i64, crate::indexes::standard::Leaf)>,
) -> Result<()> {
    use crate::tree;
    match (old, ws.get(&Key::Node(id))?) {
        (Some((root, at, leaf)), Some(Stored::Node(n)))
            if n.root == root && n.key.value.get() == at && n.leaf == leaf => {}
        (None, None) => {}
        _ => {
            return Err(Error::new(
                "corrupt_state",
                "old membership differs from source",
            ));
        }
    }
    if old == new {
        return Ok(());
    }
    if let (Some((old_root, old_at, _)), Some((new_root, new_at, leaf))) = (old, new)
        && old_root == new_root
        && old_at == new_at
    {
        return tree::revalue(ws, new_root, id, leaf);
    }
    if let Some((root, _, _)) = old {
        tree::remove(ws, root, id)?;
    }
    if let Some((root, at, leaf)) = new {
        tree::insert(ws, root, id, TimeKey::new(at), leaf)?;
    }
    Ok(())
}

/// Settle privately. Only the adapter's successful commit may release `Settled`.
pub fn settle<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    model: &Model,
    context: Context,
    commands: &[Command],
) -> Result<Settled> {
    settle_with_ids(ws, model, context, commands, &mut || Ok(Uuid::new_v4()))
}

pub fn settle_with_ids<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    model: &Model,
    context: Context,
    commands: &[Command],
    allocate: &mut dyn FnMut() -> Result<Uuid>,
) -> Result<Settled> {
    settle_inner(
        ws,
        model,
        context,
        commands,
        allocate,
        false,
        &mut |_, _, old, _| {
            if old.is_some_and(|r| r.owner != context.actor) {
                Err(Error::new("forbidden", "source authority"))
            } else {
                Ok(())
            }
        },
    )
}

/// Trusted fixture entrypoint for internal REJECT-reference controls. Never
/// select this capability from an untrusted API parameter.
pub fn settle_fixture<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    model: &Model,
    context: Context,
    commands: &[Command],
    allocate: &mut dyn FnMut() -> Result<Uuid>,
) -> Result<Settled> {
    settle_inner(
        ws,
        model,
        context,
        commands,
        allocate,
        true,
        &mut |_, _, _, _| Ok(()),
    )
}

fn settle_inner<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    model: &Model,
    context: Context,
    commands: &[Command],
    allocate: &mut dyn FnMut() -> Result<Uuid>,
    trusted: bool,
    authorize: &mut impl FnMut(
        &mut Workspace<L>,
        &Command,
        Option<&Record>,
        Option<&Record>,
    ) -> Result<()>,
) -> Result<Settled> {
    let prepared = crate::model::PreparedModel::for_native_engine(model)?;
    crate::mutation::settle_authorized(
        ws, &prepared, context, commands, allocate, trusted, authorize,
    )
}

pub(crate) fn settle_calculation_changes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    model: &crate::model::PreparedModel,
    context: Context,
    changes: &[Change],
    meta: &mut Meta,
    revision: u64,
    allocate: &mut dyn FnMut() -> Result<Uuid>,
) -> Result<()> {
    use crate::indexes::standard::{Aggregate, Leaf};
    use crate::tree;
    // Unit agreement is a calculation-model obligation, beyond shared typed
    // reference existence/tenant checks. Keep it at the model boundary.
    for change in changes {
        if let Some(new) = &change.new {
            validate_references(ws, &new.input, context)?;
        }
    }
    for change in changes {
        let old = registrations(change.id, change.old.as_ref().map(|r| &r.input));
        let new = registrations(change.id, change.new.as_ref().map(|r| &r.input));
        for ((key, member), range) in &old {
            if new.get(&(key.clone(), *member)) != Some(range) {
                routes::change(ws, key, *member, *range, false)?;
            }
        }
        for ((key, member), range) in &new {
            if old.get(&(key.clone(), *member)) != Some(range) {
                routes::change(ws, key, *member, *range, true)?;
            }
        }
    }
    let mut candidates = BTreeSet::new();
    let mut intervals = BTreeSet::new();
    for change in changes {
        let old = change.old.as_ref().map(|r| &r.input);
        let new = change.new.as_ref().map(|r| &r.input);
        if old.is_some_and(|i| i.contract() == 6) || new.is_some_and(|i| i.contract() == 6) {
            candidates.insert(change.id);
        }
        if old != new
            && (old.is_some_and(|i| i.contract() == 1) || new.is_some_and(|i| i.contract() == 1))
        {
            routes::collect(ws, &Key::Direct(change.id), &mut candidates)?;
        }
        if old != new
            && let Some((curve, at, _)) = quote(old)
        {
            intervals.insert((
                Address::new(curve, 1),
                at,
                quote_successor(ws, change.id, true)?,
            ));
        }
    }
    for change in changes {
        let old = quote(change.old.as_ref().map(|r| &r.input));
        let new = quote(change.new.as_ref().map(|r| &r.input));
        if let Some((curve, at, _)) = old
            && new.is_none_or(|(c, t, _)| (c, t) != (curve, at))
        {
            tree::remove(ws, Address::new(curve, 1), Address::new(change.id, 3))?;
        }
    }
    for change in changes {
        let old = quote(change.old.as_ref().map(|r| &r.input));
        if let Some((curve, at, rate)) = quote(change.new.as_ref().map(|r| &r.input)) {
            let root = Address::new(curve, 1);
            let node = Address::new(change.id, 3);
            if old.is_some_and(|(c, t, _)| (c, t) == (curve, at)) {
                tree::revalue(ws, root, node, Leaf::Quote(rate))?;
            } else {
                tree::insert(ws, root, node, TimeKey::new(at), Leaf::Quote(rate))?;
            }
        }
    }
    for change in changes {
        if change.old.as_ref().map(|r| &r.input) != change.new.as_ref().map(|r| &r.input)
            && let Some((curve, at, _)) = quote(change.new.as_ref().map(|r| &r.input))
        {
            intervals.insert((
                Address::new(curve, 1),
                at,
                quote_successor(ws, change.id, false)?,
            ));
        }
    }
    for (root, from, until) in intervals {
        for original in [true, false] {
            candidates.extend(
                routes::select(
                    ws,
                    &Key::Subscribers(root),
                    std::ops::Bound::Included(Endpoint::Through(from)),
                    until.map_or(std::ops::Bound::Unbounded, |at| {
                        std::ops::Bound::Excluded(Endpoint::Through(at))
                    }),
                    original,
                )?
                .into_iter()
                .map(|a| a.id),
            );
        }
    }
    ws.work.candidates = candidates.len() as u64;
    for id in candidates {
        let old = match ws.original(&Key::Record(id))? {
            Some(Stored::Record(r)) => Some(r),
            None => None,
            _ => return Err(Error::new("corrupt_state", "old posting")),
        };
        let mut new = ws.record(id)?;
        if let Some(record) = &mut new {
            let Input::Posting {
                units,
                at,
                rule,
                curve,
                ..
            } = record.input
            else {
                return Err(Error::new("corrupt_state", "nonposting reverse consumer"));
            };
            let Input::Rule { c } = required(ws, rule, 1, context)?.input else {
                unreachable!()
            };
            let selected = tree::latest(ws, Address::new(curve, 1), at)?;
            let rate = selected.map_or(1, |(_, rate)| rate);
            record.derived = Some(Calculated::Posting(
                model.engine().calculate(units, c, rate)?,
            ));
            ws.work.evaluations += 1;
            ws.put(Key::Record(id), Some(Stored::Record(record.clone())))?;
            ws.put(
                Key::Query(Address::new(id, 1)),
                Some(Stored::Query(Query {
                    source: Address::new(curve, 1),
                    operation: "latest".into(),
                    phase: "calculate".into(),
                    channel: "rate".into(),
                    range: TimeRange::through(at),
                    selected: selected.map(|(id, _)| id),
                    result: i128::from(rate),
                })),
            )?;
        } else {
            if !matches!(
                ws.get(&Key::Query(Address::new(id, 1)))?,
                Some(Stored::Query(_))
            ) {
                return Err(Error::new("corrupt_state", "missing deleted query"));
            }
            ws.put(Key::Query(Address::new(id, 1)), None)?;
        }
        for slot in [1, 2] {
            reconcile_member(
                ws,
                Address::new(id, slot),
                financial(old.as_ref(), slot)?,
                financial(new.as_ref(), slot)?,
            )?;
        }
    }
    for change in changes {
        if change
            .old
            .as_ref()
            .or(change.new.as_ref())
            .is_some_and(|r| r.contract == 8)
        {
            reconcile_member(
                ws,
                Address::new(change.id, 1),
                financial(change.old.as_ref(), 1)?,
                financial(change.new.as_ref(), 1)?,
            )?;
        }
    }

    crate::causal::settle(ws, model, context, changes, meta, revision, allocate)?;
    for id in ws.changed_roots() {
        if id.slot == 2
            && let Some(Stored::Root(root)) = ws.get(&Key::Root(id))?
        {
            let Aggregate::Financial(summary) = root.summary else {
                return Err(Error::new("corrupt_state", "account summary kind"));
            };
            if summary.complete_min() < 0 {
                return Err(Error::new(
                    "invariant",
                    "negative complete-time account balance",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn prepared_calculation_and_exact_bindings() {
        let model = Model::prepare().unwrap();
        assert!(
            model.order.iter().position(|i| *i == 1) < model.order.iter().position(|i| *i == 0)
        );
        assert_eq!(
            model.calculate(4, 3, 3).unwrap(),
            Derived {
                native_minor: 12,
                reporting_minor: 36
            }
        );
        for value in [
            json!(2),
            json!(true),
            json!(null),
            json!("02"),
            json!("-0"),
            json!("0"),
            json!("1001"),
        ] {
            assert!(Input::bind(1, json!({"c":value})).is_err());
        }
        assert!(Input::bind(1, json!({"c":"2","unknown":0})).is_err());
        assert!(Input::bind(4, json!({"native_unit":1,"reporting_unit":2})).is_err());
        let input = Input::bind(
            3,
            json!({"curve":Uuid::nil().to_string(),"at":i64::MIN.to_string(),"rate":"3"}),
        )
        .unwrap();
        assert!(matches!(input, Input::Quote { at: i64::MIN, .. }));
    }

    #[test]
    fn typed_workspace_retains_old_images_and_coalesces_current_state() {
        let key = Key::Incoming(Uuid::nil());
        let value = Stored::Incoming(Default::default());
        let bytes = native_codec::encode(&key, &value).unwrap();
        let mut loads = 0;
        let mut workspace = Workspace::new(
            |_: &[u8]| {
                loads += 1;
                Ok(Some(bytes.clone()))
            },
            100,
        );
        workspace.put(key.clone(), None).unwrap();
        assert_eq!(workspace.get(&key).unwrap(), None);
        assert_eq!(workspace.original(&key).unwrap(), Some(value.clone()));
        workspace.put(key.clone(), Some(value)).unwrap();
        assert!(workspace.finish().unwrap().is_empty());
        assert_eq!(workspace.work.key_loads, 1);
        assert_eq!(workspace.work.encoded_bytes, 0);
        drop(workspace);
        assert_eq!(loads, 1);
        assert!(Key::decode(&[3]).is_err());
        assert!(Key::decode(&[255]).is_err());
    }
}
