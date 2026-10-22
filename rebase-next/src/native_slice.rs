//! Fixed authored-key M1/M2/M4 experiment; not a public or distributed engine.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

use crate::{
    native_codec::{self, Address, Key, Stored, decimal, uuid_text},
    plan::{Field, evaluation_order},
    staging::Batch,
};

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
    pub counts: [u16; 12],
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
    fn allows(&self, field: &str) -> bool {
        match self {
            Self::Rule { .. } => field == "c",
            Self::Quote { .. } => ["curve", "at", "rate"].contains(&field),
            Self::Posting { .. } => {
                ["units", "at", "rule", "curve", "account", "subsidiary"].contains(&field)
            }
            Self::Moment { .. } => field == "at",
            Self::Entry { .. } => ["account", "at", "amount"].contains(&field),
            Self::Adjustment { .. } => {
                ["account", "moment", "offset", "target", "post"].contains(&field)
            }
            Self::Basis { .. } => {
                ["sources", "factor", "account", "at", "feedback"].contains(&field)
            }
            _ => false,
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
pub struct Record {
    pub contract: u16,
    #[serde(with = "uuid_text")]
    pub tenant: Uuid,
    #[serde(with = "uuid_text")]
    pub owner: Uuid,
    #[serde(with = "uuid_text")]
    pub reader: Uuid,
    #[serde(with = "decimal")]
    pub version: u64,
    pub input: Input,
    pub derived: Option<Calculated>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bound {
    AfterTime(#[serde(with = "decimal")] i64),
    BeforeTime(#[serde(with = "decimal")] i64),
    All,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub source: Address,
    pub operation: String,
    pub phase: String,
    pub channel: String,
    pub lower: String,
    pub upper: Bound,
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
        let sources: &[(&str, &[u8])] = &[
            ("Cargo.lock", include_bytes!("../Cargo.lock")),
            ("Cargo.toml", include_bytes!("../Cargo.toml")),
            (
                "rust-toolchain.toml",
                include_bytes!("../rust-toolchain.toml"),
            ),
            ("src/algebra.rs", include_bytes!("algebra.rs")),
            ("src/causal.rs", include_bytes!("causal.rs")),
            ("src/native_codec.rs", include_bytes!("native_codec.rs")),
            ("src/native_slice.rs", include_bytes!("native_slice.rs")),
            ("src/plan.rs", include_bytes!("plan.rs")),
            ("src/staging.rs", include_bytes!("staging.rs")),
            ("src/tree.rs", include_bytes!("tree.rs")),
        ];
        let mut hash = Sha256::new();
        hash.update(b"rebase-native-slice-model-v1\0");
        for (name, bytes) in sources {
            for data in [name.as_bytes(), *bytes] {
                hash.update((data.len() as u64).to_be_bytes());
                hash.update(data);
            }
        }
        Ok(Self {
            identity: native_codec::hex(&hash.finalize()),
            codec: native_codec::CODEC.into(),
            order,
        })
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
    pub node_visits: u64,
    pub key_loads: u64,
    pub staged_patches: u64,
    pub candidates: u64,
    pub evaluations: u64,
    pub rotations: u64,
    pub causal_candidates: u64,
    pub causal_evaluations: u64,
    pub dependency_edges: u64,
    pub dependency_checks: u64,
    pub allocations: u64,
    pub detached_outputs: u64,
    pub final_dirty_keys: u64,
    pub encoded_bytes: u64,
}

#[derive(Clone)]
struct Entry {
    before: Option<Vec<u8>>,
    original: Option<Stored>,
    current: Option<Stored>,
}

/// A synchronous point loader for this experiment, not a distributed driver API.
pub struct Workspace<L> {
    load: L,
    entries: BTreeMap<Key, Entry>,
    pub work: Work,
    limit: u64,
}

impl<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>> Workspace<L> {
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
            "node" => self.work.node_visits += count,
            "load" => self.work.key_loads += count,
            "patch" => self.work.staged_patches += count,
            "edge" => self.work.dependency_edges += count,
            "dependency" => self.work.dependency_checks += count,
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
            let original = before
                .as_deref()
                .map(|bytes| native_codec::decode(key, bytes))
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
    pub fn get(&mut self, key: &Key) -> Result<Option<Stored>> {
        self.ensure(key)?;
        Ok(self.entries[key].current.clone())
    }
    pub fn original(&mut self, key: &Key) -> Result<Option<Stored>> {
        self.ensure(key)?;
        Ok(self.entries[key].original.clone())
    }
    pub fn put(&mut self, key: Key, value: Option<Stored>) -> Result<()> {
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
                .map(|v| native_codec::encode(key, v))
                .transpose()?;
            if value != entry.before {
                self.work.encoded_bytes += value.as_ref().map_or(0, |b| b.len() as u64);
                batch.insert(key.encode(), value);
            }
        }
        self.work.final_dirty_keys = batch.len() as u64;
        Ok(batch)
    }
    pub fn record(&mut self, id: Uuid) -> Result<Option<Record>> {
        match self.get(&Key::Record(id))? {
            Some(Stored::Record(r)) => Ok(Some(r)),
            None => Ok(None),
            _ => Err(Error::new("corrupt_state", "record type")),
        }
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
                let logical = |value: &Option<Stored>| match value {
                    Some(Stored::Node(n)) => Some((n.root, n.key, n.leaf)),
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
}

#[derive(Clone)]
pub(crate) struct Change {
    pub id: Uuid,
    pub old: Option<Record>,
    pub new: Option<Record>,
}

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
                && r.owner == context.actor
                && r.reader == context.actor
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

fn owned_root(id: Uuid, input: &Input) -> Option<(Address, crate::tree::Kind)> {
    use crate::tree::Kind;
    match input {
        Input::Curve { .. } => Some((Address::new(id, 1), Kind::Quote)),
        Input::Account { .. } => Some((Address::new(id, 2), Kind::Financial)),
        Input::Subsidiary { .. } => Some((Address::new(id, 3), Kind::Financial)),
        _ => None,
    }
}

pub(crate) fn route_values(value: Option<Stored>) -> Result<Vec<Address>> {
    match value {
        Some(Stored::Incoming(v) | Stored::Direct(v) | Stored::Subscribers(v)) => Ok(v),
        _ => Err(Error::new("corrupt_state", "missing reverse-route header")),
    }
}

pub(crate) fn routes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    key: &Key,
) -> Result<Vec<Address>> {
    let result = route_values(ws.get(key)?)?;
    ws.charge("route", result.len() as u64)?;
    Ok(result)
}

pub(crate) fn change_route<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    key: Key,
    member: Address,
    add: bool,
) -> Result<()> {
    let mut values = routes(ws, &key)?;
    match (add, values.binary_search(&member)) {
        (true, Err(index)) => values.insert(index, member),
        (false, Ok(index)) => {
            values.remove(index);
        }
        _ => return Err(Error::new("corrupt_state", "reverse registration mismatch")),
    }
    let value = match key {
        Key::Incoming(_) => Stored::Incoming(values),
        Key::Direct(_) => Stored::Direct(values),
        Key::Subscribers(_) => Stored::Subscribers(values),
        _ => return Err(Error::new("internal", "not a route key")),
    };
    ws.put(key, Some(value))
}

pub(crate) fn private_headers(id: Uuid, input: &Input, revision: u64) -> Vec<(Key, Stored)> {
    let mut values = vec![(Key::Incoming(id), Stored::Incoming(vec![]))];
    if let Some((root, kind)) = owned_root(id, input) {
        values.push((
            Key::Root(root),
            Stored::Root(crate::tree::Root::empty(kind, revision)),
        ));
    }
    match input {
        Input::Rule { .. } | Input::Moment { .. } => {
            values.push((Key::Direct(id), Stored::Direct(vec![])))
        }
        Input::Curve { .. } => values.push((
            Key::Subscribers(Address::new(id, 1)),
            Stored::Subscribers(vec![]),
        )),
        Input::Account { .. } => values.push((
            Key::Subscribers(Address::new(id, 2)),
            Stored::Subscribers(vec![]),
        )),
        _ => {}
    }
    values
}

pub(crate) fn registrations(id: Uuid, input: Option<&Input>) -> BTreeSet<(Key, Address)> {
    let mut entries = BTreeSet::new();
    if let Some(input) = input {
        for (target, _, field) in input.references() {
            entries.insert((Key::Incoming(target), Address::new(id, field)));
        }
        if let Input::Posting { rule, curve, .. } = input {
            entries.insert((Key::Direct(*rule), Address::new(id, 7)));
            entries.insert((
                Key::Subscribers(Address::new(*curve, 1)),
                Address::new(id, 1),
            ));
        }
        if let Input::Adjustment {
            account, moment, ..
        } = input
        {
            entries.insert((Key::Direct(*moment), Address::new(id, 6)));
            for slot in [1, 2] {
                entries.insert((
                    Key::Subscribers(Address::new(*account, 2)),
                    Address::new(id, slot),
                ));
            }
        }
        if let Input::Basis { sources, .. } = input {
            for (i, root) in sources.iter().enumerate() {
                entries.insert((
                    Key::Subscribers(Address::new(*root, 2)),
                    Address::new(id, i as u16 + 1),
                ));
            }
        }
    }
    entries
}

pub(crate) fn subscribers<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    key: Key,
    candidates: &mut BTreeSet<Uuid>,
) -> Result<()> {
    if let Some(value) = ws.original(&key)? {
        let old = route_values(Some(value))?;
        ws.charge("route", old.len() as u64)?;
        candidates.extend(old.into_iter().map(|a| a.id));
    }
    candidates.extend(routes(ws, &key)?.into_iter().map(|a| a.id));
    Ok(())
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
) -> Result<Option<(Address, i64, crate::tree::Leaf)>> {
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
            crate::tree::Leaf::Financial(amount),
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
            crate::tree::Leaf::Financial(derived.native_minor),
        )
    } else {
        (
            Address::new(subsidiary, 3),
            at,
            crate::tree::Leaf::Financial(derived.reporting_minor),
        )
    }))
}

pub(crate) fn reconcile_member<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    id: Address,
    old: Option<(Address, i64, crate::tree::Leaf)>,
    new: Option<(Address, i64, crate::tree::Leaf)>,
) -> Result<()> {
    use crate::tree;
    match (old, ws.get(&Key::Node(id))?) {
        (Some((root, at, leaf)), Some(Stored::Node(n)))
            if n.root == root && n.key.at == at && n.leaf == leaf => {}
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
        tree::insert(ws, root, id, at, leaf)?;
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
    settle_inner(ws, model, context, commands, allocate, false)
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
    settle_inner(ws, model, context, commands, allocate, true)
}

pub(crate) fn check_counts(meta: &Meta) -> Result<()> {
    if meta.counts[..11].iter().map(|n| u32::from(*n)).sum::<u32>() > 64
        || meta.counts[2] > 16
        || meta.counts[5] > 16
        || meta.counts[8] > 16
        || meta.counts[9] > 16
        || meta.counts[11] > 48
        || meta.reserved > 256
    {
        return Err(Error::new("state_limit", "bounded prototype population"));
    }
    Ok(())
}

fn settle_inner<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    model: &Model,
    context: Context,
    commands: &[Command],
    allocate: &mut dyn FnMut() -> Result<Uuid>,
    trusted: bool,
) -> Result<Settled> {
    use crate::tree::{self, Aggregate, Leaf};
    let Some(Stored::Meta(mut meta)) = ws.get(&Key::Meta)? else {
        return Err(Error::new("corrupt_state", "missing model header"));
    };
    if model.codec != native_codec::CODEC
        || meta.codec != model.codec
        || meta.model != model.identity
    {
        return Err(Error::new("model_mismatch", "store/model identity differs"));
    }
    if meta.tenant != context.tenant || meta.actor != context.actor {
        return Err(Error::new("forbidden", "fixture actor/tenant"));
    }
    if commands.is_empty()
        || commands.len() > 64
        || commands
            .iter()
            .map(Command::id)
            .collect::<BTreeSet<_>>()
            .len()
            != commands.len()
    {
        return Err(Error::new(
            "invalid_input",
            "one command per UUID; 1..64 commands",
        ));
    }
    let revision = meta
        .revision
        .checked_add(1)
        .ok_or_else(|| Error::new("revision_exhausted", "store counter exhausted"))?;
    let mut changes = vec![];
    for command in commands {
        ws.charge("command", 1)?;
        let id = command.id();
        let old = ws.record(id)?;
        if old
            .as_ref()
            .is_some_and(|r| r.contract == 12 || (r.contract == 11 && !trusted))
        {
            return Err(Error::new("forbidden", "private record"));
        }
        let new = match command {
            Command::Create {
                contract, fields, ..
            } => {
                if *contract == 12 || (*contract == 11 && !trusted) {
                    return Err(Error::new("forbidden", "private contract"));
                }
                if old.is_some() {
                    return Err(Error::new("already_exists", "source UUID exists"));
                }
                if ws.get(&Key::Reserved(id))?.is_some()
                    || ws.get(&Key::Role(Address::new(id, 1)))?.is_some()
                    || ws.get(&Key::Role(Address::new(id, 2)))?.is_some()
                {
                    return Err(Error::new("unavailable_reference", "reserved identity"));
                }
                let input = Input::bind(*contract, fields.clone())?;
                validate_references(ws, &input, context)?;
                meta.counts[usize::from(*contract - 1)] += 1;
                Some(Record {
                    contract: *contract,
                    tenant: context.tenant,
                    owner: context.actor,
                    reader: context.actor,
                    version: revision,
                    input,
                    derived: None,
                })
            }
            Command::Update { if_version, .. } | Command::Delete { if_version, .. } => {
                let previous = old
                    .as_ref()
                    .ok_or_else(|| Error::new("unavailable_reference", "source unavailable"))?;
                if previous.tenant != context.tenant || previous.owner != context.actor {
                    return Err(Error::new("forbidden", "source authority"));
                }
                if previous.version != *if_version {
                    return Err(Error::new("stale_version", "source version"));
                }
                if let Command::Update { set, unset, .. } = command {
                    if !unset.is_empty() || !set.keys().all(|key| previous.input.allows(key)) {
                        return Err(Error::new("invalid_input", "protected or required field"));
                    }
                    let mut value = serde_json::to_value(&previous.input)
                        .map_err(|e| Error::new("codec", e.to_string()))?;
                    let fields = value
                        .as_object_mut()
                        .ok_or_else(|| Error::new("internal", "input is not an object"))?;
                    fields.extend(set.clone());
                    let mut next = previous.clone();
                    next.input = Input::bind(previous.contract, value)?;
                    validate_references(ws, &next.input, context)?;
                    Some(next)
                } else {
                    meta.counts[usize::from(previous.contract - 1)] = meta.counts
                        [usize::from(previous.contract - 1)]
                    .checked_sub(1)
                    .ok_or_else(|| Error::new("corrupt_state", "source count underflow"))?;
                    None
                }
            }
        };
        ws.put(Key::Record(id), new.clone().map(Stored::Record))?;
        changes.push(Change { id, old, new });
    }
    check_counts(&meta)?;
    for change in &changes {
        if let (None, Some(new)) = (&change.old, &change.new) {
            for (key, value) in private_headers(change.id, &new.input, revision) {
                if ws.get(&key)?.is_some() {
                    return Err(Error::new(
                        "corrupt_state",
                        "orphan private header on create",
                    ));
                }
                ws.put(key, Some(value))?;
            }
        }
    }
    for change in &changes {
        let old = registrations(change.id, change.old.as_ref().map(|r| &r.input));
        let new = registrations(change.id, change.new.as_ref().map(|r| &r.input));
        for (key, member) in old.difference(&new) {
            change_route(ws, key.clone(), *member, false)?;
        }
        for (key, member) in new.difference(&old) {
            change_route(ws, key.clone(), *member, true)?;
        }
    }
    let mut candidates = BTreeSet::new();
    let mut curves = BTreeSet::new();
    for change in &changes {
        let old = change.old.as_ref().map(|r| &r.input);
        let new = change.new.as_ref().map(|r| &r.input);
        if old.is_some_and(|i| i.contract() == 6) || new.is_some_and(|i| i.contract() == 6) {
            candidates.insert(change.id);
        }
        if old != new
            && (old.is_some_and(|i| i.contract() == 1) || new.is_some_and(|i| i.contract() == 1))
        {
            subscribers(ws, Key::Direct(change.id), &mut candidates)?;
        }
        if old != new {
            for (curve, _, _) in [quote(old), quote(new)].into_iter().flatten() {
                curves.insert(curve);
            }
        }
    }
    for curve in curves {
        subscribers(
            ws,
            Key::Subscribers(Address::new(curve, 1)),
            &mut candidates,
        )?;
    }
    for change in &changes {
        let old = quote(change.old.as_ref().map(|r| &r.input));
        let new = quote(change.new.as_ref().map(|r| &r.input));
        if let Some((curve, at, _)) = old
            && new.is_none_or(|(c, t, _)| (c, t) != (curve, at))
        {
            tree::remove(ws, Address::new(curve, 1), Address::new(change.id, 3))?;
        }
    }
    for change in &changes {
        let old = quote(change.old.as_ref().map(|r| &r.input));
        if let Some((curve, at, rate)) = quote(change.new.as_ref().map(|r| &r.input)) {
            let root = Address::new(curve, 1);
            let node = Address::new(change.id, 3);
            if old.is_some_and(|(c, t, _)| (c, t) == (curve, at)) {
                tree::revalue(ws, root, node, Leaf::Quote(rate))?;
            } else {
                tree::insert(ws, root, node, at, Leaf::Quote(rate))?;
            }
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
            record.derived = Some(Calculated::Posting(model.calculate(units, c, rate)?));
            ws.work.evaluations += 1;
            ws.put(Key::Record(id), Some(Stored::Record(record.clone())))?;
            ws.put(
                Key::Query(Address::new(id, 1)),
                Some(Stored::Query(Query {
                    source: Address::new(curve, 1),
                    operation: "latest".into(),
                    phase: "calculate".into(),
                    channel: "rate".into(),
                    lower: "negative_infinity".into(),
                    upper: Bound::AfterTime(at),
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
    for change in &changes {
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
    crate::causal::settle(ws, context, &changes, &mut meta, revision, allocate)?;
    check_counts(&meta)?;
    for change in &changes {
        if let Some(new) = &change.new {
            validate_references(ws, &new.input, context)?;
        } else if !routes(ws, &Key::Incoming(change.id))?.is_empty() {
            return Err(Error::new(
                "unavailable_reference",
                "surviving inbound reference",
            ));
        }
    }
    for change in &changes {
        if change.new.is_none() {
            for (key, _) in private_headers(
                change.id,
                &change.old.as_ref().expect("deleted source").input,
                revision,
            ) {
                match &key {
                    Key::Root(id) => {
                        if tree::root(ws, *id)?.head.is_some() {
                            return Err(Error::new("corrupt_state", "nonempty retired root"));
                        }
                    }
                    _ => {
                        if !routes(ws, &key)?.is_empty() {
                            return Err(Error::new("corrupt_state", "nonempty retired route"));
                        }
                    }
                }
                ws.put(key, None)?;
            }
        }
    }
    let changed_roots = ws.changed_roots();
    for id in changed_roots {
        if let Some(Stored::Root(mut root)) = ws.get(&Key::Root(id))? {
            if id.slot == 2 {
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
            root.revision = revision;
            ws.put(Key::Root(id), Some(Stored::Root(root)))?;
        }
    }
    let record_keys: Vec<_> = ws
        .entries
        .keys()
        .filter(|k| matches!(k, Key::Record(_)))
        .cloned()
        .collect();
    for key in record_keys {
        if let Some(Stored::Record(mut current)) = ws.get(&key)? {
            let version = if let Some(Stored::Record(old)) = ws.original(&key)? {
                current.version = old.version;
                if current == old {
                    old.version
                } else {
                    revision
                }
            } else {
                revision
            };
            current.version = version;
            ws.put(key, Some(Stored::Record(current)))?;
        }
    }
    meta.revision = revision;
    ws.put(Key::Meta, Some(Stored::Meta(meta)))?;
    Ok(Settled { revision })
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
        let value = Stored::Incoming(vec![]);
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
