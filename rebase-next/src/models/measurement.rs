//! Authored observations and reports using the common native tree and scheduler.
use crate::{
    binding::{Binding, Limits, NativeInput},
    causal::{PublicationValue, ReactiveBinding, Read, Resolved, ResolvedShape},
    index::{IndexCode, TimeKey},
    indexes::measurement::{
        Dimension, MAX_COUNT, MAX_VALUE, Observation, STATISTICS, Statistics, Summary, unit_schema,
        value_schema,
    },
    local::Store,
    model::{
        self, Calculation, Contract, InputField, Membership, Prepared, PublishedField,
        QueryDeclaration, Reference, RootDeclaration, Visibility,
    },
    native_codec::{Address, Key, decimal, optional_decimal, uuid_text},
    native_slice::{Attempt, Context, Error, Meta, Model, ModelChange, ModelRecord, Query, Result},
    time_range::{TimeBound, TimeRange},
    tree,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Measurement;
pub const REPORT: u16 = 307;
pub const REPORT_QUERY: u16 = 31;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Input {
    Instrument {
        unit: u16,
    },
    Observation {
        #[serde(with = "uuid_text")]
        instrument: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        unit: u16,
        #[serde(with = "decimal")]
        value: i128,
    },
    ObservationReport {
        #[serde(with = "uuid_text")]
        instrument: Uuid,
        range: TimeRange,
        unit: u16,
        #[serde(with = "decimal")]
        threshold: i128,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Derived {
    pub count: u64,
    #[serde(with = "optional_decimal")]
    pub min: Option<i128>,
    #[serde(with = "optional_decimal")]
    pub max: Option<i128>,
    pub unit: u16,
    pub at_least_threshold: bool,
}
fn invalid(detail: &str) -> Error {
    Error::new("invalid_input", detail)
}
impl NativeInput for Input {
    fn contract(&self) -> u16 {
        match self {
            Self::Instrument { .. } => 101,
            Self::Observation { .. } => 211,
            Self::ObservationReport { .. } => REPORT,
        }
    }
    fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::Instrument { unit } => *unit > 0,
            Self::Observation { unit, value, .. }
            | Self::ObservationReport {
                unit,
                threshold: value,
                ..
            } => *unit > 0 && (-MAX_VALUE..=MAX_VALUE).contains(value),
        };
        if valid {
            Ok(())
        } else {
            Err(invalid("measurement unit/value outside declared bounds"))
        }
    }
    fn bind(code: u16, fields: Value) -> Result<Self> {
        let input: Self =
            serde_json::from_value(fields.clone()).map_err(|e| invalid(&e.to_string()))?;
        input.validate()?;
        if input.contract() != code
            || serde_json::to_value(&input).map_err(|e| invalid(&e.to_string()))? != fields
        {
            return Err(invalid("complete canonical measurement input required"));
        }
        Ok(input)
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        match self {
            Self::Observation { instrument, .. } | Self::ObservationReport { instrument, .. } => {
                vec![(*instrument, 101, 1)]
            }
            _ => vec![],
        }
    }
}
fn declarations() -> Result<Vec<Contract>> {
    let uuid = json!({"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","x-rebase-binding":"uuid"});
    let fields = [
        (
            101,
            "Instrument",
            json!({"unit":unit_schema()}),
            vec![(1, "unit")],
        ),
        (
            211,
            "Observation",
            json!({"instrument":uuid,"at":crate::indexes::standard::time_schema(),"unit":unit_schema(),"value":value_schema()}),
            vec![(1, "instrument"), (2, "at"), (3, "unit"), (4, "value")],
        ),
        (
            REPORT,
            "ObservationReport",
            json!({"instrument":uuid,"range":TimeRange::schema(),"unit":unit_schema(),"threshold":value_schema()}),
            vec![
                (1, "instrument"),
                (2, "range"),
                (3, "unit"),
                (4, "threshold"),
            ],
        ),
    ];
    let mut contracts = vec![];
    for (code, name, properties, fields) in fields {
        let names: Vec<_> = properties
            .as_object()
            .expect("authored fields")
            .keys()
            .collect();
        let mut c = Contract {
            code,
            name,
            visibility: Visibility::Public,
            schema: json!({"$schema":model::SCHEMA_DIALECT,"type":"object","additionalProperties":false,"required":names,"properties":properties}),
            fields: fields
                .into_iter()
                .map(|(code, name)| InputField {
                    code,
                    name,
                    mutable: true,
                })
                .collect(),
            published: vec![],
            references: vec![],
            roots: vec![],
            memberships: vec![],
            queries: vec![],
            publication_inputs: vec![],
            outputs: vec![],
            calculations: vec![],
            calculation_order: vec![],
            rules: vec![],
            schema_source: "src/models/measurement.rs",
            behavior_source: "src/models/measurement.rs",
        };
        if code == 101 {
            c.roots.push(RootDeclaration {
                slot: 7,
                name: "observations",
                kind: STATISTICS,
                reads: vec!["summary", "before", "range"],
                invariant: Some("uniform observation unit equals instrument unit"),
            });
        } else {
            c.references.push(Reference {
                slot: 1,
                field: "instrument",
                targets: vec![101],
                optional: false,
                direct_fields: if code == REPORT { vec!["unit"] } else { vec![] },
                on_delete: "reject",
                reader: true,
            });
            if code == 211 {
                c.memberships.push(Membership {
                    slot: 17,
                    through: "instrument",
                    root_contract: 101,
                    root_slot: 7,
                    kind: STATISTICS,
                    key: "at",
                    value: "unit,value",
                });
            } else {
                c.queries.push(QueryDeclaration {
                    slot: REPORT_QUERY,
                    through: "instrument",
                    root_contract: 101,
                    root_slot: 7,
                    operation: "summary",
                    phase: "calculate",
                    channel: "statistics",
                    bound: "range",
                    fallback: None,
                });
                c.published = [
                    (11, "count", "u64"),
                    (12, "min", "option<i128>"),
                    (13, "max", "option<i128>"),
                    (14, "unit", "u16"),
                    (15, "at_least_threshold", "bool"),
                ]
                .into_iter()
                .map(|(code, name, binding)| PublishedField {
                    code,
                    name,
                    binding,
                })
                .collect();
                c.calculations.push(Calculation {
                    name: "report",
                    inputs: vec![],
                    expression: "typed query[31] count/extrema; nonempty minimum >= threshold in instrument unit",
                });
                c.rules
                    .push("report unit equals instrument unit; empty window threshold is false");
            }
        }
        contracts.push(c);
    }
    Ok(contracts)
}
fn member(input: Option<&Input>) -> Option<(Address, TimeKey, Observation)> {
    match input {
        Some(Input::Observation {
            instrument,
            at,
            unit,
            value,
        }) => Some((
            Address::new(*instrument, 7),
            TimeKey::new(*at),
            Observation {
                unit: *unit,
                value: *value,
            },
        )),
        _ => None,
    }
}
fn registrations(id: Uuid, input: Option<&Input>) -> BTreeSet<(Key, Address)> {
    let mut registrations: BTreeSet<_> = input
        .into_iter()
        .flat_map(NativeInput::references)
        .map(|(target, _, slot)| (Key::Incoming(target), Address::new(id, slot)))
        .collect();
    if let Some(Input::ObservationReport { instrument, .. }) = input {
        registrations.insert((Key::Direct(*instrument), Address::new(id, 1)));
    }
    registrations
}
impl Binding for Measurement {
    type Input = Input;
    type Derived = Derived;
    type Outcome = ();
    type Index = Statistics;
    const NAME: &'static str = "dimensioned-measurements";
    const BEHAVIOR: &'static str = "dimensioned-measurements-2";
    fn declarations() -> Result<Vec<Contract>> {
        declarations()
    }
    fn engine() -> Result<Model> {
        Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
    }
    fn limits() -> Limits {
        Limits {
            public_records: 64,
            outputs: 0,
            reservations: 0,
            per_contract: BTreeMap::new(),
        }
    }
    fn valid_derived(input: &Input, derived: Option<&Derived>) -> bool {
        let Input::ObservationReport {
            unit, threshold, ..
        } = input
        else {
            return derived.is_none();
        };
        let Some(value) = derived else { return false };
        value.unit == *unit
            && value.count <= MAX_COUNT
            && if value.count == 0 {
                value.min.is_none() && value.max.is_none() && !value.at_least_threshold
            } else {
                matches!((value.min, value.max), (Some(min), Some(max))
                    if -MAX_VALUE <= min && min <= max && max <= MAX_VALUE
                    && (value.count != 1 || min == max)
                    && value.at_least_threshold == (min >= *threshold))
            }
    }
    fn published_shape(code: u16) -> Value {
        if code == REPORT {
            json!({"count":0,"min":null,"max":null,"unit":1,"at_least_threshold":false})
        } else {
            Value::Null
        }
    }
    fn settle_changes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        model: &Prepared<Self>,
        context: Context,
        changes: &[ModelChange<Self>],
        meta: &mut Meta,
        revision: u64,
        allocate: &mut dyn FnMut() -> Result<Uuid>,
    ) -> Result<()> {
        let mut roots = BTreeSet::new();
        let mut memberships = vec![];
        for change in changes {
            let old = change.old.as_ref().map(|r| &r.input);
            let new = change.new.as_ref().map(|r| &r.input);
            let before = registrations(change.id, old);
            let after = registrations(change.id, new);
            for (key, address) in before.difference(&after) {
                crate::routes::change(ws, key, *address, crate::time_range::TimeRange::ALL, false)?;
            }
            for (key, address) in after.difference(&before) {
                crate::routes::change(ws, key, *address, crate::time_range::TimeRange::ALL, true)?;
            }
            for (root, _, _) in member(old).into_iter().chain(member(new)) {
                roots.insert(root);
            }
            if matches!(old, Some(Input::Instrument { .. }))
                || matches!(new, Some(Input::Instrument { .. }))
            {
                roots.insert(Address::new(change.id, 7));
            }
            let (before, after) = (member(old), member(new));
            if before != after {
                memberships.push((Address::new(change.id, 17), before, after));
            }
        }
        // A valid replacement batch can create sources before deleting old
        // ones. Remove all changed memberships first so internal summaries
        // never exceed the admitted final population merely from command order.
        for &(id, before, _) in &memberships {
            crate::mutation::reconcile_member(ws, id, before, None)?;
        }
        for (id, _, after) in memberships {
            crate::mutation::reconcile_member(ws, id, None, after)?;
        }
        // Mixed dimensions may occur during the batch. Enforce only final roots,
        // including owners whose unit changed without a membership change.
        for address in roots {
            let Some(record) = ws.record(address.id)? else {
                continue;
            };
            let Input::Instrument { unit } = record.input else {
                return Err(Error::new("corrupt_state", "measurement root owner"));
            };
            let root = tree::root(ws, address)?;
            if root.summary.dimension != Dimension::Empty
                && root.summary.dimension != (Dimension::Unit { code: unit })
            {
                return Err(Error::new(
                    "invariant",
                    "observation units must equal the instrument unit",
                ));
            }
        }
        crate::causal::settle(ws, model, context, changes, meta, revision, allocate)
    }
    fn check(store: &Store<Self>) -> Result<Value> {
        check(store)
    }
    fn fixture_catalog() -> Value {
        json!([
            {"name":"measurements","description":"Signed equal-time unit-7 observations and an empty instrument"},
            {"name":"observation-report","description":"Typed count/extrema/threshold over authored observations in [0,20)"}
        ])
    }
    fn fixture_plan(model: &Prepared<Self>, name: &str, namespace: Uuid) -> Result<Value> {
        if name == "observation-report" {
            return report_fixture(model, namespace);
        }
        if name != "measurements" {
            return Err(invalid("unknown measurement fixture"));
        }
        let ids: BTreeMap<_, _> = ["instrument", "other", "a", "b", "c"]
            .into_iter()
            .map(|name| {
                (
                    name,
                    Uuid::new_v5(&namespace, format!("measurements/{name}").as_bytes()),
                )
            })
            .collect();
        let commands = json!([
            {"op":"create","id":ids["instrument"],"contract":101,"fields":{"unit":7}},
            {"op":"create","id":ids["other"],"contract":101,"fields":{"unit":7}},
            {"op":"create","id":ids["a"],"contract":211,"fields":{"instrument":ids["instrument"],"at":"0","unit":7,"value":"5"}},
            {"op":"create","id":ids["b"],"contract":211,"fields":{"instrument":ids["instrument"],"at":"10","unit":7,"value":"-2"}},
            {"op":"create","id":ids["c"],"contract":211,"fields":{"instrument":ids["instrument"],"at":"10","unit":7,"value":"9"}},
        ]);
        for command in commands.as_array().expect("fixture array") {
            model.validate(
                command["contract"].as_u64().expect("fixture code") as u16,
                &command["fields"],
            )?;
        }
        Ok(
            json!({"model":model.identity(),"fixture":{"name":name,"namespace":namespace,"ids":ids,"expected":{"count":3,"sum":"12","min":"-2","max":"9","unit":7}},"commands":commands,"returning":[]}),
        )
    }
}

impl ReactiveBinding for Measurement {
    type Parameters = (u16, i128);
    type Publication = ();

    fn resolve<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        context: Context,
        _id: Uuid,
        record: &ModelRecord<Self>,
    ) -> Result<Resolved<Self::Parameters>> {
        let Input::ObservationReport {
            instrument,
            range,
            unit,
            threshold,
        } = record.input
        else {
            return Err(Error::new("model", "unsupported measurement calculator"));
        };
        ws.charge("dependency", 1)?;
        let parent = ws
            .record(instrument)?
            .ok_or_else(|| Error::new("unavailable_reference", "report instrument missing"))?;
        if parent.tenant != context.tenant || !matches!(parent.input, Input::Instrument { .. }) {
            return Err(Error::new(
                "unavailable_reference",
                "report instrument type or tenant",
            ));
        }
        if parent.input != (Input::Instrument { unit }) {
            return Err(Error::new(
                "invariant",
                "report unit must equal the instrument unit",
            ));
        }
        Ok(Resolved {
            shape: ResolvedShape {
                reads: vec![Read {
                    slot: REPORT_QUERY,
                    root: Address::new(instrument, 7),
                    range,
                    validate: false,
                }],
                ..Default::default()
            },
            parameters: (unit, threshold),
        })
    }

    fn evaluate(
        _id: Uuid,
        _record: &ModelRecord<Self>,
        _shape: &ResolvedShape,
        &(unit, threshold): &Self::Parameters,
        _publications: &[PublicationValue<Self::Publication>],
        values: &[Summary],
    ) -> Result<(Derived, BTreeMap<u16, i128>)> {
        let [summary] = values else {
            return Err(Error::new("model", "report requires one statistics result"));
        };
        if summary.dimension != Dimension::Empty
            && summary.dimension != (Dimension::Unit { code: unit })
        {
            return Err(Error::new("invariant", "report observation dimensions"));
        }
        Ok((
            Derived {
                count: summary.count,
                min: summary.min,
                max: summary.max,
                unit,
                at_least_threshold: summary.min.is_some_and(|min| min >= threshold),
            },
            BTreeMap::new(),
        ))
    }
}

fn report_fixture(model: &Prepared<Measurement>, namespace: Uuid) -> Result<Value> {
    let ids: BTreeMap<_, _> = ["instrument", "other", "a", "b", "c", "report"]
        .into_iter()
        .map(|name| {
            (
                name,
                Uuid::new_v5(&namespace, format!("observation-report/{name}").as_bytes()),
            )
        })
        .collect();
    let commands = json!([
        {"op":"create","id":ids["instrument"],"contract":101,"fields":{"unit":7}},
        {"op":"create","id":ids["other"],"contract":101,"fields":{"unit":7}},
        {"op":"create","id":ids["a"],"contract":211,"fields":{"instrument":ids["instrument"],"at":"0","unit":7,"value":"5"}},
        {"op":"create","id":ids["b"],"contract":211,"fields":{"instrument":ids["instrument"],"at":"10","unit":7,"value":"12"}},
        {"op":"create","id":ids["c"],"contract":211,"fields":{"instrument":ids["instrument"],"at":"20","unit":7,"value":"-2"}},
        {"op":"create","id":ids["report"],"contract":REPORT,"fields":{"instrument":ids["instrument"],"range":{"lower":{"included":"0"},"upper":{"excluded":"20"}},"unit":7,"threshold":"5"}}
    ]);
    for command in commands.as_array().expect("fixture commands") {
        model.validate(
            command["contract"].as_u64().expect("fixture code") as u16,
            &command["fields"],
        )?;
    }
    Ok(
        json!({"model":model.identity(),"fixture":{"name":"observation-report","namespace":namespace,"ids":ids,
        "expected":{"count":2,"min":"5","max":"12","unit":7,"at_least_threshold":true}},
        "commands":commands,"returning":[ids["report"]]}),
    )
}

// A literal source scan, independent of singleton/combine and tree traversal.
fn source_summary(code: IndexCode, leaves: &[(TimeKey, Observation)]) -> Result<Summary> {
    use crate::integrity::require;
    require(code == STATISTICS, "measurement source index code")?;
    let mut units = BTreeSet::new();
    let mut sum = 0i128;
    let mut min = None;
    let mut max = None;
    for (_, leaf) in leaves {
        units.insert(leaf.unit);
        sum = sum
            .checked_add(leaf.value)
            .ok_or_else(|| Error::new("corrupt_state", "measurement source overflow"))?;
        min = Some(min.map_or(leaf.value, |v: i128| v.min(leaf.value)));
        max = Some(max.map_or(leaf.value, |v: i128| v.max(leaf.value)));
    }
    let dimension = match units.len() {
        0 => Dimension::Empty,
        1 => Dimension::Unit {
            code: *units.first().expect("one unit"),
        },
        _ => Dimension::Mixed,
    };
    Ok(Summary {
        count: leaves.len() as u64,
        sum,
        min,
        max,
        dimension,
    })
}
fn check(store: &Store<Measurement>) -> Result<Value> {
    use crate::integrity::{Snapshot, require};
    let snapshot = Snapshot::load(store)?;
    let mut members = BTreeMap::new();
    let mut routes = snapshot.routes.clone();
    let mut queries = BTreeMap::new();
    for (&id, record) in &snapshot.records {
        if !matches!(record.input, Input::ObservationReport { .. }) {
            require(
                record.derived.is_none(),
                "nonreport measurement has derived fields",
            )?;
        }
        if let Input::Observation {
            instrument,
            at,
            unit,
            value,
        } = record.input
        {
            let Some(owner) = snapshot.records.get(&instrument) else {
                return Err(Error::new("corrupt_state", "missing measurement owner"));
            };
            require(
                matches!(owner.input,Input::Instrument {unit:owner_unit} if owner_unit == unit),
                "source observation dimension differs from instrument",
            )?;
            members.insert(
                Address::new(id, 17),
                (
                    Address::new(instrument, 7),
                    TimeKey::new(at),
                    Observation { unit, value },
                ),
            );
        }
    }
    for (&id, record) in &snapshot.records {
        if let Input::ObservationReport {
            instrument,
            range,
            unit,
            threshold,
        } = record.input
        {
            require(
                snapshot
                    .records
                    .get(&instrument)
                    .is_some_and(|parent| parent.input == (Input::Instrument { unit })),
                "source report dimension differs from instrument",
            )?;
            // Literal authored membership scan; no writer range predicate,
            // maintained summary, evaluator or cached query supplies expectations.
            let leaves: Vec<_> = members
                .values()
                .filter_map(|(root, key, leaf)| {
                    let lower = match range.lower {
                        TimeBound::Unbounded => true,
                        TimeBound::Included(at) => key.get() >= at,
                        TimeBound::Excluded(at) => key.get() > at,
                    };
                    let upper = match range.upper {
                        TimeBound::Unbounded => true,
                        TimeBound::Included(at) => key.get() <= at,
                        TimeBound::Excluded(at) => key.get() < at,
                    };
                    (root.id == instrument && lower && upper).then_some((*key, *leaf))
                })
                .collect();
            let summary = source_summary(STATISTICS, &leaves)?;
            let expected = Derived {
                count: leaves.len() as u64,
                min: leaves.iter().map(|(_, leaf)| leaf.value).min(),
                max: leaves.iter().map(|(_, leaf)| leaf.value).max(),
                unit,
                at_least_threshold: !leaves.is_empty()
                    && leaves.iter().all(|(_, leaf)| leaf.value >= threshold),
            };
            require(
                record.derived.as_ref() == Some(&expected),
                "source-derived observation report",
            )?;
            routes
                .entry(Key::Direct(instrument))
                .or_default()
                .insert(Address::new(id, 1));
            let root = Address::new(instrument, 7);
            let address = Address::new(id, REPORT_QUERY);
            routes
                .entry(Key::Subscribers(root))
                .or_default()
                .insert(address);
            queries.insert(
                address,
                Query::<Statistics> {
                    source: root,
                    operation: "summary".into(),
                    phase: "calculate".into(),
                    channel: "statistics".into(),
                    range,
                    selected: None,
                    result: summary,
                },
            );
        }
    }
    snapshot.finish_native(
        snapshot.expected_keys.clone(),
        members,
        routes,
        queries,
        &source_summary,
    )
}
