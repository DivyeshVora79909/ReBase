//! Bounded equipment reservations, implemented as an ordinary compiled model.
use crate::{
    binding::{Binding, NativeInput},
    causal::{Emit, ReactiveBinding, Read, Resolved, ResolvedShape},
    local::Store,
    model::{
        self, Contract, InputField, Membership, OutputRole, Prepared, PublishedField,
        QueryDeclaration, Reference, RootDeclaration, Visibility,
    },
    native_codec::{Address, Key, StoredValue, decimal, uuid_text},
    native_slice::{Attempt, Context, Error, Meta, Model, ModelChange, ModelRecord, Result},
    tree::{self, Aggregate, Kind, Leaf},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Equipment;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Input {
    Pool {
        unit: u16,
    },
    Delivery {
        #[serde(with = "uuid_text")]
        pool: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        quantity: i128,
    },
    Reservation {
        #[serde(with = "uuid_text")]
        pool: Uuid,
        #[serde(with = "decimal")]
        starts: i64,
        #[serde(with = "decimal")]
        ends: i64,
        #[serde(with = "decimal")]
        requested: i128,
        active: bool,
    },
    Output {
        #[serde(with = "uuid_text")]
        producer: Uuid,
        role: u16,
        #[serde(with = "uuid_text")]
        pool: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        quantity: i128,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Derived {
    #[serde(with = "decimal")]
    pub available_before: i128,
    #[serde(with = "decimal")]
    pub allocated: i128,
}
fn invalid(detail: &str) -> Error {
    Error::new("invalid_input", detail)
}
impl NativeInput for Input {
    fn contract(&self) -> u16 {
        match self {
            Self::Pool { .. } => 101,
            Self::Delivery { .. } => 205,
            Self::Reservation { .. } => 410,
            Self::Output { .. } => 900,
        }
    }
    fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::Pool { unit } => *unit > 0,
            Self::Delivery { quantity, .. } => (0..=1_000_000).contains(quantity),
            Self::Reservation {
                starts,
                ends,
                requested,
                ..
            } => starts < ends && (0..=1_000_000).contains(requested),
            Self::Output { role, quantity, .. } => {
                [11, 29].contains(role) && (-1_000_000..=1_000_000).contains(quantity)
            }
        };
        if valid {
            Ok(())
        } else {
            Err(invalid("equipment value outside declared bounds"))
        }
    }
    fn bind(code: u16, fields: Value) -> Result<Self> {
        let input: Self = serde_json::from_value(fields.clone())
            .map_err(|e| Error::new("invalid_input", e.to_string()))?;
        input.validate()?;
        if input.contract() != code
            || serde_json::to_value(&input).map_err(|e| Error::new("codec", e.to_string()))?
                != fields
        {
            return Err(invalid("complete canonical equipment input required"));
        }
        Ok(input)
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        match self {
            Self::Delivery { pool, .. } | Self::Reservation { pool, .. } => vec![(*pool, 101, 1)],
            Self::Output { producer, pool, .. } => vec![(*producer, 410, 1), (*pool, 101, 2)],
            _ => vec![],
        }
    }
    fn managed(&self) -> Option<(Uuid, u16)> {
        match self {
            Self::Output { producer, role, .. } => Some((*producer, *role)),
            _ => None,
        }
    }
}
fn reference(slot: u16, field: &'static str, target: u16) -> Reference {
    Reference {
        slot,
        field,
        targets: vec![target],
        optional: false,
        direct_fields: vec![],
        on_delete: "reject",
        reader: field == "pool",
    }
}
fn decimal_schema(nonnegative: bool) -> Value {
    json!({"type":"string","pattern":if nonnegative{"^(0|[1-9][0-9]*)$"}else{"^(0|-?[1-9][0-9]*)$"},"x-rebase-range":if nonnegative{json!(["0","1000000"])}else{json!(["-1000000","1000000"])}})
}
fn time_schema() -> Value {
    json!({"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","x-rebase-range":[i64::MIN.to_string(),i64::MAX.to_string()]})
}
fn declarations() -> Result<Vec<Contract>> {
    let uuid = json!({"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","x-rebase-binding":"uuid"});
    let mut contracts = vec![];
    for (code, name, fields) in [
        (
            101,
            "Pool",
            json!({"unit":{"type":"integer","minimum":1,"maximum":65535,"x-rebase-binding":"u16_code"}}),
        ),
        (
            205,
            "Delivery",
            json!({"pool":uuid,"at":time_schema(),"quantity":decimal_schema(true)}),
        ),
        (
            410,
            "Reservation",
            json!({"pool":uuid,"starts":time_schema(),"ends":time_schema(),"requested":decimal_schema(true),"active":{"type":"boolean"}}),
        ),
        (
            900,
            "EquipmentOutput",
            json!({"producer":uuid,"role":{"type":"integer","enum":[11,29]},"pool":uuid,"at":time_schema(),"quantity":decimal_schema(false)}),
        ),
    ] {
        let properties = fields.as_object().unwrap();
        let names: Vec<_> = properties.keys().map(String::as_str).collect();
        // Authored field identifiers are stable and independent of sparse contract codes.
        let field_codes: &[(u16, &'static str)] = match code {
            101 => &[(1, "unit")],
            205 => &[(1, "pool"), (2, "at"), (3, "quantity")],
            410 => &[
                (1, "pool"),
                (2, "starts"),
                (3, "ends"),
                (4, "requested"),
                (5, "active"),
            ],
            900 => &[
                (1, "producer"),
                (2, "role"),
                (3, "pool"),
                (4, "at"),
                (5, "quantity"),
            ],
            _ => unreachable!(),
        };
        let authored = field_codes
            .iter()
            .map(|&(field_code, name)| InputField {
                code: field_code,
                name,
                mutable: code == 205 || code == 410,
            })
            .collect();
        let mut c = Contract {
            code,
            name,
            visibility: if code == 900 {
                Visibility::Engine
            } else {
                Visibility::Public
            },
            schema: json!({"$schema":model::SCHEMA_DIALECT,"type":"object","additionalProperties":false,"required":names,"properties":fields}),
            fields: authored,
            published: vec![],
            references: vec![],
            roots: vec![],
            memberships: vec![],
            queries: vec![],
            outputs: vec![],
            calculations: vec![],
            calculation_order: vec![],
            rules: vec![],
            schema_source: "src/models/equipment.rs",
            behavior_source: "src/models/equipment.rs",
        };
        if code == 101 {
            c.roots.push(RootDeclaration {
                slot: 7,
                name: "availability",
                kind: Kind::Financial,
                reads: vec!["summary", "before", "range"],
                invariant: Some("nonnegative complete-time prefixes"),
            });
        }
        if code == 205 || code == 410 {
            c.references.push(reference(1, "pool", 101));
        }
        if code == 205 || code == 900 {
            c.memberships.push(Membership {
                slot: if code == 205 { 17 } else { 23 },
                through: "pool",
                root_contract: 101,
                root_slot: 7,
                kind: Kind::Financial,
                key: "at",
                value: "quantity",
            });
        }
        if code == 410 {
            c.published = vec![
                PublishedField {
                    code: 101,
                    name: "available_before",
                    binding: "i128",
                },
                PublishedField {
                    code: 102,
                    name: "allocated",
                    binding: "i128",
                },
            ];
            c.queries.push(QueryDeclaration {
                slot: 31,
                through: "pool",
                root_contract: 101,
                root_slot: 7,
                operation: "sum",
                phase: "calculate",
                channel: "amount",
                bound: "strictly before starts",
                fallback: Some("0"),
            });
            for (role, at, amount) in [(11, "starts", "-allocated"), (29, "ends", "allocated")] {
                c.outputs.push(OutputRole {
                    role,
                    contract: 900,
                    active: "active",
                    account: "pool",
                    at,
                    amount,
                    depends_on: vec!["allocated"],
                });
            }
            c.calculations.push(model::Calculation {
                name: "allocated",
                inputs: vec![],
                expression: "min(requested,max(0,query[31]))",
            });
            c.rules = vec![
                "starts < ends; inactive has no query or output; simultaneous starts use complete-time prefix and final invariant",
            ]
        }
        if code == 900 {
            c.references = vec![reference(1, "producer", 410), reference(2, "pool", 101)];
        }
        contracts.push(c);
    }
    Ok(contracts)
}
fn registrations(id: Uuid, input: Option<&Input>) -> BTreeSet<(Key, Address)> {
    let mut set = BTreeSet::new();
    if let Some(input) = input {
        for (target, _, slot) in input.references() {
            set.insert((Key::Incoming(target), Address::new(id, slot)));
        }
    }
    set
}
fn delivery(input: Option<&Input>) -> Option<(Address, i64, Leaf)> {
    match input {
        Some(Input::Delivery { pool, at, quantity }) => {
            Some((Address::new(*pool, 7), *at, Leaf::Financial(*quantity)))
        }
        _ => None,
    }
}
impl Binding for Equipment {
    type Input = Input;
    type Derived = Derived;
    const NAME: &'static str = "equipment-reservations";
    const BEHAVIOR: &'static str = "equipment-reservations-4";
    fn declarations() -> Result<Vec<Contract>> {
        declarations()
    }
    fn engine() -> Result<Model> {
        Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
    }
    fn valid_derived(input: &Input, derived: Option<&Derived>) -> bool {
        matches!((input, derived), (Input::Reservation { .. }, Some(_)))
            || (!matches!(input, Input::Reservation { .. }) && derived.is_none())
    }
    fn published_shape(code: u16) -> Value {
        if code == 410 {
            json!({"available_before":"0","allocated":"0"})
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
        for change in changes {
            let old = registrations(change.id, change.old.as_ref().map(|r| &r.input));
            let new = registrations(change.id, change.new.as_ref().map(|r| &r.input));
            for (k, a) in old.difference(&new) {
                crate::routes::change(ws, k, *a, crate::time_range::TimeRange::ALL, false)?
            }
            for (k, a) in new.difference(&old) {
                crate::routes::change(ws, k, *a, crate::time_range::TimeRange::ALL, true)?
            }
            crate::mutation::reconcile_member(
                ws,
                Address::new(change.id, 17),
                delivery(change.old.as_ref().map(|r| &r.input)),
                delivery(change.new.as_ref().map(|r| &r.input)),
            )?;
        }
        crate::causal::settle(ws, model, context, changes, meta, revision, allocate)?;
        for address in ws.changed_roots() {
            if address.slot == 7 {
                let root = tree::root(ws, address)?;
                if let Aggregate::Financial(s) = root.summary
                    && (s.sum < 0 || s.boundary_min.is_some_and(|v| v < 0))
                {
                    return Err(Error::new(
                        "invariant",
                        "negative complete-time equipment availability",
                    ));
                }
            }
        }
        Ok(())
    }
    fn check(store: &Store<Self>) -> Result<Value> {
        check(store)
    }
    fn fixture_catalog() -> Value {
        json!([{"name":"equipment","description":"10 units, two clipped interval reservations"}])
    }
    fn fixture_plan(model: &Prepared<Self>, name: &str, namespace: Uuid) -> Result<Value> {
        if name != "equipment" {
            return Err(invalid("unknown equipment fixture"));
        }
        let ids: BTreeMap<_, _> = [("pool", 1u128), ("delivery", 2), ("a", 3), ("b", 4)]
            .into_iter()
            .map(|(n, i)| {
                (
                    n,
                    Uuid::new_v5(&namespace, format!("equipment/{n}/{i}").as_bytes()),
                )
            })
            .collect();
        let commands = json!([{"op":"create","id":ids["pool"],"contract":101,"fields":{"unit":1}},{"op":"create","id":ids["delivery"],"contract":205,"fields":{"pool":ids["pool"],"at":"0","quantity":"10"}},{"op":"create","id":ids["a"],"contract":410,"fields":{"pool":ids["pool"],"starts":"10","ends":"30","requested":"8","active":true}},{"op":"create","id":ids["b"],"contract":410,"fields":{"pool":ids["pool"],"starts":"20","ends":"40","requested":"7","active":true}}]);
        for command in commands.as_array().expect("authored commands") {
            model.validate(
                command["contract"].as_u64().expect("authored contract") as u16,
                &command["fields"],
            )?;
        }
        Ok(
            json!({"model":model.identity(),"fixture":{"name":"equipment","namespace":namespace,"ids":ids,"expected":{"a":"8","b":"2"}},"commands":commands,"returning":[ids["a"],ids["b"]]}),
        )
    }
}
impl ReactiveBinding for Equipment {
    type Parameters = ();
    fn resolve<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        _ws: &mut Attempt<L, Self>,
        _context: Context,
        _id: Uuid,
        record: &ModelRecord<Self>,
    ) -> Result<Resolved<Self::Parameters>> {
        let Input::Reservation {
            pool,
            starts,
            ends,
            active,
            ..
        } = record.input
        else {
            return Err(Error::new("corrupt_state", "equipment subscriber contract"));
        };
        if !active {
            return Ok(Resolved {
                shape: ResolvedShape::default(),
                parameters: (),
            });
        }
        Ok(Resolved {
            shape: ResolvedShape {
                reads: vec![Read {
                    slot: 31,
                    root: Address::new(pool, 7),
                    range: crate::time_range::TimeRange::before(starts),
                    validate: false,
                }],
                emits: vec![
                    Emit {
                        role: 11,
                        contract: 900,
                        root: Address::new(pool, 7),
                        at: starts,
                    },
                    Emit {
                        role: 29,
                        contract: 900,
                        root: Address::new(pool, 7),
                        at: ends,
                    },
                ],
            },
            parameters: (),
        })
    }
    fn evaluate(
        _id: Uuid,
        record: &ModelRecord<Self>,
        _shape: &ResolvedShape,
        _parameters: &Self::Parameters,
        values: &[i128],
    ) -> Result<(Derived, BTreeMap<u16, i128>)> {
        let Input::Reservation {
            requested, active, ..
        } = record.input
        else {
            return Err(Error::new("corrupt_state", "equipment evaluation contract"));
        };
        let before = if active {
            *values
                .first()
                .ok_or_else(|| Error::new("internal", "missing availability"))?
        } else {
            0
        };
        let allocated = if active {
            requested.min(before.max(0))
        } else {
            0
        };
        Ok((
            Derived {
                available_before: before,
                allocated,
            },
            [(11, -allocated), (29, allocated)].into(),
        ))
    }
    fn output_input(producer: Uuid, emit: &Emit, amount: i128) -> Result<Input> {
        Ok(Input::Output {
            producer,
            role: emit.role,
            pool: emit.root.id,
            at: emit.at,
            quantity: amount,
        })
    }
    fn output_member(input: &Input) -> Result<(Address, i64, Leaf)> {
        match input {
            Input::Output {
                pool, at, quantity, ..
            } => Ok((Address::new(*pool, 7), *at, Leaf::Financial(*quantity))),
            _ => Err(Error::new("corrupt_state", "equipment output contract")),
        }
    }
}
// Independent source arithmetic and inventory checking is implemented below.
fn check(store: &Store<Equipment>) -> Result<Value> {
    use crate::integrity::{Snapshot, require};
    use crate::native_slice::Query;
    let snapshot = Snapshot::load(store)?;
    let keys = snapshot.expected_keys.clone();
    let mut routes = snapshot.routes.clone();
    let mut members = BTreeMap::new();
    let mut queries = BTreeMap::new();
    let mut events: BTreeMap<Uuid, Vec<(i64, i128)>> = BTreeMap::new();
    let mut reservations = vec![];
    for (&id, r) in &snapshot.records {
        match &r.input {
            Input::Pool { .. } => {
                events.entry(id).or_default();
            }
            Input::Delivery { pool, at, quantity } => {
                events.entry(*pool).or_default().push((*at, *quantity));
                members.insert(
                    Address::new(id, 17),
                    (Address::new(*pool, 7), *at, Leaf::Financial(*quantity)),
                );
            }
            Input::Reservation { starts, .. } => reservations.push((*starts, id)),
            Input::Output { .. } => {}
        }
    }
    reservations.sort();
    let mut expected_outputs = BTreeMap::new();
    for (_, id) in reservations {
        let r = &snapshot.records[&id];
        let Input::Reservation {
            pool,
            starts,
            ends,
            requested,
            active,
        } = r.input
        else {
            unreachable!()
        };
        let before = if active {
            events
                .get(&pool)
                .into_iter()
                .flatten()
                .filter(|(at, _)| *at < starts)
                .try_fold(0i128, |a, (_, q)| {
                    a.checked_add(*q)
                        .ok_or_else(|| Error::new("corrupt_state", "equipment oracle overflow"))
                })?
        } else {
            0
        };
        let allocation = if active {
            requested.min(before.max(0))
        } else {
            0
        };
        require(
            r.derived
                == Some(Derived {
                    available_before: before,
                    allocated: allocation,
                }),
            "equipment independently derived allocation",
        )?;
        if active {
            routes
                .entry(Key::Subscribers(Address::new(pool, 7)))
                .or_default()
                .insert(Address::new(id, 31));
            queries.insert(
                Address::new(id, 31),
                Query {
                    source: Address::new(pool, 7),
                    operation: "sum".into(),
                    phase: "calculate".into(),
                    channel: "amount".into(),
                    range: crate::time_range::TimeRange::before(starts),
                    selected: None,
                    result: before,
                },
            );
        }
        for (role, at, quantity) in [(11, starts, -allocation), (29, ends, allocation)] {
            let binding = match snapshot.all.get(&Key::Role(Address::new(id, role))) {
                Some(StoredValue::Role(b)) => Some(b),
                _ => None,
            };
            if active {
                let b = binding
                    .ok_or_else(|| Error::new("corrupt_state", "missing equipment output role"))?;
                require(!b.retired, "active equipment role retired")?;
                expected_outputs.insert(
                    b.output,
                    Input::Output {
                        producer: id,
                        role,
                        pool,
                        at,
                        quantity,
                    },
                );
                events.entry(pool).or_default().push((at, quantity));
                members.insert(
                    Address::new(b.output, 23),
                    (Address::new(pool, 7), at, Leaf::Financial(quantity)),
                );
            } else if let Some(b) = binding {
                require(
                    !snapshot.records.contains_key(&b.output),
                    "inactive equipment output survives",
                )?;
            }
        }
    }
    let actual_outputs: BTreeMap<_, _> = snapshot
        .records
        .iter()
        .filter(|(_, r)| matches!(r.input, Input::Output { .. }))
        .map(|(id, r)| (*id, r.input.clone()))
        .collect();
    require(
        actual_outputs == expected_outputs,
        "exact equipment output payload inventory",
    )?;
    for history in events.values_mut() {
        history.sort_by_key(|(at, _)| *at);
        let mut grouped = BTreeMap::<i64, i128>::new();
        for (at, q) in history {
            *grouped.entry(*at).or_default() += *q;
        }
        let mut available = 0i128;
        for q in grouped.values() {
            available += q;
            require(
                available >= 0,
                "equipment source-derived complete-time floor",
            )?;
        }
    }
    snapshot.finish(keys, members, routes, queries)
}
