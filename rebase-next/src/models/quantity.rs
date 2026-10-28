//! Small non-accounting publication model for the V1 workshop examples.
use crate::{
    binding::{Binding, NativeInput},
    causal::{PublicationRead, PublicationValue, ReactiveBinding, Resolved, ResolvedShape},
    indexes::standard::Standard,
    integrity::{Snapshot, require},
    local::Store,
    model::{
        self, Contract, InputField, Prepared, PublicationInput, PublicationSlot, PublishedField,
        Reference, Visibility,
    },
    native_codec::{Address, Key, decimal, uuid_text},
    native_slice::{Attempt, Context, Error, Model, ModelChange, ModelRecord, Population, Result},
    routes,
    time_range::TimeRange,
    values::{Rational, Rounding},
};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{ToPrimitive, Zero};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const SOURCE: u16 = 101;
pub const SCALE: u16 = 205;
pub const JOIN: u16 = 309;
pub const QUANTITY: u16 = 101;
/// Even a sum over all 16 admitted publications fits comfortably in i128.
pub const MAX_QUANTITY: i128 = 1_000_000_000_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quantity;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Input {
    Source {
        #[serde(with = "decimal")]
        value: i128,
    },
    Scale {
        #[serde(with = "uuid_text")]
        parent: Uuid,
        factor: Rational,
        rounding: Rounding,
    },
    Join {
        #[serde(with = "uuid_text")]
        left: Uuid,
        #[serde(with = "uuid_text")]
        right: Uuid,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Derived {
    #[serde(with = "decimal")]
    pub quantity: i128,
}

impl NativeInput for Input {
    fn contract(&self) -> u16 {
        match self {
            Self::Source { .. } => SOURCE,
            Self::Scale { .. } => SCALE,
            Self::Join { .. } => JOIN,
        }
    }
    fn validate(&self) -> Result<()> {
        if matches!(self, Self::Source { value } if !(-MAX_QUANTITY..=MAX_QUANTITY).contains(value))
        {
            return Err(Error::new("invalid_input", "source quantity bound"));
        }
        Ok(())
    }
    fn bind(code: u16, fields: Value) -> Result<Self> {
        let input: Self = serde_json::from_value(fields.clone())
            .map_err(|_| Error::new("invalid_input", "complete canonical quantity input"))?;
        input.validate()?;
        if input.contract() != code
            || serde_json::to_value(&input).map_err(crate::local::storage)? != fields
        {
            return Err(Error::new(
                "invalid_input",
                "complete canonical quantity input",
            ));
        }
        Ok(input)
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        // The contract hint is not a restriction: declarations admit every
        // quantity publisher and the ordinary mutation path checks the target.
        match self {
            Self::Source { .. } => vec![],
            Self::Scale { parent, .. } => vec![(*parent, SOURCE, 1)],
            Self::Join { left, right } => vec![(*left, SOURCE, 1), (*right, SOURCE, 2)],
        }
    }
}

fn reference(slot: u16, field: &'static str) -> Reference {
    Reference {
        slot,
        field,
        targets: vec![SOURCE, SCALE, JOIN],
        optional: false,
        direct_fields: vec![],
        on_delete: "reject",
        reader: true,
    }
}

fn declarations() -> Vec<Contract> {
    let uuid = json!({"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","x-rebase-binding":"uuid"});
    [
        (SOURCE, "Source", vec!["value"], json!({"value":{
            "type":"string","pattern":"^(0|-?[1-9][0-9]*)$","x-rebase-binding":"i128",
            "x-rebase-range":[(-MAX_QUANTITY).to_string(),MAX_QUANTITY.to_string()]
        }}), vec![], vec![], "quantity = authored value"),
        (SCALE, "Scale", vec!["parent", "factor", "rounding"],
            json!({"parent":uuid,"factor":Rational::schema(),"rounding":Rounding::schema()}),
            vec![reference(1, "parent")], vec![(9, 1)],
            "quantity = round(ready parent quantity * factor, rounding)"),
        (JOIN, "Join", vec!["left", "right"], json!({"left":uuid,"right":uuid}),
            vec![reference(1, "left"), reference(2, "right")], vec![(8, 1), (3, 2)],
            "quantity = ready left quantity + ready right quantity"),
    ]
    .into_iter()
    .map(|(code, name, names, properties, references, publications, expression)| Contract {
        code,
        name,
        visibility: Visibility::Public,
        schema: json!({"$schema":model::SCHEMA_DIALECT,"type":"object","additionalProperties":false,"required":names,"properties":properties}),
        fields: names.into_iter().enumerate().map(|(i, name)| InputField {
            code: i as u16 + 1, name, mutable: true,
        }).collect(),
        published: vec![PublishedField { code: QUANTITY, name: "quantity", binding: "i128" }],
        publication_inputs: publications.into_iter().map(|(slot, reference_slot)| PublicationInput {
            slot: PublicationSlot(slot), reference_slot, field_code: QUANTITY, binding: "i128",
        }).collect(),
        references,
        roots: vec![],
        memberships: vec![],
        queries: vec![],
        outputs: vec![],
        calculations: vec![model::Calculation { name: "quantity", inputs: vec![], expression }],
        calculation_order: vec![],
        rules: vec!["absolute published quantity <= 1000000000000000000", "final publication graph is acyclic"],
        schema_source: "src/models/quantity.rs",
        behavior_source: "src/models/quantity.rs",
    }).collect()
}

fn registrations(id: Uuid, input: Option<&Input>) -> BTreeSet<(Key, Address)> {
    input
        .into_iter()
        .flat_map(NativeInput::references)
        .flat_map(|(parent, _, slot)| {
            let address = Address::new(id, slot);
            [
                (Key::Incoming(parent), address),
                (Key::Direct(parent), address),
            ]
        })
        .collect()
}

impl Binding for Quantity {
    type Index = Standard;
    type Input = Input;
    type Derived = Derived;
    type Outcome = ();
    const NAME: &'static str = "quantity";
    const BEHAVIOR: &'static str = "quantity-flow-2";
    fn engine() -> Result<Model> {
        Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
    }
    fn declarations() -> Result<Vec<Contract>> {
        Ok(declarations())
    }

    fn valid_derived(_input: &Input, derived: Option<&Derived>) -> bool {
        derived.is_some_and(|v| (-MAX_QUANTITY..=MAX_QUANTITY).contains(&v.quantity))
    }
    fn published_shape(code: u16) -> Value {
        if [SOURCE, SCALE, JOIN].contains(&code) {
            json!({"quantity":"0"})
        } else {
            Value::Null
        }
    }
    fn settle_changes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        model: &Prepared<Self>,
        context: Context,
        changes: &[ModelChange<Self>],
        population: &mut Population,
        revision: Uuid,
        allocate: &mut dyn FnMut() -> Result<Uuid>,
    ) -> Result<()> {
        for change in changes {
            let before = registrations(change.id, change.old.as_ref().map(|r| &r.input));
            let after = registrations(change.id, change.new.as_ref().map(|r| &r.input));
            for (key, address) in before.difference(&after) {
                routes::change(ws, key, *address, TimeRange::ALL, false)?;
            }
            for (key, address) in after.difference(&before) {
                routes::change(ws, key, *address, TimeRange::ALL, true)?;
            }
        }
        crate::causal::settle(ws, model, context, changes, population, revision, allocate)
    }
    fn check(store: &Store<Self>) -> Result<Value> {
        check(store)
    }
    fn fixture_catalog() -> Value {
        json!([{"name":"quantities","description":"Source 12 feeds exact half and third scales, joined as 10"}])
    }
    fn fixture_plan(model: &Prepared<Self>, name: &str, namespace: Uuid) -> Result<Value> {
        if name != "quantities" {
            return Err(Error::new("invalid_input", "unknown quantity fixture"));
        }
        let ids: BTreeMap<_, _> = ["source", "left", "right", "join"]
            .into_iter()
            .map(|name| {
                (
                    name,
                    Uuid::new_v5(&namespace, format!("quantities/{name}").as_bytes()),
                )
            })
            .collect();
        let commands = json!([
            {"op":"create","id":ids["source"],"contract":SOURCE,"fields":{"value":"12"}},
            {"op":"create","id":ids["left"],"contract":SCALE,"fields":{"parent":ids["source"],"factor":{"numerator":"1","denominator":"2"},"rounding":"exact"}},
            {"op":"create","id":ids["right"],"contract":SCALE,"fields":{"parent":ids["source"],"factor":{"numerator":"1","denominator":"3"},"rounding":"exact"}},
            {"op":"create","id":ids["join"],"contract":JOIN,"fields":{"left":ids["left"],"right":ids["right"]}}
        ]);
        for command in commands.as_array().expect("authored commands") {
            model.validate(
                command["contract"].as_u64().expect("authored contract") as u16,
                &command["fields"],
            )?;
        }
        Ok(
            json!({"model":model.identity(),"fixture":{"name":name,"namespace":namespace,"ids":ids,
            "expected":{"source":"12","left":"6","right":"4","join":"10"}},
            "commands":commands,"returning":[ids["source"],ids["left"],ids["right"],ids["join"]]}),
        )
    }
}

impl ReactiveBinding for Quantity {
    type Parameters = ();
    type Publication = i128;
    fn resolve<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        _ws: &mut Attempt<L, Self>,
        _context: Context,
        _id: Uuid,
        record: &ModelRecord<Self>,
    ) -> Result<Resolved<()>> {
        let publications = match record.input {
            Input::Source { .. } => vec![],
            Input::Scale { parent, .. } => vec![PublicationRead {
                slot: PublicationSlot(9),
                parent,
            }],
            Input::Join { left, right } => vec![
                PublicationRead {
                    slot: PublicationSlot(3),
                    parent: right,
                },
                PublicationRead {
                    slot: PublicationSlot(8),
                    parent: left,
                },
            ],
        };
        Ok(Resolved {
            shape: ResolvedShape {
                publications,
                ..ResolvedShape::default()
            },
            parameters: (),
        })
    }
    fn project_publication(parent: &ModelRecord<Self>, field_code: u16) -> Result<i128> {
        if field_code != QUANTITY {
            return Err(Error::new("model", "unknown quantity publication"));
        }
        parent
            .derived
            .as_ref()
            .map(|v| v.quantity)
            .ok_or_else(|| Error::new("model", "quantity publication is not ready"))
    }
    fn evaluate(
        _id: Uuid,
        record: &ModelRecord<Self>,
        _shape: &ResolvedShape,
        _parameters: &(),
        publications: &[PublicationValue<i128>],
        _values: &[i128],
    ) -> Result<(Derived, BTreeMap<u16, i128>)> {
        let published = |slot| {
            publications
                .iter()
                .find(|v| v.slot == PublicationSlot(slot))
                .map(|v| v.value)
                .ok_or_else(|| Error::new("model", "missing quantity publication slot"))
        };
        let quantity = match record.input {
            Input::Source { value } => value,
            Input::Scale {
                factor, rounding, ..
            } => factor.apply(published(9)?, rounding)?,
            Input::Join { .. } => published(8)?
                .checked_add(published(3)?)
                .ok_or_else(|| Error::new("overflow", "quantity join"))?,
        };
        if !(-MAX_QUANTITY..=MAX_QUANTITY).contains(&quantity) {
            return Err(Error::new("overflow", "published quantity bound"));
        }
        Ok((Derived { quantity }, BTreeMap::new()))
    }
}

// This source checker uses floor division and distances between neighbouring
// integers. It never calls Rational::apply, a resolver, or the shared scheduler.
fn source_scale(value: i128, factor: Rational, rounding: Rounding) -> Result<i128> {
    let product = BigInt::from(value) * BigInt::from(factor.numerator());
    let denominator = BigInt::from(factor.denominator());
    let (floor, remainder) = product.div_mod_floor(&denominator);
    let increment = if remainder.is_zero() {
        false
    } else {
        match rounding {
            Rounding::Exact => return Err(Error::new("corrupt_state", "inexact source quantity")),
            Rounding::Floor => false,
            Rounding::Ceiling => true,
            Rounding::TowardZero => product < BigInt::zero(),
            Rounding::HalfEven => match (&remainder * 2u8).cmp(&denominator) {
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Equal => floor.is_odd(),
            },
            Rounding::HalfAwayFromZero => match (&remainder * 2u8).cmp(&denominator) {
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Equal => product > BigInt::zero(),
            },
        }
    };
    (floor + u8::from(increment))
        .to_i128()
        .ok_or_else(|| Error::new("corrupt_state", "source quantity overflow"))
}

fn check(store: &Store<Quantity>) -> Result<Value> {
    let snapshot = Snapshot::load(store)?;
    let mut values = BTreeMap::<Uuid, i128>::new();
    while values.len() < snapshot.records.len() {
        let before = values.len();
        for (&id, record) in &snapshot.records {
            if values.contains_key(&id) {
                continue;
            }
            let quantity = match record.input {
                Input::Source { value } => value,
                Input::Scale {
                    parent,
                    factor,
                    rounding,
                } => {
                    let Some(value) = values.get(&parent) else {
                        continue;
                    };
                    source_scale(*value, factor, rounding)?
                }
                Input::Join { left, right } => {
                    let (Some(left), Some(right)) = (values.get(&left), values.get(&right)) else {
                        continue;
                    };
                    left.checked_add(*right)
                        .ok_or_else(|| Error::new("corrupt_state", "source join overflow"))?
                }
            };
            require(
                (-MAX_QUANTITY..=MAX_QUANTITY).contains(&quantity),
                "source publication bound",
            )?;
            require(
                record.derived == Some(Derived { quantity }),
                "source quantity publication",
            )?;
            values.insert(id, quantity);
        }
        require(values.len() > before, "acyclic source quantity graph")?;
    }
    let mut routes = BTreeMap::<Key, BTreeSet<Address>>::new();
    for (&id, record) in &snapshot.records {
        routes.entry(Key::Incoming(id)).or_default();
        routes.entry(Key::Direct(id)).or_default();
        let parents = match record.input {
            Input::Source { .. } => vec![],
            Input::Scale { parent, .. } => vec![(parent, 1)],
            Input::Join { left, right } => vec![(left, 1), (right, 2)],
        };
        for (parent, slot) in parents {
            for key in [Key::Incoming(parent), Key::Direct(parent)] {
                routes
                    .entry(key)
                    .or_default()
                    .insert(Address::new(id, slot));
            }
        }
    }
    snapshot.finish(
        snapshot.expected_keys.clone(),
        BTreeMap::new(),
        routes,
        BTreeMap::new(),
    )
}
