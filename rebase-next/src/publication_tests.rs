//! Published inputs through the ordinary model and transaction path. Expected
//! arithmetic and edges come from authored facts, never cached derived values.
use crate::{
    binding::{Binding, NativeInput},
    causal::{
        Emit, PublicationRead, PublicationValue, ReactiveBinding, Read, Resolved, ResolvedShape,
    },
    index::TimeKey,
    indexes::standard::{FINANCIAL, Leaf, Standard},
    integrity::{Snapshot, require},
    local::{Mutation, Store},
    model::{
        self, Contract, InputField, Membership, OutputRole, Prepared, PublicationInput,
        PublicationSlot, PublishedField, QueryDeclaration, Reference, RootDeclaration, Visibility,
    },
    native_codec::{Address, Key, StoredValue, decimal, uuid_text},
    native_slice::{Attempt, Context, Error, Meta, Model, ModelChange, ModelRecord, Query, Result},
    routes,
    time_range::TimeRange,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};
use uuid::Uuid;

const BUCKET: u16 = 10;
const ENTRY: u16 = 20;
const SUM: u16 = 30;
const COPY: u16 = 40;
const JOIN: u16 = 50;
const OUTPUT: u16 = 90;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fixture<const MODE: u8>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum Input {
    Bucket {
        unit: u16,
    },
    Entry {
        #[serde(with = "uuid_text")]
        bucket: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        amount: i128,
    },
    Sum {
        #[serde(with = "uuid_text")]
        bucket: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        bias: i128,
    },
    Copy {
        #[serde(with = "uuid_text")]
        parent: Uuid,
        #[serde(with = "uuid_text")]
        bucket: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        factor: i128,
        #[serde(with = "decimal")]
        bias: i128,
        post: bool,
    },
    Join {
        #[serde(with = "uuid_text")]
        left: Uuid,
        #[serde(with = "uuid_text")]
        right: Uuid,
        #[serde(with = "decimal")]
        bias: i128,
    },
    Output {
        #[serde(with = "uuid_text")]
        producer: Uuid,
        role: u16,
        #[serde(with = "uuid_text")]
        bucket: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        amount: i128,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Derived {
    #[serde(with = "decimal")]
    amount: i128,
}

// Intentionally neither Clone nor Serialize/Deserialize. These values exist
// only in one evaluation attempt and do not need a persisted cache row.
enum NativePublication {
    Amount(i128),
    Incompatible,
}

impl Input {
    fn bias(&self) -> Result<i128> {
        match self {
            Self::Sum { bias, .. } | Self::Copy { bias, .. } | Self::Join { bias, .. } => Ok(*bias),
            _ => Err(Error::new("model", "expected authored parent bias")),
        }
    }
    fn calculated(&self) -> bool {
        matches!(
            self,
            Self::Sum { .. } | Self::Copy { .. } | Self::Join { .. }
        )
    }
}

impl NativeInput for Input {
    fn contract(&self) -> u16 {
        match self {
            Self::Bucket { .. } => BUCKET,
            Self::Entry { .. } => ENTRY,
            Self::Sum { .. } => SUM,
            Self::Copy { .. } => COPY,
            Self::Join { .. } => JOIN,
            Self::Output { .. } => OUTPUT,
        }
    }
    fn validate(&self) -> Result<()> {
        if matches!(self, Self::Bucket { unit: 0 })
            || matches!(self, Self::Output { role, .. } if *role != 7)
        {
            return Err(Error::new("invalid_input", "publication fixture scalar"));
        }
        Ok(())
    }
    fn bind(code: u16, fields: Value) -> Result<Self> {
        let input: Self = serde_json::from_value(fields.clone())
            .map_err(|e| Error::new("invalid_input", e.to_string()))?;
        input.validate()?;
        if input.contract() != code || serde_json::to_value(&input).unwrap() != fields {
            return Err(Error::new(
                "invalid_input",
                "complete canonical publication input",
            ));
        }
        Ok(input)
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        // The middle element is a hint; Reference.targets and the actual record
        // determine the contract for polymorphic publication parents.
        match self {
            Self::Entry { bucket, .. } | Self::Sum { bucket, .. } => vec![(*bucket, BUCKET, 1)],
            Self::Copy { parent, bucket, .. } => vec![(*parent, SUM, 1), (*bucket, BUCKET, 2)],
            Self::Join { left, right, .. } => vec![(*left, SUM, 1), (*right, SUM, 2)],
            Self::Output {
                producer, bucket, ..
            } => vec![(*producer, COPY, 1), (*bucket, BUCKET, 2)],
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

fn scalar(binding: &str, min: i128, max: i128) -> Value {
    json!({"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","x-rebase-binding":binding,
        "x-rebase-range":[min.to_string(),max.to_string()]})
}
fn reference(slot: u16, field: &'static str, targets: Vec<u16>) -> Reference {
    Reference {
        slot,
        field,
        targets,
        optional: false,
        direct_fields: vec![],
        on_delete: "reject",
        reader: false,
    }
}
fn contract(code: u16, name: &'static str, fields: &[&'static str], properties: Value) -> Contract {
    Contract {
        code,
        name,
        visibility: if code == OUTPUT {
            Visibility::Engine
        } else {
            Visibility::Public
        },
        schema: json!({"$schema":model::SCHEMA_DIALECT,"type":"object","additionalProperties":false,
            "properties":properties,"required":fields}),
        fields: fields
            .iter()
            .enumerate()
            .map(|(i, name)| InputField {
                code: i as u16 + 1,
                name,
                mutable: code != BUCKET,
            })
            .collect(),
        published: vec![],
        publication_inputs: vec![],
        references: vec![],
        roots: vec![],
        memberships: vec![],
        queries: vec![],
        outputs: vec![],
        calculations: vec![],
        calculation_order: vec![],
        rules: vec![],
        schema_source: "src/publication_tests.rs",
        behavior_source: "src/publication_tests.rs",
    }
}
fn declarations() -> Vec<Contract> {
    let uuid = json!({"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","x-rebase-binding":"uuid"});
    let time = scalar("i64", i128::from(i64::MIN), i128::from(i64::MAX));
    let amount = scalar("i128", i128::MIN, i128::MAX);
    let mut bucket = contract(
        BUCKET,
        "Bucket",
        &["unit"],
        json!({"unit":{"type":"integer","minimum":1,"maximum":65535,"x-rebase-binding":"u16_code"}}),
    );
    bucket.roots.push(RootDeclaration {
        slot: 7,
        name: "amounts",
        kind: FINANCIAL,
        reads: vec!["summary", "sum"],
        invariant: None,
    });
    let mut entry = contract(
        ENTRY,
        "Entry",
        &["bucket", "at", "amount"],
        json!({"bucket":uuid,"at":time,"amount":amount}),
    );
    entry.references.push(reference(1, "bucket", vec![BUCKET]));
    entry.memberships.push(Membership {
        slot: 17,
        through: "bucket",
        root_contract: BUCKET,
        root_slot: 7,
        kind: FINANCIAL,
        key: "at",
        value: "amount",
    });
    let mut sum = contract(
        SUM,
        "Sum",
        &["bucket", "at", "bias"],
        json!({"bucket":uuid,"at":time,"bias":amount}),
    );
    sum.references.push(reference(1, "bucket", vec![BUCKET]));
    sum.queries.push(QueryDeclaration {
        slot: 31,
        through: "bucket",
        root_contract: BUCKET,
        root_slot: 7,
        operation: "sum",
        phase: "calculate",
        channel: "amount",
        bound: "strictly before at",
        fallback: None,
    });
    let mut copy = contract(
        COPY,
        "Copy",
        &["parent", "bucket", "at", "factor", "bias", "post"],
        json!({"parent":uuid,"bucket":uuid,"at":time,"factor":amount,"bias":amount,"post":{"type":"boolean"}}),
    );
    let mut parent = reference(1, "parent", vec![SUM, COPY, JOIN]);
    parent.direct_fields.push("bias");
    copy.references = vec![parent, reference(2, "bucket", vec![BUCKET])];
    copy.publication_inputs.push(PublicationInput {
        slot: PublicationSlot(9),
        reference_slot: 1,
        field_code: 101,
        binding: "i128",
    });
    copy.outputs.push(OutputRole {
        role: 7,
        contract: OUTPUT,
        active: "post",
        account: "bucket",
        at: "at",
        amount: "amount",
        depends_on: vec!["amount"],
    });
    let mut join = contract(
        JOIN,
        "Join",
        &["left", "right", "bias"],
        json!({"left":uuid,"right":uuid,"bias":amount}),
    );
    join.references = vec![
        reference(1, "left", vec![SUM, COPY, JOIN]),
        reference(2, "right", vec![SUM, COPY, JOIN]),
    ];
    // Reverse numeric slots prove delivery is keyed by declaration, not position.
    join.publication_inputs = vec![
        PublicationInput {
            slot: PublicationSlot(8),
            reference_slot: 1,
            field_code: 101,
            binding: "i128",
        },
        PublicationInput {
            slot: PublicationSlot(3),
            reference_slot: 2,
            field_code: 101,
            binding: "i128",
        },
    ];
    for c in [&mut sum, &mut copy, &mut join] {
        c.published.push(PublishedField {
            code: 101,
            name: "amount",
            binding: "i128",
        });
        c.calculations.push(model::Calculation {
            name: "amount",
            inputs: vec![],
            expression: "native source formula",
        });
    }
    let mut output = contract(
        OUTPUT,
        "Output",
        &["producer", "role", "bucket", "at", "amount"],
        json!({"producer":uuid,"role":{"type":"integer","const":7},"bucket":uuid,"at":time,"amount":amount}),
    );
    output.references = vec![
        reference(1, "producer", vec![COPY]),
        reference(2, "bucket", vec![BUCKET]),
    ];
    output.memberships.push(Membership {
        slot: 17,
        through: "bucket",
        root_contract: BUCKET,
        root_slot: 7,
        kind: FINANCIAL,
        key: "at",
        value: "amount",
    });
    vec![bucket, entry, sum, copy, join, output]
}
fn registrations(id: Uuid, input: Option<&Input>) -> BTreeSet<(Key, Address)> {
    let mut result = BTreeSet::new();
    if let Some(input) = input {
        for (parent, _, slot) in input.references() {
            result.insert((Key::Incoming(parent), Address::new(id, slot)));
            if matches!(input, Input::Copy { .. }) && slot == 1
                || matches!(input, Input::Join { .. })
            {
                result.insert((Key::Direct(parent), Address::new(id, slot)));
            }
        }
    }
    result
}
fn entry_member(input: Option<&Input>) -> Option<(Address, TimeKey, Leaf)> {
    match input {
        Some(Input::Entry { bucket, at, amount }) => Some((
            Address::new(*bucket, 7),
            TimeKey(*at),
            Leaf::Financial(*amount),
        )),
        _ => None,
    }
}
impl<const MODE: u8> Binding for Fixture<MODE> {
    type Index = Standard;
    type Input = Input;
    type Derived = Derived;
    const NAME: &'static str = "test-publications";
    const BEHAVIOR: &'static str = match MODE {
        0 => "publication-0",
        1 => "publication-1",
        2 => "publication-2",
        3 => "publication-3",
        4 => "publication-4",
        5 => "publication-5",
        _ => "publication-fault",
    };
    fn declarations() -> Result<Vec<Contract>> {
        Ok(declarations())
    }
    fn engine() -> Result<Model> {
        Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
    }
    fn valid_derived(input: &Input, derived: Option<&Derived>) -> bool {
        input.calculated() == derived.is_some()
    }
    fn published_shape(code: u16) -> Value {
        if [SUM, COPY, JOIN].contains(&code) {
            json!({"amount":"0"})
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
            for (key, address) in old.difference(&new) {
                routes::change(ws, key, *address, TimeRange::ALL, false)?;
            }
            for (key, address) in new.difference(&old) {
                routes::change(ws, key, *address, TimeRange::ALL, true)?;
            }
            crate::mutation::reconcile_member(
                ws,
                Address::new(change.id, 17),
                entry_member(change.old.as_ref().map(|r| &r.input)),
                entry_member(change.new.as_ref().map(|r| &r.input)),
            )?;
        }
        crate::causal::settle(ws, model, context, changes, meta, revision, allocate)
    }
    fn check(store: &Store<Self>) -> Result<Value> {
        check(store)
    }
}
impl<const MODE: u8> ReactiveBinding for Fixture<MODE> {
    type Parameters = i128;
    type Publication = NativePublication;
    fn resolve<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        _context: Context,
        _id: Uuid,
        record: &ModelRecord<Self>,
    ) -> Result<Resolved<i128>> {
        let mut shape = ResolvedShape::default();
        let mut parameters = 0;
        match record.input {
            Input::Sum { bucket, at, .. } => shape.reads.push(Read {
                slot: 31,
                root: Address::new(bucket, 7),
                range: TimeRange::before(at),
                validate: false,
            }),
            Input::Copy {
                parent,
                bucket,
                at,
                post,
                ..
            } => {
                let source = ws
                    .record(parent)?
                    .ok_or_else(|| Error::new("unavailable_reference", "parent"))?;
                parameters = source.input.bias()?;
                shape.publications.push(PublicationRead {
                    slot: PublicationSlot(9),
                    parent,
                });
                if post {
                    shape.emits.push(Emit {
                        role: 7,
                        contract: OUTPUT,
                        root: Address::new(bucket, 7),
                        at,
                    });
                }
                match MODE {
                    1 => shape.publications.clear(),
                    2 => shape.publications[0].slot = PublicationSlot(77),
                    3 => shape.publications.push(shape.publications[0]),
                    4 => shape.publications[0].parent = id(31),
                    // Fault injection is attempt-local; rejection must roll back
                    // this write as well as staged source/tree/route changes.
                    6 => {
                        let mut wrong = source;
                        wrong.tenant = id(999);
                        ws.put(Key::Record(parent), Some(StoredValue::Record(wrong)))?;
                    }
                    // Exhaust the real meter after staging the new source and
                    // reverse route. One injection checks transaction rollback;
                    // it is not a claim about a maximum successful fanout.
                    7 => ws.charge("dependency", crate::local::MUTATION_WORK_LIMIT)?,
                    _ => {}
                }
            }
            Input::Join { left, right, .. } => {
                shape.publications = vec![
                    PublicationRead {
                        slot: PublicationSlot(3),
                        parent: right,
                    },
                    PublicationRead {
                        slot: PublicationSlot(8),
                        parent: left,
                    },
                ]
            }
            _ => return Err(Error::new("model", "publication calculator")),
        }
        Ok(Resolved { shape, parameters })
    }
    fn project_publication(
        parent: &ModelRecord<Self>,
        field_code: u16,
    ) -> Result<NativePublication> {
        if field_code != 101 || !parent.input.calculated() {
            return Err(Error::new("model", "publication code/type"));
        }
        if MODE == 5 {
            return Ok(NativePublication::Incompatible);
        }
        Ok(NativePublication::Amount(
            parent
                .derived
                .as_ref()
                .ok_or_else(|| Error::new("model", "parent publication is not ready"))?
                .amount,
        ))
    }
    fn evaluate(
        _id: Uuid,
        record: &ModelRecord<Self>,
        shape: &ResolvedShape,
        parameters: &i128,
        publications: &[PublicationValue<NativePublication>],
        values: &[i128],
    ) -> Result<(Derived, BTreeMap<u16, i128>)> {
        let publication = |slot| -> Result<i128> {
            match publications
                .iter()
                .find(|v| v.slot == PublicationSlot(slot))
                .map(|v| &v.value)
            {
                Some(NativePublication::Amount(amount)) => Ok(*amount),
                _ => Err(Error::new("model", "incompatible native publication")),
            }
        };
        let amount = match record.input {
            Input::Sum { bias, .. } => values[0].checked_add(bias),
            Input::Copy { factor, bias, .. } => publication(9)?
                .checked_mul(factor)
                .and_then(|v| v.checked_add(*parameters))
                .and_then(|v| v.checked_add(bias)),
            Input::Join { bias, .. } => publication(8)?
                .checked_add(publication(3)?)
                .and_then(|v| v.checked_add(bias)),
            _ => return Err(Error::new("model", "publication evaluation input")),
        }
        .ok_or_else(|| Error::new("overflow", "publication formula"))?;
        Ok((
            Derived { amount },
            if shape.emits.is_empty() {
                BTreeMap::new()
            } else {
                BTreeMap::from([(7, amount)])
            },
        ))
    }
    fn output_input(producer: Uuid, emit: &Emit, amount: i128) -> Result<Input> {
        Ok(Input::Output {
            producer,
            role: emit.role,
            bucket: emit.root.id,
            at: emit.at,
            amount,
        })
    }
    fn output_member(input: &Input) -> Result<(Address, i64, Leaf)> {
        match input {
            Input::Output {
                bucket, at, amount, ..
            } => Ok((Address::new(*bucket, 7), *at, Leaf::Financial(*amount))),
            _ => Err(Error::new("model", "publication output")),
        }
    }
}

// All valid orders of the tiny plain predecessor graph. No scheduler gates,
// production resolver, tree ranges or maintained query values enter this oracle.
fn orders(vertices: &BTreeSet<Uuid>, edges: &BTreeSet<(Uuid, Uuid)>) -> Vec<Vec<Uuid>> {
    fn visit(
        pending: &BTreeSet<Uuid>,
        edges: &BTreeSet<(Uuid, Uuid)>,
        prefix: &mut Vec<Uuid>,
        out: &mut Vec<Vec<Uuid>>,
    ) {
        if pending.is_empty() {
            out.push(prefix.clone());
            return;
        }
        for &next in pending {
            if edges
                .iter()
                .any(|(from, to)| *to == next && pending.contains(from))
            {
                continue;
            }
            let mut rest = pending.clone();
            rest.remove(&next);
            prefix.push(next);
            visit(&rest, edges, prefix, out);
            prefix.pop();
        }
    }
    let mut out = vec![];
    visit(vertices, edges, &mut vec![], &mut out);
    out
}
fn oracle(facts: &BTreeMap<Uuid, Input>) -> Result<BTreeMap<Uuid, i128>> {
    let vertices: BTreeSet<_> = facts
        .iter()
        .filter_map(|(&id, input)| input.calculated().then_some(id))
        .collect();
    let mut edges = BTreeSet::new();
    for (&id, input) in facts {
        match input {
            Input::Copy { parent, .. } => {
                edges.insert((*parent, id));
            }
            Input::Join { left, right, .. } => {
                edges.insert((*left, id));
                edges.insert((*right, id));
            }
            Input::Sum { bucket, at, .. } => {
                for (&producer, source) in facts {
                    if matches!(source, Input::Copy { bucket: target, at: time, post: true, .. } if target == bucket && time < at)
                    {
                        edges.insert((producer, id));
                    }
                }
            }
            _ => {}
        }
    }
    let schedules = orders(&vertices, &edges);
    require(!schedules.is_empty(), "source publication graph cycle")?;
    let mut expected = None;
    for schedule in schedules {
        let mut values: BTreeMap<Uuid, i128> = BTreeMap::new();
        for id in schedule {
            let value = match facts[&id] {
                Input::Sum { bucket, at, bias } => {
                    let mut total = bias;
                    for (&source, input) in facts {
                        let amount = match input {
                            Input::Entry {
                                bucket: target,
                                at: time,
                                amount,
                            } if *target == bucket && *time < at => *amount,
                            Input::Copy {
                                bucket: target,
                                at: time,
                                post: true,
                                ..
                            } if *target == bucket && *time < at => values[&source],
                            _ => 0,
                        };
                        total = total
                            .checked_add(amount)
                            .ok_or_else(|| Error::new("corrupt_state", "oracle sum overflow"))?;
                    }
                    total
                }
                Input::Copy {
                    parent,
                    factor,
                    bias,
                    ..
                } => {
                    let parent_bias = match facts[&parent] {
                        Input::Sum { bias, .. }
                        | Input::Copy { bias, .. }
                        | Input::Join { bias, .. } => bias,
                        _ => unreachable!(),
                    };
                    values[&parent]
                        .checked_mul(factor)
                        .and_then(|v| v.checked_add(parent_bias))
                        .and_then(|v| v.checked_add(bias))
                        .ok_or_else(|| Error::new("corrupt_state", "oracle copy overflow"))?
                }
                Input::Join { left, right, bias } => values[&left]
                    .checked_add(values[&right])
                    .and_then(|v| v.checked_add(bias))
                    .ok_or_else(|| Error::new("corrupt_state", "oracle join overflow"))?,
                _ => unreachable!(),
            };
            values.insert(id, value);
        }
        if let Some(previous) = &expected {
            require(previous == &values, "publication order independence")?;
        }
        expected = Some(values);
    }
    Ok(expected.unwrap())
}
fn check<const MODE: u8>(store: &Store<Fixture<MODE>>) -> Result<Value> {
    let snapshot = Snapshot::load(store)?;
    let facts: BTreeMap<_, _> = snapshot
        .records
        .iter()
        .filter_map(|(&id, record)| {
            (record.contract != OUTPUT).then_some((id, record.input.clone()))
        })
        .collect();
    let values = oracle(&facts)?;
    let keys = snapshot.expected_keys.clone();
    let mut expected_routes = snapshot.routes.clone();
    let mut members = BTreeMap::new();
    let mut queries = BTreeMap::new();
    let mut outputs = BTreeMap::new();
    for (&id, input) in &facts {
        if input.calculated() {
            require(
                snapshot.records[&id].derived
                    == Some(Derived {
                        amount: values[&id],
                    }),
                "source publication result",
            )?;
        }
        match input {
            Input::Entry { bucket, at, amount } => {
                members.insert(
                    Address::new(id, 17),
                    (Address::new(*bucket, 7), *at, Leaf::Financial(*amount)),
                );
            }
            Input::Sum { bucket, at, bias } => {
                let address = Address::new(id, 31);
                expected_routes
                    .entry(Key::Subscribers(Address::new(*bucket, 7)))
                    .or_default()
                    .insert(address);
                queries.insert(
                    address,
                    Query {
                        source: Address::new(*bucket, 7),
                        operation: "sum".into(),
                        phase: "calculate".into(),
                        channel: "amount".into(),
                        range: TimeRange::before(*at),
                        selected: None,
                        result: values[&id]
                            .checked_sub(*bias)
                            .ok_or_else(|| Error::new("corrupt_state", "oracle query"))?,
                    },
                );
            }
            Input::Copy {
                parent,
                bucket,
                at,
                post,
                ..
            } => {
                expected_routes
                    .entry(Key::Direct(*parent))
                    .or_default()
                    .insert(Address::new(id, 1));
                if *post {
                    let Some(StoredValue::Role(role)) =
                        snapshot.all.get(&Key::Role(Address::new(id, 7)))
                    else {
                        return Err(Error::new(
                            "corrupt_state",
                            "missing publication output role",
                        ));
                    };
                    require(!role.retired, "active publication output role")?;
                    let amount = values[&id];
                    outputs.insert(
                        role.output,
                        Input::Output {
                            producer: id,
                            role: 7,
                            bucket: *bucket,
                            at: *at,
                            amount,
                        },
                    );
                    members.insert(
                        Address::new(role.output, 17),
                        (Address::new(*bucket, 7), *at, Leaf::Financial(amount)),
                    );
                }
            }
            Input::Join { left, right, .. } => {
                expected_routes
                    .entry(Key::Direct(*left))
                    .or_default()
                    .insert(Address::new(id, 1));
                expected_routes
                    .entry(Key::Direct(*right))
                    .or_default()
                    .insert(Address::new(id, 2));
            }
            _ => {}
        }
    }
    let actual: BTreeMap<_, _> = snapshot
        .records
        .iter()
        .filter_map(|(&id, r)| (r.contract == OUTPUT).then_some((id, r.input.clone())))
        .collect();
    require(
        actual == outputs,
        "complete source publication output inventory",
    )?;
    snapshot.finish(keys, members, expected_routes, queries)
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Run<const MODE: u8> {
    store: Store<Fixture<MODE>>,
    directory: Directory,
    facts: BTreeMap<Uuid, Input>,
    operation: u128,
}
impl<const MODE: u8> Run<MODE> {
    fn new() -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/publication-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&directory).unwrap();
        let store = Store::create(
            directory.join("model.redb"),
            Arc::new(Prepared::load().unwrap()),
            Context {
                tenant: id(1),
                actor: id(2),
            },
        )
        .unwrap();
        Self {
            store,
            directory: Directory(directory),
            facts: BTreeMap::new(),
            operation: 1000,
        }
    }
    fn request(&mut self, commands: Value) -> Mutation {
        self.operation += 1;
        serde_json::from_value(json!({"model":self.store.model().identity(),
            "context":self.store.operation_context(self.store.model().identity()).unwrap(),
            "operation_id":id(self.operation),"commands":commands,"returning":[]}))
        .unwrap()
    }
    fn commit(&mut self, commands: Value) -> (Mutation, Value) {
        // Retain independently authored facts. Read actual records only for CAS
        // versions; oracle values never come from the store's derived records.
        let mut final_facts = self.facts.clone();
        for command in commands.as_array().unwrap() {
            let id: Uuid = serde_json::from_value(command["id"].clone()).unwrap();
            match command["op"].as_str().unwrap() {
                "create" => {
                    final_facts.insert(
                        id,
                        serde_json::from_value(command["fields"].clone()).unwrap(),
                    );
                }
                "update" => {
                    let mut fields = serde_json::to_value(&final_facts[&id]).unwrap();
                    for (name, value) in command["set"].as_object().unwrap() {
                        fields[name] = value.clone();
                    }
                    final_facts.insert(id, serde_json::from_value(fields).unwrap());
                }
                "delete" => {
                    final_facts.remove(&id);
                }
                _ => panic!("fixture command"),
            }
        }
        let expected = oracle(&final_facts).unwrap();
        let request = self.request(commands);
        let result = self.store.mutate(&request).unwrap();
        self.facts = final_facts;
        let snapshot = Snapshot::load(&self.store).unwrap();
        let sources: BTreeMap<_, _> = snapshot
            .records
            .iter()
            .filter_map(|(&id, r)| (r.contract != OUTPUT).then_some((id, r.input.clone())))
            .collect();
        assert_eq!(sources, self.facts);
        for (id, amount) in expected {
            assert_eq!(snapshot.records[&id].derived, Some(Derived { amount }));
        }
        self.store.check_integrity().unwrap();
        (request, result)
    }
    fn update(&self, n: u128, set: Value) -> Value {
        let version = Snapshot::load(&self.store).unwrap().records[&id(n)].version;
        json!({"op":"update","id":id(n),"if_version":version.to_string(),"set":set,"unset":[]})
    }
    fn reject(&mut self, commands: Value, kind: &str) {
        let before = self.store.observe_for_verification().unwrap();
        let inspect = self.store.inspect().unwrap();
        let request = self.request(commands);
        assert_eq!(self.store.mutate(&request).unwrap_err().code, kind);
        assert_eq!(self.store.observe_for_verification().unwrap(), before);
        assert_eq!(self.store.inspect().unwrap(), inspect);
        assert_eq!(
            self.store
                .operation_status(
                    self.store.model().identity(),
                    &request.context,
                    request.operation_id
                )
                .unwrap()["status"],
            "not_observed"
        );
        self.store.check_integrity().unwrap();
    }
    fn amount(&self, n: u128) -> i128 {
        Snapshot::load(&self.store).unwrap().records[&id(n)]
            .derived
            .as_ref()
            .unwrap()
            .amount
    }
}
fn create(n: u128, input: Input) -> Value {
    json!({"op":"create","id":id(n),"contract":input.contract(),"fields":input})
}
fn bucket(n: u128) -> Value {
    create(n, Input::Bucket { unit: 1 })
}
fn entry(n: u128, bucket: u128, at: i64, amount: i128) -> Value {
    create(
        n,
        Input::Entry {
            bucket: id(bucket),
            at,
            amount,
        },
    )
}
fn sum(n: u128, bucket: u128, at: i64, bias: i128) -> Value {
    create(
        n,
        Input::Sum {
            bucket: id(bucket),
            at,
            bias,
        },
    )
}
fn copy(n: u128, parent: u128, factor: i128, bias: i128) -> Value {
    create(
        n,
        Input::Copy {
            parent: id(parent),
            bucket: id(10),
            at: 20,
            factor,
            bias,
            post: false,
        },
    )
}
fn join(n: u128, left: u128, right: u128, bias: i128) -> Value {
    create(
        n,
        Input::Join {
            left: id(left),
            right: id(right),
            bias,
        },
    )
}

#[test]
fn aggregate_change_reaches_publication_diamond_chain_and_deduplicated_routes() {
    let mut run = Run::<0>::new();
    run.commit(json!([
        bucket(10),
        bucket(11),
        entry(20, 10, 0, 10),
        sum(30, 10, 10, 1),
        copy(40, 30, 2, 3),
        copy(41, 30, 3, 4),
        join(50, 40, 41, 5),
        copy(42, 50, 1, 6)
    ]));
    assert_eq!(
        (
            run.amount(30),
            run.amount(40),
            run.amount(41),
            run.amount(50),
            run.amount(42)
        ),
        (11, 26, 38, 69, 80)
    );
    let old_parent = run.amount(30);
    let (request, result) = run.commit(json!([run.update(20, json!({"amount":"20"}))]));
    assert_eq!(
        (
            run.amount(30),
            run.amount(40),
            run.amount(41),
            run.amount(50),
            run.amount(42)
        ),
        (21, 46, 68, 119, 130)
    );
    assert_ne!(run.amount(40), old_parent * 2 + 1 + 3);
    let snapshot = Snapshot::load(&run.store).unwrap();
    let Some(StoredValue::Direct(route)) = snapshot.all.get(&Key::Direct(id(30))) else {
        panic!("direct route")
    };
    assert_eq!(route.len, 2); // Authored bias + publication share one route per child.
    assert!(
        !snapshot
            .all
            .keys()
            .any(|key| matches!(key, Key::Query(address) if address.id == id(50)))
    );
    let before = run.store.observe_for_verification().unwrap();
    assert_eq!(
        run.store.mutate(&request).unwrap()["result"],
        result["result"]
    );
    assert_eq!(run.store.observe_for_verification().unwrap(), before);
    // Reopen and replay independently of the native publication type.
    let path = run.directory.0.join("model.redb");
    drop(run.store);
    let store = Store::<Fixture<0>>::open(path, Arc::new(Prepared::load().unwrap())).unwrap();
    store.check_integrity().unwrap();
    assert_eq!(store.observe_for_verification().unwrap(), before);
    assert_eq!(store.mutate(&request).unwrap()["result"], result["result"]);
}

#[test]
fn final_reversal_retargets_in_both_command_orders_and_equal_values_keep_edges() {
    for reverse in [false, true] {
        let mut run = Run::<0>::new();
        run.commit(json!([
            bucket(10),
            entry(20, 10, 0, 10),
            sum(30, 10, 10, 1),
            sum(31, 10, 10, 1),
            copy(40, 30, 2, 3),
            copy(41, 40, 3, 4),
            join(50, 40, 41, 0)
        ]));
        let old = run.amount(40);
        run.commit(json!([run.update(40, json!({"parent":id(31)}))]));
        assert_eq!(run.amount(40), old);
        // Old edge 40 -> 41, new edge 41 -> 40: their union is cyclic,
        // while the only graph to schedule is the final 30 -> 41 -> 40.
        let mut edits = vec![
            run.update(40, json!({"parent":id(41)})),
            run.update(41, json!({"parent":id(30)})),
            run.update(20, json!({"amount":"20"})),
        ];
        if reverse {
            edits.reverse();
        }
        run.commit(Value::Array(edits));
        assert_eq!(
            (run.amount(41), run.amount(40), run.amount(50)),
            (68, 143, 211)
        );
        run.commit(json!([run.update(40, json!({"factor":"0"}))]));
        assert_eq!(run.amount(40), 7);
        // A zero coefficient still consumes authored bias and publication.
        run.reject(
            json!([run.update(41, json!({"parent":id(40)}))]),
            "feedback",
        );
    }
}

#[test]
fn self_direct_mixed_cycles_and_overflow_roll_back_every_table_and_receipt() {
    let mut run = Run::<0>::new();
    run.commit(json!([
        bucket(10),
        entry(20, 10, 0, 10),
        sum(30, 10, 10, 1),
        copy(40, 30, 2, 3),
        copy(41, 40, 3, 4),
        join(50, 40, 41, 0)
    ]));
    run.reject(
        json!([run.update(40, json!({"parent":id(40)}))]),
        "feedback",
    );
    run.reject(
        json!([run.update(40, json!({"parent":id(41)}))]),
        "feedback",
    );
    run.reject(
        json!([
            run.update(40, json!({"post":true,"at":"0"})),
            run.update(20, json!({"amount":"20"}))
        ]),
        "feedback",
    );
    run.reject(
        json!([
            run.update(40, json!({"factor":i128::MAX.to_string()})),
            run.update(20, json!({"amount":"20"}))
        ]),
        "overflow",
    );
    run.reject(json!([copy(43, 999, 1, 0)]), "unavailable_reference");
    run.reject(
        json!([run.update(40, json!({"parent":id(10)}))]),
        "unavailable_reference",
    );
    // A valid publication -> financial -> publication chain exercises mixed readiness.
    run.commit(json!([
        run.update(40, json!({"post":true,"at":"20"})),
        sum(31, 10, 30, 2),
        copy(42, 31, 2, 0)
    ]));
    assert_eq!((run.amount(31), run.amount(42)), (38, 78));
    run.commit(json!([run.update(20, json!({"amount":"20"}))]));
    assert_eq!((run.amount(31), run.amount(42)), (68, 138));
}

fn malformed<const MODE: u8>(kind: &str) {
    let mut run = Run::<MODE>::new();
    run.commit(json!([
        bucket(10),
        entry(20, 10, 0, 10),
        sum(30, 10, 10, 1),
        sum(31, 10, 10, 7)
    ]));
    run.reject(
        json!([run.update(20, json!({"amount":"20"})), copy(40, 30, 2, 3)]),
        kind,
    );
}
#[test]
fn malformed_resolved_slots_targets_native_type_and_tenant_are_atomic() {
    malformed::<1>("model"); // Missing mandatory input.
    malformed::<2>("model"); // Undeclared slot.
    malformed::<3>("model"); // Duplicate slot.
    malformed::<4>("model"); // Existing same-contract parent substituted by resolver.
    malformed::<5>("model"); // Projector produced an incompatible native variant.
    malformed::<6>("unavailable_reference"); // Parent no longer belongs to the transaction tenant.
    malformed::<7>("work_limit"); // Charged publication resolution aborts the complete transaction.
}

#[test]
fn prepared_publication_contract_rejects_unresolved_and_incompatible_declarations() {
    for fault in 0..6 {
        let mut declarations = declarations();
        let copy = declarations.iter_mut().find(|c| c.code == COPY).unwrap();
        match fault {
            0 => copy.publication_inputs[0].reference_slot = 77,
            1 => copy.publication_inputs[0].field_code = 777,
            2 => copy.publication_inputs[0].binding = "uuid",
            3 => copy.references[0].optional = true,
            4 => copy
                .publication_inputs
                .push(copy.publication_inputs[0].clone()),
            5 => copy.publication_inputs[0].slot = PublicationSlot(0),
            _ => unreachable!(),
        }
        assert_eq!(
            Prepared::<Fixture<0>>::prepare(declarations)
                .err()
                .unwrap()
                .code,
            "model"
        );
    }
}

#[test]
fn final_publication_and_financial_graph_matches_plain_enumerated_orders() {
    let vertices: BTreeSet<_> = [id(30), id(40), id(50)].into_iter().collect();
    let ids: Vec<_> = vertices.iter().copied().collect();
    // Distinguishing publication graphs, including one duplicate financial
    // edge and two mixed cycles. Existing graph/window tests own the algorithm's
    // broad combinatorial coverage; these rows exercise the new edge source.
    for (name, mask) in [
        ("isolated", 0u16),
        ("one publication", 2),
        ("chain", 34),
        ("reversed chain", 136),
        ("join", 36),
        ("fork", 6),
        ("self cycle", 16),
        ("direct cycle", 10),
        ("three publication cycle", 98),
        ("duplicate publication and financial edge", 576),
        ("mixed two-node cycle", 516),
        ("mixed three-node cycle", 546),
        ("mixed chain", 640),
    ] {
        let mut edges = BTreeSet::new();
        let mut shapes = vec![ResolvedShape::default(); 3];
        for parent in 0..3 {
            for child in 0..3 {
                if mask & (1 << (parent * 3 + child)) != 0 {
                    edges.insert((ids[parent], ids[child]));
                    shapes[child].publications.push(PublicationRead {
                        slot: PublicationSlot(parent as u16 + 1),
                        parent: ids[parent],
                    });
                }
            }
        }
        if mask & 512 != 0 {
            edges.insert((ids[2], ids[0]));
            shapes[2].emits.push(Emit {
                role: 7,
                contract: OUTPUT,
                root: Address::new(id(10), 7),
                at: 0,
            });
            shapes[0].reads.push(Read {
                slot: 31,
                root: Address::new(id(10), 7),
                range: TimeRange::before(10),
                validate: false,
            });
        }
        let valid = orders(&vertices, &edges);
        let mut ws = Attempt::<_, Fixture<0>>::new(|_| Ok(None), 200_000);
        let actual = crate::dependency::order(&mut ws, ids.iter().copied().zip(shapes.iter()));
        if valid.is_empty() {
            assert_eq!(actual.unwrap_err().code, "feedback", "{name}");
        } else {
            assert!(valid.contains(&actual.unwrap()), "{name}");
        }
    }
}
