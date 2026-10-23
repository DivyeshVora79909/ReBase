//! Test-only model: authored parent parameters enter a pure evaluator through
//! typed resolution, alongside an independently declared aggregate query.
use crate::{
    binding::{Binding, NativeInput},
    causal::{Emit, ReactiveBinding, Read, Resolved, ResolvedShape},
    index::TimeKey,
    indexes::standard::{FINANCIAL, Leaf, Standard},
    integrity::{Snapshot, require},
    local::{Mutation, Store},
    model::{
        self, Contract, InputField, Membership, OutputRole, Prepared, PublishedField, Reference,
        RootDeclaration, Visibility,
    },
    native_codec::{Address, Key, StoredValue, decimal, uuid_text},
    native_slice::{Attempt, Context, Error, Meta, Model, ModelChange, ModelRecord, Query, Result},
    routes,
    time_range::TimeRange,
    values::{Rational, Rounding},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};
use uuid::Uuid;

const RULE: u16 = 11;
const BUCKET: u16 = 20;
const ENTRY: u16 = 30;
const TAX: u16 = 40;
const GUARD: u16 = 50;
const PROBE: u16 = 60;
const OUTPUT: u16 = 90;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ParentTax;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum Input {
    Rule {
        rate: Rational,
        rounding: Rounding,
    },
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
    Tax {
        #[serde(with = "uuid_text")]
        rule: Uuid,
        #[serde(with = "uuid_text")]
        basis: Uuid,
        #[serde(with = "uuid_text")]
        output: Uuid,
        #[serde(with = "decimal")]
        at: i64,
    },
    Guard {
        #[serde(with = "uuid_text")]
        basis: Uuid,
        #[serde(with = "decimal")]
        before: i64,
        active: bool,
    },
    Probe {
        #[serde(with = "uuid_text")]
        basis: Uuid,
        active: bool,
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
    basis_sum: i128,
    #[serde(with = "decimal")]
    tax: i128,
}

impl NativeInput for Input {
    fn contract(&self) -> u16 {
        match self {
            Self::Rule { .. } => RULE,
            Self::Bucket { .. } => BUCKET,
            Self::Entry { .. } => ENTRY,
            Self::Tax { .. } => TAX,
            Self::Guard { .. } => GUARD,
            Self::Probe { .. } => PROBE,
            Self::Output { .. } => OUTPUT,
        }
    }
    fn validate(&self) -> Result<()> {
        if matches!(self, Self::Bucket { unit: 0 })
            || matches!(self, Self::Output { role, .. } if *role != 11)
        {
            return Err(Error::new("invalid_input", "test model scalar bounds"));
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
                "complete canonical input required",
            ));
        }
        Ok(input)
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        match self {
            Self::Entry { bucket, .. } => vec![(*bucket, BUCKET, 1)],
            Self::Tax {
                rule,
                basis,
                output,
                ..
            } => {
                vec![(*rule, RULE, 1), (*basis, BUCKET, 2), (*output, BUCKET, 3)]
            }
            Self::Output {
                producer, bucket, ..
            } => {
                vec![(*producer, TAX, 1), (*bucket, BUCKET, 2)]
            }
            Self::Guard { basis, .. } | Self::Probe { basis, .. } => vec![(*basis, BUCKET, 1)],
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

fn scalar(binding: &str, minimum: i128, maximum: i128) -> Value {
    json!({"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","x-rebase-binding":binding,"x-rebase-range":[minimum.to_string(),maximum.to_string()]})
}
fn reference(slot: u16, field: &'static str, target: u16) -> Reference {
    Reference {
        slot,
        field,
        targets: vec![target],
        optional: false,
        direct_fields: if target == RULE {
            vec!["rate", "rounding"]
        } else {
            vec![]
        },
        on_delete: "reject",
        reader: false,
    }
}
fn contract(
    code: u16,
    name: &'static str,
    fields: &[(u16, &'static str)],
    properties: Value,
) -> Contract {
    Contract {
        code,
        name,
        visibility: if code == OUTPUT {
            Visibility::Engine
        } else {
            Visibility::Public
        },
        schema: json!({"$schema":model::SCHEMA_DIALECT,"type":"object","additionalProperties":false,"properties":properties,"required":fields.iter().map(|(_,name)|name).collect::<Vec<_>>()}),
        fields: fields
            .iter()
            .map(|&(code, name)| InputField {
                code,
                name,
                mutable: name != "unit",
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
        schema_source: "src/parameter_tests.rs",
        behavior_source: "src/parameter_tests.rs",
    }
}
fn declarations() -> Vec<Contract> {
    let uuid = json!({"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","x-rebase-binding":"uuid"});
    let time = scalar("i64", i128::from(i64::MIN), i128::from(i64::MAX));
    let amount = scalar("i128", i128::MIN, i128::MAX);
    let rule = contract(
        RULE,
        "Rule",
        &[(1, "rate"), (2, "rounding")],
        json!({"rate":Rational::schema(),"rounding":Rounding::schema()}),
    );
    let mut bucket = contract(
        BUCKET,
        "Bucket",
        &[(1, "unit")],
        json!({"unit":{"type":"integer","minimum":1,"maximum":65535,"x-rebase-binding":"u16_code"}}),
    );
    bucket.roots.push(RootDeclaration {
        slot: 7,
        name: "amounts",
        kind: FINANCIAL,
        reads: vec!["summary", "sum", "range"],
        invariant: None,
    });
    let mut entry = contract(
        ENTRY,
        "Entry",
        &[(1, "bucket"), (2, "at"), (3, "amount")],
        json!({"bucket":uuid,"at":time,"amount":amount}),
    );
    entry.references.push(reference(1, "bucket", BUCKET));
    entry.memberships.push(Membership {
        slot: 17,
        through: "bucket",
        root_contract: BUCKET,
        root_slot: 7,
        kind: FINANCIAL,
        key: "at",
        value: "amount",
    });
    let mut tax = contract(
        TAX,
        "Tax",
        &[(1, "rule"), (2, "basis"), (3, "output"), (4, "at")],
        json!({"rule":uuid,"basis":uuid,"output":uuid,"at":time}),
    );
    tax.references = vec![
        reference(1, "rule", RULE),
        reference(2, "basis", BUCKET),
        reference(3, "output", BUCKET),
    ];
    tax.published = vec![
        PublishedField {
            code: 101,
            name: "basis_sum",
            binding: "i128",
        },
        PublishedField {
            code: 102,
            name: "tax",
            binding: "i128",
        },
    ];
    tax.queries.push(model::QueryDeclaration {
        slot: 31,
        through: "basis",
        root_contract: BUCKET,
        root_slot: 7,
        operation: "sum",
        phase: "calculate",
        channel: "amount",
        bound: "all",
        fallback: Some("0"),
    });
    tax.outputs.push(OutputRole {
        role: 11,
        contract: OUTPUT,
        active: "always",
        account: "output",
        at: "at",
        amount: "tax",
        depends_on: vec!["tax"],
    });
    tax.calculations.push(model::Calculation {
        name: "tax",
        inputs: vec![],
        expression: "parameters.rate.apply(query[31],parameters.rounding)",
    });
    let mut output = contract(
        OUTPUT,
        "Output",
        &[
            (1, "producer"),
            (2, "role"),
            (3, "bucket"),
            (4, "at"),
            (5, "amount"),
        ],
        json!({"producer":uuid,"role":{"type":"integer","const":11},"bucket":uuid,"at":time,"amount":amount}),
    );
    output.references = vec![
        reference(1, "producer", TAX),
        reference(2, "bucket", BUCKET),
    ];
    output.memberships.push(Membership {
        slot: 23,
        through: "bucket",
        root_contract: BUCKET,
        root_slot: 7,
        kind: FINANCIAL,
        key: "at",
        value: "amount",
    });
    let mut guard = contract(
        GUARD,
        "Guard",
        &[(1, "basis"), (2, "before"), (3, "active")],
        json!({"basis":uuid,"before":time,"active":{"type":"boolean"}}),
    );
    guard.references.push(reference(1, "basis", BUCKET));
    guard.queries.push(model::QueryDeclaration {
        slot: 31,
        through: "basis",
        root_contract: BUCKET,
        root_slot: 7,
        operation: "sum",
        phase: "validate",
        channel: "amount",
        bound: "strictly before before, when active",
        fallback: Some("0"),
    });
    let mut probe = contract(
        PROBE,
        "Probe",
        &[(1, "basis"), (2, "active")],
        json!({"basis":uuid,"active":{"type":"boolean"}}),
    );
    probe.references.push(reference(1, "basis", BUCKET));
    probe.published = tax.published.clone();
    probe.queries.push(model::QueryDeclaration {
        slot: 31,
        through: "basis",
        root_contract: BUCKET,
        root_slot: 7,
        operation: "sum",
        phase: "calculate",
        channel: "amount",
        bound: "all, when active",
        fallback: Some("0"),
    });
    probe.calculations.push(model::Calculation {
        name: "basis_sum",
        inputs: vec![],
        expression: "active ? query[31] : 0",
    });
    vec![rule, bucket, entry, tax, guard, probe, output]
}

fn registrations(id: Uuid, input: Option<&Input>) -> BTreeSet<(Key, Address)> {
    let mut result = BTreeSet::new();
    if let Some(input) = input {
        for (target, _, slot) in input.references() {
            result.insert((Key::Incoming(target), Address::new(id, slot)));
        }
        if let Input::Tax { rule, .. } = input {
            result.insert((Key::Direct(*rule), Address::new(id, 1)));
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
impl Binding for ParentTax {
    type Index = Standard;
    type Input = Input;
    type Derived = Derived;
    const NAME: &'static str = "test-parent-tax";
    const BEHAVIOR: &'static str = "test-parent-tax-3";
    fn declarations() -> Result<Vec<Contract>> {
        Ok(declarations())
    }
    fn engine() -> Result<Model> {
        Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
    }
    fn valid_derived(input: &Input, derived: Option<&Derived>) -> bool {
        matches!(
            (input, derived),
            (Input::Tax { .. } | Input::Probe { .. }, Some(_))
        ) || (!matches!(input, Input::Tax { .. } | Input::Probe { .. }) && derived.is_none())
    }
    fn published_shape(code: u16) -> Value {
        if matches!(code, TAX | PROBE) {
            json!({"basis_sum":"0","tax":"0"})
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

// Deliberately no Clone, Debug, Default, Eq or serialization implementation:
// resolved parameters are an attempt-local native value, not persisted state.
enum Parameters {
    Tax { rate: Rational, rounding: Rounding },
    ReadOnly,
}
impl ReactiveBinding for ParentTax {
    type Publication = ();
    type Parameters = Parameters;
    fn resolve<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        context: Context,
        _id: Uuid,
        record: &ModelRecord<Self>,
    ) -> Result<Resolved<Parameters>> {
        if let Input::Guard {
            basis,
            before,
            active,
        } = record.input
        {
            return Ok(Resolved {
                shape: ResolvedShape {
                    publications: vec![],
                    reads: if active {
                        vec![Read {
                            slot: 31,
                            root: Address::new(basis, 7),
                            range: TimeRange::before(before),
                            validate: true,
                        }]
                    } else {
                        vec![]
                    },
                    emits: vec![],
                },
                parameters: Parameters::ReadOnly,
            });
        }
        if let Input::Probe { basis, active } = record.input {
            return Ok(Resolved {
                shape: ResolvedShape {
                    publications: vec![],
                    reads: if active {
                        vec![Read {
                            slot: 31,
                            root: Address::new(basis, 7),
                            range: TimeRange::ALL,
                            validate: false,
                        }]
                    } else {
                        vec![]
                    },
                    emits: vec![],
                },
                parameters: Parameters::ReadOnly,
            });
        }
        let Input::Tax {
            rule,
            basis,
            output,
            at,
        } = record.input
        else {
            return Err(Error::new("corrupt_state", "tax resolver contract"));
        };
        let parent = ws
            .record(rule)?
            .filter(|r| r.tenant == context.tenant && r.contract == RULE)
            .ok_or_else(|| Error::new("unavailable_reference", "authored parent unavailable"))?;
        let Input::Rule { rate, rounding } = parent.input else {
            return Err(Error::new(
                "unavailable_reference",
                "authored parent contract",
            ));
        };
        Ok(Resolved {
            shape: ResolvedShape {
                publications: vec![],
                reads: vec![Read {
                    slot: 31,
                    root: Address::new(basis, 7),
                    range: TimeRange::ALL,
                    validate: false,
                }],
                emits: vec![Emit {
                    role: 11,
                    contract: OUTPUT,
                    root: Address::new(output, 7),
                    at,
                }],
            },
            parameters: Parameters::Tax { rate, rounding },
        })
    }
    fn evaluate(
        _id: Uuid,
        record: &ModelRecord<Self>,
        _shape: &ResolvedShape,
        parameters: &Parameters,
        _publications: &[crate::causal::PublicationValue<Self::Publication>],
        values: &[i128],
    ) -> Result<(Derived, BTreeMap<u16, i128>)> {
        assert!(
            !matches!(record.input, Input::Guard { .. }),
            "terminal validators must never enter the formula evaluator"
        );
        match parameters {
            Parameters::Tax { rate, rounding } => {
                let basis_sum = *values
                    .first()
                    .ok_or_else(|| Error::new("internal", "missing basis sum"))?;
                let tax = rate.apply(basis_sum, *rounding)?;
                Ok((Derived { basis_sum, tax }, BTreeMap::from([(11, tax)])))
            }
            Parameters::ReadOnly => Ok((
                Derived {
                    basis_sum: values.first().copied().unwrap_or(0),
                    tax: 0,
                },
                BTreeMap::new(),
            )),
        }
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
            _ => Err(Error::new("corrupt_state", "tax output contract")),
        }
    }
}

// Independent small-number checker for the authored acceptance states. It
// derives quantities solely from Rule/Entry sources, never native query/output
// caches, and uses ordinary quotient/remainder rather than Rational::apply.
fn expected_tax(amount: i128, rate: Rational, rounding: Rounding) -> Result<i128> {
    let product = amount
        .checked_mul(rate.numerator())
        .ok_or_else(|| Error::new("corrupt_state", "test oracle product bound"))?;
    let denominator = rate.denominator();
    let quotient = product / denominator;
    let remainder = product % denominator;
    let magnitude = remainder.abs();
    let sign = product.signum();
    let step = match rounding {
        Rounding::TowardZero => false,
        Rounding::Floor => remainder < 0,
        Rounding::Ceiling => remainder > 0,
        Rounding::HalfEven => {
            magnitude > denominator - magnitude
                || (magnitude == denominator - magnitude && quotient % 2 != 0)
        }
        Rounding::HalfAwayFromZero => magnitude >= denominator - magnitude,
        Rounding::Exact if remainder != 0 => {
            return Err(Error::new("corrupt_state", "test oracle inexact"));
        }
        Rounding::Exact => false,
    };
    quotient
        .checked_add(if step { sign } else { 0 })
        .ok_or_else(|| Error::new("corrupt_state", "test oracle result bound"))
}
fn check(store: &Store<ParentTax>) -> Result<Value> {
    let snapshot = Snapshot::load(store)?;
    let keys = snapshot.expected_keys.clone();
    let mut routes = snapshot.routes.clone();
    let mut members = BTreeMap::new();
    let mut queries = BTreeMap::new();
    let mut sums = BTreeMap::<Uuid, i128>::new();
    for (&id, record) in &snapshot.records {
        if let Input::Entry { bucket, at, amount } = record.input {
            let sum = sums.entry(bucket).or_default();
            *sum = sum
                .checked_add(amount)
                .ok_or_else(|| Error::new("corrupt_state", "test source sum"))?;
            members.insert(
                Address::new(id, 17),
                (Address::new(bucket, 7), at, Leaf::Financial(amount)),
            );
        }
    }
    let mut outputs = BTreeMap::new();
    for (&id, record) in &snapshot.records {
        if let Input::Tax {
            rule,
            basis,
            output,
            at,
        } = record.input
        {
            let Input::Rule { rate, rounding } = snapshot.records[&rule].input else {
                return Err(Error::new("corrupt_state", "test parent type"));
            };
            let basis_sum = sums.get(&basis).copied().unwrap_or(0);
            let tax = expected_tax(basis_sum, rate, rounding)?;
            require(
                record.derived == Some(Derived { basis_sum, tax }),
                "source-derived inherited tax",
            )?;
            routes
                .entry(Key::Direct(rule))
                .or_default()
                .insert(Address::new(id, 1));
            routes
                .entry(Key::Subscribers(Address::new(basis, 7)))
                .or_default()
                .insert(Address::new(id, 31));
            queries.insert(
                Address::new(id, 31),
                Query {
                    source: Address::new(basis, 7),
                    operation: "sum".into(),
                    phase: "calculate".into(),
                    channel: "amount".into(),
                    range: TimeRange::ALL,
                    selected: None,
                    result: basis_sum,
                },
            );
            let Some(StoredValue::Role(binding)) =
                snapshot.all.get(&Key::Role(Address::new(id, 11)))
            else {
                return Err(Error::new("corrupt_state", "missing tax output role"));
            };
            require(!binding.retired, "active tax role")?;
            outputs.insert(
                binding.output,
                Input::Output {
                    producer: id,
                    role: 11,
                    bucket: output,
                    at,
                    amount: tax,
                },
            );
            members.insert(
                Address::new(binding.output, 23),
                (Address::new(output, 7), at, Leaf::Financial(tax)),
            );
        }
    }
    let actual: BTreeMap<_, _> = snapshot
        .records
        .iter()
        .filter(|(_, r)| matches!(r.input, Input::Output { .. }))
        .map(|(id, r)| (*id, r.input.clone()))
        .collect();
    require(
        actual == outputs,
        "complete source-derived tax output inventory",
    )?;
    // Guard and probe expectations include source-derived managed emissions,
    // never the actual private output records or maintained root summaries.
    for (&id, record) in &snapshot.records {
        let (basis, before, validate) = match record.input {
            Input::Guard {
                basis,
                before,
                active,
            } => {
                require(record.derived.is_none(), "guard has no derived value")?;
                if !active {
                    continue;
                }
                (basis, Some(before), true)
            }
            Input::Probe { basis, active } => {
                if !active {
                    require(
                        record.derived
                            == Some(Derived {
                                basis_sum: 0,
                                tax: 0,
                            }),
                        "inactive calculation reader recomputes its authored fallback",
                    )?;
                    continue;
                }
                (basis, None, false)
            }
            _ => continue,
        };
        let mut result = 0i128;
        for (root, at, leaf) in members.values() {
            if *root == Address::new(basis, 7) && before.is_none_or(|bound| *at < bound) {
                let Leaf::Financial(amount) = leaf else {
                    return Err(Error::new("corrupt_state", "test expected member kind"));
                };
                result = result
                    .checked_add(*amount)
                    .ok_or_else(|| Error::new("corrupt_state", "test reader sum"))?;
            }
        }
        if validate {
            require(result >= 0, "source-derived terminal nonnegative sum")?;
        } else {
            require(
                record.derived
                    == Some(Derived {
                        basis_sum: result,
                        tax: 0,
                    }),
                "source-derived calculation without outputs",
            )?;
        }
        routes
            .entry(Key::Subscribers(Address::new(basis, 7)))
            .or_default()
            .insert(Address::new(id, 31));
        queries.insert(
            Address::new(id, 31),
            Query {
                source: Address::new(basis, 7),
                operation: "sum".into(),
                phase: if validate { "validate" } else { "calculate" }.into(),
                channel: "amount".into(),
                range: before.map_or(TimeRange::ALL, TimeRange::before),
                selected: None,
                result,
            },
        );
    }
    snapshot.finish(keys, members, routes, queries)
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/parent-parameter-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn file(&self) -> PathBuf {
        self.0.join("model.redb")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn create(directory: &Directory) -> Store<ParentTax> {
    Store::create(
        directory.file(),
        Arc::new(Prepared::load().unwrap()),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap()
}
fn request(store: &Store<ParentTax>, operation: u128, commands: Value) -> Mutation {
    serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":id(operation),"commands":commands,"returning":[id(40)]})).unwrap()
}
fn commit(store: &Store<ParentTax>, operation: u128, commands: Value) -> (Mutation, Value) {
    let request = request(store, operation, commands);
    let result = store
        .mutate_with_ids(&request, &mut || Ok(id(100)))
        .unwrap();
    store.check_integrity().unwrap();
    (request, result)
}
fn seed(store: &Store<ParentTax>) {
    commit(
        store,
        1000,
        json!([
            {"op":"create","id":id(10),"contract":RULE,"fields":{"rate":{"numerator":"1","denominator":"10"},"rounding":"half_even"}},
            {"op":"create","id":id(11),"contract":RULE,"fields":{"rate":{"numerator":"1","denominator":"4"},"rounding":"half_even"}},
            {"op":"create","id":id(20),"contract":BUCKET,"fields":{"unit":1}},
            {"op":"create","id":id(21),"contract":BUCKET,"fields":{"unit":1}},
            {"op":"create","id":id(30),"contract":ENTRY,"fields":{"bucket":id(20),"at":"0","amount":"10005"}},
            {"op":"create","id":id(40),"contract":TAX,"fields":{"rule":id(10),"basis":id(20),"output":id(21),"at":"1"}}
        ]),
    );
}
fn record(store: &Store<ParentTax>, n: u128) -> ModelRecord<ParentTax> {
    Snapshot::load(store).unwrap().records[&id(n)].clone()
}
fn update(store: &Store<ParentTax>, n: u128, set: Value) -> Value {
    json!({"op":"update","id":id(n),"if_version":record(store,n).version.to_string(),"set":set,"unset":[]})
}
fn assert_tax(store: &Store<ParentTax>, basis: i128, tax: i128) {
    assert_eq!(
        record(store, 40).derived,
        Some(Derived {
            basis_sum: basis,
            tax
        })
    );
    assert_eq!(
        record(store, 100).input,
        Input::Output {
            producer: id(40),
            role: 11,
            bucket: id(21),
            at: 1,
            amount: tax
        }
    );
    let snapshot = Snapshot::load(store).unwrap();
    let Some(StoredValue::Role(binding)) = snapshot.all.get(&Key::Role(Address::new(id(40), 11)))
    else {
        panic!("output role");
    };
    assert_eq!(binding.output, id(100));
    store.check_integrity().unwrap();
}

fn commit_reader(store: &Store<ParentTax>, operation: u128, commands: Value) -> (Mutation, Value) {
    let request = request(store, operation, commands);
    let result = store
        .mutate_with_ids(&request, &mut || {
            panic!("readers without outputs must not allocate output identities")
        })
        .unwrap();
    store.check_integrity().unwrap();
    (request, result)
}
fn reject(store: &Store<ParentTax>, operation: u128, commands: Value, kind: &str) {
    let before = store.observe_for_verification().unwrap();
    let before_inspect = store.inspect().unwrap();
    let request = request(store, operation, commands);
    assert_eq!(store.mutate(&request).unwrap_err().code, kind);
    assert_eq!(store.observe_for_verification().unwrap(), before);
    assert_eq!(store.inspect().unwrap(), before_inspect);
    assert_eq!(
        store
            .operation_status(
                store.model().identity(),
                &request.context,
                request.operation_id
            )
            .unwrap()["status"],
        "not_observed"
    );
    store.check_integrity().unwrap();
}
fn reader_query(store: &Store<ParentTax>, n: u128) -> Option<Query> {
    match Snapshot::load(store)
        .unwrap()
        .all
        .get(&Key::Query(Address::new(id(n), 31)))
    {
        Some(StoredValue::Query(query)) => Some(query.clone()),
        None => None,
        _ => panic!("reader query type"),
    }
}

#[test]
fn terminal_only_reader_tracks_strict_bounds_roots_activation_and_deletion() {
    let directory = Directory::new();
    let store = create(&directory);
    seed(&store);
    commit(
        &store,
        1300,
        json!([
            {"op":"create","id":id(22),"contract":BUCKET,"fields":{"unit":1}},
            {"op":"create","id":id(31),"contract":ENTRY,"fields":{"bucket":id(22),"at":"5","amount":"-7"}}
        ]),
    );
    reject(
        &store,
        1301,
        json!([{"op":"create","id":id(51),"contract":GUARD,"fields":{"basis":id(22),"before":"6","active":true}}]),
        "invariant",
    );
    commit_reader(
        &store,
        1302,
        json!([{"op":"create","id":id(50),"contract":GUARD,"fields":{"basis":id(20),"before":"1","active":true}}]),
    );
    assert!(record(&store, 50).derived.is_none());
    assert_eq!(reader_query(&store, 50).unwrap().result, 10005);
    let guard = record(&store, 50);
    // Equal-time contributions are outside a strict prefix, including changes
    // that make the whole root negative. No root invariant protects this guard.
    commit(
        &store,
        1303,
        json!([{"op":"create","id":id(32),"contract":ENTRY,"fields":{"bucket":id(20),"at":"1","amount":"-20000"}}]),
    );
    assert_eq!(record(&store, 50), guard);
    assert_eq!(reader_query(&store, 50).unwrap().result, 10005);
    reject(
        &store,
        1304,
        json!([update(&store, 50, json!({"before":"2"}))]),
        "invariant",
    );
    commit_reader(
        &store,
        1305,
        json!([update(&store, 50, json!({"basis":id(22),"before":"5"}))]),
    );
    assert_eq!(reader_query(&store, 50).unwrap().result, 0);
    let guard = record(&store, 50);
    commit(
        &store,
        1306,
        json!([update(&store, 30, json!({"amount":"-10005"}))]),
    );
    assert_eq!(record(&store, 50), guard);
    reject(
        &store,
        1307,
        json!([update(&store, 50, json!({"before":"6"}))]),
        "invariant",
    );
    commit_reader(
        &store,
        1308,
        json!([update(&store, 50, json!({"active":false}))]),
    );
    assert!(reader_query(&store, 50).is_none());
    commit(
        &store,
        1309,
        json!([update(&store, 31, json!({"amount":"-9"}))]),
    );
    reject(
        &store,
        1310,
        json!([update(&store, 50, json!({"active":true,"before":"6"}))]),
        "invariant",
    );
    commit_reader(
        &store,
        1311,
        json!([update(&store, 50, json!({"active":true,"before":"5"}))]),
    );
    assert_eq!(reader_query(&store, 50).unwrap().result, 0);
    reject(
        &store,
        1312,
        json!([update(&store, 31, json!({"at":"4"}))]),
        "invariant",
    );
    let (last_request, last_result) = commit_reader(
        &store,
        1313,
        json!([{"op":"delete","id":id(50),"if_version":record(&store,50).version.to_string()}]),
    );
    assert!(reader_query(&store, 50).is_none());
    let before = store.observe_for_verification().unwrap();
    let replay = store.mutate(&last_request).unwrap();
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["result"], last_result["result"]);
    assert_eq!(store.observe_for_verification().unwrap(), before);
    commit(&store, 1314, json!([update(&store, 31, json!({"at":"4"}))]));
    let before = store.observe_for_verification().unwrap();
    drop(store);
    let reopened =
        Store::<ParentTax>::open(directory.file(), Arc::new(Prepared::load().unwrap())).unwrap();
    reopened.check_integrity().unwrap();
    assert_eq!(reopened.observe_for_verification().unwrap(), before);
    assert_eq!(
        reopened.mutate(&last_request).unwrap()["result"],
        last_result["result"]
    );
}

#[test]
fn terminal_reader_checks_the_final_repaired_prefix_in_both_command_orders() {
    let mut expected = None;
    for reverse in [false, true] {
        let directory = Directory::new();
        let store = create(&directory);
        seed(&store);
        commit_reader(
            &store,
            1400,
            json!([{"op":"create","id":id(50),"contract":GUARD,"fields":{"basis":id(20),"before":"1","active":true}}]),
        );
        reject(
            &store,
            1401,
            json!([update(&store, 30, json!({"amount":"-1"}))]),
            "invariant",
        );
        let negative = update(&store, 30, json!({"amount":"-1"}));
        let repair = json!({"op":"create","id":id(31),"contract":ENTRY,"fields":{"bucket":id(20),"at":"0","amount":"2"}});
        commit(
            &store,
            1402,
            if reverse {
                json!([repair, negative])
            } else {
                json!([negative, repair])
            },
        );
        assert_eq!(reader_query(&store, 50).unwrap().result, 1);
        let snapshot = Snapshot::load(&store).unwrap();
        let logical: BTreeMap<_, _> = snapshot
            .all
            .iter()
            .filter(|(key, _)| matches!(key, Key::Record(_) | Key::Query(_)))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        if let Some(expected) = &expected {
            assert_eq!(&logical, expected);
        } else {
            expected = Some(logical);
        }
    }
}

#[test]
fn calculation_only_reader_recomputes_fallback_when_its_query_is_inactive() {
    let directory = Directory::new();
    let store = create(&directory);
    seed(&store);
    commit_reader(
        &store,
        1450,
        json!([{"op":"create","id":id(60),"contract":PROBE,"fields":{"basis":id(20),"active":false}}]),
    );
    assert!(reader_query(&store, 60).is_none());
    assert_eq!(
        record(&store, 60).derived,
        Some(Derived {
            basis_sum: 0,
            tax: 0
        })
    );
    commit_reader(
        &store,
        1451,
        json!([update(&store, 60, json!({"active":true}))]),
    );
    assert_eq!(reader_query(&store, 60).unwrap().result, 10005);
    assert_eq!(
        record(&store, 60).derived,
        Some(Derived {
            basis_sum: 10005,
            tax: 0
        })
    );
    // Clearing the resolved read still runs the declared calculation with an
    // empty input slice. Retaining the old derived value would be stale state.
    let (last_request, last_result) = commit_reader(
        &store,
        1452,
        json!([update(&store, 60, json!({"active":false}))]),
    );
    assert!(reader_query(&store, 60).is_none());
    assert_eq!(
        record(&store, 60).derived,
        Some(Derived {
            basis_sum: 0,
            tax: 0
        })
    );
    let inactive = record(&store, 60);
    commit(
        &store,
        1453,
        json!([update(&store, 30, json!({"amount":"10007"}))]),
    );
    assert_eq!(record(&store, 60), inactive);
    let before = store.observe_for_verification().unwrap();
    assert_eq!(
        store.mutate(&last_request).unwrap()["result"],
        last_result["result"]
    );
    assert_eq!(store.observe_for_verification().unwrap(), before);
    commit_reader(
        &store,
        1454,
        json!([update(&store, 60, json!({"active":true}))]),
    );
    assert_eq!(reader_query(&store, 60).unwrap().result, 10007);
    assert_eq!(
        record(&store, 60).derived,
        Some(Derived {
            basis_sum: 10007,
            tax: 0
        })
    );
}

#[test]
fn terminal_reader_waits_for_managed_outputs_and_calculation_only_reader_evaluates() {
    let mut expected = None;
    for reverse in [false, true] {
        let directory = Directory::new();
        let store = create(&directory);
        seed(&store);
        commit(
            &store,
            1500,
            json!([{"op":"create","id":id(31),"contract":ENTRY,"fields":{"bucket":id(21),"at":"0","amount":"-1000"}}]),
        );
        commit_reader(
            &store,
            1501,
            json!([
                {"op":"create","id":id(50),"contract":GUARD,"fields":{"basis":id(21),"before":"2","active":true}},
                {"op":"create","id":id(60),"contract":PROBE,"fields":{"basis":id(21),"active":true}}
            ]),
        );
        assert_eq!(reader_query(&store, 50).unwrap().result, 0);
        assert_eq!(
            record(&store, 60).derived,
            Some(Derived {
                basis_sum: 0,
                tax: 0
            })
        );
        let stale = update(&store, 50, json!({"before":"3"}));
        commit_reader(
            &store,
            1502,
            json!([update(&store, 50, json!({"before":"4"}))]),
        );
        reject(&store, 1503, json!([stale]), "stale_version");
        reject(
            &store,
            1504,
            json!([update(&store, 30, json!({"amount":"9985"}))]),
            "invariant",
        );
        let producer = update(&store, 30, json!({"amount":"9985"}));
        let repair = update(&store, 31, json!({"amount":"-998"}));
        let (last_request, last_result) = commit(
            &store,
            1505,
            if reverse {
                json!([repair, producer])
            } else {
                json!([producer, repair])
            },
        );
        assert_tax(&store, 9985, 998);
        assert_eq!(reader_query(&store, 50).unwrap().result, 0);
        assert_eq!(
            record(&store, 60).derived,
            Some(Derived {
                basis_sum: 0,
                tax: 0
            })
        );
        let snapshot = Snapshot::load(&store).unwrap();
        let logical: BTreeMap<_, _> = snapshot
            .all
            .iter()
            .filter(|(key, _)| matches!(key, Key::Record(_) | Key::Query(_)))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        if let Some(expected) = &expected {
            assert_eq!(&logical, expected);
        } else {
            expected = Some(logical);
        }
        drop(snapshot);
        // A later producer edit must refresh the output-free calculation even
        // if the validator remains valid and has no formula of its own.
        commit(
            &store,
            1506,
            json!([update(&store, 30, json!({"amount":"10005"}))]),
        );
        assert_eq!(reader_query(&store, 50).unwrap().result, 2);
        assert_eq!(
            record(&store, 60).derived,
            Some(Derived {
                basis_sum: 2,
                tax: 0
            })
        );
        let before = store.observe_for_verification().unwrap();
        assert_eq!(
            store.mutate(&last_request).unwrap()["result"],
            last_result["result"]
        );
        assert_eq!(store.observe_for_verification().unwrap(), before);
        drop(store);
        let reopened =
            Store::<ParentTax>::open(directory.file(), Arc::new(Prepared::load().unwrap()))
                .unwrap();
        reopened.check_integrity().unwrap();
        assert_eq!(reopened.observe_for_verification().unwrap(), before);
    }
}

#[test]
fn inherited_parameters_react_retarget_and_survive_replay_and_reopening() {
    let directory = Directory::new();
    let store = create(&directory);
    seed(&store);
    assert_tax(&store, 10005, 1000);
    let declaration = store.model().contract(TAX).unwrap();
    assert_eq!(
        declaration.references[0].direct_fields,
        vec!["rate", "rounding"]
    );
    assert_eq!(
        store.model().contract(RULE).unwrap().schema["properties"]["rate"],
        Rational::schema()
    );
    commit(
        &store,
        1001,
        json!([update(
            &store,
            10,
            json!({"rounding":"half_away_from_zero"})
        )]),
    );
    assert_tax(&store, 10005, 1001);
    commit(
        &store,
        1002,
        json!([update(&store, 10, json!({"rounding":"half_even"}))]),
    );
    assert_tax(&store, 10005, 1000);
    // The rounded value stays equal; the direct registration must still survive.
    commit(
        &store,
        1003,
        json!([update(
            &store,
            10,
            json!({"rate":{"numerator":"10000","denominator":"100001"}})
        )]),
    );
    assert_tax(&store, 10005, 1000);
    commit(
        &store,
        1004,
        json!([update(
            &store,
            10,
            json!({"rate":{"numerator":"1","denominator":"5"}})
        )]),
    );
    assert_tax(&store, 10005, 2001);
    commit(
        &store,
        1005,
        json!([update(&store, 40, json!({"rule":id(11)}))]),
    );
    assert_tax(&store, 10005, 2501);
    let old_output = record(&store, 100);
    let old_tax = record(&store, 40);
    // A stale direct registration would select/rewrite the producer and output.
    commit(
        &store,
        1006,
        json!([update(
            &store,
            10,
            json!({"rate":{"numerator":i128::MAX.to_string(),"denominator":"1"},"rounding":"exact"})
        )]),
    );
    assert_eq!(record(&store, 100), old_output);
    assert_eq!(record(&store, 40), old_tax);
    let snapshot = Snapshot::load(&store).unwrap();
    let Some(StoredValue::Direct(old_route)) = snapshot.all.get(&Key::Direct(id(10))) else {
        panic!("old direct header");
    };
    assert_eq!(old_route.len, 0);
    drop(snapshot);
    let (last_request, last_result) = commit(
        &store,
        1007,
        json!([update(&store, 30, json!({"amount":"10007"}))]),
    );
    assert_tax(&store, 10007, 2502);
    let before = store.observe_for_verification().unwrap();
    let replay = store.mutate(&last_request).unwrap();
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["result"], last_result["result"]);
    assert_eq!(store.observe_for_verification().unwrap(), before);
    drop(store);
    let reopened =
        Store::<ParentTax>::open(directory.file(), Arc::new(Prepared::load().unwrap())).unwrap();
    assert_tax(&reopened, 10007, 2502);
    assert_eq!(reopened.observe_for_verification().unwrap(), before);
    assert_eq!(
        reopened.mutate(&last_request).unwrap()["result"],
        last_result["result"]
    );
}

#[test]
fn rejected_parent_changes_leave_all_tables_revision_and_receipts_unchanged() {
    let directory = Directory::new();
    let store = create(&directory);
    seed(&store);
    let before = store.observe_for_verification().unwrap();
    let before_inspect = store.inspect().unwrap();
    for (index, (command, kind)) in [
        (update(&store, 10, json!({"rounding":"exact"})), "inexact"),
        (
            update(
                &store,
                10,
                json!({"rate":{"numerator":i128::MAX.to_string(),"denominator":"1"}}),
            ),
            "overflow",
        ),
        (
            update(&store, 40, json!({"rule":id(999)})),
            "unavailable_reference",
        ),
        (
            update(&store, 40, json!({"rule":id(20)})),
            "unavailable_reference",
        ),
        (
            json!({"op":"delete","id":id(10),"if_version":record(&store,10).version.to_string()}),
            "unavailable_reference",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        // Stage another valid write first; rejection must discard every change.
        let request = request(
            &store,
            1100 + index as u128,
            json!([update(&store, 11, json!({"rounding":"floor"})), command]),
        );
        assert_eq!(store.mutate(&request).unwrap_err().code, kind);
        assert_eq!(store.observe_for_verification().unwrap(), before);
        assert_eq!(store.inspect().unwrap(), before_inspect);
        assert_eq!(
            store
                .operation_status(
                    store.model().identity(),
                    &request.context,
                    request.operation_id
                )
                .unwrap()["status"],
            "not_observed"
        );
        store.check_integrity().unwrap();
    }
    assert_tax(&store, 10005, 1000);
}

#[test]
fn parent_edit_and_retarget_use_the_final_authored_state_in_both_orders() {
    for edit_old_parent in [false, true] {
        let mut expected_records = None;
        let mut expected_queries = None;
        for reverse in [false, true] {
            let directory = Directory::new();
            let store = create(&directory);
            seed(&store);
            let parent = if edit_old_parent {
                // Invalid for the old consumer but harmless after retargeting.
                update(&store, 10, json!({"rounding":"exact"}))
            } else {
                update(
                    &store,
                    11,
                    json!({"rate":{"numerator":"1","denominator":"5"}}),
                )
            };
            let child = update(&store, 40, json!({"rule":id(11)}));
            let commands = if reverse {
                json!([child, parent])
            } else {
                json!([parent, child])
            };
            commit(&store, 1200, commands);
            assert_tax(&store, 10005, if edit_old_parent { 2501 } else { 2001 });
            let snapshot = Snapshot::load(&store).unwrap();
            let queries: BTreeMap<_, _> = snapshot
                .all
                .iter()
                .filter(|(key, _)| matches!(key, Key::Query(_)))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            if let Some(expected) = &expected_records {
                assert_eq!(&snapshot.records, expected);
                assert_eq!(Some(&queries), expected_queries.as_ref());
            } else {
                expected_records = Some(snapshot.records.clone());
                expected_queries = Some(queries);
            }
        }
    }
}
