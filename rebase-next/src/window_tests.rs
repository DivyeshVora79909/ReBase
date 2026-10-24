//! Independent source-window fixture. This test binding uses the ordinary
//! model/transaction interfaces; its checker never calls the writer, tree query,
//! evaluator, range predicate or production dependency graph for expectations.
use crate::{
    binding::{Binding, NativeInput},
    causal::{Emit, ReactiveBinding, Read, Resolved, ResolvedShape},
    index::TimeKey,
    indexes::standard::{FINANCIAL, Leaf, Standard},
    integrity::{Snapshot, require},
    local::{Mutation, Store},
    model::{
        self, Contract, InputField, Membership, OutputRole, Prepared, PublishedField,
        QueryDeclaration, Reference, RootDeclaration, Visibility,
    },
    native_codec::{Address, Key, StoredValue, decimal, uuid_text},
    native_slice::{
        Attempt, Context, Error, Model, ModelChange, ModelRecord, Population, Query, Result,
    },
    routes,
    time_range::{TimeBound, TimeRange},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};
use uuid::Uuid;

const ROOT: u16 = 10;
const ENTRY: u16 = 20;
const READER: u16 = 30;
const OUTPUT: u16 = 90;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowModel;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum Input {
    Root {
        unit: u16,
    },
    Entry {
        #[serde(with = "uuid_text")]
        root: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        amount: i128,
    },
    Reader {
        #[serde(with = "uuid_text")]
        source: Uuid,
        #[serde(with = "uuid_text")]
        target: Uuid,
        range: TimeRange,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        offset: i128,
        #[serde(with = "decimal")]
        factor: i128,
        emit: bool,
        validate: bool,
        active: bool,
    },
    Output {
        #[serde(with = "uuid_text")]
        producer: Uuid,
        role: u16,
        #[serde(with = "uuid_text")]
        target: Uuid,
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

impl NativeInput for Input {
    fn contract(&self) -> u16 {
        match self {
            Self::Root { .. } => ROOT,
            Self::Entry { .. } => ENTRY,
            Self::Reader { .. } => READER,
            Self::Output { .. } => OUTPUT,
        }
    }
    fn validate(&self) -> Result<()> {
        if matches!(self, Self::Root { unit: 0 })
            || matches!(self, Self::Output { role, .. } if *role != 11)
        {
            return Err(Error::new("invalid_input", "window fixture scalar bounds"));
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
                "complete canonical window input required",
            ));
        }
        Ok(input)
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        match self {
            Self::Entry { root, .. } => vec![(*root, ROOT, 1)],
            Self::Reader { source, target, .. } => vec![(*source, ROOT, 1), (*target, ROOT, 2)],
            Self::Output {
                producer, target, ..
            } => vec![(*producer, READER, 1), (*target, ROOT, 2)],
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
    json!({"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","x-rebase-binding":binding,
        "x-rebase-range":[minimum.to_string(),maximum.to_string()]})
}
fn reference(slot: u16, field: &'static str, target: u16) -> Reference {
    Reference {
        slot,
        field,
        targets: vec![target],
        optional: false,
        direct_fields: vec![],
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
        schema: json!({"$schema":model::SCHEMA_DIALECT,"type":"object","additionalProperties":false,
            "properties":properties,"required":fields.iter().map(|(_,name)|name).collect::<Vec<_>>()}),
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
        schema_source: "src/window_tests.rs",
        behavior_source: "src/window_tests.rs",
    }
}
fn declarations() -> Vec<Contract> {
    let uuid = json!({"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","x-rebase-binding":"uuid"});
    let time = scalar("i64", i128::from(i64::MIN), i128::from(i64::MAX));
    let amount = scalar("i128", i128::MIN, i128::MAX);
    let mut root = contract(
        ROOT,
        "Root",
        &[(1, "unit")],
        json!({"unit":{"type":"integer","minimum":1,"maximum":65535,"x-rebase-binding":"u16_code"}}),
    );
    root.roots.push(RootDeclaration {
        slot: 7,
        name: "amounts",
        kind: FINANCIAL,
        reads: vec!["summary", "sum"],
        invariant: None,
    });
    let mut entry = contract(
        ENTRY,
        "Entry",
        &[(1, "root"), (2, "at"), (3, "amount")],
        json!({"root":uuid,"at":time,"amount":amount}),
    );
    entry.references.push(reference(1, "root", ROOT));
    entry.memberships.push(Membership {
        slot: 17,
        through: "root",
        root_contract: ROOT,
        root_slot: 7,
        kind: FINANCIAL,
        key: "at",
        value: "amount",
    });
    let mut reader = contract(
        READER,
        "Reader",
        &[
            (1, "source"),
            (2, "target"),
            (3, "range"),
            (4, "at"),
            (5, "offset"),
            (6, "factor"),
            (7, "emit"),
            (8, "validate"),
            (9, "active"),
        ],
        json!({"source":uuid,"target":uuid,"range":TimeRange::schema(),"at":time,"offset":amount,
            "factor":amount,"emit":{"type":"boolean"},"validate":{"type":"boolean"},"active":{"type":"boolean"}}),
    );
    reader.references = vec![reference(1, "source", ROOT), reference(2, "target", ROOT)];
    reader.published = vec![PublishedField {
        code: 101,
        name: "amount",
        binding: "i128",
    }];
    reader.queries = [(31, "calculate"), (32, "validate")]
        .into_iter()
        .map(|(slot, phase)| QueryDeclaration {
            slot,
            through: "source",
            root_contract: ROOT,
            root_slot: 7,
            operation: "sum",
            phase,
            channel: "amount",
            bound: "authored range when active and phase matches",
            fallback: Some("0"),
        })
        .collect();
    reader.outputs.push(OutputRole {
        role: 11,
        contract: OUTPUT,
        active: "emit && active && !validate",
        account: "target",
        at: "at",
        amount: "amount",
        depends_on: vec!["amount"],
    });
    reader.calculations.push(model::Calculation {
        name: "amount",
        inputs: vec![],
        expression: "offset + factor * query[31]",
    });
    let mut output = contract(
        OUTPUT,
        "Output",
        &[
            (1, "producer"),
            (2, "role"),
            (3, "target"),
            (4, "at"),
            (5, "amount"),
        ],
        json!({"producer":uuid,"role":{"type":"integer","const":11},"target":uuid,"at":time,"amount":amount}),
    );
    output.references = vec![
        reference(1, "producer", READER),
        reference(2, "target", ROOT),
    ];
    output.memberships.push(Membership {
        slot: 23,
        through: "target",
        root_contract: ROOT,
        root_slot: 7,
        kind: FINANCIAL,
        key: "at",
        value: "amount",
    });
    vec![root, entry, reader, output]
}
fn registrations(id: Uuid, input: Option<&Input>) -> BTreeSet<(Key, Address)> {
    input
        .into_iter()
        .flat_map(NativeInput::references)
        .map(|(target, _, slot)| (Key::Incoming(target), Address::new(id, slot)))
        .collect()
}
fn entry_member(input: Option<&Input>) -> Option<(Address, TimeKey, Leaf)> {
    match input {
        Some(Input::Entry { root, at, amount }) => Some((
            Address::new(*root, 7),
            TimeKey(*at),
            Leaf::Financial(*amount),
        )),
        _ => None,
    }
}
impl Binding for WindowModel {
    type Index = Standard;
    type Input = Input;
    type Derived = Derived;
    type Outcome = ();
    const NAME: &'static str = "test-reactive-windows";
    const BEHAVIOR: &'static str = "test-reactive-windows-1";
    fn declarations() -> Result<Vec<Contract>> {
        Ok(declarations())
    }
    fn engine() -> Result<Model> {
        Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
    }
    fn valid_derived(input: &Input, derived: Option<&Derived>) -> bool {
        matches!((input, derived), (Input::Reader { .. }, Some(_)))
            || (!matches!(input, Input::Reader { .. }) && derived.is_none())
    }
    fn published_shape(code: u16) -> Value {
        if code == READER {
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
        population: &mut Population,
        revision: Uuid,
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
        crate::causal::settle(ws, model, context, changes, population, revision, allocate)
    }
    fn check(store: &Store<Self>) -> Result<Value> {
        check(store)
    }
}
impl ReactiveBinding for WindowModel {
    type Publication = ();
    type Parameters = ();
    fn resolve<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        _ws: &mut Attempt<L, Self>,
        _context: Context,
        _id: Uuid,
        record: &ModelRecord<Self>,
    ) -> Result<Resolved<()>> {
        let Input::Reader {
            source,
            target,
            range,
            at,
            emit,
            validate,
            active,
            ..
        } = record.input
        else {
            return Err(Error::new("corrupt_state", "window reader contract"));
        };
        Ok(Resolved {
            shape: ResolvedShape {
                publications: vec![],
                reads: if active {
                    vec![Read {
                        slot: if validate { 32 } else { 31 },
                        root: Address::new(source, 7),
                        range,
                        validate,
                    }]
                } else {
                    vec![]
                },
                emits: if active && emit && !validate {
                    vec![Emit {
                        role: 11,
                        contract: OUTPUT,
                        root: Address::new(target, 7),
                        at,
                    }]
                } else {
                    vec![]
                },
            },
            parameters: (),
        })
    }
    fn evaluate(
        _id: Uuid,
        record: &ModelRecord<Self>,
        shape: &ResolvedShape,
        _parameters: &(),
        _publications: &[crate::causal::PublicationValue<Self::Publication>],
        values: &[i128],
    ) -> Result<(Derived, BTreeMap<u16, i128>)> {
        let Input::Reader { offset, factor, .. } = record.input else {
            unreachable!()
        };
        let sum = values
            .iter()
            .try_fold(0i128, |a, b| a.checked_add(*b))
            .ok_or_else(|| Error::new("overflow", "window input sum"))?;
        let amount = factor
            .checked_mul(sum)
            .and_then(|value| offset.checked_add(value))
            .ok_or_else(|| Error::new("overflow", "window calculation"))?;
        Ok((
            Derived { amount },
            if shape.emits.is_empty() {
                BTreeMap::new()
            } else {
                BTreeMap::from([(11, amount)])
            },
        ))
    }
    fn output_input(producer: Uuid, emit: &Emit, amount: i128) -> Result<Input> {
        Ok(Input::Output {
            producer,
            role: emit.role,
            target: emit.root.id,
            at: emit.at,
            amount,
        })
    }
    fn output_member(input: &Input) -> Result<(Address, i64, Leaf)> {
        match input {
            Input::Output {
                target, at, amount, ..
            } => Ok((Address::new(*target, 7), *at, Leaf::Financial(*amount))),
            _ => Err(Error::new("corrupt_state", "window output contract")),
        }
    }
}

// Independent expectations: literal endpoint comparisons and pairwise authored
// emissions, with no TimeRange::contains, production graph or evaluator calls.
fn literal(range: TimeRange, at: i64) -> bool {
    let lower = match range.lower {
        TimeBound::Unbounded => true,
        TimeBound::Included(value) => at >= value,
        TimeBound::Excluded(value) => at > value,
    };
    let upper = match range.upper {
        TimeBound::Unbounded => true,
        TimeBound::Included(value) => at <= value,
        TimeBound::Excluded(value) => at < value,
    };
    lower && upper
}
fn check(store: &Store<WindowModel>) -> Result<Value> {
    let snapshot = Snapshot::load(store)?;
    let keys = snapshot.expected_keys.clone();
    let mut routes = snapshot.routes.clone();
    let mut members = BTreeMap::new();
    let mut queries = BTreeMap::new();
    let readers: BTreeMap<_, _> = snapshot
        .records
        .iter()
        .filter_map(|(&id, r)| matches!(r.input, Input::Reader { .. }).then_some((id, &r.input)))
        .collect();
    for (&id, record) in &snapshot.records {
        if let Input::Entry { root, at, amount } = record.input {
            members.insert(
                Address::new(id, 17),
                (Address::new(root, 7), at, Leaf::Financial(amount)),
            );
        }
    }
    let mut edges = BTreeSet::new();
    for (&upstream, input) in &readers {
        let Input::Reader {
            target,
            at,
            emit: true,
            validate: false,
            active: true,
            ..
        } = input
        else {
            continue;
        };
        for (&downstream, input) in &readers {
            if let Input::Reader {
                source,
                range,
                validate: false,
                active: true,
                ..
            } = input
                && target == source
                && literal(*range, *at)
            {
                edges.insert((upstream, downstream));
            }
        }
    }
    let mut pending: BTreeSet<_> = readers.keys().copied().collect();
    let mut expected_outputs = BTreeMap::new();
    while !pending.is_empty() {
        let id = *pending
            .iter()
            .find(|&&candidate| {
                !edges
                    .iter()
                    .any(|(source, target)| *target == candidate && pending.contains(source))
            })
            .ok_or_else(|| {
                Error::new("corrupt_state", "source-derived final window graph cycle")
            })?;
        let Input::Reader {
            source,
            target,
            range,
            at,
            offset,
            factor,
            emit,
            validate,
            active,
            ..
        } = readers[&id]
        else {
            unreachable!()
        };
        let mut sum = 0i128;
        if *active && !*validate {
            for (root, time, leaf) in members.values() {
                if *root == Address::new(*source, 7) && literal(*range, *time) {
                    let Leaf::Financial(amount) = leaf else {
                        unreachable!()
                    };
                    sum = sum
                        .checked_add(*amount)
                        .ok_or_else(|| Error::new("corrupt_state", "window oracle sum"))?;
                }
            }
        }
        let amount = factor
            .checked_mul(sum)
            .and_then(|value| offset.checked_add(value))
            .ok_or_else(|| Error::new("corrupt_state", "window oracle amount"))?;
        require(
            snapshot.records[&id].derived == Some(Derived { amount }),
            "source-derived window amount",
        )?;
        if *active && *emit && !*validate {
            let Some(StoredValue::Role(binding)) =
                snapshot.all.get(&Key::Role(Address::new(id, 11)))
            else {
                return Err(Error::new(
                    "corrupt_state",
                    "missing expected window output role",
                ));
            };
            require(!binding.retired, "active expected window role")?;
            expected_outputs.insert(
                binding.output,
                Input::Output {
                    producer: id,
                    role: 11,
                    target: *target,
                    at: *at,
                    amount,
                },
            );
            members.insert(
                Address::new(binding.output, 23),
                (Address::new(*target, 7), *at, Leaf::Financial(amount)),
            );
        }
        pending.remove(&id);
    }
    let actual_outputs: BTreeMap<_, _> = snapshot
        .records
        .iter()
        .filter_map(|(&id, r)| {
            matches!(r.input, Input::Output { .. }).then_some((id, r.input.clone()))
        })
        .collect();
    require(
        actual_outputs == expected_outputs,
        "complete source-derived window output inventory",
    )?;
    for (&id, input) in &readers {
        let Input::Reader {
            source,
            range,
            validate,
            active,
            ..
        } = input
        else {
            unreachable!()
        };
        if !*active {
            continue;
        }
        let mut result = 0i128;
        for (root, at, leaf) in members.values() {
            if *root == Address::new(*source, 7) && literal(*range, *at) {
                let Leaf::Financial(amount) = leaf else {
                    unreachable!()
                };
                result = result
                    .checked_add(*amount)
                    .ok_or_else(|| Error::new("corrupt_state", "window query oracle sum"))?;
            }
        }
        if *validate {
            require(result >= 0, "source-derived terminal window nonnegative")?;
        }
        let address = Address::new(id, if *validate { 32 } else { 31 });
        routes
            .entry(Key::Subscribers(Address::new(*source, 7)))
            .or_default()
            .insert(address);
        queries.insert(
            address,
            Query {
                source: Address::new(*source, 7),
                operation: "sum".into(),
                phase: if *validate { "validate" } else { "calculate" }.into(),
                channel: "amount".into(),
                range: *range,
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
            .join("target/window-tests")
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
fn create(directory: &Directory) -> Store<WindowModel> {
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
fn request(store: &Store<WindowModel>, operation: u128, commands: Value) -> Mutation {
    serde_json::from_value(json!({"model":store.model().identity(),
        "context":store.operation_context(store.model().identity()).unwrap(),"operation_id":id(operation),
        "commands":commands,"returning":[]})).unwrap()
}
fn commit(store: &Store<WindowModel>, operation: u128, commands: Value) -> (Mutation, Value) {
    let request = request(store, operation, commands);
    let mut allocation = 100_000 + operation * 100;
    let result = store
        .mutate_with_ids(&request, &mut || {
            allocation += 1;
            Ok(id(allocation))
        })
        .unwrap();
    store.check_integrity().unwrap();
    (request, result)
}
fn record(store: &Store<WindowModel>, n: u128) -> ModelRecord<WindowModel> {
    Snapshot::load(store).unwrap().records[&id(n)].clone()
}
fn update(store: &Store<WindowModel>, n: u128, set: Value) -> Value {
    json!({"op":"update","id":id(n),"if_version":record(store,n).version.to_string(),"set":set,"unset":[]})
}
fn reject(store: &Store<WindowModel>, operation: u128, commands: Value, kind: &str) {
    let before = store.observe_for_verification().unwrap();
    let inspect = store.inspect().unwrap();
    let request = request(store, operation, commands);
    assert_eq!(store.mutate(&request).unwrap_err().code, kind);
    assert_eq!(store.observe_for_verification().unwrap(), before);
    assert_eq!(store.inspect().unwrap(), inspect);
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
fn root(n: u128) -> Value {
    json!({"op":"create","id":id(n),"contract":ROOT,"fields":{"unit":1}})
}
fn entry(n: u128, root: u128, at: i64, amount: i128) -> Value {
    json!({"op":"create","id":id(n),"contract":ENTRY,"fields":{"root":id(root),"at":at.to_string(),"amount":amount.to_string()}})
}
#[allow(clippy::too_many_arguments)] // Compact authored fixture rows, not a public API.
fn reader(
    n: u128,
    source: u128,
    target: u128,
    range: TimeRange,
    at: i64,
    offset: i128,
    emit: bool,
    validate: bool,
) -> Value {
    json!({"op":"create","id":id(n),"contract":READER,"fields":{"source":id(source),"target":id(target),
        "range":range,"at":at.to_string(),"offset":offset.to_string(),"factor":"1","emit":emit,"validate":validate,"active":true}})
}
fn closed(a: i64, b: i64) -> TimeRange {
    TimeRange {
        lower: TimeBound::Included(a),
        upper: TimeBound::Included(b),
    }
}
fn amount(store: &Store<WindowModel>, n: u128) -> i128 {
    record(store, n).derived.unwrap().amount
}
fn query(store: &Store<WindowModel>, n: u128, slot: u16) -> Option<Query> {
    match Snapshot::load(store)
        .unwrap()
        .all
        .get(&Key::Query(Address::new(id(n), slot)))
    {
        Some(StoredValue::Query(query)) => Some(query.clone()),
        None => None,
        _ => panic!("window query type"),
    }
}
fn reopen_replay(
    directory: &Directory,
    store: Store<WindowModel>,
    request: Mutation,
    result: Value,
) {
    let before = store.observe_for_verification().unwrap();
    assert_eq!(store.mutate(&request).unwrap()["result"], result["result"]);
    assert_eq!(store.observe_for_verification().unwrap(), before);
    drop(store);
    let reopened =
        Store::<WindowModel>::open(directory.file(), Arc::new(Prepared::load().unwrap())).unwrap();
    reopened.check_integrity().unwrap();
    assert_eq!(reopened.observe_for_verification().unwrap(), before);
    assert_eq!(
        reopened.mutate(&request).unwrap()["result"],
        result["result"]
    );
}

#[test]
fn windows_preserve_groups_extremes_disjoint_impacts_and_bound_retargeting() {
    let directory = Directory::new();
    let store = create(&directory);
    commit(
        &store,
        1000,
        json!([
            root(10),
            root(11),
            root(12),
            entry(20, 10, 0, 9_007_199_254_740_993),
            entry(21, 10, 0, -9_007_199_254_740_990),
            entry(22, 10, 10, 7),
            entry(23, 10, i64::MIN, 19),
            entry(24, 10, i64::MAX, 23),
            entry(25, 12, 5, 99),
            reader(30, 10, 11, closed(0, 0), 20, 0, true, false),
            reader(31, 10, 11, closed(9, 11), 21, 0, true, false),
            reader(32, 10, 11, TimeRange::before(i64::MIN), 0, 0, false, false),
            reader(33, 10, 11, closed(i64::MAX, i64::MAX), 0, 0, false, false),
            reader(34, 10, 11, TimeRange::ALL, 0, 0, false, false),
            reader(35, 10, 11, closed(2, 1), 0, 0, false, false),
            reader(
                36,
                10,
                11,
                TimeRange {
                    lower: TimeBound::Excluded(0),
                    upper: TimeBound::Excluded(1)
                },
                0,
                0,
                false,
                false
            )
        ]),
    );
    assert_eq!(
        (
            amount(&store, 30),
            amount(&store, 31),
            amount(&store, 32),
            amount(&store, 33),
            amount(&store, 34),
            amount(&store, 35),
            amount(&store, 36)
        ),
        (3, 7, 0, 23, 52, 0, 0)
    );
    assert!(query(&store, 32, 31).is_some());
    assert!(query(&store, 35, 31).is_some());
    // Both changed times on one root must survive discovery: retaining only
    // the earliest point leaves the second disjoint reader stale.
    commit(
        &store,
        1001,
        json!([
            update(&store, 20, json!({"amount":"9007199254740994"})),
            update(&store, 22, json!({"amount":"8"}))
        ]),
    );
    assert_eq!(
        (amount(&store, 30), amount(&store, 31), amount(&store, 34)),
        (4, 8, 54)
    );
    commit(
        &store,
        1002,
        json!([reader(37, 11, 12, closed(20, 21), 30, 0, true, false)]),
    );
    assert_eq!(amount(&store, 37), 12);
    commit(
        &store,
        1003,
        json!([update(
            &store,
            30,
            json!({"source":id(12),"range":closed(5,5)})
        )]),
    );
    assert_eq!((amount(&store, 30), amount(&store, 37)), (99, 107));
    let untouched = record(&store, 30);
    commit(
        &store,
        1004,
        json!([update(&store, 20, json!({"amount":"9007199254740995"}))]),
    );
    assert_eq!(record(&store, 30), untouched);
    // The changed output moves out of the downstream window. Discovery must
    // see its old and new times and remove its old contribution.
    commit(
        &store,
        1005,
        json!([update(&store, 30, json!({"at":"22"}))]),
    );
    assert_eq!(amount(&store, 37), 8);
    commit(
        &store,
        1006,
        json!([update(&store, 31, json!({"range":closed(10,9)}))]),
    );
    assert_eq!(amount(&store, 31), 0);
    assert!(query(&store, 31, 31).is_some());
    let (request, result) = commit(
        &store,
        1007,
        json!([update(
            &store,
            31,
            json!({"range":TimeRange {lower:TimeBound::Excluded(9),upper:TimeBound::Included(10)}})
        )]),
    );
    assert_eq!(amount(&store, 31), 8);
    reopen_replay(&directory, store, request, result);
}

#[test]
fn windows_reject_zero_feedback_and_preserve_activation_and_phase_identity() {
    let directory = Directory::new();
    let store = create(&directory);
    commit(&store, 1100, json!([root(10), root(11)]));
    reject(
        &store,
        1101,
        json!([reader(30, 10, 10, closed(0, 0), 0, 0, true, false)]),
        "feedback",
    );
    reject(
        &store,
        1102,
        json!([
            reader(31, 10, 11, closed(0, 0), 0, 0, true, false),
            reader(32, 11, 10, closed(0, 0), 0, 0, true, false)
        ]),
        "feedback",
    );
    commit(
        &store,
        1103,
        json!([reader(30, 10, 10, closed(0, 0), 0, 7, false, false)]),
    );
    assert_eq!(amount(&store, 30), 7);
    reject(
        &store,
        1104,
        json!([update(&store, 30, json!({"emit":true,"offset":"0"}))]),
        "feedback",
    );
    commit(
        &store,
        1105,
        json!([update(&store, 30, json!({"active":false,"emit":true}))]),
    );
    assert_eq!(amount(&store, 30), 7);
    assert!(query(&store, 30, 31).is_none());
    reject(
        &store,
        1106,
        json!([update(&store, 30, json!({"active":true}))]),
        "feedback",
    );
    commit(
        &store,
        1107,
        json!([update(&store, 30, json!({"validate":true,"active":true}))]),
    );
    assert_eq!(amount(&store, 30), 7);
    assert!(query(&store, 30, 31).is_none());
    assert_eq!(query(&store, 30, 32).unwrap().result, 0);
    let (request, result) = commit(
        &store,
        1108,
        json!([update(&store, 30, json!({"validate":false,"emit":false}))]),
    );
    assert_eq!(amount(&store, 30), 7);
    assert!(query(&store, 30, 32).is_none());
    assert!(query(&store, 30, 31).is_some());
    reopen_replay(&directory, store, request, result);
}

#[test]
fn windows_accept_edge_reversal_even_when_old_new_union_is_cyclic() {
    for reverse in [false, true] {
        let directory = Directory::new();
        let store = create(&directory);
        commit(
            &store,
            1200,
            json!([
                root(10),
                reader(30, 10, 10, closed(100, 100), 1, 2, true, false),
                reader(31, 10, 10, closed(1, 1), 3, 7, true, false)
            ]),
        );
        assert_eq!((amount(&store, 30), amount(&store, 31)), (2, 9));
        let x = update(&store, 30, json!({"range":closed(3,3)}));
        let y = update(&store, 31, json!({"range":closed(100,100)}));
        let (request, result) = commit(
            &store,
            1201,
            if reverse {
                json!([y, x])
            } else {
                json!([x, y])
            },
        );
        assert_eq!((amount(&store, 30), amount(&store, 31)), (9, 7));
        let stale = update(&store, 30, json!({"offset":"3"}));
        commit(
            &store,
            1202,
            json!([update(&store, 30, json!({"offset":"4"}))]),
        );
        reject(&store, 1203, json!([stale]), "stale_version");
        reject(
            &store,
            1204,
            json!([update(&store, 31, json!({"range":closed(1,1)}))]),
            "feedback",
        );
        // Replaying the accepted reversal retains its receipt after later edits.
        reopen_replay(&directory, store, request, result);
    }
}

#[test]
fn terminal_windows_validate_final_managed_repairs_in_both_command_orders() {
    for reverse in [false, true] {
        let directory = Directory::new();
        let store = create(&directory);
        commit(
            &store,
            1300,
            json!([
                root(10),
                root(11),
                entry(20, 10, 0, -5),
                entry(21, 11, 0, 5),
                reader(30, 11, 10, closed(0, 0), 0, 0, true, false),
                reader(31, 10, 11, closed(0, 0), 0, 0, false, true)
            ]),
        );
        assert_eq!(query(&store, 31, 32).unwrap().result, 0);
        reject(
            &store,
            1301,
            json!([update(&store, 21, json!({"amount":"4"}))]),
            "invariant",
        );
        let change = update(&store, 21, json!({"amount":"4"}));
        let repair = update(&store, 20, json!({"amount":"-4"}));
        commit(
            &store,
            1302,
            if reverse {
                json!([repair, change])
            } else {
                json!([change, repair])
            },
        );
        assert_eq!(amount(&store, 30), 4);
        assert_eq!(query(&store, 31, 32).unwrap().result, 0);
        commit(
            &store,
            1303,
            json!([update(
                &store,
                31,
                json!({"range":TimeRange {lower:TimeBound::Excluded(0),upper:TimeBound::Unbounded}})
            )]),
        );
        commit(
            &store,
            1304,
            json!([update(&store, 20, json!({"amount":"-9"}))]),
        );
        assert_eq!(query(&store, 31, 32).unwrap().result, 0);
        reject(
            &store,
            1305,
            json!([update(&store, 31, json!({"range":closed(0,0)}))]),
            "invariant",
        );
        let (request, result) = commit(
            &store,
            1306,
            json!([update(&store, 31, json!({"active":false}))]),
        );
        assert!(query(&store, 31, 32).is_none());
        reopen_replay(&directory, store, request, result);
    }
}
