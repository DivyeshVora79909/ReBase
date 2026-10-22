//! Shared resolved-shape causal settlement for compiled model bindings.
use crate::{
    binding::{Binding, NativeInput, headers},
    model::{Prepared, Visibility},
    mutation::{check_counts, reconcile_member},
    native_codec::{Address, Key, Role, StoredValue},
    native_slice::{Attempt, Bound, Context, Error, Meta, ModelChange, ModelRecord, Query, Result},
    tree::{self, Kind, Leaf},
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
#[derive(Clone, Debug)]
pub struct Read {
    pub slot: u16,
    pub root: Address,
    pub before: Option<i64>,
    pub validate: bool,
}
#[derive(Clone, Copy, Debug)]
pub struct Emit {
    pub role: u16,
    pub contract: u16,
    pub root: Address,
    pub at: i64,
}
#[derive(Clone, Debug, Default)]
pub struct ResolvedShape {
    pub reads: Vec<Read>,
    pub emits: Vec<Emit>,
}
pub trait ReactiveBinding: Binding {
    fn shape<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        context: Context,
        id: Uuid,
        record: &ModelRecord<Self>,
    ) -> Result<ResolvedShape>;
    fn evaluate(
        id: Uuid,
        record: &ModelRecord<Self>,
        shape: &ResolvedShape,
        values: &[i128],
    ) -> Result<(Self::Derived, BTreeMap<u16, i128>)>;
    fn output_input(producer: Uuid, emit: &Emit, amount: i128) -> Result<Self::Input>;
    fn output_member(input: &Self::Input) -> Result<(Address, i64, Leaf)>;
}
/// Check the authored topology before reserving identities or changing membership.
fn validate_shape<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    context: Context,
    record: &ModelRecord<B>,
    shape: &ResolvedShape,
) -> Result<()> {
    let contract = model.contract(record.contract)?;
    let references = record.input.references();
    let mut slots = BTreeSet::new();
    for read in &shape.reads {
        if read.slot == 0 || !slots.insert(read.slot) {
            return Err(Error::new("model", "duplicate or zero resolved query slot"));
        }
        let query = contract
            .queries
            .iter()
            .find(|q| q.slot == read.slot)
            .ok_or_else(|| Error::new("model", "undeclared resolved query"))?;
        if query.operation != "sum"
            || query.channel != "amount"
            || query.phase
                != if read.validate {
                    "validate"
                } else {
                    "calculate"
                }
            || query.root_slot != read.root.slot
        {
            return Err(Error::new(
                "model",
                "resolved query disagrees with declaration",
            ));
        }
        let reference = contract
            .references
            .iter()
            .find(|r| r.field == query.through)
            .ok_or_else(|| Error::new("model", "query reference declaration"))?;
        if !references
            .iter()
            .any(|(id, _, slot)| *slot == reference.slot && *id == read.root.id)
        {
            return Err(Error::new(
                "model",
                "resolved query uses a different authored reference",
            ));
        }
        validate_root(ws, model, context, read.root, query.root_contract)?;
    }
    let mut roles = BTreeSet::new();
    for emit in &shape.emits {
        if emit.role == 0 || !roles.insert(emit.role) {
            return Err(Error::new(
                "model",
                "duplicate or zero resolved output role",
            ));
        }
        let role = contract
            .outputs
            .iter()
            .find(|o| o.role == emit.role)
            .ok_or_else(|| Error::new("model", "undeclared resolved output role"))?;
        let output = model.contract(emit.contract)?;
        if role.contract != emit.contract || output.visibility != Visibility::Engine {
            return Err(Error::new("model", "resolved output contract mismatch"));
        }
        member_slot(model, emit.contract)?;
        let member = &output.memberships[0];
        if member.root_slot != emit.root.slot || member.kind != Kind::Financial {
            return Err(Error::new("model", "resolved output membership mismatch"));
        }
        validate_root(ws, model, context, emit.root, member.root_contract)?;
    }
    Ok(())
}
fn validate_root<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    context: Context,
    address: Address,
    code: u16,
) -> Result<()> {
    if !model
        .contract(code)?
        .roots
        .iter()
        .any(|r| r.slot == address.slot && r.kind == Kind::Financial)
    {
        return Err(Error::new(
            "model",
            "resolved root is not a declared financial root",
        ));
    }
    if ws
        .record(address.id)?
        .is_none_or(|r| r.tenant != context.tenant || r.contract != code)
    {
        return Err(Error::new(
            "unavailable_reference",
            "resolved root target unavailable",
        ));
    }
    match ws.get(&Key::Root(address))? {
        Some(StoredValue::Root(root)) if root.kind == Kind::Financial => Ok(()),
        _ => Err(Error::new(
            "corrupt_state",
            "resolved financial root missing",
        )),
    }
}
struct Plan<B: Binding> {
    record: Option<ModelRecord<B>>,
    old_record: Option<ModelRecord<B>>,
    shape: ResolvedShape,
    old_outputs: BTreeMap<u16, (Uuid, ModelRecord<B>)>,
    bindings: BTreeMap<u16, Uuid>,
}
fn original<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    id: Uuid,
) -> Result<Option<ModelRecord<B>>> {
    match ws.original(&Key::Record(id))? {
        Some(StoredValue::Record(r)) => Ok(Some(r)),
        None => Ok(None),
        _ => Err(Error::new("corrupt_state", "old record type")),
    }
}
fn route_values<B: Binding>(value: Option<StoredValue<B>>) -> Result<Vec<Address>> {
    match value {
        None => Ok(vec![]),
        Some(StoredValue::Incoming(v) | StoredValue::Direct(v) | StoredValue::Subscribers(v)) => {
            Ok(v)
        }
        _ => Err(Error::new("corrupt_state", "route type")),
    }
}
fn routes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    key: &Key,
) -> Result<Vec<Address>> {
    let v = route_values(ws.get(key)?)?;
    ws.charge("route", v.len() as u64)?;
    Ok(v)
}
fn subscribers<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    key: Key,
    set: &mut BTreeSet<Uuid>,
) -> Result<()> {
    let old = route_values(ws.original(&key)?)?;
    ws.charge("route", old.len() as u64)?;
    set.extend(old.into_iter().map(|a| a.id));
    set.extend(routes(ws, &key)?.into_iter().map(|a| a.id));
    Ok(())
}
fn change_route<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    key: Key,
    member: Address,
    add: bool,
) -> Result<()> {
    let mut v = routes(ws, &key)?;
    match (add, v.binary_search(&member)) {
        (true, Err(i)) => v.insert(i, member),
        (false, Ok(i)) => {
            v.remove(i);
        }
        _ => return Err(Error::new("corrupt_state", "reverse registration mismatch")),
    };
    let value = match key {
        Key::Incoming(_) => StoredValue::Incoming(v),
        _ => return Err(Error::new("internal", "output route")),
    };
    ws.put(key, Some(value))
}
fn incoming<B: Binding>(id: Uuid, r: Option<&ModelRecord<B>>) -> BTreeSet<(Key, Address)> {
    r.into_iter()
        .flat_map(|r| r.input.references())
        .map(|(target, _, slot)| (Key::Incoming(target), Address::new(id, slot)))
        .collect()
}
fn write_output<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    id: Uuid,
    old: Option<&ModelRecord<B>>,
    new: Option<ModelRecord<B>>,
    meta: &mut Meta,
    revision: u64,
) -> Result<()> {
    if old.is_none() && new.is_none() {
        return Ok(());
    }
    if old.is_none() {
        let r = new.as_ref().unwrap();
        for (k, v) in headers(model, id, &r.input, revision)? {
            if ws.get(&k)?.is_some() {
                return Err(Error::new("corrupt_state", "orphan output header"));
            }
            ws.put(k, Some(v))?;
        }
        let n = meta.counts.entry(r.contract).or_default();
        *n = n
            .checked_add(1)
            .ok_or_else(|| Error::new("state_limit", "output count"))?;
    }
    let before = incoming(id, old);
    let after = incoming(id, new.as_ref());
    for (k, a) in before.difference(&after) {
        change_route(ws, k.clone(), *a, false)?;
    }
    for (k, a) in after.difference(&before) {
        change_route(ws, k.clone(), *a, true)?;
    }
    if new.is_none() {
        if !routes(ws, &Key::Incoming(id))?.is_empty() {
            return Err(Error::new(
                "unavailable_reference",
                "surviving reference to private output",
            ));
        }
        ws.put(Key::Incoming(id), None)?;
        let n = meta.counts.entry(old.unwrap().contract).or_default();
        *n = n
            .checked_sub(1)
            .ok_or_else(|| Error::new("corrupt_state", "output count"))?;
    }
    check_counts(model, meta)?;
    ws.put(Key::Record(id), new.map(StoredValue::Record))
}
fn read_query<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    id: Uuid,
    r: &Read,
) -> Result<i128> {
    let result = tree::prefix(ws, r.root, r.before)?;
    ws.put(
        Key::Query(Address::new(id, r.slot)),
        Some(StoredValue::Query(Query {
            source: r.root,
            operation: "sum".into(),
            phase: if r.validate { "validate" } else { "calculate" }.into(),
            channel: "amount".into(),
            lower: "negative_infinity".into(),
            upper: r.before.map_or(Bound::All, Bound::BeforeTime),
            selected: None,
            result,
        })),
    )?;
    Ok(result)
}
pub fn settle<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: ReactiveBinding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    context: Context,
    changes: &[ModelChange<B>],
    meta: &mut Meta,
    revision: u64,
    allocate: &mut dyn FnMut() -> Result<Uuid>,
) -> Result<()> {
    let mut pending = BTreeSet::new();
    let mut roots: BTreeSet<_> = ws.changed_roots().into_iter().collect();
    for c in changes {
        if c.old.as_ref().into_iter().chain(c.new.as_ref()).any(|r| {
            model
                .contract(r.contract)
                .is_ok_and(|c| !c.outputs.is_empty())
        }) {
            pending.insert(c.id);
        }
        if c.old.as_ref().map(|r| &r.input) != c.new.as_ref().map(|r| &r.input) {
            subscribers(ws, Key::Direct(c.id), &mut pending)?;
        }
    }
    let mut visited = BTreeSet::new();
    let mut plans: BTreeMap<Uuid, Plan<B>> = BTreeMap::new();
    loop {
        while let Some(root) = roots.pop_first() {
            if visited.insert(root) {
                subscribers(ws, Key::Subscribers(root), &mut pending)?;
            }
        }
        let Some(id) = pending.pop_first() else { break };
        if plans.contains_key(&id) {
            continue;
        }
        let record = ws.record(id)?;
        let old_record = original(ws, id)?;
        let producer = record
            .as_ref()
            .or(old_record.as_ref())
            .ok_or_else(|| Error::new("corrupt_state", "missing subscriber"))?;
        if model.contract(producer.contract)?.outputs.is_empty() {
            continue;
        }
        let shape = match &record {
            Some(r) => {
                let shape = B::shape(ws, context, id, r)?;
                validate_shape(ws, model, context, r, &shape)?;
                shape
            }
            None => ResolvedShape::default(),
        };
        let mut plan = Plan {
            record,
            old_record,
            shape,
            old_outputs: BTreeMap::new(),
            bindings: BTreeMap::new(),
        };
        let mut roles = BTreeSet::new();
        for r in plan.record.iter().chain(plan.old_record.iter()) {
            roles.extend(model.contract(r.contract)?.outputs.iter().map(|o| o.role));
        }
        for role in roles {
            let a = Address::new(id, role);
            if let Some(v) = ws.original(&Key::Role(a))? {
                let StoredValue::Role(b) = v else {
                    return Err(Error::new("corrupt_state", "role type"));
                };
                if b.retired
                    || ws.original(&Key::Reserved(b.output))? != Some(StoredValue::Reserved(a))
                {
                    return Err(Error::new("corrupt_state", "role reservation"));
                }
                plan.bindings.insert(role, b.output);
                if let Some(output) = original(ws, b.output)? {
                    if output.input.managed() != Some((id, role)) {
                        return Err(Error::new("corrupt_state", "role output owner"));
                    }
                    roots.insert(B::output_member(&output.input)?.0);
                    plan.old_outputs.insert(role, (b.output, output));
                }
            }
        }
        for e in &plan.shape.emits {
            roots.insert(e.root);
        }
        plans.insert(id, plan);
        if plans.len() > 64 {
            return Err(Error::new("state_limit", "causal closure"));
        }
    }
    ws.work.causal_candidates = plans.len() as u64;
    let mut deps: BTreeMap<Uuid, BTreeSet<Uuid>> = plans
        .iter()
        .filter(|(_, p)| p.record.is_some())
        .map(|(id, _)| (*id, BTreeSet::new()))
        .collect();
    for (consumer, p) in &plans {
        if p.record.is_none() {
            continue;
        }
        for r in p.shape.reads.iter().filter(|r| !r.validate) {
            for (producer, s) in &plans {
                for e in &s.shape.emits {
                    ws.charge("dependency", 1)?;
                    if r.root == e.root
                        && r.before.is_none_or(|at| e.at < at)
                        && deps.get_mut(consumer).unwrap().insert(*producer)
                    {
                        ws.charge("edge", 1)?;
                    }
                }
            }
        }
    }
    let mut order = vec![];
    while !deps.is_empty() {
        let ready: Vec<_> = deps
            .iter()
            .filter(|(_, d)| d.is_empty())
            .map(|(id, _)| *id)
            .collect();
        if ready.is_empty() {
            return Err(Error::new("feedback", "final active calculation cycle"));
        }
        for id in ready {
            deps.remove(&id);
            order.push(id);
            for d in deps.values_mut() {
                d.remove(&id);
            }
        }
    }
    let role_slots: BTreeSet<_> = model
        .contracts()
        .flat_map(|c| c.outputs.iter().map(|o| o.role))
        .collect();
    for (producer, p) in &mut plans {
        for e in &p.shape.emits {
            if p.bindings.contains_key(&e.role) {
                continue;
            }
            let mut chosen = None;
            for _ in 0..8 {
                ws.charge("allocate", 1)?;
                let id = allocate()?;
                let mut collision = ws.get(&Key::Record(id))?.is_some()
                    || ws.original(&Key::Record(id))?.is_some()
                    || ws.get(&Key::Reserved(id))?.is_some()
                    || ws.original(&Key::Reserved(id))?.is_some();
                for slot in &role_slots {
                    collision |= ws.get(&Key::Role(Address::new(id, *slot)))?.is_some()
                        || ws.original(&Key::Role(Address::new(id, *slot)))?.is_some();
                }
                if !collision {
                    chosen = Some(id);
                    break;
                }
            }
            let id = chosen.ok_or_else(|| {
                Error::new("allocation_collision", "output allocation retry limit")
            })?;
            meta.reserved = meta
                .reserved
                .checked_add(1)
                .ok_or_else(|| Error::new("state_limit", "reservation count"))?;
            check_counts(model, meta)?;
            let a = Address::new(*producer, e.role);
            ws.put(
                Key::Role(a),
                Some(StoredValue::Role(Role {
                    output: id,
                    retired: false,
                })),
            )?;
            ws.put(Key::Reserved(id), Some(StoredValue::Reserved(a)))?;
            p.bindings.insert(e.role, id);
        }
    }
    for (producer, p) in &plans {
        for (role, (id, old)) in &p.old_outputs {
            let slot = member_slot(model, old.contract)?;
            reconcile_member(
                ws,
                Address::new(*id, slot),
                Some(B::output_member(&old.input)?),
                None,
            )?;
            ws.work.detached_outputs += 1;
            if !p.shape.emits.iter().any(|e| e.role == *role) {
                write_output(ws, model, *id, Some(old), None, meta, revision)?;
            }
        }
        let mut slots = BTreeSet::new();
        for r in p.record.iter().chain(p.old_record.iter()) {
            slots.extend(model.contract(r.contract)?.queries.iter().map(|q| q.slot));
        }
        for slot in slots {
            if !p.shape.reads.iter().any(|r| r.slot == slot) {
                ws.put(Key::Query(Address::new(*producer, slot)), None)?;
            }
        }
        if p.record.is_none() {
            for (role, output) in &p.bindings {
                ws.put(
                    Key::Role(Address::new(*producer, *role)),
                    Some(StoredValue::Role(Role {
                        output: *output,
                        retired: true,
                    })),
                )?;
            }
        }
    }
    for id in order {
        let p = &plans[&id];
        let mut r = p.record.clone().unwrap();
        let mut values = vec![];
        for read in p.shape.reads.iter().filter(|r| !r.validate) {
            values.push(read_query(ws, id, read)?);
        }
        let (derived, amounts) = B::evaluate(id, &r, &p.shape, &values)?;
        r.derived = Some(derived);
        ws.work.causal_evaluations += 1;
        ws.put(Key::Record(id), Some(StoredValue::Record(r.clone())))?;
        for e in &p.shape.emits {
            let output = p.bindings[&e.role];
            let amount = *amounts
                .get(&e.role)
                .ok_or_else(|| Error::new("internal", "missing output amount"))?;
            let input = B::output_input(id, e, amount)?;
            input.validate()?;
            let fields = serde_json::to_value(&input)
                .map_err(|error| Error::new("model", error.to_string()))?;
            if input.contract() != e.contract
                || model.validate(e.contract, &fields)? != input
                || input.managed() != Some((id, e.role))
                || B::output_member(&input)? != (e.root, e.at, Leaf::Financial(amount))
            {
                return Err(Error::new(
                    "model",
                    "managed output disagrees with resolved topology or value",
                ));
            }
            for (target, _, slot) in input.references() {
                let declaration = model
                    .contract(e.contract)?
                    .references
                    .iter()
                    .find(|r| r.slot == slot)
                    .ok_or_else(|| Error::new("model", "undeclared output reference"))?;
                if ws.record(target)?.is_none_or(|r| {
                    r.tenant != context.tenant || !declaration.targets.contains(&r.contract)
                }) {
                    return Err(Error::new(
                        "unavailable_reference",
                        "output reference unavailable",
                    ));
                }
            }
            let new = ModelRecord {
                contract: e.contract,
                tenant: context.tenant,
                owner: r.owner,
                reader: r.reader,
                version: revision,
                input,
                derived: None,
            };
            write_output(
                ws,
                model,
                output,
                p.old_outputs.get(&e.role).map(|(_, r)| r),
                Some(new.clone()),
                meta,
                revision,
            )?;
            reconcile_member(
                ws,
                Address::new(output, member_slot(model, e.contract)?),
                None,
                Some(B::output_member(&new.input)?),
            )?;
        }
    }
    for (id, p) in &plans {
        for r in p.shape.reads.iter().filter(|r| r.validate) {
            if read_query(ws, *id, r)? < 0 {
                return Err(Error::new("invariant", "negative validation prefix"));
            }
        }
    }
    Ok(())
}
fn member_slot<B: Binding>(model: &Prepared<B>, contract: u16) -> Result<u16> {
    let members = &model.contract(contract)?.memberships;
    if members.len() != 1 {
        return Err(Error::new(
            "model",
            "managed output requires one membership",
        ));
    }
    Ok(members[0].slot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{binding::Calculation, native_slice::Input};

    #[test]
    fn resolved_query_cannot_substitute_an_unauthored_account() {
        let model = Prepared::<Calculation>::load().unwrap();
        let context = Context {
            tenant: Uuid::from_u128(1),
            actor: Uuid::from_u128(2),
        };
        let record = ModelRecord::<Calculation> {
            contract: 10,
            tenant: context.tenant,
            owner: context.actor,
            reader: context.actor,
            version: 1,
            input: Input::Basis {
                sources: vec![Uuid::from_u128(3)],
                factor: 1,
                account: Uuid::from_u128(4),
                at: 1,
                feedback: None,
            },
            derived: None,
        };
        let shape = ResolvedShape {
            reads: vec![Read {
                slot: 1,
                root: Address::new(Uuid::from_u128(99), 2),
                before: None,
                validate: false,
            }],
            emits: vec![],
        };
        let mut ws = Attempt::new(|_| Ok(None), 10_000);
        let error = validate_shape(&mut ws, &model, context, &record, &shape).unwrap_err();
        assert_eq!(error.code, "model");
        assert!(error.detail.contains("different authored reference"));
    }
}
