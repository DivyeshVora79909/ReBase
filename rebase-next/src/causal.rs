//! Shared resolved-shape causal settlement for compiled model bindings.
use crate::{
    binding::{Binding, NativeInput, headers},
    index::TimeKey,
    indexes::standard::{Aggregate, FINANCIAL, Leaf, Standard},
    model::{Prepared, Visibility},
    mutation::{check_counts, reconcile_member},
    native_codec::{Address, Key, Role, StoredValue},
    native_slice::{Attempt, Context, Error, Meta, ModelChange, ModelRecord, Query, Result},
    routes::{self, Endpoint, Route},
    time_range::{TimeBound, TimeRange},
    tree,
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
#[derive(Clone, Debug)]
pub struct Read {
    pub slot: u16,
    pub root: Address,
    pub range: TimeRange,
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
/// Attempt-local authored inputs alongside the declared ordered-read topology.
/// Parameters remain native model values; they are neither persisted nor used
/// to discover dependencies. References and direct reverse registrations must
/// explicitly cover the authored fields that the resolver consumes.
pub struct Resolved<P> {
    pub shape: ResolvedShape,
    pub parameters: P,
}
pub trait ReactiveBinding: Binding<Index = Standard> {
    /// Owned parameters from this source and its declared direct authored fields.
    /// Resolving published derived fields or following undeclared reference chains
    /// would require additional invalidation and causal contracts.
    type Parameters;
    /// All authored commands have been staged before resolution. Capture their
    /// final values here so evaluation needs no workspace or mutable parent copy.
    fn resolve<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        context: Context,
        id: Uuid,
        record: &ModelRecord<Self>,
    ) -> Result<Resolved<Self::Parameters>>;
    fn evaluate(
        id: Uuid,
        record: &ModelRecord<Self>,
        shape: &ResolvedShape,
        parameters: &Self::Parameters,
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
        if member.root_slot != emit.root.slot || member.kind != FINANCIAL {
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
        .any(|r| r.slot == address.slot && r.kind == FINANCIAL)
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
        Some(StoredValue::Root(root)) if root.kind == FINANCIAL => Ok(()),
        _ => Err(Error::new(
            "corrupt_state",
            "resolved financial root missing",
        )),
    }
}
struct Plan<B: ReactiveBinding> {
    record: Option<ModelRecord<B>>,
    old_record: Option<ModelRecord<B>>,
    shape: ResolvedShape,
    parameters: Option<B::Parameters>,
    old_outputs: BTreeMap<u16, (Uuid, ModelRecord<B>)>,
    bindings: BTreeMap<u16, Uuid>,
}
// Quote/latest readers have their own settlement path. Only declared sum reads
// and managed outputs belong to this scheduler, including terminal-only readers.
fn uses_sum_scheduler(contract: &crate::model::Contract) -> bool {
    !contract.outputs.is_empty() || contract.queries.iter().any(|q| q.operation == "sum")
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
fn subscriptions<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    id: Uuid,
    old: Option<&ModelRecord<B>>,
    shape: &ResolvedShape,
) -> Result<()> {
    let mut before = BTreeMap::new();
    if let Some(old) = old {
        for query in &model.contract(old.contract)?.queries {
            if let Some(value) = ws.original(&Key::Query(Address::new(id, query.slot)))? {
                let StoredValue::Query(q) = value else {
                    return Err(Error::new("corrupt_state", "old query type"));
                };
                before.insert(
                    (Key::Subscribers(q.source), Address::new(id, query.slot)),
                    q.range,
                );
            }
        }
    }
    let after: BTreeMap<_, _> = shape
        .reads
        .iter()
        .map(|r| {
            (
                (Key::Subscribers(r.root), Address::new(id, r.slot)),
                r.range,
            )
        })
        .collect();
    for ((key, member), range) in &before {
        if after.get(&(key.clone(), *member)) != Some(range) {
            routes::change(ws, key, *member, *range, false)?;
        }
    }
    for ((key, member), range) in &after {
        if before.get(&(key.clone(), *member)) != Some(range) {
            routes::change(ws, key, *member, *range, true)?;
        }
    }
    Ok(())
}
fn impact(roots: &mut BTreeMap<Address, BTreeSet<i64>>, root: Address, at: i64) {
    roots.entry(root).or_default().insert(at);
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
        routes::change(ws, k, *a, TimeRange::ALL, false)?;
    }
    for (k, a) in after.difference(&before) {
        routes::change(ws, k, *a, TimeRange::ALL, true)?;
    }
    if new.is_none() {
        if routes::header(ws, Route::Incoming(id), false)?.is_some_and(|h| !h.is_empty()) {
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
fn read_query<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding<Index = Standard>>(
    ws: &mut Attempt<L, B>,
    id: Uuid,
    r: &Read,
) -> Result<i128> {
    // Prefix sums need no non-invertible summary fold. Preserve their narrow
    // balanced search path; general windows retain the ordered range fold.
    let result = match (r.range.lower, r.range.upper) {
        (TimeBound::Unbounded, TimeBound::Excluded(at)) => tree::prefix(ws, r.root, Some(at))?,
        (TimeBound::Unbounded, TimeBound::Unbounded) => tree::prefix(ws, r.root, None)?,
        _ => {
            let Aggregate::Financial(summary) = tree::range(ws, r.root, r.range)? else {
                return Err(Error::new(
                    "corrupt_state",
                    "sum query on nonfinancial root",
                ));
            };
            summary.sum
        }
    };
    ws.put(
        Key::Query(Address::new(id, r.slot)),
        Some(StoredValue::Query(Query {
            source: r.root,
            operation: "sum".into(),
            phase: if r.validate { "validate" } else { "calculate" }.into(),
            channel: "amount".into(),
            range: r.range,
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
    let mut roots = ws.financial_impacts();
    for c in changes {
        if c.old
            .as_ref()
            .into_iter()
            .chain(c.new.as_ref())
            .any(|r| model.contract(r.contract).is_ok_and(uses_sum_scheduler))
        {
            pending.insert(c.id);
        }
        if c.old.as_ref().map(|r| &r.input) != c.new.as_ref().map(|r| &r.input) {
            routes::collect(ws, &Key::Direct(c.id), &mut pending)?;
        }
    }
    let mut visited_prefix: BTreeMap<Address, i64> = BTreeMap::new();
    let mut prefix_impacts: BTreeMap<Address, BTreeSet<i64>> = BTreeMap::new();
    let mut visited_points = BTreeSet::new();
    let mut plans: BTreeMap<Uuid, Plan<B>> = BTreeMap::new();
    loop {
        while let Some((root, mut points)) = roots.pop_first() {
            ws.charge("dependency", points.len() as u64)?;
            let mut prefix_only = true;
            for original in [true, false] {
                prefix_only &= routes::header(ws, Route::Subscribers(root), original)?
                    .is_none_or(|header| header.bounded == 0);
            }
            if prefix_only {
                // Save the points as well as their minimum: later shape repair
                // can introduce the first bounded reader in the staged index.
                prefix_impacts.entry(root).or_default().extend(&points);
                let Some(&at) = points.first() else { continue };
                if visited_prefix
                    .get(&root)
                    .is_some_and(|previous| *previous <= at)
                {
                    continue;
                }
                // Reopen only the newly exposed suffix band. Through(at) sorts
                // after Time(at), so equal-time inclusive readers are selected.
                let upper = visited_prefix
                    .insert(root, at)
                    .map_or(std::ops::Bound::Unbounded, |previous| {
                        std::ops::Bound::Included(Endpoint::Time(previous))
                    });
                for original in [true, false] {
                    pending.extend(
                        routes::select(
                            ws,
                            &Key::Subscribers(root),
                            std::ops::Bound::Excluded(Endpoint::Time(at)),
                            upper,
                            original,
                        )?
                        .into_iter()
                        .map(|address| address.id),
                    );
                }
            } else {
                if let Some(previous) = prefix_impacts.remove(&root) {
                    points.extend(previous);
                }
                for at in points {
                    if !visited_points.insert((root, at)) {
                        continue;
                    }
                    for original in [true, false] {
                        pending.extend(
                            routes::stab(ws, &Key::Subscribers(root), at, original)?
                                .into_iter()
                                .map(|address| address.id),
                        );
                    }
                }
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
        if !uses_sum_scheduler(model.contract(producer.contract)?) {
            continue;
        }
        let (shape, parameters) = match &record {
            Some(r) => {
                let resolved = B::resolve(ws, context, id, r)?;
                validate_shape(ws, model, context, r, &resolved.shape)?;
                (resolved.shape, Some(resolved.parameters))
            }
            None => (ResolvedShape::default(), None),
        };
        subscriptions(ws, model, id, old_record.as_ref(), &shape)?;
        let mut plan = Plan {
            record,
            old_record,
            shape,
            parameters,
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
                    let (root, at, _) = B::output_member(&output.input)?;
                    impact(&mut roots, root, at);
                    plan.old_outputs.insert(role, (b.output, output));
                }
            }
        }
        for e in &plan.shape.emits {
            impact(&mut roots, e.root, e.at);
        }
        plans.insert(id, plan);
        if plans.len() > usize::from(B::limits().public_records) {
            return Err(Error::new("state_limit", "causal closure"));
        }
    }
    ws.work.causal_candidates = plans.len() as u64;
    let order = crate::dependency::order(
        ws,
        plans
            .iter()
            .filter(|(_, p)| p.record.is_some())
            .map(|(id, p)| (*id, &p.shape)),
    )?;
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
                Some(
                    B::output_member(&old.input)
                        .map(|(root, at, leaf)| (root, TimeKey::new(at), leaf))?,
                ),
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
        // Terminal-only readers register and resolve like other subscribers,
        // but have no formula or derived value. Declaration-level calculation
        // semantics survive temporarily inactive reads and output shapes.
        let contract = model.contract(r.contract)?;
        if contract.outputs.is_empty()
            && contract.calculations.is_empty()
            && contract.published.is_empty()
            && !contract
                .queries
                .iter()
                .any(|query| query.phase == "calculate")
        {
            continue;
        }
        let mut values = vec![];
        for read in p.shape.reads.iter().filter(|r| !r.validate) {
            values.push(read_query(ws, id, read)?);
        }
        let parameters = p
            .parameters
            .as_ref()
            .ok_or_else(|| Error::new("internal", "missing resolved parameters"))?;
        let (derived, amounts) = B::evaluate(id, &r, &p.shape, parameters, &values)?;
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
                Some(
                    B::output_member(&new.input)
                        .map(|(root, at, leaf)| (root, TimeKey::new(at), leaf))?,
                ),
            )?;
        }
    }
    for (id, p) in &plans {
        for r in p.shape.reads.iter().filter(|r| r.validate) {
            if read_query(ws, *id, r)? < 0 {
                return Err(Error::new("invariant", "negative validation sum"));
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

    // Keep authored inputs separately from the native image: expected results
    // must never depend on writer-produced private outputs or query caches.
    #[test]
    fn selective_closure_matches_source_arithmetic_through_repeated_topology_edits() {
        use crate::{
            models::equipment::{Derived, Equipment, Input as EquipmentInput},
            native_codec,
            native_slice::{Command, Work},
        };
        use serde_json::json;
        type Bytes = BTreeMap<Vec<u8>, Vec<u8>>;

        fn expected(sources: &BTreeMap<Uuid, EquipmentInput>) -> (BTreeMap<Uuid, Derived>, bool) {
            let mut events: BTreeMap<Uuid, Vec<(i64, i128)>> = BTreeMap::new();
            let mut reservations = vec![];
            for (id, input) in sources {
                match input {
                    EquipmentInput::Delivery { pool, at, quantity } => {
                        events.entry(*pool).or_default().push((*at, *quantity));
                    }
                    EquipmentInput::Reservation { starts, .. } => reservations.push((*starts, *id)),
                    _ => {}
                }
            }
            reservations.sort();
            let mut derived = BTreeMap::new();
            for (_, id) in reservations {
                let EquipmentInput::Reservation {
                    pool,
                    starts,
                    ends,
                    requested,
                    active,
                } = sources[&id]
                else {
                    unreachable!()
                };
                let events = events.entry(pool).or_default();
                let before = if active {
                    events
                        .iter()
                        .filter(|(at, _)| *at < starts)
                        .map(|(_, amount)| amount)
                        .sum::<i128>()
                } else {
                    0
                };
                let allocated = if active {
                    requested.min(before.max(0))
                } else {
                    0
                };
                derived.insert(
                    id,
                    Derived {
                        available_before: before,
                        allocated,
                    },
                );
                if active {
                    events.extend([(starts, -allocated), (ends, allocated)]);
                }
            }
            let valid = events.values().all(|events| {
                let mut grouped = BTreeMap::<i64, i128>::new();
                for (at, amount) in events {
                    *grouped.entry(*at).or_default() += amount;
                }
                let mut balance = 0;
                grouped.values().all(|amount| {
                    balance += amount;
                    balance >= 0
                })
            });
            (derived, valid)
        }
        fn mutate(
            bytes: &mut Bytes,
            model: &Prepared<Equipment>,
            commands: Vec<Command>,
        ) -> Result<Work> {
            let mut ws =
                Attempt::<_, Equipment>::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 200_000);
            crate::mutation::settle_authorized(
                &mut ws,
                model,
                Context {
                    tenant: Uuid::from_u128(1),
                    actor: Uuid::from_u128(2),
                },
                &commands,
                &mut || Ok(Uuid::new_v4()),
                false,
                &mut |_, _, _, _| Ok(()),
            )?;
            let batch = ws.finish()?;
            let work = ws.work.clone();
            drop(ws);
            for (key, value) in batch {
                if let Some(value) = value {
                    bytes.insert(key, value);
                } else {
                    bytes.remove(&key);
                }
            }
            Ok(work)
        }
        fn check(bytes: &Bytes, sources: &BTreeMap<Uuid, EquipmentInput>) {
            let (expected, valid) = expected(sources);
            assert!(valid);
            let mut ws =
                Attempt::<_, Equipment>::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 200_000);
            let mut active = 0;
            for (id, input) in sources {
                let record = ws.record(*id).unwrap().unwrap();
                assert_eq!(&record.input, input);
                let Some(derived) = expected.get(id) else {
                    continue;
                };
                assert_eq!(record.derived.as_ref(), Some(derived));
                let EquipmentInput::Reservation {
                    pool,
                    starts,
                    ends,
                    active: enabled,
                    ..
                } = input
                else {
                    unreachable!()
                };
                let query = ws.get(&Key::Query(Address::new(*id, 31))).unwrap();
                if *enabled {
                    active += 1;
                    let Some(StoredValue::Query(query)) = query else {
                        panic!("active query missing")
                    };
                    assert_eq!(
                        (query.source, query.result),
                        (Address::new(*pool, 7), derived.available_before)
                    );
                    for (role, at, quantity) in [
                        (11, *starts, -derived.allocated),
                        (29, *ends, derived.allocated),
                    ] {
                        let Some(StoredValue::Role(binding)) =
                            ws.get(&Key::Role(Address::new(*id, role))).unwrap()
                        else {
                            panic!("role missing")
                        };
                        assert_eq!(
                            ws.record(binding.output).unwrap().unwrap().input,
                            EquipmentInput::Output {
                                producer: *id,
                                role,
                                pool: *pool,
                                at,
                                quantity
                            }
                        );
                    }
                } else {
                    assert_eq!(query, None);
                }
            }
            // Detect stale outputs after deactivation as well as missing ones.
            let outputs = bytes.iter().filter(|(key, value)| {
                let key = Key::decode(key).unwrap();
                matches!(native_codec::decode_for::<Equipment>(&key, value).unwrap(), StoredValue::Record(r) if r.contract == 900)
            }).count();
            assert_eq!(outputs, 2 * active);
        }

        let model = Prepared::<Equipment>::load().unwrap();
        let meta = Meta {
            model: model.identity().into(),
            codec: native_codec::CODEC.into(),
            tenant: Uuid::from_u128(1),
            actor: Uuid::from_u128(2),
            revision: 0,
            counts: model.contracts().map(|c| (c.code, 0)).collect(),
            reserved: 0,
        };
        let mut bytes = BTreeMap::from([(
            Key::Meta.encode(),
            native_codec::encode_for::<Equipment>(&Key::Meta, &StoredValue::Meta(meta)).unwrap(),
        )]);
        let mut sources = BTreeMap::new();
        for (id, pool) in [(100, 100), (101, 101)] {
            sources.insert(Uuid::from_u128(id), EquipmentInput::Pool { unit: 1 });
            sources.insert(
                Uuid::from_u128(id + 100),
                EquipmentInput::Delivery {
                    pool: Uuid::from_u128(pool),
                    at: 0,
                    quantity: if pool == 100 { 10 } else { 7 },
                },
            );
        }
        for i in 0..6 {
            sources.insert(
                Uuid::from_u128(300 + i),
                EquipmentInput::Reservation {
                    pool: Uuid::from_u128(100 + i % 2),
                    starts: (i as i64 + 1) * 10,
                    ends: (i as i64 + 1) * 10 + 5,
                    requested: 8,
                    active: true,
                },
            );
        }
        sources.insert(
            Uuid::from_u128(202),
            EquipmentInput::Delivery {
                pool: Uuid::from_u128(101),
                at: i64::MAX,
                quantity: 1,
            },
        );
        // Roots precede referencing sources; reservation UUIDs deliberately do
        // not change when their temporal order is changed below.
        let creates = sources
            .iter()
            .map(|(id, input)| Command::Create {
                id: *id,
                contract: input.contract(),
                fields: serde_json::to_value(input).unwrap(),
            })
            .collect();
        mutate(&mut bytes, &model, creates).unwrap();
        check(&bytes, &sources);
        let mut random = 41u64;
        let mut commits = 0;
        let mut rejections = 0;
        for step in 0..160 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            let draw = random >> 32;
            let id = Uuid::from_u128(if step < 2 {
                202
            } else {
                300 + u128::from(draw % 6)
            });
            let mut proposed = sources.clone();
            let set = if step < 2 {
                let EquipmentInput::Delivery { at, quantity, .. } = proposed.get_mut(&id).unwrap()
                else {
                    unreachable!()
                };
                *quantity = 2;
                if step == 1 {
                    *at = 55;
                }
                json!({"at":at.to_string(), "quantity":quantity.to_string()})
            } else {
                let EquipmentInput::Reservation {
                    pool,
                    starts,
                    ends,
                    requested,
                    active,
                } = proposed.get_mut(&id).unwrap()
                else {
                    unreachable!()
                };
                *pool = Uuid::from_u128(100 + u128::from((draw >> 4) % 2));
                *starts = ((draw >> 7) % 15) as i64 * 5 + 5;
                *ends = *starts + ((draw >> 12) % 5) as i64 * 5 + 5;
                *requested = i128::from((draw >> 17) % 13);
                *active = !(draw >> 22).is_multiple_of(4);
                json!({"pool":pool, "starts":starts.to_string(), "ends":ends.to_string(), "requested":requested.to_string(), "active":active})
            };
            let mut ws =
                Attempt::<_, Equipment>::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 200_000);
            let version = ws.record(id).unwrap().unwrap().version;
            drop(ws);
            let before = bytes.clone();
            let result = mutate(
                &mut bytes,
                &model,
                vec![Command::Update {
                    id,
                    if_version: version,
                    set: set.as_object().unwrap().clone().into_iter().collect(),
                    unset: vec![],
                }],
            );
            if expected(&proposed).1 {
                let work = result.unwrap();
                if step < 2 {
                    assert_eq!(work.causal_candidates, step);
                }
                sources = proposed;
                commits += 1;
            } else {
                assert_eq!(result.unwrap_err().code, "invariant");
                assert_eq!(bytes, before);
                rejections += 1;
            }
            check(&bytes, &sources);
        }
        assert!(commits > 100 && rejections > 0);
    }

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
                range: TimeRange::ALL,
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
