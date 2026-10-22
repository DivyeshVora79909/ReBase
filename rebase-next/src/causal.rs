//! Authored-shape prefix/required-output settlement. Discovery is conservative
//! per root; ordering depends only on final active query/output intersections.

use crate::{
    native_codec::{Address, Key, Role, Stored},
    native_slice::{
        Bound, Calculated, Change, Context, Error, Input, Meta, Query, Record, Result, Workspace,
        change_route, check_counts, financial, private_headers, reconcile_member, registrations,
        required, routes, subscribers, validate_references,
    },
    tree,
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Clone)]
struct Read {
    id: Address,
    root: Address,
    before: Option<i64>,
    validate: bool,
}

#[derive(Clone, Copy)]
struct Emit {
    role: u16,
    account: Uuid,
    at: i64,
    zero: bool,
}

struct Plan {
    record: Option<Record>,
    reads: Vec<Read>,
    emits: Vec<Emit>,
    old_outputs: BTreeMap<u16, (Uuid, Record)>,
    bindings: BTreeMap<u16, Uuid>,
}

fn original<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    id: Uuid,
) -> Result<Option<Record>> {
    match ws.original(&Key::Record(id))? {
        Some(Stored::Record(r)) => Ok(Some(r)),
        None => Ok(None),
        _ => Err(Error::new("corrupt_state", "old record type")),
    }
}

fn shape<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    context: Context,
    id: Uuid,
    record: Option<Record>,
) -> Result<Plan> {
    let mut reads = vec![];
    let mut emits = vec![];
    if let Some(record) = &record {
        validate_references(ws, &record.input, context)?;
        match &record.input {
            Input::Adjustment {
                account,
                moment,
                offset,
                post,
                ..
            } => {
                let Input::Moment { at } = required(ws, *moment, 7, context)?.input else {
                    unreachable!()
                };
                let at = at
                    .checked_add(*offset)
                    .ok_or_else(|| Error::new("invalid_input", "resolved timestamp overflow"))?;
                for slot in [1, 2] {
                    reads.push(Read {
                        id: Address::new(id, slot),
                        root: Address::new(*account, 2),
                        before: Some(at),
                        validate: slot == 2,
                    });
                }
                if *post {
                    emits.push(Emit {
                        role: 1,
                        account: *account,
                        at,
                        zero: false,
                    });
                }
            }
            Input::Basis {
                sources,
                account,
                at,
                feedback,
                ..
            } => {
                for (i, root) in sources.iter().enumerate() {
                    reads.push(Read {
                        id: Address::new(id, i as u16 + 1),
                        root: Address::new(*root, 2),
                        before: None,
                        validate: false,
                    });
                }
                emits.push(Emit {
                    role: 1,
                    account: *account,
                    at: *at,
                    zero: false,
                });
                if let Some(f) = feedback {
                    emits.push(Emit {
                        role: 2,
                        account: f.account,
                        at: f.at,
                        zero: true,
                    });
                }
            }
            _ => return Err(Error::new("corrupt_state", "noncausal subscriber")),
        }
    }
    let mut old_outputs = BTreeMap::new();
    let mut bindings = BTreeMap::new();
    for role in [1, 2] {
        let key = Key::Role(Address::new(id, role));
        if let Some(value) = ws.original(&key)? {
            let Stored::Role(binding) = value else {
                return Err(Error::new("corrupt_state", "role type"));
            };
            if binding.retired {
                return Err(Error::new("corrupt_state", "active retired producer"));
            }
            if ws.original(&Key::Reserved(binding.output))?
                != Some(Stored::Reserved(Address::new(id, role)))
            {
                return Err(Error::new("corrupt_state", "missing reverse reservation"));
            }
            bindings.insert(role, binding.output);
            if let Some(output) = original(ws, binding.output)? {
                if !matches!(output.input,Input::Output{producer,role:r,..} if producer==id && r==role)
                {
                    return Err(Error::new("corrupt_state", "role output owner"));
                }
                old_outputs.insert(role, (binding.output, output));
            }
        }
    }
    Ok(Plan {
        record,
        reads,
        emits,
        old_outputs,
        bindings,
    })
}

fn allocate_role<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    role: Address,
    meta: &mut Meta,
    allocate: &mut dyn FnMut() -> Result<Uuid>,
) -> Result<Uuid> {
    for _ in 0..8 {
        ws.charge("allocate", 1)?;
        let id = allocate()?;
        if ws.get(&Key::Record(id))?.is_some()
            || ws.original(&Key::Record(id))?.is_some()
            || ws.get(&Key::Reserved(id))?.is_some()
            || ws.get(&Key::Role(Address::new(id, 1)))?.is_some()
            || ws.get(&Key::Role(Address::new(id, 2)))?.is_some()
        {
            continue;
        }
        meta.reserved = meta
            .reserved
            .checked_add(1)
            .ok_or_else(|| Error::new("state_limit", "reservation count"))?;
        check_counts(meta)?;
        ws.put(
            Key::Role(role),
            Some(Stored::Role(Role {
                output: id,
                retired: false,
            })),
        )?;
        ws.put(Key::Reserved(id), Some(Stored::Reserved(role)))?;
        return Ok(id);
    }
    Err(Error::new(
        "allocation_collision",
        "output allocation retry limit",
    ))
}

fn write_output<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    id: Uuid,
    old: Option<&Record>,
    new: Option<Record>,
    meta: &mut Meta,
    revision: u64,
) -> Result<()> {
    if old.is_none() && new.is_none() {
        return Ok(());
    }
    if old.is_none() {
        for (key, value) in private_headers(id, &new.as_ref().expect("new output").input, revision)
        {
            if ws.get(&key)?.is_some() {
                return Err(Error::new("corrupt_state", "orphan output header"));
            }
            ws.put(key, Some(value))?;
        }
        meta.counts[11] += 1;
    }
    let before = registrations(id, old.map(|r| &r.input));
    let after = registrations(id, new.as_ref().map(|r| &r.input));
    for (key, member) in before.difference(&after) {
        change_route(ws, key.clone(), *member, false)?;
    }
    for (key, member) in after.difference(&before) {
        change_route(ws, key.clone(), *member, true)?;
    }
    if new.is_none() {
        if !routes(ws, &Key::Incoming(id))?.is_empty() {
            return Err(Error::new(
                "unavailable_reference",
                "surviving reference to private output",
            ));
        }
        ws.put(Key::Incoming(id), None)?;
        meta.counts[11] = meta.counts[11]
            .checked_sub(1)
            .ok_or_else(|| Error::new("corrupt_state", "output count"))?;
    }
    ws.put(Key::Record(id), new.map(Stored::Record))
}

fn read_query<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    read: &Read,
) -> Result<i128> {
    let result = tree::prefix(ws, read.root, read.before)?;
    ws.put(
        Key::Query(read.id),
        Some(Stored::Query(Query {
            source: read.root,
            operation: "sum".into(),
            phase: if read.validate {
                "validate"
            } else {
                "calculate"
            }
            .into(),
            channel: "amount".into(),
            lower: "negative_infinity".into(),
            upper: read.before.map_or(Bound::All, Bound::BeforeTime),
            selected: None,
            result,
        })),
    )?;
    Ok(result)
}

pub(crate) fn settle<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    context: Context,
    changes: &[Change],
    meta: &mut Meta,
    revision: u64,
    allocate: &mut dyn FnMut() -> Result<Uuid>,
) -> Result<()> {
    let mut pending = BTreeSet::new();
    let mut root_queue: BTreeSet<_> = ws
        .changed_roots()
        .into_iter()
        .filter(|r| r.slot == 2)
        .collect();
    for change in changes {
        if change
            .old
            .as_ref()
            .or(change.new.as_ref())
            .is_some_and(|r| matches!(r.contract, 9 | 10))
        {
            pending.insert(change.id);
        }
        if change
            .old
            .as_ref()
            .or(change.new.as_ref())
            .is_some_and(|r| r.contract == 7)
            && change.old.as_ref().map(|r| &r.input) != change.new.as_ref().map(|r| &r.input)
        {
            subscribers(ws, Key::Direct(change.id), &mut pending)?;
        }
    }
    let mut visited_roots = BTreeSet::new();
    let mut plans = BTreeMap::new();
    loop {
        while let Some(root) = root_queue.pop_first() {
            if visited_roots.insert(root) {
                subscribers(ws, Key::Subscribers(root), &mut pending)?;
            }
        }
        let Some(id) = pending.pop_first() else {
            break;
        };
        if plans.contains_key(&id) {
            continue;
        }
        let record = ws.record(id)?;
        let plan = shape(ws, context, id, record)?;
        for (_, output) in plan.old_outputs.values() {
            let Input::Output { account, .. } = output.input else {
                unreachable!()
            };
            root_queue.insert(Address::new(account, 2));
        }
        for emit in &plan.emits {
            root_queue.insert(Address::new(emit.account, 2));
        }
        plans.insert(id, plan);
        if plans.len() > 64 {
            return Err(Error::new("state_limit", "causal closure"));
        }
    }
    ws.work.causal_candidates = plans.len() as u64;
    let mut dependencies: BTreeMap<_, BTreeSet<Uuid>> = plans
        .iter()
        .filter(|(_, p)| p.record.is_some())
        .map(|(id, _)| (*id, BTreeSet::new()))
        .collect();
    for (consumer, plan) in &plans {
        if plan.record.is_none() {
            continue;
        }
        for read in plan.reads.iter().filter(|q| !q.validate) {
            for (producer, source) in &plans {
                for emit in &source.emits {
                    ws.charge("dependency", 1)?;
                    if read.root == Address::new(emit.account, 2)
                        && read.before.is_none_or(|upper| emit.at < upper)
                        && dependencies
                            .get_mut(consumer)
                            .expect("consumer")
                            .insert(*producer)
                    {
                        ws.charge("edge", 1)?;
                    }
                }
            }
        }
    }
    let mut order = vec![];
    while !dependencies.is_empty() {
        let ready: Vec<_> = dependencies
            .iter()
            .filter(|(_, inputs)| inputs.is_empty())
            .map(|(id, _)| *id)
            .collect();
        if ready.is_empty() {
            return Err(Error::new("feedback", "final active calculation cycle"));
        }
        for id in ready {
            dependencies.remove(&id);
            order.push(id);
            for inputs in dependencies.values_mut() {
                inputs.remove(&id);
            }
        }
    }
    // Allocate every prerequisite identity before constructing dependent state.
    for (producer, plan) in &mut plans {
        for emit in &plan.emits {
            if let std::collections::btree_map::Entry::Vacant(binding) =
                plan.bindings.entry(emit.role)
            {
                let output = allocate_role(ws, Address::new(*producer, emit.role), meta, allocate)?;
                binding.insert(output);
            }
        }
    }
    for (producer, plan) in &plans {
        for (role, (id, old)) in &plan.old_outputs {
            reconcile_member(ws, Address::new(*id, 1), financial(Some(old), 1)?, None)?;
            ws.work.detached_outputs += 1;
            if !plan.emits.iter().any(|e| e.role == *role) {
                write_output(ws, *id, Some(old), None, meta, revision)?;
            }
        }
        for slot in [1, 2] {
            if !plan.reads.iter().any(|q| q.id.slot == slot) {
                ws.put(Key::Query(Address::new(*producer, slot)), None)?;
            }
        }
        if plan.record.is_none() {
            for (role, output) in &plan.bindings {
                ws.put(
                    Key::Role(Address::new(*producer, *role)),
                    Some(Stored::Role(Role {
                        output: *output,
                        retired: true,
                    })),
                )?;
            }
        }
    }
    for id in order {
        let plan = &plans[&id];
        let mut record = plan.record.clone().expect("surviving calculation");
        let mut values = vec![];
        for read in plan.reads.iter().filter(|q| !q.validate) {
            values.push(read_query(ws, read)?);
        }
        let amount = match &record.input {
            Input::Adjustment { target, .. } => {
                let delta = target
                    .checked_sub(values[0])
                    .ok_or_else(|| Error::new("overflow", "adjustment difference"))?;
                record.derived = Some(Calculated::Adjustment {
                    at: plan.reads[0].before.expect("prefix time"),
                    before: values[0],
                    delta,
                });
                delta
            }
            Input::Basis { factor, .. } => {
                let sum = values.into_iter().try_fold(0i128, |a, b| {
                    a.checked_add(b)
                        .ok_or_else(|| Error::new("overflow", "basis sum"))
                })?;
                let value = sum
                    .checked_mul(i128::from(*factor))
                    .ok_or_else(|| Error::new("overflow", "basis product"))?;
                record.derived = Some(Calculated::Basis { value });
                value
            }
            _ => unreachable!(),
        };
        ws.work.causal_evaluations += 1;
        ws.put(Key::Record(id), Some(Stored::Record(record)))?;
        for emit in &plan.emits {
            let output = plan.bindings[&emit.role];
            let new = Record {
                contract: 12,
                tenant: context.tenant,
                owner: plan.record.as_ref().expect("producer").owner,
                reader: plan.record.as_ref().expect("producer").reader,
                version: revision,
                input: Input::Output {
                    producer: id,
                    role: emit.role,
                    account: emit.account,
                    at: emit.at,
                    amount: if emit.zero { 0 } else { amount },
                },
                derived: None,
            };
            validate_references(ws, &new.input, context)?;
            write_output(
                ws,
                output,
                plan.old_outputs.get(&emit.role).map(|(_, r)| r),
                Some(new.clone()),
                meta,
                revision,
            )?;
            reconcile_member(ws, Address::new(output, 1), None, financial(Some(&new), 1)?)?;
        }
    }
    for plan in plans.values() {
        for read in plan.reads.iter().filter(|q| q.validate) {
            if read_query(ws, read)? < 0 {
                return Err(Error::new("invariant", "negative validation prefix"));
            }
        }
    }
    Ok(())
}
