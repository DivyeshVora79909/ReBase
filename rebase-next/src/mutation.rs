//! Shared command staging and final publication. Model behavior cannot select a
//! different receipt, authority, CAS or transaction implementation.
use crate::{
    binding::{self, Binding, NativeInput},
    index::NativeIndex,
    model::{Prepared, Visibility},
    native_codec::{Address, Key, StoredValue},
    native_slice::{
        Attempt, Command, Context, Error, Meta, ModelChange, ModelRecord, Result, Settled,
    },
    tree,
};
use std::collections::BTreeSet;
use uuid::Uuid;

pub fn check_counts<B: Binding>(model: &Prepared<B>, meta: &Meta) -> Result<()> {
    let limits = B::limits();
    let mut public = 0u32;
    let mut private = 0u32;
    for (&code, &count) in &meta.counts {
        let declaration = model.contract(code)?;
        if declaration.visibility == Visibility::Engine {
            private += u32::from(count)
        } else {
            public += u32::from(count)
        }
        if limits
            .per_contract
            .get(&code)
            .is_some_and(|limit| count > *limit)
        {
            return Err(Error::new("state_limit", "contract population"));
        }
    }
    if public > u32::from(limits.public_records)
        || private > u32::from(limits.outputs)
        || meta.reserved > limits.reservations
    {
        return Err(Error::new("state_limit", "bounded model population"));
    }
    Ok(())
}

pub fn validate_references<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    input: &B::Input,
    context: Context,
) -> Result<()> {
    let contract = model.contract(input.contract())?;
    for (id, _, slot) in input.references() {
        let declaration = contract
            .references
            .iter()
            .find(|r| r.slot == slot)
            .ok_or_else(|| Error::new("model", "undeclared bound reference"))?;
        let record = ws
            .record(id)?
            .ok_or_else(|| Error::new("unavailable_reference", "required source unavailable"))?;
        if record.tenant != context.tenant || !declaration.targets.contains(&record.contract) {
            return Err(Error::new(
                "unavailable_reference",
                "reference type or tenant",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::type_complexity)]
pub fn reconcile_member<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    id: Address,
    old: Option<(
        Address,
        <B::Index as NativeIndex>::Key,
        <B::Index as NativeIndex>::Leaf,
    )>,
    new: Option<(
        Address,
        <B::Index as NativeIndex>::Key,
        <B::Index as NativeIndex>::Leaf,
    )>,
) -> Result<()> {
    if old == new {
        return Ok(());
    }
    if let Some((root, at, leaf)) = old {
        let actual = tree::node(ws, root, id)?;
        if actual.key.value != at || actual.leaf != leaf {
            return Err(Error::new(
                "corrupt_state",
                "old membership differs from source",
            ));
        }
        tree::remove(ws, root, id)?;
    }
    if let Some((root, at, leaf)) = new {
        tree::insert(ws, root, id, at, leaf)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn settle_authorized<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    model: &Prepared<B>,
    context: Context,
    commands: &[Command],
    allocate: &mut dyn FnMut() -> Result<Uuid>,
    trusted: bool,
    authorize: &mut dyn FnMut(
        &mut Attempt<L, B>,
        &Command,
        Option<&ModelRecord<B>>,
        Option<&ModelRecord<B>>,
    ) -> Result<()>,
) -> Result<Settled> {
    let Some(StoredValue::Meta(mut meta)) = ws.get(&Key::Meta)? else {
        return Err(Error::new("corrupt_state", "missing model header"));
    };
    if meta.model != model.identity()
        || meta.codec != crate::native_codec::CODEC
        || model.engine().codec != crate::native_codec::CODEC
    {
        return Err(Error::new("model_mismatch", "store/model identity differs"));
    }
    if meta.tenant != context.tenant {
        return Err(Error::new("forbidden", "tenant differs"));
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
    let role_slots: BTreeSet<_> = model
        .contracts()
        .flat_map(|c| c.outputs.iter().map(|o| o.role))
        .collect();
    let mut changes = vec![];
    for command in commands {
        ws.charge("command", 1)?;
        let id = command.id();
        let old = ws.record(id)?;
        authorize(ws, command, old.as_ref(), None)?;
        if let Some(old) = &old {
            let visibility = model.contract(old.contract)?.visibility;
            if visibility == Visibility::Engine || visibility == Visibility::Fixture && !trusted {
                return Err(Error::new("forbidden", "private record"));
            }
        }
        let new = match command {
            Command::Create {
                contract, fields, ..
            } => {
                let declaration = model.contract(*contract)?;
                if declaration.visibility == Visibility::Engine
                    || declaration.visibility == Visibility::Fixture && !trusted
                {
                    return Err(Error::new("forbidden", "private contract"));
                }
                if old.is_some() {
                    return Err(Error::new("already_exists", "source UUID exists"));
                }
                if ws.get(&Key::Reserved(id))?.is_some() {
                    return Err(Error::new("unavailable_reference", "reserved identity"));
                }
                for slot in &role_slots {
                    if ws.get(&Key::Role(Address::new(id, *slot)))?.is_some() {
                        return Err(Error::new(
                            "unavailable_reference",
                            "retired producer identity",
                        ));
                    }
                }
                let input = model.validate(*contract, fields)?;
                validate_references(ws, model, &input, context)?;
                let count = meta.counts.entry(*contract).or_default();
                *count = count
                    .checked_add(1)
                    .ok_or_else(|| Error::new("state_limit", "source count"))?;
                Some(ModelRecord {
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
                if previous.tenant != context.tenant {
                    return Err(Error::new("forbidden", "source authority"));
                }
                if previous.version != *if_version {
                    return Err(Error::new("stale_version", "source version"));
                }
                if let Command::Update { set, unset, .. } = command {
                    let declaration = model.contract(previous.contract)?;
                    if !unset.is_empty()
                        || set.keys().any(|key| {
                            !declaration
                                .fields
                                .iter()
                                .any(|f| f.name == key && f.mutable)
                        })
                    {
                        return Err(Error::new("invalid_input", "protected or required field"));
                    }
                    let mut value = serde_json::to_value(&previous.input)
                        .map_err(|e| Error::new("codec", e.to_string()))?;
                    value
                        .as_object_mut()
                        .ok_or_else(|| Error::new("internal", "input object"))?
                        .extend(set.clone());
                    let mut next = previous.clone();
                    next.input = model.validate(previous.contract, &value)?;
                    validate_references(ws, model, &next.input, context)?;
                    Some(next)
                } else {
                    let count = meta
                        .counts
                        .get_mut(&previous.contract)
                        .ok_or_else(|| Error::new("corrupt_state", "missing source count"))?;
                    *count = count
                        .checked_sub(1)
                        .ok_or_else(|| Error::new("corrupt_state", "source count underflow"))?;
                    None
                }
            }
        };
        authorize(ws, command, old.as_ref(), new.as_ref())?;
        ws.put(Key::Record(id), new.clone().map(StoredValue::Record))?;
        changes.push(ModelChange { id, old, new });
    }
    check_counts(model, &meta)?;
    for change in &changes {
        if let (None, Some(new)) = (&change.old, &change.new) {
            for (key, value) in binding::headers(model, change.id, &new.input, revision)? {
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
    B::settle_changes(ws, model, context, &changes, &mut meta, revision, allocate)?;
    check_counts(model, &meta)?;
    for change in &changes {
        if let Some(new) = ws.record(change.id)? {
            validate_references(ws, model, &new.input, context)?;
        } else {
            for (key, _) in binding::headers(
                model,
                change.id,
                &change
                    .old
                    .as_ref()
                    .ok_or_else(|| Error::new("internal", "missing deleted source"))?
                    .input,
                revision,
            )? {
                match ws.get(&key)? {
                    Some(StoredValue::Root(root)) if root.head.is_some() => {
                        return Err(Error::new("unavailable_reference", "nonempty retired root"));
                    }
                    Some(
                        StoredValue::Incoming(rows)
                        | StoredValue::Direct(rows)
                        | StoredValue::Subscribers(rows),
                    ) if !rows.is_empty() => {
                        return Err(Error::new(
                            "unavailable_reference",
                            "surviving reference or subscriber",
                        ));
                    }
                    _ => {}
                }
                ws.put(key, None)?;
            }
        }
    }
    for id in ws.changed_roots() {
        if let Some(StoredValue::Root(mut root)) = ws.get(&Key::Root(id))? {
            root.revision = revision;
            ws.put(Key::Root(id), Some(StoredValue::Root(root)))?;
        }
    }
    for id in ws.changed_records() {
        if let Some(mut current) = ws.record(id)? {
            if let Some(StoredValue::Record(old)) = ws.original(&Key::Record(id))? {
                current.version = old.version;
                if current != old {
                    current.version = revision;
                }
            } else {
                current.version = revision;
            }
            ws.put(Key::Record(id), Some(StoredValue::Record(current)))?;
        }
    }
    meta.revision = revision;
    ws.put(Key::Meta, Some(StoredValue::Meta(meta)))?;
    Ok(Settled { revision })
}
