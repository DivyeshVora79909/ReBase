//! Complete invoicing checks from authored sources and chronological histories.
//! No settlement, route-discovery, evaluator or maintained query value supplies
//! an expected amount. The exact scalar primitive has a separate Fraction oracle.
use super::invoicing::{Derived, Input, Invoicing, TaxKind};
use crate::{
    binding::NativeInput,
    indexes::standard::Leaf,
    integrity::{Members, Snapshot, require},
    local::Store,
    native_codec::{Address, Key, StoredValue},
    native_slice::{Error, Query, Result},
    time_range::TimeRange,
};
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

type Histories = BTreeMap<Address, Vec<(i64, i128)>>;

fn corrupt(detail: &str) -> Error {
    Error::new("corrupt_state", detail)
}
fn prefix(events: &Histories, root: Address, before: i64) -> Result<i128> {
    events
        .get(&root)
        .into_iter()
        .flatten()
        .filter(|(at, _)| *at < before)
        .fold(BigInt::zero(), |sum, (_, amount)| sum + *amount)
        .to_i128()
        .ok_or_else(|| corrupt("invoicing source prefix overflow"))
}
fn add_query(
    routes: &mut BTreeMap<Key, BTreeSet<Address>>,
    queries: &mut BTreeMap<Address, Query>,
    producer: Uuid,
    slot: u16,
    source: Address,
    at: i64,
    result: i128,
) {
    let query = Address::new(producer, slot);
    routes
        .entry(Key::Subscribers(source))
        .or_default()
        .insert(query);
    queries.insert(
        query,
        Query {
            source,
            operation: "sum".into(),
            phase: "calculate".into(),
            channel: "amount".into(),
            range: TimeRange::before(at),
            selected: None,
            result,
        },
    );
}

// Only the independently checked role reservation supplies physical identity.
// Its target, time and amount all come from the source-derived expectation.
fn expect_output(
    snapshot: &Snapshot<'_, Invoicing>,
    outputs: &mut BTreeMap<Uuid, Input>,
    members: &mut Members,
    producer: Uuid,
    role: u16,
    root: Address,
    event: (i64, i128),
) -> Result<()> {
    let Some(StoredValue::Role(binding)) =
        snapshot.all.get(&Key::Role(Address::new(producer, role)))
    else {
        return Err(corrupt("missing invoicing output role"));
    };
    require(!binding.retired, "active invoicing output role retired")?;
    let (at, amount) = event;
    require(
        outputs
            .insert(
                binding.output,
                Input::Output {
                    producer,
                    role,
                    target: root.id,
                    at,
                    amount,
                },
            )
            .is_none(),
        "duplicate invoicing output identity",
    )?;
    require(
        members
            .insert(
                Address::new(binding.output, role),
                (root, at, Leaf::Financial(amount)),
            )
            .is_none(),
        "duplicate invoicing output membership",
    )
}

pub(crate) fn check(store: &Store<Invoicing>) -> Result<serde_json::Value> {
    let snapshot = Snapshot::load(store)?;
    let keys = snapshot.expected_keys.clone();
    let mut routes = snapshot.routes.clone();
    let mut members = BTreeMap::new();
    let mut queries = BTreeMap::new();
    let mut outputs = BTreeMap::new();
    let mut events = Histories::new();
    let mut assessments = vec![];
    let mut unique_dates = BTreeSet::new();

    for (&id, record) in &snapshot.records {
        // Independently derive the single parent-level registration from the
        // authored reference and declarations, not the mutation's route helper.
        let declaration = store.model().contract(record.contract)?;
        for (target, _, slot) in record.input.references() {
            let reference = declaration
                .references
                .iter()
                .find(|r| r.slot == slot)
                .ok_or_else(|| corrupt("undeclared invoicing source reference"))?;
            if !reference.direct_fields.is_empty()
                || declaration
                    .publication_inputs
                    .iter()
                    .any(|input| input.reference_slot == slot)
            {
                routes
                    .entry(Key::Direct(target))
                    .or_default()
                    .insert(Address::new(id, slot));
            }
        }
        match record.input {
            Input::Invoice { .. } => {
                for slot in [7, 13, 21, 23, 29, 31] {
                    events.entry(Address::new(id, slot)).or_default();
                }
            }
            Input::Treasury { .. } => {
                events.entry(Address::new(id, 37)).or_default();
            }
            Input::TaxRule { .. } => {
                events.entry(Address::new(id, 19)).or_default();
            }
            Input::Issue {
                invoice,
                at,
                quantity,
                unit_price_minor,
                rounding,
            } => {
                let amount_minor = quantity
                    .apply(unit_price_minor, rounding)
                    .map_err(|_| corrupt("invoicing source price cannot be quantized"))?;
                require(
                    record.derived == Some(Derived::Issue { amount_minor }),
                    "source-derived invoicing issue amount",
                )?;
                for (role, root) in [
                    (11, Address::new(invoice, 7)),
                    (13, Address::new(invoice, 13)),
                    (17, Address::new(id, 17)),
                    (23, Address::new(invoice, 23)),
                    (29, Address::new(invoice, 29)),
                ] {
                    events.entry(root).or_default().push((at, amount_minor));
                    expect_output(
                        &snapshot,
                        &mut outputs,
                        &mut members,
                        id,
                        role,
                        root,
                        (at, amount_minor),
                    )?;
                }
            }
            Input::IssueShare {
                issue,
                ratio,
                rounding,
            } => {
                let Some(parent) = snapshot.records.get(&issue) else {
                    return Err(corrupt("missing IssueShare parent"));
                };
                let Input::Issue {
                    quantity,
                    unit_price_minor,
                    rounding: parent_rounding,
                    ..
                } = parent.input
                else {
                    return Err(corrupt("IssueShare parent contract"));
                };
                let basis_minor = quantity
                    .apply(unit_price_minor, parent_rounding)
                    .map_err(|_| corrupt("IssueShare source parent cannot be quantized"))?;
                let amount_minor = ratio
                    .apply(basis_minor, rounding)
                    .map_err(|_| corrupt("IssueShare source ratio cannot be quantized"))?;
                require(
                    record.derived
                        == Some(Derived::IssueShare {
                            basis_minor,
                            amount_minor,
                        }),
                    "source-derived IssueShare publication",
                )?;
            }
            Input::Credit {
                invoice,
                issue,
                at,
                amount_minor,
            } => {
                let Some(source) = snapshot.records.get(&issue) else {
                    return Err(corrupt("missing credited issue"));
                };
                require(
                    matches!(source.input,Input::Issue { invoice: owner,.. } if owner == invoice),
                    "credit and issue belong to the same invoice",
                )?;
                let amount = amount_minor
                    .checked_neg()
                    .ok_or_else(|| corrupt("invoicing source credit overflow"))?;
                for (slot, root, amount) in [
                    (11, Address::new(invoice, 7), amount),
                    (13, Address::new(invoice, 13), amount),
                    (17, Address::new(issue, 17), amount),
                    (23, Address::new(invoice, 23), amount),
                    (31, Address::new(invoice, 31), amount_minor),
                ] {
                    events.entry(root).or_default().push((at, amount));
                    members.insert(Address::new(id, slot), (root, at, Leaf::Financial(amount)));
                }
            }
            Input::Payment {
                invoice,
                treasury,
                at,
                amount_minor,
            }
            | Input::Refund {
                invoice,
                treasury,
                at,
                amount_minor,
                ..
            } => {
                let Some(invoice_source) = snapshot.records.get(&invoice) else {
                    return Err(corrupt("missing settlement invoice"));
                };
                let Some(treasury_source) = snapshot.records.get(&treasury) else {
                    return Err(corrupt("missing settlement treasury"));
                };
                require(
                    matches!((&invoice_source.input, &treasury_source.input),
                        (Input::Invoice { currency }, Input::Treasury { currency: cash_currency, .. })
                        if currency == cash_currency),
                    "source settlement currencies agree",
                )?;
                let negative = amount_minor
                    .checked_neg()
                    .ok_or_else(|| corrupt("invoicing source settlement overflow"))?;
                let contributions = if let Input::Refund { payment, .. } = record.input {
                    let Some(original) = snapshot.records.get(&payment) else {
                        return Err(corrupt("missing refunded payment"));
                    };
                    require(
                        matches!(original.input, Input::Payment { invoice: original_invoice, treasury: original_treasury, .. }
                            if original_invoice == invoice && original_treasury == treasury),
                        "refund agrees with its source payment",
                    )?;
                    [
                        (21, Address::new(invoice, 21), negative),
                        (23, Address::new(invoice, 23), amount_minor),
                        (29, Address::new(invoice, 29), amount_minor),
                        (37, Address::new(treasury, 37), negative),
                        (41, Address::new(payment, 41), negative),
                    ]
                } else {
                    [
                        (21, Address::new(invoice, 21), amount_minor),
                        (23, Address::new(invoice, 23), negative),
                        (31, Address::new(invoice, 31), amount_minor),
                        (37, Address::new(treasury, 37), amount_minor),
                        (41, Address::new(id, 41), amount_minor),
                    ]
                };
                for (slot, root, amount) in contributions {
                    events.entry(root).or_default().push((at, amount));
                    members.insert(Address::new(id, slot), (root, at, Leaf::Financial(amount)));
                }
            }
            Input::Assessment { invoice, rule, at } => {
                let Some(parent) = snapshot.records.get(&rule) else {
                    return Err(corrupt("missing assessment rule"));
                };
                require(
                    matches!(parent.input,Input::TaxRule { invoice: owner,.. } if owner == invoice),
                    "assessment and rule belong to the same invoice",
                )?;
                require(
                    unique_dates.insert((rule, at)),
                    "same-time assessment of the same rule",
                )?;
                assessments.push((at, id));
            }
            _ => {}
        }
    }

    // Strict-before reads exclude other events at the same timestamp, even if
    // this source-order walk has already produced their expectations.
    assessments.sort();
    for (at, id) in assessments {
        let record = &snapshot.records[&id];
        let Input::Assessment { invoice, rule, .. } = record.input else {
            unreachable!()
        };
        let Input::TaxRule {
            kind,
            rate,
            rounding,
            ..
        } = snapshot.records[&rule].input
        else {
            return Err(corrupt("assessment source rule contract"));
        };
        let assessed_root = Address::new(rule, 19);
        let prior_minor = prefix(&events, assessed_root, at)?;
        let (slot, source) = match kind {
            TaxKind::Base => (31, Address::new(invoice, 7)),
            TaxKind::Net => (37, Address::new(invoice, 13)),
        };
        let source_total = prefix(&events, source, at)?;
        let basis_minor = match kind {
            TaxKind::Base => source_total,
            TaxKind::Net => source_total
                .checked_sub(prior_minor)
                .ok_or_else(|| corrupt("invoicing source net basis overflow"))?,
        };
        let assessed_minor = rate
            .apply(basis_minor, rounding)
            .map_err(|_| corrupt("invoicing source tax cannot be quantized"))?;
        let delta_minor = assessed_minor
            .checked_sub(prior_minor)
            .ok_or_else(|| corrupt("invoicing source assessment delta overflow"))?;
        require(
            record.derived
                == Some(Derived::Assessment {
                    basis_minor,
                    prior_minor,
                    assessed_minor,
                    delta_minor,
                }),
            "source-derived chronological assessment",
        )?;
        add_query(
            &mut routes,
            &mut queries,
            id,
            slot,
            source,
            at,
            source_total,
        );
        add_query(
            &mut routes,
            &mut queries,
            id,
            41,
            assessed_root,
            at,
            prior_minor,
        );
        let payable = if delta_minor < 0 {
            delta_minor
                .checked_neg()
                .ok_or_else(|| corrupt("source payable overflow"))?
        } else {
            0
        };
        for (role, root, amount) in [
            (13, Address::new(invoice, 13), delta_minor),
            (19, assessed_root, delta_minor),
            (23, Address::new(invoice, 23), delta_minor),
            (29, Address::new(invoice, 29), delta_minor.max(0)),
            (31, Address::new(invoice, 31), payable),
        ] {
            events.entry(root).or_default().push((at, amount));
            expect_output(
                &snapshot,
                &mut outputs,
                &mut members,
                id,
                role,
                root,
                (at, amount),
            )?;
        }
    }

    let actual_outputs: BTreeMap<_, _> = snapshot
        .records
        .iter()
        .filter(|(_, r)| matches!(r.input, Input::Output { .. }))
        .map(|(id, r)| (*id, r.input.clone()))
        .collect();
    require(
        actual_outputs == outputs,
        "complete source-derived invoicing output inventory",
    )?;
    for history in events.values() {
        let mut grouped = BTreeMap::<i64, BigInt>::new();
        for &(at, amount) in history {
            *grouped.entry(at).or_default() += amount;
        }
        let mut total = BigInt::zero();
        for amount in grouped.values() {
            total += amount;
            require(
                !total.is_negative(),
                "source-derived invoicing historical floor",
            )?;
        }
    }
    snapshot.finish(keys, members, routes, queries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::ReadableTable;
    use crate::{
        binding::Binding,
        local::{KV, Mutation},
        model::Prepared,
        native_slice::Context,
    };
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    fn independent_invoicing_checker_rejects_numeric_and_structural_corruption() {
        let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/invoicing-checker-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&directory).unwrap();
        let id = Uuid::from_u128;
        let store = Store::<Invoicing>::create(
            directory.join("model.redb"),
            Arc::new(Prepared::load().unwrap()),
            Context {
                tenant: id(1),
                actor: id(2),
            },
        )
        .unwrap();
        let fixture = Invoicing::fixture_plan(store.model(), "invoice-refund", id(200)).unwrap();
        let request: Mutation = serde_json::from_value(json!({
            "model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),
            "operation_id":id(100),"returning":[],"commands":fixture["commands"]
        })).unwrap();
        store.mutate(&request).unwrap();
        store.check_integrity().unwrap();
        let snapshot = Snapshot::load(&store).unwrap();
        let mut corruptions = vec![];
        for (key, value) in &snapshot.all {
            let mut bad = value.clone();
            let changed = match &mut bad {
                StoredValue::Record(record) => match (&mut record.input, &mut record.derived) {
                    (Input::Output { amount, .. }, _) => {
                        *amount += 1;
                        true
                    }
                    (
                        Input::Payment { amount_minor, .. } | Input::Refund { amount_minor, .. },
                        _,
                    ) => {
                        *amount_minor += 1;
                        true
                    }
                    (Input::Treasury { currency, .. }, _) => {
                        *currency += 1;
                        true
                    }
                    (_, Some(Derived::Issue { amount_minor })) => {
                        *amount_minor += 1;
                        true
                    }
                    (_, Some(Derived::Assessment { delta_minor, .. })) => {
                        *delta_minor += 1;
                        true
                    }
                    _ => false,
                },
                StoredValue::Query(query) => {
                    query.result += 1;
                    true
                }
                StoredValue::Node(node) => {
                    node.height += 1;
                    true
                }
                _ => false,
            };
            if changed {
                corruptions.push((key.clone(), Some(bad)));
            }
            if matches!(value, StoredValue::RouteNode(_) | StoredValue::Node(_)) {
                corruptions.push((key.clone(), None));
            }
        }
        drop(snapshot);
        assert!(corruptions.len() >= 6);
        for (key, bad) in corruptions {
            let original = {
                let read = store.db.begin_read().unwrap();
                read.open_table(KV)
                    .unwrap()
                    .get(key.encode().as_slice())
                    .unwrap()
                    .unwrap()
                    .value()
                    .to_vec()
            };
            let write = store.db.begin_write().unwrap();
            {
                let mut table = write.open_table(KV).unwrap();
                if let Some(bad) = bad {
                    // Corrupt persisted bytes directly; validating encoding may reject first.
                    let bytes = serde_json::to_vec(&bad).unwrap();
                    table
                        .insert(key.encode().as_slice(), bytes.as_slice())
                        .unwrap();
                } else {
                    table.remove(key.encode().as_slice()).unwrap();
                }
            }
            write.commit().unwrap();
            assert!(
                store.check_integrity().is_err(),
                "accepted corrupted {key:?}"
            );
            let write = store.db.begin_write().unwrap();
            write
                .open_table(KV)
                .unwrap()
                .insert(key.encode().as_slice(), original.as_slice())
                .unwrap();
            write.commit().unwrap();
            store.check_integrity().unwrap();
        }
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
