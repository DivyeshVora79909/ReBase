//! Literal native acceptance for the bounded authored invoicing model.
//! Numeric expectations are source facts, not copies of settled output values.
use rebase_semantic_proof::{
    binding::Binding,
    local::{Mutation, Store},
    model::Prepared,
    models::invoicing::{Derived, Invoicing},
    native_slice::{Context, ModelRecord},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
use uuid::Uuid;

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/invoicing-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn file(&self) -> PathBuf {
        self.0.join("invoice.redb")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn create(directory: &Directory) -> Store<Invoicing> {
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

#[test]
fn developer_fixtures_are_repeatable_and_execute_through_the_shared_store() {
    for (name, base, gross) in [
        ("invoice", 10005, 11555),
        ("invoice-credit", 8004, 9244),
        ("invoice-paid", 10005, 11555),
        ("invoice-refund", 8004, 9244),
    ] {
        let directory = Directory::new();
        let store = create(&directory);
        let draft = Invoicing::fixture_plan(store.model(), name, id(123)).unwrap();
        assert_eq!(
            draft,
            Invoicing::fixture_plan(store.model(), name, id(123)).unwrap()
        );
        let other = Invoicing::fixture_plan(store.model(), name, id(124)).unwrap();
        let ids: std::collections::BTreeSet<_> = draft["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|command| command["id"].as_str().unwrap())
            .collect();
        assert!(
            other["commands"]
                .as_array()
                .unwrap()
                .iter()
                .all(|command| !ids.contains(command["id"].as_str().unwrap()))
        );
        let mutation: Mutation = serde_json::from_value(json!({
            "model":store.model().identity(),
            "context":store.operation_context(store.model().identity()).unwrap(),
            "operation_id":id(5000),"commands":draft["commands"],"returning":draft["returning"]
        }))
        .unwrap();
        store.mutate(&mutation).unwrap();
        store.check_integrity().unwrap();
        let invoice =
            Uuid::parse_str(draft["fixture"]["ids"]["Invoice"].as_str().unwrap()).unwrap();
        assert_eq!(root_sum(&store, invoice.as_u128(), 7), base);
        assert_eq!(root_sum(&store, invoice.as_u128(), 13), gross);
        assert_eq!(draft["fixture"]["expected"]["gross"], gross.to_string());
        if matches!(name, "invoice-paid" | "invoice-refund") {
            for (slot, key) in [
                (21, "paid"),
                (23, "balance"),
                (29, "receivable"),
                (31, "payable"),
            ] {
                assert_eq!(
                    root_sum(&store, invoice.as_u128(), slot).to_string(),
                    draft["fixture"]["expected"][key]
                );
            }
            for (label, slot, key) in [("Treasury", 37, "cash"), ("Payment", 41, "refund_capacity")]
            {
                let owner =
                    Uuid::parse_str(draft["fixture"]["ids"][label].as_str().unwrap()).unwrap();
                assert_eq!(
                    root_sum(&store, owner.as_u128(), slot).to_string(),
                    draft["fixture"]["expected"][key]
                );
            }
        }
        assert!(Invoicing::fixture_plan(store.model(), "unknown", id(1)).is_err());
    }
}
fn request(store: &Store<Invoicing>, operation: u128, commands: Value) -> Mutation {
    serde_json::from_value(json!({
        "model":store.model().identity(),
        "context":store.operation_context(store.model().identity()).unwrap(),
        "operation_id":id(operation),"commands":commands,"returning":[id(20),id(40),id(41)]
    }))
    .unwrap()
}
fn commit(store: &Store<Invoicing>, operation: u128, commands: Value) -> (Mutation, Value) {
    let request = request(store, operation, commands);
    let result = store.mutate(&request).unwrap();
    store.check_integrity().unwrap();
    (request, result)
}
fn records(store: &Store<Invoicing>) -> BTreeMap<Uuid, ModelRecord<Invoicing>> {
    store.inspect().unwrap()["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                serde_json::from_value(row["id"].clone()).unwrap(),
                serde_json::from_value(row["record"].clone()).unwrap(),
            )
        })
        .collect()
}
fn update(store: &Store<Invoicing>, record: u128, set: Value) -> Value {
    json!({"op":"update","id":id(record),"if_version":records(store)[&id(record)].version.to_string(),"set":set,"unset":[]})
}
fn root_sum(store: &Store<Invoicing>, owner: u128, slot: u16) -> i128 {
    let image = store.inspect().unwrap();
    image["roots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["root"]["id"] == id(owner).to_string() && row["root"]["slot"] == slot)
        .unwrap()["summary"]["value"]["sum"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}
fn output_ids(store: &Store<Invoicing>) -> BTreeMap<(Uuid, u16), Uuid> {
    store.inspect().unwrap()["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let role = &row["source_role"];
            (
                (
                    serde_json::from_value(role["id"].clone()).unwrap(),
                    role["slot"].as_u64().unwrap() as u16,
                ),
                serde_json::from_value(row["binding"]["output"].clone()).unwrap(),
            )
        })
        .collect()
}
fn baseline(store: &Store<Invoicing>) {
    commit(
        store,
        1000,
        json!([
            {"op":"create","id":id(10),"contract":101,"fields":{"currency":1}},
            {"op":"create","id":id(11),"contract":101,"fields":{"currency":1}},
            {"op":"create","id":id(20),"contract":211,"fields":{"invoice":id(10),"at":"0","quantity":{"numerator":"3","denominator":"2"},"unit_price_minor":"6670","rounding":"half_even"}},
            {"op":"create","id":id(30),"contract":401,"fields":{"invoice":id(10),"kind":"base","rate":{"numerator":"1","denominator":"10"},"rounding":"half_even"}},
            {"op":"create","id":id(31),"contract":401,"fields":{"invoice":id(10),"kind":"net","rate":{"numerator":"1","denominator":"20"},"rounding":"half_even"}},
            {"op":"create","id":id(40),"contract":509,"fields":{"invoice":id(10),"rule":id(30),"at":"10"}},
            {"op":"create","id":id(41),"contract":509,"fields":{"invoice":id(10),"rule":id(31),"at":"20"}}
        ]),
    );
}
fn correction(store: &Store<Invoicing>) -> (Mutation, Value) {
    commit(
        store,
        1001,
        json!([
            {"op":"create","id":id(50),"contract":307,"fields":{"invoice":id(10),"issue":id(20),"at":"50","amount_minor":"2001"}},
            {"op":"create","id":id(51),"contract":509,"fields":{"invoice":id(10),"rule":id(30),"at":"51"}},
            {"op":"create","id":id(52),"contract":509,"fields":{"invoice":id(10),"rule":id(31),"at":"52"}}
        ]),
    )
}
fn assessment(
    store: &Store<Invoicing>,
    record: u128,
    basis: i128,
    prior: i128,
    assessed: i128,
    delta: i128,
) {
    assert_eq!(
        records(store)[&id(record)].derived,
        Some(Derived::Assessment {
            basis_minor: basis,
            prior_minor: prior,
            assessed_minor: assessed,
            delta_minor: delta,
        })
    );
}

#[test]
fn fractional_issue_dated_taxes_and_linked_credit_reach_literal_totals() {
    let directory = Directory::new();
    let store = create(&directory);
    baseline(&store);
    assert_eq!(
        records(&store)[&id(20)].derived,
        Some(Derived::Issue {
            amount_minor: 10005
        })
    );
    assessment(&store, 40, 10005, 0, 1000, 1000);
    assessment(&store, 41, 11005, 0, 550, 550);
    assert_eq!(root_sum(&store, 10, 7), 10005);
    assert_eq!(root_sum(&store, 10, 13), 11555);
    let original_ids = output_ids(&store);
    let (request, result) = correction(&store);
    assessment(&store, 51, 8004, 1000, 800, -200);
    assessment(&store, 52, 8804, 550, 440, -110);
    assert_eq!(root_sum(&store, 10, 7), 8004);
    assert_eq!(root_sum(&store, 10, 13), 9244);
    assert_eq!(root_sum(&store, 20, 17), 8004);
    assert_eq!(root_sum(&store, 30, 19), 800);
    assert_eq!(root_sum(&store, 31, 19), 440);
    for (role, output) in &original_ids {
        assert_eq!(output_ids(&store)[role], *output);
    }
    let before = store.observe_for_verification().unwrap();
    let replay = store.mutate(&request).unwrap();
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["result"], result["result"]);
    assert_eq!(store.observe_for_verification().unwrap(), before);
    drop(store);
    let reopened =
        Store::<Invoicing>::open(directory.file(), Arc::new(Prepared::load().unwrap())).unwrap();
    assert_eq!(reopened.observe_for_verification().unwrap(), before);
    assert_eq!(
        reopened.mutate(&request).unwrap()["result"],
        result["result"]
    );
    reopened.check_integrity().unwrap();
}

#[test]
fn dated_source_and_rule_edits_recompute_taxes_and_preserve_zero_roles() {
    let directory = Directory::new();
    let store = create(&directory);
    baseline(&store);
    correction(&store);
    commit(
        &store,
        1002,
        json!([
            {"op":"create","id":id(60),"contract":509,"fields":{"invoice":id(10),"rule":id(30),"at":"60"}},
            {"op":"create","id":id(61),"contract":509,"fields":{"invoice":id(10),"rule":id(31),"at":"61"}}
        ]),
    );
    assessment(&store, 60, 8004, 800, 800, 0);
    assessment(&store, 61, 8804, 440, 440, 0);
    let stable_ids = output_ids(&store);
    // Moving a historical credit changes early assessments, even though the
    // final invoice amount stays equal and later correction outputs become zero.
    commit(&store, 1003, json!([update(&store, 50, json!({"at":"5"}))]));
    assessment(&store, 40, 8004, 0, 800, 800);
    assessment(&store, 41, 8804, 0, 440, 440);
    assessment(&store, 51, 8004, 800, 800, 0);
    assessment(&store, 52, 8804, 440, 440, 0);
    assert_eq!(root_sum(&store, 10, 13), 9244);
    assert_eq!(output_ids(&store), stable_ids);
    // A price edit at time zero also repairs all the later query consumers.
    commit(
        &store,
        1004,
        json!([
            update(&store, 50, json!({"at":"50"})),
            update(&store, 20, json!({"unit_price_minor":"6000"}))
        ]),
    );
    assert_eq!(
        records(&store)[&id(20)].derived,
        Some(Derived::Issue { amount_minor: 9000 })
    );
    assessment(&store, 40, 9000, 0, 900, 900);
    assessment(&store, 41, 9900, 0, 495, 495);
    assessment(&store, 51, 6999, 900, 700, -200);
    assessment(&store, 52, 7699, 495, 385, -110);
    assert_eq!(root_sum(&store, 10, 13), 8084);
    commit(
        &store,
        1005,
        json!([update(
            &store,
            30,
            json!({"rate":{"numerator":"1","denominator":"5"}})
        )]),
    );
    assert_eq!(root_sum(&store, 30, 19), 1400);
    assert_eq!(root_sum(&store, 31, 19), 420);
    assert_eq!(root_sum(&store, 10, 13), 8819);
    // Kind is a directly resolved parent field: it changes the active query
    // from gross slot37 to base slot31 and removes old query registrations.
    commit(
        &store,
        1006,
        json!([update(&store, 31, json!({"kind":"base"}))]),
    );
    assert_eq!(root_sum(&store, 31, 19), 350);
    assert_eq!(root_sum(&store, 10, 13), 8749);
    let image = store.inspect().unwrap();
    let own_queries: Vec<_> = image["queries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["query"]["id"] == id(41).to_string())
        .map(|row| row["query"]["slot"].as_u64().unwrap())
        .collect();
    assert!(own_queries.contains(&31));
    assert!(own_queries.contains(&41));
    assert!(!own_queries.contains(&37));
    assert_eq!(output_ids(&store), stable_ids);
    store.check_integrity().unwrap();
}

#[test]
fn invalid_invoicing_batches_preserve_every_table_revision_and_receipt() {
    let directory = Directory::new();
    let store = create(&directory);
    baseline(&store);
    let before = store.observe_for_verification().unwrap();
    let before_inspect = store.inspect().unwrap();
    let cases = [
        (
            json!({"op":"create","id":id(60),"contract":509,"fields":{"invoice":id(10),"rule":id(30),"at":"10"}}),
            "invariant",
        ),
        (
            json!({"op":"create","id":id(61),"contract":307,"fields":{"invoice":id(10),"issue":id(20),"at":"50","amount_minor":"10006"}}),
            "invariant",
        ),
        (
            json!({"op":"create","id":id(62),"contract":307,"fields":{"invoice":id(11),"issue":id(20),"at":"50","amount_minor":"1"}}),
            "unavailable_reference",
        ),
        (
            json!({"op":"create","id":id(63),"contract":509,"fields":{"invoice":id(11),"rule":id(30),"at":"50"}}),
            "unavailable_reference",
        ),
        (
            update(
                &store,
                20,
                json!({"unit_price_minor":i128::MAX.to_string()}),
            ),
            "overflow",
        ),
        (
            update(
                &store,
                20,
                json!({"quantity":{"numerator":"1","denominator":"3"},"rounding":"exact"}),
            ),
            "inexact",
        ),
        (
            update(
                &store,
                30,
                json!({"rate":{"numerator":i128::MAX.to_string(),"denominator":"1"}}),
            ),
            "overflow",
        ),
        (update(&store, 30, json!({"rounding":"exact"})), "inexact"),
        (
            json!({"op":"create","id":id(64),"contract":307,"fields":{"invoice":id(10),"issue":id(20),"at":"-1","amount_minor":"1"}}),
            "invariant",
        ),
        (
            update(&store, 20, json!({"invoice":id(11)})),
            "invalid_input",
        ),
        (
            update(&store, 30, json!({"invoice":id(11)})),
            "invalid_input",
        ),
    ];
    for (index, (command, kind)) in cases.into_iter().enumerate() {
        let request = request(
            &store,
            2000 + index as u128,
            json!([
                {"op":"create","id":id(9000 + index as u128),"contract":101,"fields":{"currency":1}},
                command
            ]),
        );
        assert_eq!(
            store.mutate(&request).unwrap_err().code,
            kind,
            "case {index}"
        );
        assert_eq!(
            store.observe_for_verification().unwrap(),
            before,
            "case {index}"
        );
        assert_eq!(store.inspect().unwrap(), before_inspect, "case {index}");
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
}

#[test]
fn zero_outputs_and_owned_roots_retire_with_their_authored_producers() {
    let directory = Directory::new();
    let store = create(&directory);
    commit(
        &store,
        3000,
        json!([
            {"op":"create","id":id(10),"contract":101,"fields":{"currency":1}},
            {"op":"create","id":id(20),"contract":211,"fields":{"invoice":id(10),"at":"0","quantity":{"numerator":"0","denominator":"1"},"unit_price_minor":"6670","rounding":"exact"}}
        ]),
    );
    assert_eq!(
        records(&store)[&id(20)].derived,
        Some(Derived::Issue { amount_minor: 0 })
    );
    let roles = output_ids(&store);
    assert_eq!(roles.len(), 5);
    assert_eq!(root_sum(&store, 10, 7), 0);
    assert_eq!(root_sum(&store, 10, 13), 0);
    assert_eq!(root_sum(&store, 20, 17), 0);
    let deletion = json!({"op":"delete","id":id(20),"if_version":records(&store)[&id(20)].version.to_string()});
    commit(&store, 3001, json!([deletion]));
    assert_eq!(records(&store).len(), 1);
    assert_eq!(output_ids(&store), roles);
    let image = store.inspect().unwrap();
    assert_eq!(image["roots"].as_array().unwrap().len(), 6);
    for role in image["roles"].as_array().unwrap() {
        assert_eq!(role["binding"]["retired"], true);
    }
    store.check_integrity().unwrap();

    let full_directory = Directory::new();
    let full_store = create(&full_directory);
    baseline(&full_store);
    let before_roles = output_ids(&full_store);
    // Parent-first order is intentional: only the final transaction graph
    // determines whether references, roots and managed outputs survive.
    let commands: Vec<_> = [10,11,20,30,31,40,41].into_iter().map(|record| {
        json!({"op":"delete","id":id(record),"if_version":records(&full_store)[&id(record)].version.to_string()})
    }).collect();
    commit(&full_store, 3002, json!(commands));
    assert!(records(&full_store).is_empty());
    assert!(
        full_store.inspect().unwrap()["roots"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(output_ids(&full_store), before_roles);
    full_store.check_integrity().unwrap();
}

fn remove(store: &Store<Invoicing>, record: u128) -> Value {
    json!({"op":"delete","id":id(record),"if_version":records(store)[&id(record)].version.to_string()})
}

fn reject(store: &Store<Invoicing>, operation: u128, commands: Value, kind: &str) {
    let before = store.observe_for_verification().unwrap();
    let request = request(store, operation, commands);
    assert_eq!(
        store.mutate(&request).unwrap_err().code,
        kind,
        "operation {operation}"
    );
    assert_eq!(
        store.observe_for_verification().unwrap(),
        before,
        "operation {operation}"
    );
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

fn settlement_correction() -> Vec<Value> {
    vec![
        json!({"op":"create","id":id(50),"contract":307,"fields":{"invoice":id(10),"issue":id(20),"at":"50","amount_minor":"2001"}}),
        json!({"op":"create","id":id(51),"contract":509,"fields":{"invoice":id(10),"rule":id(30),"at":"51"}}),
        json!({"op":"create","id":id(52),"contract":509,"fields":{"invoice":id(10),"rule":id(31),"at":"52"}}),
        json!({"op":"create","id":id(80),"contract":809,"fields":{"invoice":id(10),"treasury":id(60),"payment":id(70),"at":"50","amount_minor":"2311"}}),
    ]
}

#[test]
fn settlement_preserves_historical_balance_and_claim_identity_across_sign_changes() {
    for reversed in [false, true] {
        let directory = Directory::new();
        let store = create(&directory);
        baseline(&store);
        commit(
            &store,
            4000,
            json!([
                {"op":"create","id":id(60),"contract":601,"fields":{"currency":1,"name":"Cash"}},
                {"op":"create","id":id(70),"contract":701,"fields":{"invoice":id(10),"treasury":id(60),"at":"30","amount_minor":"11555"}}
            ]),
        );
        assert_eq!(root_sum(&store, 10, 23), 0);
        let mut correction = settlement_correction();
        reject(&store, 4001, json!(&correction[..3]), "invariant");
        correction[3]["fields"]["at"] = json!("52");
        reject(&store, 4002, json!(correction), "invariant");
        correction[3]["fields"]["at"] = json!("50");
        if reversed {
            correction.reverse();
        }
        commit(&store, 4003, json!(correction));
        for (owner, slot, amount) in [
            (10, 7, 8004),
            (10, 13, 9244),
            (10, 21, 9244),
            (10, 23, 0),
            (10, 29, 13866),
            (10, 31, 13866),
            (60, 37, 9244),
            (70, 41, 9244),
        ] {
            assert_eq!(root_sum(&store, owner, slot), amount);
        }
        for (before, expected) in [(31, "0"), (51, "310"), (52, "110"), (53, "0")] {
            let query = serde_json::from_value(json!({"model":store.model().identity(),"owner":id(10),"slot":23,"read":{"kind":"before","at":before.to_string()}})).unwrap();
            assert_eq!(store.root_read(&query).unwrap()["value"]["sum"], expected);
        }
        let stable = output_ids(&store);
        // Extra priced source makes both negative reassessments positive. Both
        // directional roles remain present even when their amount becomes zero.
        commit(
            &store,
            4004,
            json!([
                {"op":"create","id":id(21),"contract":211,"fields":{"invoice":id(10),"at":"40","quantity":{"numerator":"1","denominator":"1"},"unit_price_minor":"3000","rounding":"exact"}}
            ]),
        );
        assessment(&store, 51, 11004, 1000, 1100, 100);
        assessment(&store, 52, 12104, 550, 605, 55);
        for (slot, amount) in [
            (13, 12709),
            (21, 9244),
            (23, 3465),
            (29, 17021),
            (31, 13556),
        ] {
            assert_eq!(root_sum(&store, 10, slot), amount);
        }
        for (role, output) in &stable {
            assert_eq!(output_ids(&store)[role], *output);
        }
        let (request, outcome) = commit(&store, 4005, json!([remove(&store, 21)]));
        reject(
            &store,
            4006,
            json!([
                {"op":"create","id":id(21),"contract":211,"fields":{"invoice":id(10),"at":"40","quantity":{"numerator":"1","denominator":"1"},"unit_price_minor":"3000","rounding":"exact"}}
            ]),
            "unavailable_reference",
        );
        for (role, output) in &stable {
            assert_eq!(output_ids(&store)[role], *output);
        }
        assert_eq!(root_sum(&store, 10, 23), 0);
        let before = store.observe_for_verification().unwrap();
        assert_eq!(store.mutate(&request).unwrap()["result"], outcome["result"]);
        assert_eq!(store.observe_for_verification().unwrap(), before);
        drop(store);
        let reopened =
            Store::<Invoicing>::open(directory.file(), Arc::new(Prepared::load().unwrap()))
                .unwrap();
        assert_eq!(reopened.observe_for_verification().unwrap(), before);
        reopened.check_integrity().unwrap();
    }
}

#[test]
fn invalid_settlement_batches_roll_back_every_table_revision_and_receipt() {
    let directory = Directory::new();
    let store = create(&directory);
    baseline(&store);
    commit(
        &store,
        5000,
        json!([
            {"op":"create","id":id(60),"contract":601,"fields":{"currency":1,"name":"Cash"}},
            {"op":"create","id":id(61),"contract":601,"fields":{"currency":2,"name":"Other currency"}},
            {"op":"create","id":id(62),"contract":601,"fields":{"currency":1,"name":"Other cash"}},
            {"op":"create","id":id(70),"contract":701,"fields":{"invoice":id(10),"treasury":id(60),"at":"30","amount_minor":"5000"}},
            {"op":"create","id":id(71),"contract":701,"fields":{"invoice":id(10),"treasury":id(60),"at":"30","amount_minor":"3000"}},
            {"op":"create","id":id(80),"contract":809,"fields":{"invoice":id(10),"treasury":id(60),"payment":id(70),"at":"40","amount_minor":"1000"}}
        ]),
    );
    let payment = |treasury, at, amount| json!({"op":"create","id":id(72),"contract":701,"fields":{"invoice":id(10),"treasury":id(treasury),"at":at,"amount_minor":amount}});
    let refund = |invoice, treasury, payment, amount| json!({"op":"create","id":id(81),"contract":809,"fields":{"invoice":id(invoice),"treasury":id(treasury),"payment":id(payment),"at":"50","amount_minor":amount}});
    let cases = [
        (payment(60, "30", "4000"), "invariant"),
        (payment(60, "-1", "1"), "invariant"),
        (payment(61, "30", "1"), "unavailable_reference"),
        (refund(11, 60, 70, "1"), "unavailable_reference"),
        (refund(10, 62, 70, "1"), "unavailable_reference"),
        (refund(10, 60, 999, "1"), "unavailable_reference"),
        (refund(10, 60, 70, "4001"), "invariant"),
        (update(&store, 70, json!({"at":"41"})), "invariant"),
        (
            update(&store, 70, json!({"amount_minor":"999"})),
            "invariant",
        ),
        (
            update(&store, 70, json!({"amount_minor":"9000"})),
            "invariant",
        ),
        (update(&store, 80, json!({"at":"29"})), "invariant"),
        (
            update(&store, 80, json!({"amount_minor":"5001"})),
            "invariant",
        ),
        (
            update(&store, 80, json!({"amount_minor":"0"})),
            "invalid_input",
        ),
        (
            update(&store, 70, json!({"amount_minor":"-1"})),
            "invalid_input",
        ),
        (
            update(&store, 70, json!({"invoice":id(11)})),
            "invalid_input",
        ),
        (
            update(&store, 70, json!({"treasury":id(62)})),
            "invalid_input",
        ),
        (
            update(&store, 80, json!({"payment":id(71)})),
            "invalid_input",
        ),
        (
            update(&store, 80, json!({"treasury":id(62)})),
            "invalid_input",
        ),
        (update(&store, 60, json!({"currency":2})), "invalid_input"),
        (update(&store, 60, json!({"name":""})), "invalid_input"),
        (remove(&store, 70), "invariant"),
        (remove(&store, 60), "unavailable_reference"),
        (
            json!({"op":"create","id":id(90),"contract":907,"fields":{"producer":id(40),"role":31,"target":id(10),"at":"10","amount":"1"}}),
            "forbidden",
        ),
        (
            update(&store, 20, json!({"unit_price_minor":"1000"})),
            "invariant",
        ),
    ];
    for (index, (command, kind)) in cases.into_iter().enumerate() {
        reject(
            &store,
            5100 + index as u128,
            json!([
                {"op":"create","id":id(9000),"contract":101,"fields":{"currency":1}}, command
            ]),
            kind,
        );
    }
}

#[test]
fn partial_payments_repeated_refunds_and_self_memberships_follow_the_final_graph() {
    for reversed in [false, true] {
        let directory = Directory::new();
        let store = create(&directory);
        baseline(&store);
        // New parent links follow the shared API's creation order. Once the
        // parents exist, both simultaneous refund command orders are valid.
        reject(
            &store,
            5998,
            json!([
                {"op":"create","id":id(80),"contract":809,"fields":{"invoice":id(10),"treasury":id(60),"payment":id(70),"at":"0","amount_minor":"2000"}},
                {"op":"create","id":id(60),"contract":601,"fields":{"currency":1,"name":"Cash"}},
                {"op":"create","id":id(70),"contract":701,"fields":{"invoice":id(10),"treasury":id(60),"at":"0","amount_minor":"5000"}}
            ]),
            "unavailable_reference",
        );
        commit(
            &store,
            5999,
            json!([
                json!({"op":"create","id":id(60),"contract":601,"fields":{"currency":1,"name":"Cash"}}),
                json!({"op":"create","id":id(70),"contract":701,"fields":{"invoice":id(10),"treasury":id(60),"at":"0","amount_minor":"5000"}}),
            ]),
        );
        assert_eq!(root_sum(&store, 10, 21), 5000);
        // Refund UUIDs sort before the payment. An ordinary per-record prefix
        // floor would reject this valid complete-timestamp cancellation.
        let mut commands = vec![
            json!({"op":"create","id":id(68),"contract":809,"fields":{"invoice":id(10),"treasury":id(60),"payment":id(70),"at":"0","amount_minor":"2000"}}),
            json!({"op":"create","id":id(69),"contract":809,"fields":{"invoice":id(10),"treasury":id(60),"payment":id(70),"at":"0","amount_minor":"3000"}}),
        ];
        if reversed {
            commands.reverse();
        }
        commit(&store, 6000, json!(commands));
        for (owner, slot) in [(10, 21), (60, 37), (70, 41)] {
            assert_eq!(root_sum(&store, owner, slot), 0);
        }
        commit(
            &store,
            6001,
            json!([update(&store, 70, json!({"amount_minor":"6000"}))]),
        );
        assert_eq!(root_sum(&store, 10, 21), 1000);
        assert_eq!(root_sum(&store, 10, 23), 10555);
        commit(
            &store,
            6002,
            json!([
                {"op":"create","id":id(82),"contract":809,"fields":{"invoice":id(10),"treasury":id(60),"payment":id(70),"at":"30","amount_minor":"1000"}}
            ]),
        );
        reject(
            &store,
            6003,
            json!([
                {"op":"create","id":id(83),"contract":809,"fields":{"invoice":id(10),"treasury":id(60),"payment":id(70),"at":"31","amount_minor":"1"}}
            ]),
            "invariant",
        );
        // Deleting a parent before its children is valid when none survive.
        let mut commands: Vec<_> = [10, 11, 60, 70, 20, 30, 31, 40, 41, 68, 69, 82]
            .into_iter()
            .map(|record| remove(&store, record))
            .collect();
        if reversed {
            commands.reverse();
        }
        commit(&store, 6004, json!(commands));
        assert!(records(&store).is_empty());
        assert!(
            store.inspect().unwrap()["roots"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        store.check_integrity().unwrap();
    }
}

#[test]
fn self_membership_resolves_only_a_declared_root_of_its_own_contract() {
    for corruption in 0..3 {
        let mut declarations = Invoicing::declarations().unwrap();
        let payment = declarations.iter_mut().find(|c| c.code == 701).unwrap();
        let member = payment
            .memberships
            .iter_mut()
            .find(|m| m.through == "self")
            .unwrap();
        match corruption {
            0 => {
                member.root_contract = 101;
                member.root_slot = 23;
            }
            1 => member.root_slot = 99,
            _ => member.kind = rebase_semantic_proof::indexes::standard::QUOTE,
        }
        assert!(Prepared::<Invoicing>::prepare(declarations).is_err());
    }
    Prepared::<Invoicing>::load().unwrap();
}
