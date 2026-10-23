//! Independent source-literal acceptance for ready quantity publications.
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{ToPrimitive, Zero};
use rebase_semantic_proof::{
    binding::Binding,
    lifecycle,
    local::{Mutation, Store},
    model::Prepared,
    models::quantity::{JOIN, MAX_QUANTITY, Quantity, SCALE, SOURCE},
    native_slice::Context,
    values::{Rational, Rounding},
};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};
use uuid::Uuid;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/quantity-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
fn request(store: &Store<Quantity>, commands: Value) -> Mutation {
    serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity()).unwrap(),"operation_id":Uuid::new_v4(),"commands":commands,"returning":[]})).unwrap()
}
fn update(store: &Store<Quantity>, record: Uuid, set: Value) -> Value {
    json!({"op":"update","id":record,"if_version":store.get(store.model().identity(),record).unwrap().unwrap().version.to_string(),"set":set,"unset":[]})
}
fn source(value: i128) -> Value {
    json!({"op":"create","id":id(10),"contract":SOURCE,"fields":{"value":value.to_string()}})
}
fn scale(record: Uuid, parent: Uuid, n: i128, d: i128, rounding: &str) -> Value {
    json!({"op":"create","id":record,"contract":SCALE,"fields":{"parent":parent,"factor":{"numerator":n.to_string(),"denominator":d.to_string()},"rounding":rounding}})
}
fn commit(store: &Store<Quantity>, commands: Value) -> (Mutation, Value) {
    let req = request(store, commands);
    let result = store.mutate(&req).unwrap();
    store.check_integrity().unwrap();
    (req, result)
}
fn value(store: &Store<Quantity>, record: Uuid) -> i128 {
    let record = store
        .get(store.model().identity(), record)
        .unwrap()
        .unwrap();
    serde_json::from_value::<rebase_semantic_proof::models::quantity::Derived>(
        record.derived.unwrap(),
    )
    .unwrap()
    .quantity
}
fn error_code(store: &Store<Quantity>, commands: Value) -> &'static str {
    store.mutate(&request(store, commands)).unwrap_err().code
}
fn seeded() -> (Directory, Arc<Prepared<Quantity>>, Store<Quantity>) {
    let dir = Directory::new();
    let model = Arc::new(Prepared::<Quantity>::load().unwrap());
    let store = Store::<Quantity>::create_secured(
        dir.0.join("app.redb"),
        model.clone(),
        Context {
            tenant: id(1),
            actor: id(2),
        },
    )
    .unwrap();
    (dir, model, store)
}

// Independent exact integer oracle: quotient and remainder only, without calling apply().
fn oracle(value: i128, numerator: i128, denominator: i128, rounding: Rounding) -> i128 {
    let product = BigInt::from(value) * BigInt::from(numerator);
    let divisor = BigInt::from(denominator);
    let (floor, rem) = product.div_mod_floor(&divisor);
    let inc = !rem.is_zero()
        && match rounding {
            Rounding::Exact => panic!("oracle called for inexact value"),
            Rounding::Floor => false,
            Rounding::Ceiling => true,
            Rounding::TowardZero => product < BigInt::zero(),
            Rounding::HalfEven => match (&rem * 2u8).cmp(&divisor) {
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Equal => floor.is_odd(),
            },
            Rounding::HalfAwayFromZero => match (&rem * 2u8).cmp(&divisor) {
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Equal => product > BigInt::zero(),
            },
        };
    (floor + u8::from(inc)).to_i128().unwrap()
}

#[test]
fn ready_publication_chain_diamond_repeat_slots_and_source_edit() {
    let (_dir, model, store) = seeded();
    let plan = Quantity::fixture_plan(&model, "quantities", id(40)).unwrap();
    let ids = &plan["fixture"]["ids"];
    let get = |n: &str| Uuid::parse_str(ids[n].as_str().unwrap()).unwrap();
    let (source_id, left, right, join) = (get("source"), get("left"), get("right"), get("join"));
    let (seed, output) = commit(&store, plan["commands"].clone());
    assert_eq!(
        (
            value(&store, left),
            value(&store, right),
            value(&store, join)
        ),
        (6, 4, 10)
    );
    assert_eq!(store.mutate(&seed).unwrap()["result"], output["result"]);
    commit(
        &store,
        json!([update(&store, source_id, json!({"value":"18"}))]),
    );
    assert_eq!(
        (
            value(&store, left),
            value(&store, right),
            value(&store, join)
        ),
        (9, 6, 15)
    );
    // Same source occupies two distinct declared join slots, so the sum is twice its value.
    commit(
        &store,
        json!([{"op":"create","id":id(20),"contract":JOIN,"fields":{"left":source_id,"right":source_id}}]),
    );
    assert_eq!(value(&store, id(20)), 36);
    // Scale -> Join -> Scale is an ordinary multi-hop publication chain.
    commit(&store, json!([scale(id(21), join, 2, 3, "exact")]));
    assert_eq!(value(&store, id(21)), 10);
}

#[test]
fn exact_rounding_rejects_every_scale_atomically_and_zero_factor_does_not_hide_cycle() {
    let (_dir, _model, store) = seeded();
    let source_id = id(10);
    let left = id(11);
    let right = id(12);
    let join = id(13);
    commit(
        &store,
        json!([source(12),scale(left,source_id,1,2,"exact"),scale(right,source_id,1,3,"exact"),{"op":"create","id":join,"contract":JOIN,"fields":{"left":left,"right":right}}]),
    );
    let before = store.observe_for_verification().unwrap();
    let rejected = request(
        &store,
        json!([update(&store, source_id, json!({"value":"13"}))]),
    );
    assert_eq!(store.mutate(&rejected).unwrap_err().code, "inexact");
    // The transaction leaves every table unchanged, including its operation receipt.
    assert_eq!(store.observe_for_verification().unwrap(), before);
    assert_eq!(
        (
            value(&store, left),
            value(&store, right),
            value(&store, join)
        ),
        (6, 4, 10)
    );
    // Retargeting left to the join closes a cycle, even though factor is zero.
    assert_eq!(
        error_code(
            &store,
            json!([update(
                &store,
                left,
                json!({"parent":join,"factor":{"numerator":"0","denominator":"1"}})
            )])
        ),
        "feedback"
    );
    assert_eq!((value(&store, left), value(&store, join)), (6, 10));
}

#[test]
fn retargets_and_parent_edits_settle_final_state_in_either_order() {
    for reverse in [false, true] {
        let (_dir, _model, store) = seeded();
        let a = id(10);
        let b = id(11);
        let s = id(12);
        commit(
            &store,
            json!([source(12),{"op":"create","id":b,"contract":SOURCE,"fields":{"value":"18"}},scale(s,a,1,2,"exact")]),
        );
        let edit_parent = update(&store, b, json!({"value":"20"}));
        let retarget = update(&store, s, json!({"parent":b}));
        let commands = if reverse {
            json!([retarget, edit_parent])
        } else {
            json!([edit_parent, retarget])
        };
        commit(&store, commands);
        assert_eq!(value(&store, s), 10);
    }
    // Reverse the final dependency edges in one mutation; both command orders
    // must settle against the complete graph rather than transient edges.
    for reverse in [false, true] {
        let (_dir, _model, store) = seeded();
        let a = id(30);
        let b = id(31);
        let x = id(32);
        let y = id(33);
        commit(
            &store,
            json!([
                {"op":"create","id":a,"contract":SOURCE,"fields":{"value":"12"}},
                {"op":"create","id":b,"contract":SOURCE,"fields":{"value":"18"}},
                scale(x, a, 1, 1, "exact"),
                scale(y, b, 1, 1, "exact")
            ]),
        );
        let x_to_b = update(&store, x, json!({"parent":b}));
        let y_to_a = update(&store, y, json!({"parent":a}));
        commit(
            &store,
            if reverse {
                json!([y_to_a, x_to_b])
            } else {
                json!([x_to_b, y_to_a])
            },
        );
        assert_eq!((value(&store, x), value(&store, y)), (18, 12));
    }
}

#[test]
fn source_literal_rational_oracle_covers_signed_ties_large_values_and_bounds() {
    for (v, n, d, mode, want) in [
        (5, 1, 2, Rounding::HalfEven, 2),
        (7, 1, 2, Rounding::HalfEven, 4),
        (-5, 1, 2, Rounding::HalfEven, -2),
        (-7, 1, 2, Rounding::HalfEven, -4),
        (5, 1, 2, Rounding::HalfAwayFromZero, 3),
        (-5, 1, 2, Rounding::HalfAwayFromZero, -3),
        (-5, 1, 2, Rounding::Floor, -3),
        (-5, 1, 2, Rounding::Ceiling, -2),
        (
            -(1i128 << 54) + 1,
            1,
            3,
            Rounding::HalfEven,
            oracle(-(1i128 << 54) + 1, 1, 3, Rounding::HalfEven),
        ),
    ] {
        assert_eq!(oracle(v, n, d, mode), want);
        assert_eq!(Rational::new(n, d).unwrap().apply(v, mode).unwrap(), want);
    }
    assert!(Rational::new(1, 0).is_err());
    assert!(
        Rational::new(i128::MAX, 1)
            .unwrap()
            .apply(2, Rounding::Exact)
            .is_err()
    );
    assert!(
        Rational::new(1, 1)
            .unwrap()
            .apply(i128::MAX, Rounding::Exact)
            .is_ok()
    );
}

#[test]
fn source_bounds_accept_signed_limits_and_reject_values_outside_them() {
    let (_dir, _model, store) = seeded();
    let src = id(10);
    commit(&store, json!([source(MAX_QUANTITY)]));
    assert_eq!(value(&store, src), MAX_QUANTITY);
    commit(
        &store,
        json!([update(
            &store,
            src,
            json!({"value":(-MAX_QUANTITY).to_string()})
        )]),
    );
    assert_eq!(value(&store, src), -MAX_QUANTITY);
    assert_eq!(
        error_code(
            &store,
            json!([update(
                &store,
                src,
                json!({"value":(MAX_QUANTITY + 1).to_string()})
            )])
        ),
        "invalid_input"
    );
    assert_eq!(
        error_code(
            &store,
            json!([update(
                &store,
                src,
                json!({"value":(-MAX_QUANTITY - 1).to_string()})
            )])
        ),
        "invalid_input"
    );
    assert_eq!(value(&store, src), -MAX_QUANTITY);
}

#[test]
fn cas_replay_reopen_and_lifecycle_preserve_quantities() {
    let (dir, model, store) = seeded();
    let src = id(10);
    let (seed, first) = commit(&store, json!([source(12)]));
    assert_eq!(store.mutate(&seed).unwrap()["result"], first["result"]);
    let stale = update(&store, src, json!({"value":"14"}));
    commit(&store, json!([update(&store, src, json!({"value":"18"}))]));
    assert_eq!(error_code(&store, json!([stale])), "stale_version");
    let before = store.observe_for_verification().unwrap();
    let backup = dir.0.join("backup.json");
    store.backup(&backup).unwrap();
    let path = dir.0.join("restored.redb");
    lifecycle::restore(&backup, &path, model.clone()).unwrap();
    let restored = Store::<Quantity>::open(&path, model).unwrap();
    assert_eq!(restored.observe_for_verification().unwrap(), before);
    restored.check_integrity().unwrap();
    assert_eq!(value(&restored, src), 18);
}
