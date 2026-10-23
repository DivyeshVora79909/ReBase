//! Persisted route edits and snapshot selection versus an independent inventory.
use rebase_semantic_proof::{
    native_codec::{self, Address, Key, Stored},
    native_slice::Workspace,
    routes::{self, Endpoint, Order, Route},
    time_range::TimeRange,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound,
};
use uuid::Uuid;
type Bytes = BTreeMap<Vec<u8>, Vec<u8>>;
type Expected = BTreeMap<Address, (Route, Endpoint)>;
fn addr(n: u128, slot: u16) -> Address {
    Address::new(Uuid::from_u128(n), slot)
}
fn range(endpoint: Endpoint) -> TimeRange {
    match endpoint {
        Endpoint::Time(at) => TimeRange::before(at),
        Endpoint::Through(at) => TimeRange::through(at),
        Endpoint::All => TimeRange::ALL,
    }
}
fn flush(bytes: &mut Bytes, batch: BTreeMap<Vec<u8>, Option<Vec<u8>>>) {
    for (key, value) in batch {
        if let Some(value) = value {
            bytes.insert(key, value);
        } else {
            bytes.remove(&key);
        }
    }
}
fn check(bytes: &Bytes, expected: &Expected, owners: &[Route]) {
    let all: BTreeMap<_, _> = bytes
        .iter()
        .map(|(key, value)| {
            let key = Key::decode(key).unwrap();
            let value = native_codec::decode(&key, value).unwrap();
            (key, value)
        })
        .collect();
    fn visit(
        all: &BTreeMap<Key, Stored>,
        expected: &Expected,
        seen: &mut BTreeSet<Key>,
        route: Route,
        id: Option<Address>,
        lower: Option<Order>,
        upper: Option<Order>,
    ) -> (u16, usize) {
        let Some(id) = id else {
            return (0, 0);
        };
        let key = route.node_key(id);
        assert!(seen.insert(key.clone()));
        let Stored::RouteNode(n) = &all[&key] else {
            panic!("registration type");
        };
        assert_eq!((n.route, n.key.endpoint), expected[&id]);
        assert_eq!(n.range, range(expected[&id].1));
        assert_eq!(n.key.member, id);
        assert_eq!(route, n.route);
        assert!(lower.is_none_or(|v| v < n.key) && upper.is_none_or(|v| n.key < v));
        let (lh, lc) = visit(all, expected, seen, route, n.left, lower, Some(n.key));
        let (rh, rc) = visit(all, expected, seen, route, n.right, Some(n.key), upper);
        assert!(lh.abs_diff(rh) <= 1);
        assert_eq!(n.height, 1 + lh.max(rh));
        (n.height, lc + rc + 1)
    }
    let mut seen = BTreeSet::new();
    for &route in owners {
        let h = match (route, &all[&route.key()]) {
            (Route::Incoming(_), Stored::Incoming(h))
            | (Route::Direct(_), Stored::Direct(h))
            | (Route::Subscribers(_), Stored::Subscribers(h)) => h,
            _ => panic!("header type"),
        };
        let (_, count) = visit(&all, expected, &mut seen, route, h.head, None, None);
        assert_eq!(
            count,
            expected.values().filter(|(r, _)| *r == route).count()
        );
        assert_eq!(count, h.len as usize);
        assert_eq!(h.bounded, 0);
        seen.insert(route.key());
    }
    assert_eq!(seen, all.keys().cloned().collect());
}
fn inside(value: Endpoint, lower: Bound<Endpoint>, upper: Bound<Endpoint>) -> bool {
    let lo = match lower {
        Bound::Unbounded => true,
        Bound::Included(v) => value >= v,
        Bound::Excluded(v) => value > v,
    };
    let hi = match upper {
        Bound::Unbounded => true,
        Bound::Included(v) => value <= v,
        Bound::Excluded(v) => value < v,
    };
    lo && hi
}
fn empty_routes(owners: &[Route]) -> Bytes {
    owners
        .iter()
        .map(|&route| {
            let value = match route {
                Route::Incoming(_) => Stored::Incoming(Default::default()),
                Route::Direct(_) => Stored::Direct(Default::default()),
                Route::Subscribers(_) => Stored::Subscribers(Default::default()),
            };
            (
                route.key().encode(),
                native_codec::encode(&route.key(), &value).unwrap(),
            )
        })
        .collect()
}
#[test]
fn ordered_routes_preserve_old_and_new_memberships_through_rotations_and_moves() {
    let owners = [
        Route::Subscribers(addr(900, 2)),
        Route::Subscribers(addr(901, 2)),
    ];
    let mut bytes = Bytes::new();
    for route in owners {
        bytes.insert(
            route.key().encode(),
            native_codec::encode(&route.key(), &Stored::Subscribers(Default::default())).unwrap(),
        );
    }
    let mut expected = Expected::new();
    let endpoints = [
        Endpoint::Time(i64::MIN),
        Endpoint::Time(-1),
        Endpoint::Time(0),
        Endpoint::Time(1),
        Endpoint::Time(i64::MAX),
        Endpoint::All,
    ];
    for i in 0..96 {
        let id = addr(1 + (i * 53 % 96), 31);
        let endpoint = endpoints[(i % 6) as usize];
        let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 50_000);
        routes::change(&mut ws, &owners[0].key(), id, range(endpoint), true).unwrap();
        let batch = ws.finish().unwrap();
        drop(ws);
        flush(&mut bytes, batch);
        expected.insert(id, (owners[0], endpoint));
        check(&bytes, &expected, &owners);
    }
    for i in 0..96 {
        let id = addr(1 + (i * 37 % 96), 31);
        let old = expected.clone();
        let (route, endpoint) = expected.remove(&id).unwrap();
        let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 50_000);
        routes::change(&mut ws, &route.key(), id, range(endpoint), false).unwrap();
        if i % 2 == 0 {
            let next = endpoints[((i + 3) % 6) as usize];
            routes::change(&mut ws, &owners[1].key(), id, range(next), true).unwrap();
            expected.insert(id, (owners[1], next));
        }
        for route in owners {
            for (lower, upper) in [
                (Bound::Unbounded, Bound::Unbounded),
                (Bound::Excluded(Endpoint::Time(i64::MAX)), Bound::Unbounded),
                (
                    Bound::Included(Endpoint::Time(0)),
                    Bound::Excluded(Endpoint::Time(1)),
                ),
                (
                    Bound::Excluded(Endpoint::Time(i64::MIN)),
                    Bound::Included(Endpoint::Time(0)),
                ),
            ] {
                for (original, source) in [(true, &old), (false, &expected)] {
                    let found: BTreeSet<_> =
                        routes::select(&mut ws, &route.key(), lower, upper, original)
                            .unwrap()
                            .into_iter()
                            .collect();
                    let oracle = source
                        .iter()
                        .filter(|(_, (r, e))| *r == route && inside(*e, lower, upper))
                        .map(|(id, _)| *id)
                        .collect();
                    assert_eq!(found, oracle);
                }
            }
        }
        let batch = ws.finish().unwrap();
        drop(ws);
        flush(&mut bytes, batch);
        check(&bytes, &expected, &owners);
    }
    let before = bytes.clone();
    let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 1);
    assert_eq!(
        routes::change(
            &mut ws,
            &owners[1].key(),
            addr(500, 31),
            TimeRange::ALL,
            true
        )
        .unwrap_err()
        .code,
        "work_limit"
    );
    drop(ws);
    assert_eq!(bytes, before);
}

#[test]
fn endpoint_rewrites_keep_original_snapshot_and_exact_endpoint_bounds() {
    let route = Route::Subscribers(addr(900, 2));
    let mut bytes = empty_routes(&[route]);
    let endpoints = [
        Endpoint::Time(i64::MIN),
        Endpoint::Time(-1),
        Endpoint::Time(0),
        Endpoint::Time(1),
        Endpoint::Time(i64::MAX),
        Endpoint::All,
    ];
    let mut expected = Expected::new();
    let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 100_000);
    for i in 0..18 {
        let id = addr(i + 1, 31);
        let endpoint = endpoints[i as usize % endpoints.len()];
        routes::change(&mut ws, &route.key(), id, range(endpoint), true).unwrap();
        expected.insert(id, (route, endpoint));
    }
    let batch = ws.finish().unwrap();
    drop(ws);
    flush(&mut bytes, batch);
    let old = expected.clone();
    let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 100_000);
    // Reuse a point identity repeatedly inside one attempt, including All and
    // both signed extremes. Original traversal must ignore every staged relink.
    for next in [
        Endpoint::All,
        Endpoint::Time(i64::MIN),
        Endpoint::Time(i64::MAX),
    ] {
        let id = addr(1, 31);
        let (_, previous) = expected[&id];
        routes::change(&mut ws, &route.key(), id, range(previous), false).unwrap();
        routes::change(&mut ws, &route.key(), id, range(next), true).unwrap();
        expected.insert(id, (route, next));
    }
    let bounds: Vec<_> = std::iter::once(Bound::Unbounded)
        .chain(
            endpoints
                .into_iter()
                .flat_map(|e| [Bound::Included(e), Bound::Excluded(e)]),
        )
        .collect();
    for &lower in &bounds {
        for &upper in &bounds {
            for (original, source) in [(true, &old), (false, &expected)] {
                let selected =
                    routes::select(&mut ws, &route.key(), lower, upper, original).unwrap();
                let actual: BTreeSet<_> = selected.iter().copied().collect();
                assert_eq!(actual.len(), selected.len(), "duplicate selection");
                let oracle = source
                    .iter()
                    .filter(|(_, (_, e))| inside(*e, lower, upper))
                    .map(|(id, _)| *id)
                    .collect();
                assert_eq!(
                    actual, oracle,
                    "{lower:?} .. {upper:?}, original={original}"
                );
            }
        }
    }
    let batch = ws.finish().unwrap();
    drop(ws);
    flush(&mut bytes, batch);
    check(&bytes, &expected, &[route]);
}

#[test]
fn every_route_kind_drains_and_reuses_deleted_registration_identities() {
    let owners = [
        Route::Incoming(Uuid::from_u128(900)),
        Route::Direct(Uuid::from_u128(901)),
        Route::Subscribers(addr(902, 2)),
    ];
    let mut bytes = empty_routes(&owners);
    let mut expected = Expected::new();
    for pass in 0..2 {
        for i in 0..24 {
            let id = addr(1 + (i * 17 % 24), 31);
            let route = owners[(i as usize + pass) % owners.len()];
            let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 10_000);
            routes::change(&mut ws, &route.key(), id, TimeRange::ALL, true).unwrap();
            let batch = ws.finish().unwrap();
            drop(ws);
            flush(&mut bytes, batch);
            expected.insert(id, (route, Endpoint::All));
            check(&bytes, &expected, &owners);
        }
        for i in 0..24 {
            let id = addr(1 + (i * 13 % 24), 31);
            let (route, endpoint) = expected.remove(&id).unwrap();
            let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 10_000);
            routes::change(&mut ws, &route.key(), id, range(endpoint), false).unwrap();
            let mut selected = BTreeSet::new();
            routes::collect(&mut ws, &route.key(), &mut selected).unwrap();
            let mut oracle: BTreeSet<_> = expected
                .iter()
                .filter(|(_, (r, _))| *r == route)
                .map(|(id, _)| id.id)
                .collect();
            oracle.insert(id.id);
            assert_eq!(selected, oracle);
            let batch = ws.finish().unwrap();
            drop(ws);
            flush(&mut bytes, batch);
            check(&bytes, &expected, &owners);
        }
        assert_eq!(bytes, empty_routes(&owners));
    }
}

#[test]
fn narrow_selection_loads_only_a_balanced_path_at_gate_population() {
    let route = Route::Subscribers(addr(9000, 2));
    let mut bytes = empty_routes(&[route]);
    let mut expected = Expected::new();
    let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 5_000_000);
    for i in 0..4096 {
        let id = addr(i + 1, 31);
        let endpoint = Endpoint::Time(i as i64);
        routes::change(&mut ws, &route.key(), id, range(endpoint), true).unwrap();
        expected.insert(id, (route, endpoint));
    }
    let batch = ws.finish().unwrap();
    drop(ws);
    flush(&mut bytes, batch);
    check(&bytes, &expected, &[route]);
    for (at, oracle) in [(4095, vec![]), (4094, vec![addr(4096, 31)])] {
        let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 256);
        assert_eq!(
            routes::select(
                &mut ws,
                &route.key(),
                Bound::Excluded(Endpoint::Time(at)),
                Bound::Unbounded,
                false
            )
            .unwrap(),
            oracle
        );
        assert!(ws.work.selector_visits <= 32, "{:?}", ws.work);
        assert!(ws.work.key_loads <= 33, "{:?}", ws.work);
        assert!(ws.work.loaded_bytes <= 16_384, "{:?}", ws.work);
        assert!(ws.finish().unwrap().is_empty());
    }
}

#[test]
fn selection_rejects_dangling_cross_route_and_cyclic_links() {
    let route = Route::Subscribers(addr(900, 2));
    let mut bytes = empty_routes(&[route]);
    let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 10_000);
    for i in 1..=7 {
        routes::change(
            &mut ws,
            &route.key(),
            addr(i, 31),
            TimeRange::before(i as i64),
            true,
        )
        .unwrap();
    }
    let batch = ws.finish().unwrap();
    drop(ws);
    flush(&mut bytes, batch);
    let Stored::Subscribers(h) =
        native_codec::decode(&route.key(), &bytes[&route.key().encode()]).unwrap()
    else {
        panic!("header type")
    };
    let head = h.head.unwrap();
    let key = route.node_key(head);
    let Stored::RouteNode(node) = native_codec::decode(&key, &bytes[&key.encode()]).unwrap() else {
        panic!("node type")
    };
    let mut corruptions = vec![];
    let mut dangling = node.clone();
    dangling.left = Some(addr(999, 31));
    corruptions.push((key.clone(), dangling));
    let mut cross_route = node.clone();
    cross_route.route = Route::Subscribers(addr(901, 2));
    corruptions.push((key, cross_route));
    let leaf_key = route.node_key(addr(1, 31));
    let Stored::RouteNode(mut cycle) =
        native_codec::decode(&leaf_key, &bytes[&leaf_key.encode()]).unwrap()
    else {
        panic!("leaf type")
    };
    assert!(cycle.left.is_none() && cycle.right.is_none());
    cycle.right = Some(head);
    corruptions.push((leaf_key, cycle));
    for (key, node) in corruptions {
        let mut bad = bytes.clone();
        bad.insert(
            key.encode(),
            native_codec::encode(&key, &Stored::RouteNode(node)).unwrap(),
        );
        let before = bad.clone();
        let mut ws = Workspace::new(|key: &[u8]| Ok(bad.get(key).cloned()), 1000);
        assert_eq!(
            routes::select(
                &mut ws,
                &route.key(),
                Bound::Unbounded,
                Bound::Unbounded,
                false
            )
            .unwrap_err()
            .code,
            "corrupt_state"
        );
        assert!(ws.finish().unwrap().is_empty());
        drop(ws);
        assert_eq!(bad, before);
    }
}
