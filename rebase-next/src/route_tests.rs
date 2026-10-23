//! Window registrations checked against literal source membership and inventory.
use crate::{
    native_codec::{self, Address, Key, Stored},
    native_slice::Workspace,
    routes::{self, Endpoint, Order, Route},
    time_range::{TimeBound, TimeRange},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound,
};
use uuid::Uuid;

type Bytes = BTreeMap<Vec<u8>, Vec<u8>>;
type Sources = BTreeMap<Address, (Route, TimeRange)>;
fn addr(n: u128) -> Address {
    Address::new(Uuid::from_u128(n), 31)
}
fn empty(owners: &[Route]) -> Bytes {
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
fn flush(bytes: &mut Bytes, batch: BTreeMap<Vec<u8>, Option<Vec<u8>>>) {
    for (key, value) in batch {
        match value {
            Some(value) => {
                bytes.insert(key, value);
            }
            None => {
                bytes.remove(&key);
            }
        }
    }
}
// i128 is only the independent oracle: the implementation never shifts times.
fn limits(range: TimeRange) -> (i128, i128) {
    let low = match range.lower {
        TimeBound::Unbounded => i128::from(i64::MIN),
        TimeBound::Included(at) => i128::from(at),
        TimeBound::Excluded(at) => i128::from(at) + 1,
    };
    let high = match range.upper {
        TimeBound::Unbounded => i128::from(i64::MAX),
        TimeBound::Included(at) => i128::from(at),
        TimeBound::Excluded(at) => i128::from(at) - 1,
    };
    (low, high)
}
fn lower_order(bound: TimeBound) -> (i128, bool) {
    match bound {
        TimeBound::Unbounded => (i128::from(i64::MIN) - 1, false),
        TimeBound::Included(at) => (i128::from(at), false),
        TimeBound::Excluded(at) => (i128::from(at), true),
    }
}
fn check(bytes: &Bytes, sources: &Sources, owners: &[Route]) {
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
        sources: &Sources,
        seen: &mut BTreeSet<Key>,
        route: Route,
        id: Option<Address>,
        bounds: (Option<Order>, Option<Order>),
    ) -> (u16, u32, Option<TimeBound>) {
        let Some(id) = id else {
            return (0, 0, None);
        };
        let key = route.node_key(id);
        assert!(seen.insert(key.clone()));
        let Stored::RouteNode(n) = &all[&key] else {
            panic!("node type");
        };
        assert_eq!((n.route, n.range), sources[&id]);
        assert_eq!(n.key.member, id);
        let upper = match n.range.upper {
            TimeBound::Unbounded => Endpoint::All,
            TimeBound::Included(at) => Endpoint::Through(at),
            TimeBound::Excluded(at) => Endpoint::Time(at),
        };
        assert_eq!(n.key.endpoint, upper);
        assert!(bounds.0.is_none_or(|v| v < n.key));
        assert!(bounds.1.is_none_or(|v| n.key < v));
        let (lh, lc, lm) = visit(all, sources, seen, route, n.left, (bounds.0, Some(n.key)));
        let (rh, rc, rm) = visit(all, sources, seen, route, n.right, (Some(n.key), bounds.1));
        assert!(lh.abs_diff(rh) <= 1);
        assert_eq!(n.height, 1 + lh.max(rh));
        let (low, high) = limits(n.range);
        let own = (low <= high).then_some(n.range.lower);
        let minimum = [own, lm, rm]
            .into_iter()
            .flatten()
            .min_by_key(|v| lower_order(*v));
        assert_eq!(n.min_lower, minimum, "{id:?}");
        (n.height, lc + rc + 1, minimum)
    }
    let mut seen = BTreeSet::new();
    for &route in owners {
        let h = match &all[&route.key()] {
            Stored::Incoming(h) | Stored::Direct(h) | Stored::Subscribers(h) => h,
            _ => panic!("header type"),
        };
        let (_, len, _) = visit(&all, sources, &mut seen, route, h.head, (None, None));
        assert_eq!(h.len, len);
        assert_eq!(
            len as usize,
            sources.values().filter(|(r, _)| *r == route).count()
        );
        assert_eq!(
            h.bounded as usize,
            sources
                .values()
                .filter(|(r, w)| *r == route && w.lower != TimeBound::Unbounded)
                .count()
        );
        seen.insert(route.key());
    }
    assert_eq!(seen, all.keys().cloned().collect());
}
fn assert_stabs<L: FnMut(&[u8]) -> crate::native_slice::Result<Option<Vec<u8>>>>(
    ws: &mut Workspace<L>,
    sources: &Sources,
    owners: &[Route],
    original: bool,
) {
    for &route in owners {
        for at in [
            i64::MIN,
            i64::MIN + 1,
            -5,
            -2,
            -1,
            0,
            1,
            2,
            5,
            i64::MAX - 1,
            i64::MAX,
        ] {
            let actual = routes::stab(ws, &route.key(), at, original).unwrap();
            let unique: BTreeSet<_> = actual.iter().copied().collect();
            assert_eq!(actual.len(), unique.len());
            let expected = sources
                .iter()
                .filter(|(_, (r, w))| {
                    let (low, high) = limits(*w);
                    *r == route && low <= i128::from(at) && i128::from(at) <= high
                })
                .map(|(id, _)| *id)
                .collect();
            assert_eq!(unique, expected, "at={at}, original={original}");
        }
    }
}
fn next(seed: &mut u64) -> usize {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed as usize
}
fn random_range(seed: &mut u64) -> TimeRange {
    let bounds = [
        TimeBound::Unbounded,
        TimeBound::Included(i64::MIN),
        TimeBound::Excluded(i64::MIN),
        TimeBound::Included(-2),
        TimeBound::Excluded(-2),
        TimeBound::Included(-1),
        TimeBound::Excluded(-1),
        TimeBound::Included(0),
        TimeBound::Excluded(0),
        TimeBound::Included(1),
        TimeBound::Excluded(1),
        TimeBound::Included(2),
        TimeBound::Excluded(2),
        TimeBound::Included(i64::MAX),
        TimeBound::Excluded(i64::MAX),
    ];
    TimeRange {
        lower: bounds[next(seed) % bounds.len()],
        upper: bounds[next(seed) % bounds.len()],
    }
}

#[test]
fn window_routes_match_literal_sources_after_rotations_rekeys_and_old_new_moves() {
    let owners = [Route::Subscribers(addr(900)), Route::Subscribers(addr(901))];
    let mut bytes = empty(&owners);
    let mut sources = Sources::new();
    let mut seed = 0x6a09e667f3bcc909;
    for i in 0..96 {
        let id = addr(1 + (i * 53 % 96));
        let range = random_range(&mut seed);
        let route = owners[next(&mut seed) % owners.len()];
        let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 100_000);
        routes::change(&mut ws, &route.key(), id, range, true).unwrap();
        let batch = ws.finish().unwrap();
        drop(ws);
        flush(&mut bytes, batch);
        sources.insert(id, (route, range));
        check(&bytes, &sources, &owners);
    }
    for i in 0..160 {
        let old = sources.clone();
        let id = addr(1 + next(&mut seed) as u128 % 96);
        let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 200_000);
        if let Some((route, range)) = sources.remove(&id) {
            routes::change(&mut ws, &route.key(), id, range, false).unwrap();
        }
        if i % 4 != 0 {
            let route = owners[next(&mut seed) % owners.len()];
            let range = random_range(&mut seed);
            routes::change(&mut ws, &route.key(), id, range, true).unwrap();
            sources.insert(id, (route, range));
        }
        assert_stabs(&mut ws, &old, &owners, true);
        assert_stabs(&mut ws, &sources, &owners, false);
        let batch = ws.finish().unwrap();
        drop(ws);
        flush(&mut bytes, batch);
        check(&bytes, &sources, &owners);
    }
}

#[test]
fn empty_identity_minimum_cache_extremes_and_exact_remove_are_preserved() {
    let route = Route::Subscribers(addr(900));
    let mut bytes = empty(&[route]);
    let windows = [
        TimeRange {
            lower: TimeBound::Excluded(0),
            upper: TimeBound::Excluded(1),
        },
        TimeRange {
            lower: TimeBound::Excluded(i64::MAX),
            upper: TimeBound::Unbounded,
        },
        TimeRange::before(i64::MIN),
        TimeRange {
            lower: TimeBound::Included(5),
            upper: TimeBound::Included(-5),
        },
    ];
    let mut sources = Sources::new();
    let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 100_000);
    for (i, range) in windows.into_iter().enumerate() {
        let id = addr(i as u128 + 1);
        routes::change(&mut ws, &route.key(), id, range, true).unwrap();
        sources.insert(id, (route, range));
    }
    let batch = ws.finish().unwrap();
    drop(ws);
    flush(&mut bytes, batch);
    check(&bytes, &sources, &[route]);
    let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 20);
    assert!(
        routes::stab(&mut ws, &route.key(), 0, false)
            .unwrap()
            .is_empty()
    );
    assert_eq!(ws.work.selector_visits, 1);
    drop(ws);
    let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 100_000);
    let bad = TimeRange {
        lower: TimeBound::Included(0),
        upper: TimeBound::Excluded(1),
    };
    assert_eq!(
        routes::change(&mut ws, &route.key(), addr(1), bad, false)
            .unwrap_err()
            .code,
        "corrupt_state"
    );
    assert!(ws.finish().unwrap().is_empty());
    drop(ws);
    // Nonempty unbounded minima and empty minima must survive distinct wire forms.
    let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 100_000);
    routes::change(&mut ws, &route.key(), addr(5), TimeRange::ALL, true).unwrap();
    sources.insert(addr(5), (route, TimeRange::ALL));
    routes::change(
        &mut ws,
        &route.key(),
        addr(6),
        TimeRange::through(i64::MIN),
        true,
    )
    .unwrap();
    sources.insert(addr(6), (route, TimeRange::through(i64::MIN)));
    assert_stabs(&mut ws, &sources, &[route], false);
    let batch = ws.finish().unwrap();
    drop(ws);
    flush(&mut bytes, batch);
    check(&bytes, &sources, &[route]);
    for budget in [0, 1, 2] {
        let before = bytes.clone();
        let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), budget);
        assert_eq!(
            routes::stab(&mut ws, &route.key(), 0, false)
                .unwrap_err()
                .code,
            "work_limit"
        );
        drop(ws);
        let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), budget);
        assert_eq!(
            routes::change(&mut ws, &route.key(), addr(7), TimeRange::ALL, true)
                .unwrap_err()
                .code,
            "work_limit"
        );
        drop(ws);
        assert_eq!(bytes, before);
    }
}

#[test]
fn through_endpoints_interleave_and_only_subscribers_accept_windows() {
    let ordered = [
        Endpoint::Time(i64::MIN),
        Endpoint::Through(i64::MIN),
        Endpoint::Time(-1),
        Endpoint::Through(-1),
        Endpoint::Time(0),
        Endpoint::Through(0),
        Endpoint::Time(i64::MAX),
        Endpoint::Through(i64::MAX),
        Endpoint::All,
    ];
    assert!(ordered.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        serde_json::to_value(Endpoint::Through(-1)).unwrap(),
        serde_json::json!({"kind":"through", "at":"-1"})
    );
    let owners = [
        Route::Incoming(Uuid::from_u128(900)),
        Route::Direct(Uuid::from_u128(901)),
    ];
    let bytes = empty(&owners);
    for route in owners {
        let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 1000);
        assert_eq!(
            routes::change(&mut ws, &route.key(), addr(1), TimeRange::before(0), true)
                .unwrap_err()
                .code,
            "corrupt_state"
        );
        assert!(ws.finish().unwrap().is_empty());
        routes::change(&mut ws, &route.key(), addr(1), TimeRange::ALL, true).unwrap();
        assert_eq!(
            routes::select(
                &mut ws,
                &route.key(),
                Bound::Unbounded,
                Bound::Unbounded,
                false
            )
            .unwrap(),
            vec![addr(1)]
        );
        assert_eq!(
            routes::header(&mut ws, route, false)
                .unwrap()
                .unwrap()
                .bounded,
            0
        );
        routes::change(&mut ws, &route.key(), addr(1), TimeRange::ALL, false).unwrap();
        assert!(
            routes::header(&mut ws, route, false)
                .unwrap()
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn bounded_stabbing_prunes_both_sides_at_gate_population() {
    let route = Route::Subscribers(addr(9000));
    let mut bytes = empty(&[route]);
    let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 5_000_000);
    for at in 0..4096 {
        let range = TimeRange {
            lower: TimeBound::Included(at),
            upper: TimeBound::Included(at),
        };
        routes::change(&mut ws, &route.key(), addr(at as u128 + 1), range, true).unwrap();
    }
    let batch = ws.finish().unwrap();
    drop(ws);
    flush(&mut bytes, batch);
    for (at, expected) in [
        (-1, vec![]),
        (4096, vec![]),
        (0, vec![addr(1)]),
        (2047, vec![addr(2048)]),
        (4095, vec![addr(4096)]),
    ] {
        let mut ws = Workspace::new(|key: &[u8]| Ok(bytes.get(key).cloned()), 256);
        assert_eq!(
            routes::stab(&mut ws, &route.key(), at, false).unwrap(),
            expected
        );
        assert!(ws.work.selector_visits <= 32, "{:?}", ws.work);
        assert!(ws.work.key_loads <= 33, "{:?}", ws.work);
        assert!(ws.finish().unwrap().is_empty());
    }
}
