use rebase_semantic_proof::{
    algebra::Summary,
    native_codec::{self, Address, Key, Stored},
    native_slice::{Result, Workspace},
    tree::{self, Aggregate, FullKey, Kind, Leaf, Node, QuoteSummary, Root},
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

type Bytes = BTreeMap<Vec<u8>, Vec<u8>>;
type Leaves = BTreeMap<Address, (i64, Leaf)>;

fn addr(id: u128, slot: u16) -> Address {
    Address::new(Uuid::from_u128(id), slot)
}

fn scanned(kind: Kind, leaves: &[(FullKey, Leaf)]) -> Aggregate {
    let first = leaves.first().map(|x| x.0.at);
    let last = leaves.last().map(|x| x.0.at);
    if kind == Kind::Quote {
        return Aggregate::Quote(QuoteSummary {
            count: leaves.len() as u64,
            first,
            last,
        });
    }
    let (mut sum, mut min, mut max) = (0_i128, 0_i128, 0_i128);
    let mut boundaries = vec![];
    for (i, (key, leaf)) in leaves.iter().enumerate() {
        let Leaf::Financial(amount) = leaf else {
            panic!("mixed leaves")
        };
        sum += amount;
        min = min.min(sum);
        max = max.max(sum);
        if i + 1 < leaves.len() && key.at != leaves[i + 1].0.at {
            boundaries.push(sum);
        }
    }
    Aggregate::Financial(Summary {
        count: leaves.len() as u64,
        first,
        last,
        sum,
        min_prefix: min,
        max_prefix: max,
        boundary_min: boundaries.iter().copied().min(),
        boundary_max: boundaries.iter().copied().max(),
    })
}

fn check(store: &Bytes, owner: Address, expected: &Leaves) {
    let mut nodes = BTreeMap::new();
    let mut header = None;
    for (bytes, value) in store {
        let key = Key::decode(bytes).unwrap();
        match native_codec::decode(&key, value).unwrap() {
            Stored::Root(r) => {
                assert_eq!(key, Key::Root(owner));
                header = Some(r);
            }
            Stored::Node(n) => {
                let Key::Node(id) = key else { panic!() };
                nodes.insert(id, n);
            }
            _ => panic!("unexpected tree-test row"),
        }
    }
    assert_eq!(
        nodes.keys().collect::<Vec<_>>(),
        expected.keys().collect::<Vec<_>>()
    );
    let header = header.unwrap();
    struct Walk<'a> {
        nodes: &'a BTreeMap<Address, Node>,
        expected: &'a Leaves,
        seen: BTreeSet<Address>,
        owner: Address,
        kind: Kind,
    }
    impl Walk<'_> {
        fn visit(
            &mut self,
            id: Option<Address>,
            parent: Option<Address>,
            low: Option<FullKey>,
            high: Option<FullKey>,
        ) -> (u16, Vec<(FullKey, Leaf)>) {
            let Some(id) = id else {
                return (0, vec![]);
            };
            assert!(self.seen.insert(id));
            let n = &self.nodes[&id];
            assert_eq!(n.root, self.owner);
            assert_eq!(n.parent, parent);
            assert_eq!((n.key.at, n.leaf), self.expected[&id]);
            assert_eq!(n.key.id, id.id);
            assert_eq!(n.key.slot, id.slot);
            assert!(low.is_none_or(|k| k < n.key) && high.is_none_or(|k| n.key < k));
            let (lh, mut left) = self.visit(n.left, Some(id), low, Some(n.key));
            let (rh, right) = self.visit(n.right, Some(id), Some(n.key), high);
            assert!(lh.abs_diff(rh) <= 1);
            assert_eq!(n.height, 1 + lh.max(rh));
            left.push((n.key, n.leaf));
            left.extend(right);
            assert_eq!(n.summary, scanned(self.kind, &left));
            (n.height, left)
        }
    }
    let mut walk = Walk {
        nodes: &nodes,
        expected,
        seen: BTreeSet::new(),
        owner,
        kind: header.kind,
    };
    let (height, leaves) = walk.visit(header.head, None, None, None);
    assert_eq!(walk.seen.len(), expected.len());
    assert_eq!(header.height, height);
    assert_eq!(header.summary, scanned(header.kind, &leaves));
    let ids: Vec<_> = leaves
        .iter()
        .map(|(key, _)| Address::new(key.id, key.slot))
        .collect();
    assert_eq!(header.first, ids.first().copied());
    assert_eq!(header.last, ids.last().copied());
    for (i, id) in ids.iter().enumerate() {
        assert_eq!(nodes[id].prev, i.checked_sub(1).map(|p| ids[p]));
        assert_eq!(nodes[id].next, ids.get(i + 1).copied());
    }
}

fn initial(owner: Address, kind: Kind) -> Bytes {
    let key = Key::Root(owner);
    [(
        key.encode(),
        native_codec::encode(&key, &Stored::Root(Root::empty(kind, 0))).unwrap(),
    )]
    .into()
}

fn apply(store: &mut Bytes, owner: Address, id: Address, value: Option<(i64, Leaf)>) -> u64 {
    let mut ws = Workspace::new(|key: &[u8]| Ok(store.get(key).cloned()), 100000);
    match value {
        Some((at, leaf)) => tree::insert(&mut ws, owner, id, at, leaf).unwrap(),
        None => tree::remove(&mut ws, owner, id).unwrap(),
    }
    let batch = ws.finish().unwrap();
    let rotations = ws.work.rotations;
    drop(ws);
    for (key, value) in batch {
        match value {
            Some(v) => {
                store.insert(key, v);
            }
            None => {
                store.remove(&key);
            }
        }
    }
    rotations
}

#[test]
fn all_rotation_directions_and_intrusive_deletions_match_source_scans() {
    for kind in [Kind::Financial, Kind::Quote] {
        let owner = addr(1000, if kind == Kind::Quote { 1 } else { 2 });
        let slot = if kind == Kind::Quote { 3 } else { 1 };
        for times in [
            vec![3, 2, 1],
            vec![1, 2, 3],
            vec![3, 1, 2],
            vec![1, 3, 2],
            vec![4, 2, 6, 1, 3, 5, 7],
            vec![7, 3, 9, 1, 5, 8, 10, 4, 6],
        ] {
            let mut store = initial(owner, kind);
            let mut expected = Leaves::new();
            let mut rotations = 0;
            for (i, &at) in times.iter().enumerate() {
                let id = addr(i as u128 + 1, slot);
                let leaf = if kind == Kind::Quote {
                    Leaf::Quote(3)
                } else {
                    Leaf::Financial(i as i128 - 3)
                };
                rotations += apply(&mut store, owner, id, Some((at, leaf)));
                expected.insert(id, (at, leaf));
                check(&store, owner, &expected);
            }
            if times.len() == 3 {
                assert!(rotations > 0);
            }
            for i in [3, 1, 0, 2, 4, 5, 6, 7, 8] {
                if i >= times.len() {
                    continue;
                }
                let id = addr(i as u128 + 1, slot);
                apply(&mut store, owner, id, None);
                expected.remove(&id);
                check(&store, owner, &expected);
            }
        }
    }
}

#[test]
fn equal_time_complete_boundaries_and_latest_extremes() -> Result<()> {
    let owner = addr(1000, 2);
    let mut store = initial(owner, Kind::Financial);
    let mut expected = Leaves::new();
    for (id, amount) in [(addr(2, 1), 10), (addr(1, 1), -10), (addr(3, 1), 0)] {
        apply(
            &mut store,
            owner,
            id,
            Some((i64::MAX, Leaf::Financial(amount))),
        );
        expected.insert(id, (i64::MAX, Leaf::Financial(amount)));
        check(&store, owner, &expected);
    }
    let mut ws = Workspace::new(|key: &[u8]| Ok(store.get(key).cloned()), 100000);
    let Aggregate::Financial(summary) = tree::root(&mut ws, owner)?.summary else {
        panic!()
    };
    assert_eq!(summary.min_prefix, -10);
    assert_eq!(summary.complete_min(), 0);
    let owner = addr(1001, 1);
    let mut store = initial(owner, Kind::Quote);
    apply(
        &mut store,
        owner,
        addr(1, 3),
        Some((i64::MIN, Leaf::Quote(2))),
    );
    apply(
        &mut store,
        owner,
        addr(2, 3),
        Some((i64::MAX, Leaf::Quote(3))),
    );
    let mut ws = Workspace::new(|key: &[u8]| Ok(store.get(key).cloned()), 100000);
    assert_eq!(
        tree::latest(&mut ws, owner, i64::MIN)?,
        Some((Uuid::from_u128(1), 2))
    );
    assert_eq!(
        tree::latest(&mut ws, owner, i64::MAX)?,
        Some((Uuid::from_u128(2), 3))
    );
    assert_eq!(
        tree::insert(&mut ws, owner, addr(3, 3), i64::MAX, Leaf::Quote(2))
            .unwrap_err()
            .code,
        "duplicate_time"
    );
    Ok(())
}

#[test]
fn strict_prefix_matches_authored_scan_at_equal_times_and_extremes() -> Result<()> {
    let owner = addr(1000, 2);
    let mut store = initial(owner, Kind::Financial);
    let mut expected = Leaves::new();
    for (i, (at, amount)) in [
        (0, -4),
        (i64::MAX, 8),
        (i64::MIN, 11),
        (-20, -3),
        (0, 6),
        (20, 5),
        (0, 0),
        (i64::MAX, -2),
    ]
    .into_iter()
    .enumerate()
    {
        let id = addr(i as u128 + 1, 1);
        let value = (at, Leaf::Financial(amount));
        apply(&mut store, owner, id, Some(value));
        expected.insert(id, value);
    }
    for removed in [None, Some(addr(1, 1)), Some(addr(3, 1))] {
        if let Some(id) = removed {
            apply(&mut store, owner, id, None);
            expected.remove(&id);
        }
        check(&store, owner, &expected);
        for before in [
            Some(i64::MIN),
            Some(i64::MIN + 1),
            Some(-20),
            Some(-19),
            Some(0),
            Some(1),
            Some(20),
            Some(21),
            Some(i64::MAX),
            None,
        ] {
            let sum: i128 = expected
                .values()
                .filter(|(at, _)| before.is_none_or(|bound| *at < bound))
                .map(|(_, leaf)| match leaf {
                    Leaf::Financial(amount) => *amount,
                    _ => unreachable!(),
                })
                .sum();
            let mut ws = Workspace::new(|key: &[u8]| Ok(store.get(key).cloned()), 100);
            let height = tree::root(&mut ws, owner)?.height;
            assert_eq!(tree::prefix(&mut ws, owner, before)?, sum);
            assert!(ws.work.node_visits <= u64::from(height) * 2);
        }
    }
    let mut ws = Workspace::new(|key: &[u8]| Ok(store.get(key).cloned()), 100);
    let head = tree::root(&mut ws, owner)?.head.unwrap();
    let mut damaged = tree::node(&mut ws, owner, head)?;
    damaged.parent = Some(head);
    ws.put(Key::Node(head), Some(Stored::Node(damaged)))?;
    assert_eq!(
        tree::prefix(&mut ws, owner, Some(1)).unwrap_err().code,
        "corrupt_state"
    );
    Ok(())
}
