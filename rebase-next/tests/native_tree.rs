use rebase_semantic_proof::{
    algebra::Summary,
    index::{IndexCode, TimeKey},
    indexes::standard::{Aggregate, FINANCIAL, Leaf, QUOTE, QuoteSummary, Standard},
    native_codec::{self, Address, Key, Stored},
    native_slice::{Result, Workspace},
    time_range::{TimeBound, TimeRange},
    tree::{self, FullKey, Node, Root, Span},
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

type Bytes = BTreeMap<Vec<u8>, Vec<u8>>;
type Leaves = BTreeMap<Address, (i64, Leaf)>;

fn addr(id: u128, slot: u16) -> Address {
    Address::new(Uuid::from_u128(id), slot)
}

fn scanned(kind: IndexCode, leaves: &[(FullKey<TimeKey>, Leaf)]) -> Aggregate {
    let first = leaves.first().map(|x| x.0.value.0);
    let last = leaves.last().map(|x| x.0.value.0);
    if kind == QUOTE {
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
        if i + 1 < leaves.len() && key.value.0 != leaves[i + 1].0.value.0 {
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
        nodes: &'a BTreeMap<Address, Node<Standard>>,
        expected: &'a Leaves,
        seen: BTreeSet<Address>,
        owner: Address,
        kind: IndexCode,
    }
    impl Walk<'_> {
        fn visit(
            &mut self,
            id: Option<Address>,
            parent: Option<Address>,
            low: Option<FullKey<TimeKey>>,
            high: Option<FullKey<TimeKey>>,
        ) -> (u16, Vec<(FullKey<TimeKey>, Leaf)>) {
            let Some(id) = id else {
                return (0, vec![]);
            };
            assert!(self.seen.insert(id));
            let n = &self.nodes[&id];
            assert_eq!(n.root, self.owner);
            assert_eq!(n.parent, parent);
            assert_eq!((n.key.value.0, n.leaf), self.expected[&id]);
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
            assert_eq!(n.span.first, left.first().unwrap().0.value);
            assert_eq!(n.span.last, left.last().unwrap().0.value);
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
    assert_eq!(
        header.span,
        leaves.first().zip(leaves.last()).map(|(first, last)| Span {
            first: first.0.value,
            last: last.0.value,
        })
    );
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

fn initial(owner: Address, kind: IndexCode) -> Bytes {
    let key = Key::Root(owner);
    [(
        key.encode(),
        native_codec::encode(
            &key,
            &Stored::Root(Root::empty(kind, Uuid::new_v4()).unwrap()),
        )
        .unwrap(),
    )]
    .into()
}

fn apply(store: &mut Bytes, owner: Address, id: Address, value: Option<(i64, Leaf)>) -> u64 {
    let mut ws = Workspace::new(|key: &[u8]| Ok(store.get(key).cloned()), 100000);
    match value {
        Some((at, leaf)) => tree::insert(&mut ws, owner, id, TimeKey(at), leaf).unwrap(),
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
    for kind in [FINANCIAL, QUOTE] {
        let owner = addr(1000, if kind == QUOTE { 1 } else { 2 });
        let slot = if kind == QUOTE { 3 } else { 1 };
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
                let leaf = if kind == QUOTE {
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
    let mut store = initial(owner, FINANCIAL);
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
    let mut store = initial(owner, QUOTE);
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
        tree::insert(
            &mut ws,
            owner,
            addr(3, 3),
            TimeKey(i64::MAX),
            Leaf::Quote(2)
        )
        .unwrap_err()
        .code,
        "duplicate_time"
    );
    Ok(())
}

#[test]
fn strict_prefix_matches_authored_scan_at_equal_times_and_extremes() -> Result<()> {
    let owner = addr(1000, 2);
    let mut store = initial(owner, FINANCIAL);
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

fn literal_range(kind: IndexCode, leaves: &Leaves, window: TimeRange) -> Aggregate {
    // Deliberately spell out both predicates: do not reuse range membership or
    // the writer's Aggregate::combine when deriving expected summaries.
    let mut selected: Vec<_> = leaves
        .iter()
        .filter(|(_, (at, _))| {
            let lower = match window.lower {
                TimeBound::Unbounded => true,
                TimeBound::Included(bound) => bound <= *at,
                TimeBound::Excluded(bound) => bound < *at,
            };
            let upper = match window.upper {
                TimeBound::Unbounded => true,
                TimeBound::Included(bound) => *at <= bound,
                TimeBound::Excluded(bound) => *at < bound,
            };
            lower && upper
        })
        .map(|(id, (at, leaf))| {
            (
                FullKey {
                    value: TimeKey(*at),
                    id: id.id,
                    slot: id.slot,
                },
                *leaf,
            )
        })
        .collect();
    selected.sort_by_key(|(key, _)| *key);
    scanned(kind, &selected)
}

#[test]
fn ranges_match_literal_subsets_complete_groups_and_extreme_bounds() -> Result<()> {
    use TimeBound::{Excluded, Included, Unbounded};
    for kind in [FINANCIAL, QUOTE] {
        let owner = addr(1000, if kind == QUOTE { 1 } else { 2 });
        let mut store = initial(owner, kind);
        let mut expected = Leaves::new();
        let values = [
            (0, -8),
            (i64::MAX, 7),
            (i64::MIN, 10),
            (-20, -3),
            (0, 8),
            (20, -9),
            (0, 0),
            (i64::MAX, -2),
            (i64::MIN, -4),
            (21, 5),
        ];
        for (i, (at, amount)) in values.into_iter().enumerate() {
            if kind == QUOTE && expected.values().any(|(time, _)| *time == at) {
                continue;
            }
            let id = addr(i as u128 + 1, 1);
            let value = (
                at,
                if kind == QUOTE {
                    Leaf::Quote(i as u16 + 1)
                } else {
                    Leaf::Financial(amount)
                },
            );
            apply(&mut store, owner, id, Some(value));
            expected.insert(id, value);
        }
        let mut bounds = vec![Unbounded];
        for at in [i64::MIN, i64::MIN + 1, -21, -20, -1, 0, 1, 20, 21, i64::MAX] {
            bounds.extend([Included(at), Excluded(at)]);
        }
        for removed in [None, Some(addr(1, 1)), Some(addr(3, 1))] {
            if let Some(id) = removed {
                apply(&mut store, owner, id, None);
                expected.remove(&id);
            }
            check(&store, owner, &expected);
            for &lower in &bounds {
                for &upper in &bounds {
                    let window = TimeRange { lower, upper };
                    let mut ws = Workspace::new(|key: &[u8]| Ok(store.get(key).cloned()), 200);
                    assert_eq!(
                        tree::range(&mut ws, owner, window)?,
                        literal_range(kind, &expected, window),
                        "{kind:?}: {window:?}"
                    );
                }
            }
        }
        // Empty roots and reversed/discrete-empty intervals return their own
        // summary kind without pretending an absent group is financial zero.
        let empty = initial(owner, kind);
        for window in [
            TimeRange::ALL,
            TimeRange {
                lower: Excluded(0),
                upper: Excluded(1),
            },
            TimeRange {
                lower: Included(1),
                upper: Included(0),
            },
        ] {
            let mut ws = Workspace::new(|key: &[u8]| Ok(empty.get(key).cloned()), 1);
            assert_eq!(
                tree::range(&mut ws, owner, window)?,
                Aggregate::empty(kind)?
            );
            assert_eq!(ws.work.node_visits, 0);
        }
    }
    Ok(())
}

#[test]
fn range_extrema_are_rebased_folds_not_differences_of_prefix_minima() -> Result<()> {
    use TimeBound::{Excluded, Included};
    let owner = addr(1000, 2);
    let mut store = initial(owner, FINANCIAL);
    let mut expected = Leaves::new();
    // The excluded prefix bottoms out at -100, then recovers. The window has
    // total -2, min prefix -7, and complete-time minimum -2 because -7/+5 share
    // one timestamp. Neither prefix minimum difference reconstructs the window.
    for (number, (at, amount)) in [(0, -100), (1, 100), (2, -7), (2, 5)]
        .into_iter()
        .enumerate()
    {
        let id = addr(number as u128 + 1, 1);
        let value = (at, Leaf::Financial(amount));
        apply(&mut store, owner, id, Some(value));
        expected.insert(id, value);
    }
    let window = TimeRange {
        lower: Excluded(1),
        upper: Included(2),
    };
    let mut ws = Workspace::new(|key: &[u8]| Ok(store.get(key).cloned()), 100);
    let Aggregate::Financial(value) = tree::range(&mut ws, owner, window)? else {
        panic!("financial range")
    };
    assert_eq!(
        Aggregate::Financial(value),
        literal_range(FINANCIAL, &expected, window)
    );
    assert_eq!(
        (value.sum, value.min_prefix, value.complete_min()),
        (-2, -7, -2)
    );
    let Aggregate::Financial(before) = literal_range(FINANCIAL, &expected, TimeRange::through(1))
    else {
        panic!()
    };
    let Aggregate::Financial(through) = literal_range(FINANCIAL, &expected, TimeRange::through(2))
    else {
        panic!()
    };
    assert_ne!(value.min_prefix, through.min_prefix - before.min_prefix);
    assert_ne!(
        value.complete_min(),
        through.complete_min() - before.complete_min()
    );
    Ok(())
}

#[test]
fn range_prunes_many_positions_under_a_population_independent_budget() -> Result<()> {
    use TimeBound::{Excluded, Included};
    let owner = addr(1000, 2);
    let mut store = initial(owner, FINANCIAL);
    let mut expected = Leaves::new();
    for number in 0..511 {
        let id = addr(number + 1, 1);
        let value = (
            number as i64 - 255,
            Leaf::Financial(number as i128 % 11 - 5),
        );
        apply(&mut store, owner, id, Some(value));
        expected.insert(id, value);
    }
    check(&store, owner, &expected);
    let mut ws = Workspace::new(|key: &[u8]| Ok(store.get(key).cloned()), 1);
    assert_eq!(
        tree::range(&mut ws, owner, TimeRange::ALL)?,
        literal_range(FINANCIAL, &expected, TimeRange::ALL)
    );
    assert_eq!((ws.work.key_loads, ws.work.node_visits), (1, 0));
    for position in (-256..=256).step_by(8) {
        for window in [
            TimeRange {
                lower: Included(position),
                upper: Included(position),
            },
            TimeRange {
                lower: Excluded(position),
                upper: Included(position + 3),
            },
            TimeRange {
                lower: Included(-200),
                upper: Excluded(position),
            },
        ] {
            // A 511-row scan cannot fit 128 charged loads/visits. The result
            // includes every summary field, so sum-only prefix subtraction also
            // cannot satisfy this comparison.
            let mut ws = Workspace::new(|key: &[u8]| Ok(store.get(key).cloned()), 128);
            let height = tree::root(&mut ws, owner)?.height;
            assert_eq!(
                tree::range(&mut ws, owner, window)?,
                literal_range(FINANCIAL, &expected, window)
            );
            assert!(
                ws.work.node_visits <= 4 * u64::from(height) + 2,
                "{window:?}: {:?}",
                ws.work
            );
        }
    }
    let mut ws = Workspace::new(|key: &[u8]| Ok(store.get(key).cloned()), 1);
    assert_eq!(
        tree::range(
            &mut ws,
            owner,
            TimeRange {
                lower: Included(0),
                upper: Included(0)
            }
        )
        .unwrap_err()
        .code,
        "work_limit"
    );
    Ok(())
}

#[test]
fn range_rejects_overflow_and_corrupt_traversed_links() -> Result<()> {
    use TimeBound::{Included, Unbounded};
    let owner = addr(1000, 2);
    let mut store = initial(owner, FINANCIAL);
    // Insert the compensating tail before the second positive leaf so every
    // intermediate AVL subtree also has a representable exact summary.
    for (number, (at, amount)) in [
        (0, -i128::MAX),
        (1, i128::MAX),
        (3, -i128::MAX),
        (2, i128::MAX),
    ]
    .into_iter()
    .enumerate()
    {
        apply(
            &mut store,
            owner,
            addr(number as u128 + 1, 1),
            Some((at, Leaf::Financial(amount))),
        );
    }
    let mut ws = Workspace::new(|key: &[u8]| Ok(store.get(key).cloned()), 100);
    assert_eq!(
        tree::range(
            &mut ws,
            owner,
            TimeRange {
                lower: Included(1),
                upper: Included(2)
            }
        )
        .unwrap_err()
        .code,
        "overflow"
    );

    // Mutation controls retain otherwise valid summaries so rejection depends
    // on the links/kinds actually reached by a partial range traversal.
    for corruption in 0..4 {
        let mut ws = Workspace::new(|key: &[u8]| Ok(store.get(key).cloned()), 100);
        let head = tree::root(&mut ws, owner)?.head.unwrap();
        let mut damaged = tree::node(&mut ws, owner, head)?;
        let upper = Included(damaged.key.value.0);
        match corruption {
            0 => damaged.parent = Some(head),
            1 => damaged.left = Some(head),
            2 => damaged.root = addr(9999, 2),
            3 => {
                damaged.leaf = Leaf::Quote(1);
                damaged.summary = Aggregate::Quote(QuoteSummary {
                    count: 1,
                    first: Some(damaged.key.value.0),
                    last: Some(damaged.key.value.0),
                });
            }
            _ => unreachable!(),
        }
        // Bypass the validating writer: this is a damaged persisted row,
        // including envelopes that the new codec rejects before traversal.
        drop(ws);
        let mut corrupted = store.clone();
        corrupted.insert(
            Key::Node(head).encode(),
            serde_json::to_vec(&Stored::Node(damaged)).unwrap(),
        );
        let mut ws = Workspace::new(|key: &[u8]| Ok(corrupted.get(key).cloned()), 100);
        assert_eq!(
            tree::range(
                &mut ws,
                owner,
                TimeRange {
                    lower: Unbounded,
                    upper
                }
            )
            .unwrap_err()
            .code,
            "corrupt_state"
        );
    }
    // A malformed long chain must stop before recursive descent can grow with
    // the corrupt store's population. Its cached spans deliberately force a
    // boundary search rather than the covered-subtree shortcut.
    let mut malformed = initial(owner, FINANCIAL);
    let summary = Aggregate::Financial(Summary {
        count: 2,
        first: Some(0),
        last: Some(100),
        boundary_min: Some(0),
        boundary_max: Some(0),
        ..Summary::default()
    });
    let header = Root {
        head: Some(addr(1, 1)),
        first: Some(addr(1, 1)),
        last: Some(addr(65, 1)),
        height: 1,
        span: Some(Span {
            first: TimeKey(0),
            last: TimeKey(100),
        }),
        summary,
        ..Root::empty(FINANCIAL, Uuid::new_v4())?
    };
    let key = Key::Root(owner);
    malformed.insert(
        key.encode(),
        native_codec::encode(&key, &Stored::Root(header))?,
    );
    for number in 1..=65 {
        let id = addr(number, 1);
        let key = Key::Node(id);
        let node = Node {
            kind: FINANCIAL,
            root: owner,
            key: FullKey {
                value: TimeKey(0),
                id: id.id,
                slot: id.slot,
            },
            leaf: Leaf::Financial(0),
            parent: (number > 1).then(|| addr(number - 1, 1)),
            left: None,
            right: (number < 65).then(|| addr(number + 1, 1)),
            prev: None,
            next: None,
            height: 1,
            span: Span {
                first: TimeKey(0),
                last: TimeKey(100),
            },
            summary,
        };
        malformed.insert(
            key.encode(),
            native_codec::encode(&key, &Stored::Node(node))?,
        );
    }
    let mut ws = Workspace::new(|key: &[u8]| Ok(malformed.get(key).cloned()), 200);
    let error = tree::range(
        &mut ws,
        owner,
        TimeRange {
            lower: Included(50),
            upper: Included(50),
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "corrupt_state");
    assert_eq!(error.detail, "range path depth");
    assert_eq!(ws.work.node_visits, 64);
    Ok(())
}
