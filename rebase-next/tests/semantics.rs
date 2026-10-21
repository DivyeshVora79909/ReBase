use std::collections::BTreeMap;

use rebase_semantic_proof::{
    algebra::Summary,
    merge::{self, Entry, Exists},
    plan::{Field, choose_reader, evaluation_order},
    staging::Overlay,
};

// Independent raw scan; it does not use the summary combine formula.
fn scan(events: &[(i64, Option<i128>)]) -> Summary {
    let mut result = Summary::default();
    let mut groups = BTreeMap::<i64, i128>::new();
    for &(time, value) in events {
        result.sum += value.unwrap_or(0);
        result.min_prefix = result.min_prefix.min(result.sum);
        result.max_prefix = result.max_prefix.max(result.sum);
        *groups.entry(time).or_default() += value.unwrap_or(0);
    }
    let mut sum = 0;
    let mut boundaries = Vec::new();
    for (index, value) in groups.values().enumerate() {
        sum += value;
        if index + 1 < groups.len() {
            boundaries.push(sum);
        }
    }
    result.count = events.len() as u64;
    result.first = events.first().map(|x| x.0);
    result.last = events.last().map(|x| x.0);
    result.boundary_min = boundaries.iter().copied().min();
    result.boundary_max = boundaries.iter().copied().max();
    result
}

fn fold(events: &[(i64, Option<i128>)]) -> Summary {
    events
        .iter()
        .fold(Summary::default(), |summary, &(time, amount)| {
            summary.combine(Summary::leaf(time, amount)).unwrap()
        })
}

#[test]
fn complete_time_summary_matches_scan_at_every_split_and_grouping() {
    let cases: &[&[(i64, Option<i128>)]] = &[
        &[],
        &[(0, Some(-100)), (0, Some(100))],
        &[(0, Some(-100)), (1, Some(100))],
        &[(0, Some(100)), (1, Some(-150)), (2, Some(100))],
        &[(0, Some(-5)), (1, None), (2, None), (3, Some(10))],
        &[
            (0, Some(5)),
            (0, None),
            (1, Some(-8)),
            (1, Some(4)),
            (2, Some(7)),
        ],
        &[(0, None), (1, None), (2, Some(-4)), (2, Some(4)), (3, None)],
    ];
    for &events in cases {
        let expected = scan(events);
        assert_eq!(fold(events), expected);
        for a in 0..=events.len() {
            for b in a..=events.len() {
                let left = fold(&events[..a]);
                let mid = fold(&events[a..b]);
                let right = fold(&events[b..]);
                let first = left.combine(mid).unwrap().combine(right).unwrap();
                let second = left.combine(mid.combine(right).unwrap()).unwrap();
                assert_eq!(first, expected);
                assert_eq!(second, expected);
            }
        }
    }
    let simultaneous = fold(&[(0, Some(-100)), (0, Some(100))]);
    assert_eq!(simultaneous.min_prefix, -100);
    assert_eq!(simultaneous.complete_min(), 0);
    assert_eq!(
        fold(&[(0, Some(-100)), (1, Some(100))]).complete_min(),
        -100
    );
}

#[test]
fn exact_algebra_rejects_overflow_and_reversed_segments() {
    assert!(
        Summary::leaf(0, Some(i128::MAX))
            .combine(Summary::leaf(1, Some(1)))
            .is_err()
    );
    assert!(
        Summary::leaf(2, Some(1))
            .combine(Summary::leaf(1, Some(1)))
            .is_err()
    );
    assert_ne!(
        fold(&[(0, Some(5)), (1, Some(-3))]),
        fold(&[(0, Some(-3)), (1, Some(5))])
    );
}

#[test]
fn linear_guard_needs_a_shared_difference_measure_and_historical_extrema() {
    let x = fold(&[(0, Some(10)), (1, Some(0)), (2, Some(10))]);
    let y = fold(&[(0, Some(0)), (1, Some(15)), (2, Some(0))]);
    let difference = fold(&[(0, Some(10)), (1, Some(-15)), (2, Some(10))]);
    assert_eq!(difference.sum, 5);
    assert_eq!(difference.complete_min(), -5);
    assert_eq!(x.complete_min() - y.complete_min(), 0);
}

fn field(name: &str, inputs: &[&str]) -> Field {
    Field {
        name: name.into(),
        inputs: inputs.iter().map(|x| (*x).into()).collect(),
    }
}

#[test]
fn declaration_order_never_overrides_actual_field_dependencies() {
    let fields = [
        field("a_result", &["z_price"]),
        field("z_price", &["m_input"]),
        field("m_input", &[]),
    ];
    assert_eq!(evaluation_order(&fields).unwrap(), vec![2, 1, 0]);
    assert!(evaluation_order(&[field("a", &["b"]), field("b", &["a"])]).is_err());
    assert!(evaluation_order(&[field("a", &["missing"])]).is_err());
    assert!(evaluation_order(&[field("a", &[]), field("a", &[])]).is_err());
}

#[test]
fn scalar_reader_preserves_first_incomparable_choice_and_owner_fallback() {
    let dominates = |a, b| [(1, 2), (2, 3), (1, 3), (1, 4)].contains(&(a, b));
    assert_eq!(choose_reader(&[1, 2, 3], 9, dominates), 3);
    assert_eq!(choose_reader(&[3, 4], 9, dominates), 3);
    assert_eq!(choose_reader(&[4, 3], 9, dominates), 4);
    assert_eq!(choose_reader(&[], 9, dominates), 9);
}

#[test]
fn merge_preserves_authorized_order_ties_and_budgeted_existence() {
    let first = [
        Entry {
            key: (0, 1),
            reader: 1,
        },
        Entry {
            key: (2, 5),
            reader: 1,
        },
    ];
    let second = [
        Entry {
            key: (0, 2),
            reader: 3,
        },
        Entry {
            key: (1, 3),
            reader: 3,
        },
        Entry {
            key: (3, 6),
            reader: 3,
        },
    ];
    let streams = [&first[..], &second[..]]; // An inaccessible partition is never supplied.
    let mut expected: Vec<_> = streams.iter().flat_map(|x| x.iter().copied()).collect();
    expected.sort_by_key(|x| x.key);
    let mut actual = Vec::new();
    let mut after = None;
    loop {
        let page = merge::page(&streams, after, 2, 2, |_| true);
        actual.extend(page.items);
        if page.exhausted {
            break;
        }
        after = page.next;
    }
    assert_eq!(actual, expected);
    let limited = merge::page(&streams, None, 1, 2, |entry| entry.key.1 == 6);
    assert_eq!(limited.exists(), Exists::Unknown((0, 2)));
    let resumed = merge::page(&streams, limited.next, 1, 3, |entry| entry.key.1 == 6);
    assert_eq!(resumed.exists(), Exists::Yes);
    let absent = merge::page(&streams, None, 1, 10, |_| false);
    assert_eq!(absent.exists(), Exists::No);
}

#[test]
fn point_overlay_coalesces_patches_preserves_absence_and_drops_no_ops() {
    let mut overlay = Overlay::default();
    overlay
        .stage(b"a", Some(vec![2]), || Ok::<_, ()>(Some(vec![1])))
        .unwrap();
    overlay
        .stage::<()>(b"a", Some(vec![3]), || panic!("already cached"))
        .unwrap();
    assert_eq!(
        overlay
            .read::<()>(b"a", || panic!("read own write"))
            .unwrap(),
        Some(vec![3])
    );
    overlay
        .stage(b"b", Some(vec![4]), || Ok::<_, ()>(None))
        .unwrap();
    overlay
        .stage::<()>(b"b", None, || panic!("cached absent key"))
        .unwrap();
    overlay
        .stage(b"c", None, || Ok::<_, ()>(Some(vec![5])))
        .unwrap();
    assert_eq!(
        overlay
            .read::<()>(b"c", || panic!("read own tombstone"))
            .unwrap(),
        None
    );
    assert_eq!(
        overlay.read(b"missing", || Ok::<_, ()>(None)).unwrap(),
        None
    );
    assert_eq!(
        overlay
            .read::<()>(b"missing", || panic!("cached absence"))
            .unwrap(),
        None
    );
    assert_eq!(overlay.reads, 4);
    let batch = overlay.finish();
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[b"a".as_slice()], Some(vec![3]));
    assert_eq!(batch[b"c".as_slice()], None);
}

#[test]
fn conflict_set_counterexample_requires_a_tracked_guard_read() {
    // This is a conflict-set model, not a test against either database server.
    let intersects = |a: &[&str], b: &[&str]| a.iter().any(|key| b.contains(key));
    let si_rejects =
        |first_writes: &[&str], second_writes: &[&str]| intersects(first_writes, second_writes);
    let fdb_rejects =
        |first_writes: &[&str], second_reads: &[&str]| intersects(first_writes, second_reads);
    // Disjoint write skew under SI; common writes under SI; blind FDB writes.
    assert!(!si_rejects(&["posting_a"], &["posting_b"]));
    assert!(si_rejects(&["posting_a", "guard"], &["posting_b", "guard"]));
    assert!(!fdb_rejects(&["guard"], &[]));
    assert!(fdb_rejects(&["guard"], &["guard"]));
    // A zero amount must still protect the rate used to derive it.
    assert!(fdb_rejects(&["rate", "source_guard"], &["source_guard"]));
}
