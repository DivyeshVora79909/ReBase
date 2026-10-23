//! Final producer reachability for complete-timestamp sum windows.
//! Prefix gates retain the linear-edge path for lower-unbounded reads. Bounded
//! windows depend on canonical segment-cover gates, never on excluded prefixes.
use crate::{
    binding::Binding,
    causal::ResolvedShape,
    native_codec::Address,
    native_slice::{Attempt, Error, Result},
    time_range::TimeBound,
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

struct Graph {
    outgoing: Vec<BTreeSet<usize>>,
    producers: Vec<Uuid>,
}
struct Index {
    times: Vec<i64>,
    prefixes: Vec<usize>,
    // Ordinary iterative segment tree: leaves occupy [len, 2*len). Each
    // internal gate depends on its children. Index zero is unused.
    segments: Option<Vec<usize>>,
}
impl Graph {
    fn gate(&mut self, charge: &mut impl FnMut(&str, u64) -> Result<()>) -> Result<usize> {
        charge("graph", 1)?;
        let node = self.outgoing.len();
        self.outgoing.push(BTreeSet::new());
        Ok(node)
    }
    fn edge(
        &mut self,
        from: usize,
        to: usize,
        charge: &mut impl FnMut(&str, u64) -> Result<()>,
    ) -> Result<()> {
        if self.outgoing[from].insert(to) {
            charge("edge", 1)?;
        }
        Ok(())
    }
    fn build(
        shapes: &[(Uuid, &ResolvedShape)],
        charge: &mut impl FnMut(&str, u64) -> Result<()>,
    ) -> Result<Self> {
        let mut graph = Self {
            outgoing: vec![BTreeSet::new(); shapes.len()],
            producers: shapes.iter().map(|(id, _)| *id).collect(),
        };
        charge("graph", shapes.len() as u64)?;
        let mut roots: BTreeMap<Address, BTreeMap<i64, BTreeSet<usize>>> = BTreeMap::new();
        let mut bounded = BTreeSet::new();
        for (producer, (_, shape)) in shapes.iter().enumerate() {
            for emit in &shape.emits {
                charge("dependency", 1)?;
                roots
                    .entry(emit.root)
                    .or_default()
                    .entry(emit.at)
                    .or_default()
                    .insert(producer);
            }
            for read in shape.reads.iter().filter(|read| !read.validate) {
                charge("dependency", 1)?;
                if read.range.lower != TimeBound::Unbounded && !read.range.is_empty() {
                    bounded.insert(read.root);
                }
            }
        }
        let mut indexes = BTreeMap::new();
        for (root, times) in roots {
            let times: Vec<_> = times.into_iter().collect();
            let mut prefixes = Vec::with_capacity(times.len());
            for (_, producers) in &times {
                let gate = graph.gate(charge)?;
                if let Some(&previous) = prefixes.last() {
                    graph.edge(previous, gate, charge)?;
                }
                for &producer in producers {
                    graph.edge(producer, gate, charge)?;
                }
                prefixes.push(gate);
            }
            let segments = if bounded.contains(&root) {
                let len = times.len();
                let mut nodes = vec![0; 2 * len];
                for node in nodes.iter_mut().skip(1) {
                    *node = graph.gate(charge)?;
                }
                for parent in 1..len {
                    graph.edge(nodes[2 * parent], nodes[parent], charge)?;
                    graph.edge(nodes[2 * parent + 1], nodes[parent], charge)?;
                }
                for (i, (_, producers)) in times.iter().enumerate() {
                    for &producer in producers {
                        graph.edge(producer, nodes[len + i], charge)?;
                    }
                }
                Some(nodes)
            } else {
                None
            };
            indexes.insert(
                root,
                Index {
                    times: times.into_iter().map(|(at, _)| at).collect(),
                    prefixes,
                    segments,
                },
            );
        }
        for (consumer, (_, shape)) in shapes.iter().enumerate() {
            for read in shape.reads.iter().filter(|read| !read.validate) {
                charge("dependency", 1)?;
                if read.range.is_empty() {
                    continue;
                }
                let Some(index) = indexes.get(&read.root) else {
                    continue;
                };
                let mut comparisons = 0;
                let end = match read.range.upper {
                    TimeBound::Unbounded => index.times.len(),
                    TimeBound::Included(upper) => index.times.partition_point(|at| {
                        comparisons += 1;
                        *at <= upper
                    }),
                    TimeBound::Excluded(upper) => index.times.partition_point(|at| {
                        comparisons += 1;
                        *at < upper
                    }),
                };
                let start = match read.range.lower {
                    TimeBound::Unbounded => 0,
                    TimeBound::Included(lower) => index.times.partition_point(|at| {
                        comparisons += 1;
                        *at < lower
                    }),
                    TimeBound::Excluded(lower) => index.times.partition_point(|at| {
                        comparisons += 1;
                        *at <= lower
                    }),
                };
                charge("dependency", comparisons)?;
                if start >= end {
                    continue;
                }
                if read.range.lower == TimeBound::Unbounded {
                    graph.edge(index.prefixes[end - 1], consumer, charge)?;
                    continue;
                }
                let nodes = index
                    .segments
                    .as_ref()
                    .ok_or_else(|| Error::new("internal", "missing window dependency gates"))?;
                let (mut left, mut right) = (start + index.times.len(), end + index.times.len());
                while left < right {
                    charge("dependency", 1)?;
                    if left % 2 == 1 {
                        graph.edge(nodes[left], consumer, charge)?;
                        left += 1;
                    }
                    if right % 2 == 1 {
                        right -= 1;
                        graph.edge(nodes[right], consumer, charge)?;
                    }
                    left /= 2;
                    right /= 2;
                }
            }
        }
        Ok(graph)
    }
    fn order(&self, charge: &mut impl FnMut(&str, u64) -> Result<()>) -> Result<Vec<Uuid>> {
        let mut incoming = vec![0usize; self.outgoing.len()];
        for edges in &self.outgoing {
            for &to in edges {
                incoming[to] += 1;
            }
        }
        let mut ready: BTreeSet<_> = incoming
            .iter()
            .enumerate()
            .filter(|(_, n)| **n == 0)
            .map(|(i, _)| i)
            .collect();
        let mut visited = 0;
        let mut order = vec![];
        while let Some(node) = ready.pop_first() {
            charge("schedule", 1)?;
            visited += 1;
            if let Some(id) = self.producers.get(node) {
                order.push(*id);
            }
            for &next in &self.outgoing[node] {
                charge("schedule", 1)?;
                incoming[next] -= 1;
                if incoming[next] == 0 {
                    ready.insert(next);
                }
            }
        }
        if visited != self.outgoing.len() {
            return Err(Error::new("feedback", "final active calculation cycle"));
        }
        Ok(order)
    }
}
pub(crate) fn order<'a, L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    shapes: impl Iterator<Item = (Uuid, &'a ResolvedShape)>,
) -> Result<Vec<Uuid>> {
    let shapes: Vec<_> = shapes.collect();
    let mut charge = |kind: &str, count| ws.charge(kind, count);
    Graph::build(&shapes, &mut charge)?.order(&mut charge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        causal::{Emit, Read},
        time_range::TimeRange,
    };

    fn reachable(edges: &[BTreeSet<usize>], start: usize) -> BTreeSet<usize> {
        let mut seen = BTreeSet::new();
        let mut todo: Vec<_> = edges[start].iter().copied().collect();
        while let Some(at) = todo.pop() {
            if seen.insert(at) {
                todo.extend(edges[at].iter().copied());
            }
        }
        seen
    }
    // Literal comparisons supply the oracle; do not reuse range membership,
    // index partitioning, gates or the production topological sort.
    fn pairwise(shapes: &[(Uuid, ResolvedShape)]) -> Vec<BTreeSet<usize>> {
        let mut expected = vec![BTreeSet::new(); shapes.len()];
        for (consumer, (_, shape)) in shapes.iter().enumerate() {
            for read in shape.reads.iter().filter(|read| !read.validate) {
                for (producer, (_, other)) in shapes.iter().enumerate() {
                    for emit in &other.emits {
                        let lower = match read.range.lower {
                            TimeBound::Unbounded => true,
                            TimeBound::Included(at) => emit.at >= at,
                            TimeBound::Excluded(at) => emit.at > at,
                        };
                        let upper = match read.range.upper {
                            TimeBound::Unbounded => true,
                            TimeBound::Included(at) => emit.at <= at,
                            TimeBound::Excluded(at) => emit.at < at,
                        };
                        if read.root == emit.root && lower && upper {
                            expected[producer].insert(consumer);
                        }
                    }
                }
            }
        }
        expected
    }
    fn check(shapes: &[(Uuid, ResolvedShape)]) -> Result<Vec<Uuid>> {
        let expected = pairwise(shapes);
        let refs: Vec<_> = shapes.iter().map(|(id, shape)| (*id, shape)).collect();
        let graph = Graph::build(&refs, &mut |_, _| Ok(())).unwrap();
        let mut cyclic = false;
        for i in 0..shapes.len() {
            let oracle = reachable(&expected, i);
            cyclic |= oracle.contains(&i);
            assert_eq!(
                oracle,
                reachable(&graph.outgoing, i)
                    .into_iter()
                    .filter(|node| *node < shapes.len())
                    .collect()
            );
        }
        let ordered = graph.order(&mut |_, _| Ok(()));
        assert_eq!(ordered.is_err(), cyclic);
        if let Ok(order) = &ordered {
            for (from, edges) in expected.iter().enumerate() {
                for &to in edges {
                    assert!(
                        order.iter().position(|id| *id == shapes[from].0)
                            < order.iter().position(|id| *id == shapes[to].0)
                    );
                }
            }
        }
        ordered
    }
    fn shape(id: u128, root: Address, at: i64, range: Option<TimeRange>) -> (Uuid, ResolvedShape) {
        (
            Uuid::from_u128(id),
            ResolvedShape {
                reads: range
                    .into_iter()
                    .map(|range| Read {
                        slot: 31,
                        root,
                        range,
                        validate: false,
                    })
                    .collect(),
                emits: vec![Emit {
                    role: 11,
                    contract: 900,
                    root,
                    at,
                }],
            },
        )
    }
    #[test]
    fn window_gates_match_independent_pairwise_reachability_and_cycles() {
        let mut random = 41u64;
        let mut draw = || {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            random >> 32
        };
        let times = [i64::MIN, -1, 0, 1, i64::MAX];
        let bound = |n: u64| match n {
            0 => TimeBound::Unbounded,
            1..=5 => TimeBound::Included(times[(n - 1) as usize]),
            _ => TimeBound::Excluded(times[(n - 6) as usize]),
        };
        for _ in 0..512 {
            let mut shapes = vec![];
            for id in 0..8 {
                let mut shape = ResolvedShape::default();
                for slot in 1..=draw() % 3 {
                    shape.reads.push(Read {
                        slot: slot as u16,
                        root: Address::new(Uuid::from_u128(u128::from(draw() % 3)), 7),
                        range: TimeRange {
                            lower: bound(draw() % 11),
                            upper: bound(draw() % 11),
                        },
                        validate: draw() % 5 == 0,
                    });
                }
                for role in 1..=draw() % 3 {
                    shape.emits.push(Emit {
                        role: role as u16,
                        contract: 900,
                        root: Address::new(Uuid::from_u128(u128::from(draw() % 3)), 7),
                        at: times[(draw() % 5) as usize],
                    });
                }
                shapes.push((Uuid::from_u128(id), shape));
            }
            let _ = check(&shapes);
        }
    }
    #[test]
    fn final_moves_reverse_edges_without_union_cycles_or_excluded_prefix_feedback() {
        use TimeBound::{Excluded, Included, Unbounded};
        let root = Address::new(Uuid::nil(), 7);
        let before = vec![
            shape(1, root, 10, Some(TimeRange::before(10))),
            shape(2, root, 20, Some(TimeRange::before(20))),
        ];
        let after = vec![
            shape(1, root, 30, Some(TimeRange::before(30))),
            shape(2, root, 20, Some(TimeRange::before(20))),
        ];
        assert_eq!(
            check(&before).unwrap(),
            vec![Uuid::from_u128(1), Uuid::from_u128(2)]
        );
        assert_eq!(
            check(&after).unwrap(),
            vec![Uuid::from_u128(2), Uuid::from_u128(1)]
        );
        let mut union = pairwise(&before);
        for (edges, other) in union.iter_mut().zip(pairwise(&after)) {
            edges.extend(other);
        }
        assert!(reachable(&union, 0).contains(&0));
        // Producer 1 emits before its own window. A dependency on its upper
        // prefix would invent self-feedback; only producer 2 is consumed.
        let closed = TimeRange {
            lower: Included(1),
            upper: Included(1),
        };
        assert_eq!(
            check(&[shape(1, root, 0, Some(closed)), shape(2, root, 1, None)]).unwrap(),
            vec![Uuid::from_u128(2), Uuid::from_u128(1)]
        );
        for range in [
            TimeRange {
                lower: Included(1),
                upper: Excluded(1),
            },
            TimeRange {
                lower: Included(1),
                upper: Included(0),
            },
            TimeRange {
                lower: Excluded(i64::MAX),
                upper: Unbounded,
            },
            TimeRange {
                lower: Excluded(0),
                upper: Excluded(1),
            },
        ] {
            check(&[shape(1, root, 0, Some(range))]).unwrap();
        }
        assert_eq!(
            check(&[shape(1, root, 1, Some(closed))]).unwrap_err().code,
            "feedback"
        );
        let mut validator = shape(1, root, 1, Some(closed));
        validator.1.reads[0].validate = true;
        check(&[validator]).unwrap();
    }
    #[test]
    fn inclusive_bounds_consume_whole_equal_time_groups_and_extreme_timestamps() {
        use TimeBound::{Excluded, Included};
        let root = Address::new(Uuid::nil(), 7);
        for at in [i64::MIN, 0, i64::MAX] {
            for range in [
                TimeRange::before(at),
                TimeRange::through(at),
                TimeRange {
                    lower: Included(at),
                    upper: Included(at),
                },
                TimeRange {
                    lower: Excluded(at),
                    upper: Included(at),
                },
                TimeRange::ALL,
            ] {
                let mut shapes = vec![shape(1, root, at, None), shape(2, root, at, None)];
                shapes.push((
                    Uuid::from_u128(3),
                    ResolvedShape {
                        reads: vec![Read {
                            slot: 31,
                            root,
                            range,
                            validate: false,
                        }],
                        emits: vec![],
                    },
                ));
                check(&shapes).unwrap();
            }
        }
    }
    #[test]
    fn sparse_windows_use_linear_graph_space_and_enforce_build_and_schedule_budgets() {
        for n in [16, 127, 1024, 4096] {
            let root = Address::new(Uuid::nil(), 7);
            let shapes: Vec<_> = (0..n)
                .map(|i| {
                    shape(
                        i as u128,
                        root,
                        i * 4,
                        Some(TimeRange {
                            lower: TimeBound::Included(i * 4 - 4),
                            upper: TimeBound::Included(i * 4 - 4),
                        }),
                    )
                })
                .collect();
            let refs: Vec<_> = shapes.iter().map(|(id, shape)| (*id, shape)).collect();
            let mut work = BTreeMap::new();
            let mut charge = |kind: &str, count| {
                *work.entry(kind.to_owned()).or_insert(0u64) += count;
                Ok(())
            };
            let graph = Graph::build(&refs, &mut charge).unwrap();
            assert_eq!(
                graph.order(&mut charge).unwrap(),
                shapes.iter().map(|(id, _)| *id).collect::<Vec<_>>()
            );
            assert_eq!(work["graph"], 4 * n as u64 - 1);
            assert!(work["edge"] <= 6 * n as u64);
            assert!(work["dependency"] <= 40 * n as u64);
            let mut remaining = 128u64;
            let error = Graph::build(&refs, &mut |_, count| {
                remaining = remaining
                    .checked_sub(count)
                    .ok_or_else(|| Error::new("work_limit", "test build budget"))?;
                Ok(())
            })
            .err()
            .expect("window graph exceeds tiny build budget");
            assert_eq!(error.code, "work_limit");
            let mut remaining = 1u64;
            let error = graph
                .order(&mut |_, count| {
                    remaining = remaining
                        .checked_sub(count)
                        .ok_or_else(|| Error::new("work_limit", "test schedule budget"))?;
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(error.code, "work_limit");
        }
    }
    #[test]
    fn dense_prefix_dependencies_keep_the_existing_linear_gate_path() {
        for n in [16, 128, 1024, 4096] {
            let root = Address::new(Uuid::nil(), 7);
            let shapes: Vec<_> = (0..n)
                .map(|i| {
                    let mut shape = shape(i as u128, root, i * 4, Some(TimeRange::before(i * 4)));
                    shape.1.emits.push(Emit {
                        role: 29,
                        contract: 900,
                        root,
                        at: i * 4 + 2,
                    });
                    shape
                })
                .collect();
            let refs: Vec<_> = shapes.iter().map(|(id, shape)| (*id, shape)).collect();
            let mut work = BTreeMap::new();
            let mut charge = |kind: &str, count| {
                *work.entry(kind.to_owned()).or_insert(0u64) += count;
                Ok(())
            };
            let graph = Graph::build(&refs, &mut charge).unwrap();
            assert_eq!(
                graph.order(&mut charge).unwrap(),
                shapes.iter().map(|(id, _)| *id).collect::<Vec<_>>()
            );
            assert_eq!(work["graph"], 3 * n as u64);
            assert!(work["edge"] <= 5 * n as u64);
            assert!(work["dependency"] <= 16 * (4 * n) as u64);
            let mut remaining = 128u64;
            let error = Graph::build(&refs, &mut |_, count| {
                remaining = remaining
                    .checked_sub(count)
                    .ok_or_else(|| Error::new("work_limit", "test budget"))?;
                Ok(())
            })
            .err()
            .expect("prefix graph exceeds tiny work budget");
            assert_eq!(error.code, "work_limit");
        }
    }
}
