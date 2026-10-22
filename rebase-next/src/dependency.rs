//! Prefix gates compress producer dependency edges without changing reachability.
//! A gate at t depends on the previous gate and every producer emitting at t.
//! A strict prefix read depends on the last gate before its bound.
use crate::{
    binding::Binding,
    causal::ResolvedShape,
    native_codec::Address,
    native_slice::{Attempt, Error, Result},
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

struct Graph {
    outgoing: Vec<BTreeSet<usize>>,
    producers: Vec<Uuid>,
}
impl Graph {
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
        }
        let mut prefixes = BTreeMap::new();
        for (root, times) in roots {
            let mut previous = None;
            let mut index = vec![];
            for (at, producers) in times {
                charge("graph", 1)?;
                let gate = graph.outgoing.len();
                graph.outgoing.push(BTreeSet::new());
                if let Some(previous) = previous {
                    graph.edge(previous, gate, charge)?;
                }
                for producer in producers {
                    graph.edge(producer, gate, charge)?;
                }
                index.push((at, gate));
                previous = Some(gate);
            }
            prefixes.insert(root, index);
        }
        for (consumer, (_, shape)) in shapes.iter().enumerate() {
            for read in shape.reads.iter().filter(|r| !r.validate) {
                charge("dependency", 1)?;
                let Some(index) = prefixes.get(&read.root) else {
                    continue;
                };
                let mut comparisons = 0;
                let end = read.before.map_or(index.len(), |before| {
                    index.partition_point(|(at, _)| {
                        comparisons += 1;
                        *at < before
                    })
                });
                charge("dependency", comparisons)?;
                if let Some((_, gate)) = end.checked_sub(1).map(|i| index[i]) {
                    graph.edge(gate, consumer, charge)?;
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
    use crate::causal::{Emit, Read};

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
    #[test]
    fn prefix_gates_match_independent_pairwise_reachability_and_cycles() {
        let mut random = 41u64;
        let mut draw = || {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            random >> 32
        };
        let times = [i64::MIN, -1, 0, 1, i64::MAX];
        for _ in 0..512 {
            let mut shapes = vec![];
            for i in 0..8 {
                let mut s = ResolvedShape::default();
                for slot in 1..=draw() % 3 {
                    let time = draw() % 6;
                    s.reads.push(Read {
                        slot: slot as u16,
                        root: Address::new(Uuid::from_u128(u128::from(draw() % 3)), 7),
                        before: if time == 5 {
                            None
                        } else {
                            Some(times[time as usize])
                        },
                        validate: draw() % 5 == 0,
                    });
                }
                for role in 1..=draw() % 3 {
                    s.emits.push(Emit {
                        role: role as u16,
                        contract: 900,
                        root: Address::new(Uuid::from_u128(u128::from(draw() % 3)), 7),
                        at: times[(draw() % 5) as usize],
                    });
                }
                shapes.push((Uuid::from_u128(i), s));
            }
            // This oracle explicitly enumerates each read/emission pair. It
            // neither builds prefix gates nor calls the production ordering.
            let mut expected = vec![BTreeSet::new(); shapes.len()];
            for (consumer, (_, shape)) in shapes.iter().enumerate() {
                for read in shape.reads.iter().filter(|r| !r.validate) {
                    for (producer, (_, other)) in shapes.iter().enumerate() {
                        for emit in &other.emits {
                            if read.root == emit.root && read.before.is_none_or(|t| emit.at < t) {
                                expected[producer].insert(consumer);
                            }
                        }
                    }
                }
            }
            let refs: Vec<_> = shapes.iter().map(|(id, s)| (*id, s)).collect();
            let mut charged = BTreeMap::new();
            let mut charge = |kind: &str, n| {
                *charged.entry(kind.to_owned()).or_insert(0u64) += n;
                Ok(())
            };
            let graph = Graph::build(&refs, &mut charge).unwrap();
            let mut cyclic = false;
            for i in 0..shapes.len() {
                let oracle = reachable(&expected, i);
                cyclic |= oracle.contains(&i);
                assert_eq!(
                    oracle,
                    reachable(&graph.outgoing, i)
                        .into_iter()
                        .filter(|n| *n < shapes.len())
                        .collect()
                );
            }
            let ordered = graph.order(&mut charge);
            assert_eq!(ordered.is_err(), cyclic);
            if let Ok(order) = ordered {
                for (from, edges) in expected.iter().enumerate() {
                    for &to in edges {
                        assert!(
                            order.iter().position(|id| *id == shapes[from].0)
                                < order.iter().position(|id| *id == shapes[to].0)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn dense_prefix_dependencies_use_linear_edges_and_enforce_the_work_budget() {
        for n in [16, 128, 1024, 4096] {
            let root = Address::new(Uuid::nil(), 7);
            let shapes: Vec<_> = (0..n)
                .map(|i| {
                    (
                        Uuid::from_u128(i as u128),
                        ResolvedShape {
                            reads: vec![Read {
                                slot: 31,
                                root,
                                before: Some(i * 4),
                                validate: false,
                            }],
                            emits: vec![
                                Emit {
                                    role: 11,
                                    contract: 900,
                                    root,
                                    at: i * 4,
                                },
                                Emit {
                                    role: 29,
                                    contract: 900,
                                    root,
                                    at: i * 4 + 2,
                                },
                            ],
                        },
                    )
                })
                .collect();
            let refs: Vec<_> = shapes.iter().map(|(id, s)| (*id, s)).collect();
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
            let err = Graph::build(&refs, &mut |_, count| {
                remaining = remaining
                    .checked_sub(count)
                    .ok_or_else(|| Error::new("work_limit", "test budget"))?;
                Ok(())
            })
            .err()
            .expect("a real graph exceeds a tiny work budget");
            assert_eq!(err.code, "work_limit");
        }
    }
}
