use std::{cmp::Reverse, collections::BinaryHeap};

pub type OrderKey = (i64, u128);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: OrderKey,
    pub reader: u16,
}

#[derive(Debug)]
pub struct Page {
    pub items: Vec<Entry>,
    pub visited: usize,
    pub next: Option<OrderKey>,
    pub exhausted: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Exists {
    Yes,
    No,
    Unknown(OrderKey),
}

impl Page {
    pub fn exists(&self) -> Exists {
        if !self.items.is_empty() {
            Exists::Yes
        } else if self.exhausted {
            Exists::No
        } else {
            Exists::Unknown(self.next.expect("nonempty budget advances continuation"))
        }
    }
}

/// Demonstration over sorted disjoint streams. Scope selection happens upstream.
/// A storage adapter would refill bounded buffers instead of owning these slices.
pub fn page(
    streams: &[&[Entry]],
    after: Option<OrderKey>,
    limit: usize,
    budget: usize,
    mut predicate: impl FnMut(&Entry) -> bool,
) -> Page {
    assert!(
        limit > 0 && budget > 0,
        "page needs a positive limit and visit budget"
    );
    let mut positions: Vec<_> = streams
        .iter()
        .map(|stream| after.map_or(0, |key| stream.partition_point(|entry| entry.key <= key)))
        .collect();
    let mut heap = BinaryHeap::new();
    for (index, stream) in streams.iter().enumerate() {
        if let Some(entry) = stream.get(positions[index]) {
            heap.push(Reverse((entry.key, index)));
        }
    }
    let mut items = Vec::new();
    let mut visited = 0;
    let mut last = after;
    while visited < budget && items.len() < limit {
        let Some(Reverse((key, index))) = heap.pop() else {
            break;
        };
        let entry = streams[index][positions[index]];
        visited += 1;
        last = Some(key);
        if predicate(&entry) {
            items.push(entry);
        }
        positions[index] += 1;
        if let Some(next) = streams[index].get(positions[index]) {
            heap.push(Reverse((next.key, index)));
        }
    }
    let exhausted = heap.is_empty();
    Page {
        items,
        visited,
        next: if exhausted { None } else { last },
        exhausted,
    }
}
