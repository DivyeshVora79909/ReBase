//! Linked quote and financial index representation for the bounded native slice.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::binding::Binding;
use crate::{
    algebra::Summary,
    native_codec::{Address, decimal, optional_decimal, summary, uuid_text},
};
use crate::{
    native_codec::{Key, StoredValue},
    native_slice::{Attempt, Error, Result},
    time_range::{TimeBound, TimeRange},
};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Financial,
    Quote,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullKey {
    #[serde(with = "decimal")]
    pub at: i64,
    #[serde(with = "uuid_text")]
    pub id: Uuid,
    pub slot: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "lowercase",
    deny_unknown_fields
)]
pub enum Leaf {
    Financial(#[serde(with = "decimal")] i128),
    Quote(#[serde(with = "decimal")] u16),
}

impl Leaf {
    pub fn kind(self) -> Kind {
        match self {
            Self::Financial(_) => Kind::Financial,
            Self::Quote(_) => Kind::Quote,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteSummary {
    pub count: u64,
    #[serde(with = "optional_decimal")]
    pub first: Option<i64>,
    #[serde(with = "optional_decimal")]
    pub last: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "lowercase",
    deny_unknown_fields
)]
pub enum Aggregate {
    Financial(#[serde(with = "summary")] Summary),
    Quote(QuoteSummary),
}

impl Aggregate {
    pub fn kind(self) -> Kind {
        match self {
            Self::Financial(_) => Kind::Financial,
            Self::Quote(_) => Kind::Quote,
        }
    }
    pub fn empty(kind: Kind) -> Self {
        match kind {
            Kind::Financial => Self::Financial(Summary::default()),
            Kind::Quote => Self::Quote(QuoteSummary::default()),
        }
    }
    fn leaf(at: i64, leaf: Leaf) -> Self {
        match leaf {
            Leaf::Financial(amount) => Self::Financial(Summary::leaf(at, Some(amount))),
            Leaf::Quote(_) => Self::Quote(QuoteSummary {
                count: 1,
                first: Some(at),
                last: Some(at),
            }),
        }
    }
    fn combine(self, other: Self) -> Result<Self> {
        match (self, other) {
            (Self::Financial(a), Self::Financial(b)) => a
                .combine(b)
                .map(Self::Financial)
                .map_err(|e| Error::new("overflow", e)),
            (Self::Quote(a), Self::Quote(b)) => {
                if a.count == 0 {
                    return Ok(Self::Quote(b));
                }
                if b.count == 0 {
                    return Ok(Self::Quote(a));
                }
                if a.last > b.first {
                    return Err(broken("unordered quote segments"));
                }
                Ok(Self::Quote(QuoteSummary {
                    count: a
                        .count
                        .checked_add(b.count)
                        .ok_or_else(|| broken("quote count overflow"))?,
                    first: a.first,
                    last: b.last,
                }))
            }
            _ => Err(broken("mixed summary kinds")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub kind: Kind,
    pub head: Option<Address>,
    pub first: Option<Address>,
    pub last: Option<Address>,
    pub height: u16,
    pub summary: Aggregate,
    #[serde(with = "decimal")]
    pub revision: u64,
}

impl Root {
    pub fn empty(kind: Kind, revision: u64) -> Self {
        Self {
            kind,
            head: None,
            first: None,
            last: None,
            height: 0,
            summary: Aggregate::empty(kind),
            revision,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub root: Address,
    pub key: FullKey,
    pub leaf: Leaf,
    pub parent: Option<Address>,
    pub left: Option<Address>,
    pub right: Option<Address>,
    pub prev: Option<Address>,
    pub next: Option<Address>,
    pub height: u16,
    pub summary: Aggregate,
}

fn broken(detail: &str) -> Error {
    Error::new("corrupt_state", detail)
}

pub fn root<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    id: Address,
) -> Result<Root> {
    match ws.get(&Key::Root(id))? {
        Some(StoredValue::Root(r)) => Ok(r),
        _ => Err(broken("missing root")),
    }
}

pub fn node<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    owner: Address,
    id: Address,
) -> Result<Node> {
    ws.charge("node", 1)?;
    match ws.get(&Key::Node(id))? {
        Some(StoredValue::Node(n)) if n.root == owner => Ok(n),
        _ => Err(broken("missing or cross-root node")),
    }
}

fn edit<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    owner: Address,
    id: Address,
    change: impl FnOnce(&mut Node),
) -> Result<()> {
    let mut current = node(ws, owner, id)?;
    change(&mut current);
    ws.put(Key::Node(id), Some(StoredValue::Node(current)))
}

fn child_info<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    owner: Address,
    parent: Address,
    child: Option<Address>,
    kind: Kind,
) -> Result<(u16, Aggregate)> {
    match child {
        None => Ok((0, Aggregate::empty(kind))),
        Some(id) => {
            let n = node(ws, owner, id)?;
            if n.parent != Some(parent) || n.summary.kind() != kind {
                return Err(broken("child parent/kind mismatch"));
            }
            Ok((n.height, n.summary))
        }
    }
}

fn refresh<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    owner: Address,
    id: Address,
) -> Result<i32> {
    let current = node(ws, owner, id)?;
    let kind = current.leaf.kind();
    let (lh, ls) = child_info(ws, owner, id, current.left, kind)?;
    let (rh, rs) = child_info(ws, owner, id, current.right, kind)?;
    let summary = ls
        .combine(Aggregate::leaf(current.key.at, current.leaf))?
        .combine(rs)?;
    let height = lh
        .max(rh)
        .checked_add(1)
        .ok_or_else(|| broken("height overflow"))?;
    edit(ws, owner, id, |n| {
        n.height = height;
        n.summary = summary;
    })?;
    Ok(i32::from(lh) - i32::from(rh))
}

fn replace_parent_link<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    owner: Address,
    old: Address,
    new: Option<Address>,
) -> Result<()> {
    let parent = node(ws, owner, old)?.parent;
    if let Some(p) = parent {
        let current = node(ws, owner, p)?;
        if (current.left == Some(old)) == (current.right == Some(old)) {
            return Err(broken("ambiguous parent link"));
        }
        edit(ws, owner, p, |n| {
            if current.left == Some(old) {
                n.left = new;
            } else {
                n.right = new;
            }
        })?;
    } else {
        let mut header = root(ws, owner)?;
        if header.head != Some(old) {
            return Err(broken("root head mismatch"));
        }
        header.head = new;
        ws.put(Key::Root(owner), Some(StoredValue::Root(header)))?;
    }
    if let Some(id) = new {
        edit(ws, owner, id, |n| n.parent = parent)?;
    }
    Ok(())
}

fn rotate_left<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    owner: Address,
    x: Address,
) -> Result<Address> {
    let y = node(ws, owner, x)?
        .right
        .ok_or_else(|| broken("missing rotation child"))?;
    let upper = node(ws, owner, y)?;
    if upper.parent != Some(x) {
        return Err(broken("rotation parent mismatch"));
    }
    let beta = upper.left;
    edit(ws, owner, x, |n| n.right = beta)?;
    if let Some(b) = beta {
        edit(ws, owner, b, |n| n.parent = Some(x))?;
    }
    replace_parent_link(ws, owner, x, Some(y))?;
    edit(ws, owner, y, |n| n.left = Some(x))?;
    edit(ws, owner, x, |n| n.parent = Some(y))?;
    refresh(ws, owner, x)?;
    refresh(ws, owner, y)?;
    ws.work.rotations += 1;
    Ok(y)
}

fn rotate_right<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    owner: Address,
    x: Address,
) -> Result<Address> {
    let y = node(ws, owner, x)?
        .left
        .ok_or_else(|| broken("missing rotation child"))?;
    let upper = node(ws, owner, y)?;
    if upper.parent != Some(x) {
        return Err(broken("rotation parent mismatch"));
    }
    let beta = upper.right;
    edit(ws, owner, x, |n| n.left = beta)?;
    if let Some(b) = beta {
        edit(ws, owner, b, |n| n.parent = Some(x))?;
    }
    replace_parent_link(ws, owner, x, Some(y))?;
    edit(ws, owner, y, |n| n.right = Some(x))?;
    edit(ws, owner, x, |n| n.parent = Some(y))?;
    refresh(ws, owner, x)?;
    refresh(ws, owner, y)?;
    ws.work.rotations += 1;
    Ok(y)
}

fn balance<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    owner: Address,
    mut at: Option<Address>,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    while let Some(id) = at {
        if !seen.insert(id) {
            return Err(broken("cyclic parent chain"));
        }
        let difference = refresh(ws, owner, id)?;
        let top = if difference > 1 {
            let left = node(ws, owner, id)?
                .left
                .ok_or_else(|| broken("missing heavy child"))?;
            if refresh(ws, owner, left)? < 0 {
                rotate_left(ws, owner, left)?;
            }
            rotate_right(ws, owner, id)?
        } else if difference < -1 {
            let right = node(ws, owner, id)?
                .right
                .ok_or_else(|| broken("missing heavy child"))?;
            if refresh(ws, owner, right)? > 0 {
                rotate_right(ws, owner, right)?;
            }
            rotate_left(ws, owner, id)?
        } else {
            id
        };
        at = node(ws, owner, top)?.parent;
    }
    let mut header = root(ws, owner)?;
    if let Some(head) = header.head {
        let n = node(ws, owner, head)?;
        if n.parent.is_some() {
            return Err(broken("root has parent"));
        }
        header.height = n.height;
        header.summary = n.summary;
    } else {
        if header.first.is_some() || header.last.is_some() {
            return Err(broken("nonempty endpoints for empty root"));
        }
        header.height = 0;
        header.summary = Aggregate::empty(header.kind);
    }
    ws.put(Key::Root(owner), Some(StoredValue::Root(header)))
}

pub fn insert<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    owner: Address,
    id: Address,
    at: i64,
    leaf: Leaf,
) -> Result<()> {
    let mut header = root(ws, owner)?;
    if id.slot == 0 || owner.slot == 0 || header.kind != leaf.kind() {
        return Err(broken("invalid member/root kind"));
    }
    if ws.get(&Key::Node(id))?.is_some() {
        return Err(broken("existing member identity"));
    }
    let key = FullKey {
        at,
        id: id.id,
        slot: id.slot,
    };
    let (mut cursor, mut parent, mut previous, mut next) = (header.head, None, None, None);
    let mut seen = BTreeSet::new();
    while let Some(current) = cursor {
        if !seen.insert(current) {
            return Err(broken("cyclic search path"));
        }
        let n = node(ws, owner, current)?;
        if n.parent != parent {
            return Err(broken("search parent mismatch"));
        }
        if header.kind == Kind::Quote && n.key.at == at {
            return Err(Error::new("duplicate_time", "curve quote time"));
        }
        if key == n.key {
            return Err(broken("duplicate full key"));
        }
        parent = Some(current);
        if key < n.key {
            next = Some(current);
            cursor = n.left;
        } else {
            previous = Some(current);
            cursor = n.right;
        }
    }
    ws.put(
        Key::Node(id),
        Some(StoredValue::Node(Node {
            root: owner,
            key,
            leaf,
            parent,
            left: None,
            right: None,
            prev: previous,
            next,
            height: 1,
            summary: Aggregate::leaf(at, leaf),
        })),
    )?;
    if let Some(p) = parent {
        edit(ws, owner, p, |n| {
            if key < n.key {
                n.left = Some(id);
            } else {
                n.right = Some(id);
            }
        })?;
    } else {
        header.head = Some(id);
    }
    if let Some(p) = previous {
        edit(ws, owner, p, |n| n.next = Some(id))?;
    } else {
        header.first = Some(id);
    }
    if let Some(n) = next {
        edit(ws, owner, n, |n| n.prev = Some(id))?;
    } else {
        header.last = Some(id);
    }
    ws.put(Key::Root(owner), Some(StoredValue::Root(header)))?;
    balance(ws, owner, Some(id))
}

pub fn revalue<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    owner: Address,
    id: Address,
    leaf: Leaf,
) -> Result<()> {
    let n = node(ws, owner, id)?;
    if n.leaf.kind() != leaf.kind() {
        return Err(broken("revalue kind mismatch"));
    }
    if n.leaf == leaf {
        return Ok(());
    }
    edit(ws, owner, id, |n| n.leaf = leaf)?;
    balance(ws, owner, Some(id))
}

pub fn remove<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    owner: Address,
    id: Address,
) -> Result<()> {
    let n = node(ws, owner, id)?;
    let mut header = root(ws, owner)?;
    if let Some(p) = n.prev {
        if node(ws, owner, p)?.next != Some(id) {
            return Err(broken("previous neighbour mismatch"));
        }
        edit(ws, owner, p, |p| p.next = n.next)?;
    } else {
        header.first = n.next;
    }
    if let Some(next) = n.next {
        if node(ws, owner, next)?.prev != Some(id) {
            return Err(broken("next neighbour mismatch"));
        }
        edit(ws, owner, next, |next| next.prev = n.prev)?;
    } else {
        header.last = n.prev;
    }
    ws.put(Key::Root(owner), Some(StoredValue::Root(header)))?;
    let start = match (n.left, n.right) {
        (None, child) | (child, None) => {
            replace_parent_link(ws, owner, id, child)?;
            n.parent.or(child)
        }
        (Some(left), Some(right)) => {
            let mut successor = right;
            let mut seen = BTreeSet::new();
            loop {
                if !seen.insert(successor) {
                    return Err(broken("cyclic successor path"));
                }
                if let Some(next) = node(ws, owner, successor)?.left {
                    successor = next;
                } else {
                    break;
                }
            }
            let replacement = node(ws, owner, successor)?;
            let start = if replacement.parent == Some(id) {
                Some(successor)
            } else {
                replace_parent_link(ws, owner, successor, replacement.right)?;
                edit(ws, owner, successor, |s| s.right = Some(right))?;
                edit(ws, owner, right, |r| r.parent = Some(successor))?;
                replacement.parent
            };
            replace_parent_link(ws, owner, id, Some(successor))?;
            edit(ws, owner, successor, |s| s.left = Some(left))?;
            edit(ws, owner, left, |l| l.parent = Some(successor))?;
            start
        }
    };
    ws.put(Key::Node(id), None)?;
    balance(ws, owner, start)
}

pub fn latest<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    owner: Address,
    at: i64,
) -> Result<Option<(Uuid, u16)>> {
    let header = root(ws, owner)?;
    if header.kind != Kind::Quote {
        return Err(broken("latest requires a quote root"));
    }
    let (mut cursor, mut parent, mut selected) = (header.head, None, None);
    let mut seen = BTreeSet::new();
    while let Some(id) = cursor {
        if !seen.insert(id) {
            return Err(broken("cyclic quote search"));
        }
        let n = node(ws, owner, id)?;
        if n.parent != parent {
            return Err(broken("quote parent mismatch"));
        }
        parent = Some(id);
        if n.key.at <= at {
            let Leaf::Quote(rate) = n.leaf else {
                return Err(broken("nonquote selection"));
            };
            selected = Some((id.id, rate));
            cursor = n.right;
        } else {
            cursor = n.left;
        }
    }
    Ok(selected)
}

/// Sum complete occurrences strictly before a timestamp. Equal-time members
/// never depend on their UUID order; None means the whole settled root.
pub fn prefix<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    owner: Address,
    before: Option<i64>,
) -> Result<i128> {
    let header = root(ws, owner)?;
    let Aggregate::Financial(total) = header.summary else {
        return Err(broken("prefix on quote root"));
    };
    let Some(before) = before else {
        return Ok(total.sum);
    };
    let mut sum: i128 = 0;
    let mut cursor = header.head;
    let mut parent = None;
    let mut visited = BTreeSet::new();
    while let Some(id) = cursor {
        if !visited.insert(id) {
            return Err(broken("prefix cycle"));
        }
        let current = node(ws, owner, id)?;
        if current.parent != parent {
            return Err(broken("prefix parent mismatch"));
        }
        parent = Some(id);
        if current.key.at < before {
            let left = child_info(ws, owner, id, current.left, Kind::Financial)?.1;
            let (Aggregate::Financial(left), Leaf::Financial(leaf)) = (left, current.leaf) else {
                return Err(broken("prefix kind"));
            };
            sum = sum
                .checked_add(left.sum)
                .and_then(|s| s.checked_add(leaf))
                .ok_or_else(|| Error::new("overflow", "prefix sum"))?;
            cursor = current.right;
        } else {
            cursor = current.left;
        }
    }
    Ok(sum)
}

fn span(summary: Aggregate) -> Result<Option<(i64, i64)>> {
    let (count, first, last) = match summary {
        Aggregate::Financial(value) => (value.count, value.first, value.last),
        Aggregate::Quote(value) => (value.count, value.first, value.last),
    };
    match (count, first, last) {
        (0, None, None) => Ok(None),
        (1.., Some(first), Some(last)) if first <= last => Ok(Some((first, last))),
        _ => Err(broken("range summary span")),
    }
}

struct RangeFold {
    owner: Address,
    window: TimeRange,
    kind: Kind,
    seen: BTreeSet<Address>,
}

impl RangeFold {
    fn visit<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
        &mut self,
        ws: &mut Attempt<L, B>,
        id: Option<Address>,
        parent: Option<Address>,
        depth: u16,
    ) -> Result<Aggregate> {
        let Some(id) = id else {
            return Ok(Aggregate::empty(self.kind));
        };
        if depth >= 64 {
            return Err(broken("range path depth"));
        }
        if !self.seen.insert(id) {
            return Err(broken("range cycle or duplicate reachability"));
        }
        let current = node(ws, self.owner, id)?;
        if current.parent != parent
            || current.leaf.kind() != self.kind
            || current.summary.kind() != self.kind
            || current.height == 0
            || current.height >= 64
        {
            return Err(broken("range parent/kind/height mismatch"));
        }
        let Some((first, last)) = span(current.summary)? else {
            return Err(broken("empty node summary"));
        };
        if !(first <= current.key.at && current.key.at <= last) {
            return Err(broken("range leaf outside summary span"));
        }
        if self.window.contains(first) && self.window.contains(last) {
            return Ok(current.summary);
        }
        let below = match self.window.lower {
            TimeBound::Unbounded => false,
            TimeBound::Included(at) => last < at,
            TimeBound::Excluded(at) => last <= at,
        };
        let above = match self.window.upper {
            TimeBound::Unbounded => false,
            TimeBound::Included(at) => first > at,
            TimeBound::Excluded(at) => first >= at,
        };
        if below || above {
            return Ok(Aggregate::empty(self.kind));
        }
        // Skip sides excluded by the boundary point itself. Equal timestamps
        // stay together even when their UUID ties straddle several subtrees.
        let left_possible = match self.window.lower {
            TimeBound::Unbounded => true,
            TimeBound::Included(at) => at <= current.key.at,
            TimeBound::Excluded(at) => at < current.key.at,
        };
        let right_possible = match self.window.upper {
            TimeBound::Unbounded => true,
            TimeBound::Included(at) => current.key.at <= at,
            TimeBound::Excluded(at) => current.key.at < at,
        };
        let mut result = if left_possible {
            self.visit(ws, current.left, Some(id), depth + 1)?
        } else {
            Aggregate::empty(self.kind)
        };
        if self.window.contains(current.key.at) {
            result = result.combine(Aggregate::leaf(current.key.at, current.leaf))?;
        }
        if right_possible {
            result = result.combine(self.visit(ws, current.right, Some(id), depth + 1)?)?;
        }
        Ok(result)
    }
}

/// Fold complete timestamp groups in source order. Canonically covered subtrees
/// contribute their cached aggregate; boundary leaves preserve non-invertible
/// prefix and complete-time extrema without subtracting two prefix summaries.
pub fn range<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    owner: Address,
    window: TimeRange,
) -> Result<Aggregate> {
    let header = root(ws, owner)?;
    if header.summary.kind() != header.kind || header.height >= 64 {
        return Err(broken("range root kind/height"));
    }
    let bounds = span(header.summary)?;
    if header.head.is_none() != bounds.is_none() || header.head.is_none() != (header.height == 0) {
        return Err(broken("range root population"));
    }
    if window.is_empty() {
        return Ok(Aggregate::empty(header.kind));
    }
    let Some((first, last)) = bounds else {
        return Ok(Aggregate::empty(header.kind));
    };
    if window.contains(first) && window.contains(last) {
        return Ok(header.summary);
    }
    RangeFold {
        owner,
        window,
        kind: header.kind,
        seen: BTreeSet::new(),
    }
    .visit(ws, header.head, None, 0)
}
