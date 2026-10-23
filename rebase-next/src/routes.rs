//! Ordered reverse routes. Each registration is a point-addressed AVL node;
//! selecting a suffix does not decode or rewrite the rest of a subscriber list.
use crate::{
    binding::Binding,
    native_codec::{Address, Key, StoredValue, decimal, uuid_text},
    native_slice::{Attempt, Error, Result},
    time_range::{TimeBound, TimeRange},
};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::BTreeSet, ops::Bound};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "at",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Endpoint {
    Time(#[serde(with = "decimal")] i64),
    Through(#[serde(with = "decimal")] i64),
    All,
}

impl Endpoint {
    fn bound(self) -> TimeBound {
        match self {
            Self::Time(at) => TimeBound::Excluded(at),
            Self::Through(at) => TimeBound::Included(at),
            Self::All => TimeBound::Unbounded,
        }
    }
}
impl Ord for Endpoint {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bound().upper_cut().cmp(&other.bound().upper_cut())
    }
}
impl PartialOrd for Endpoint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
/// The route's sort position is the exact upper cut of its window.
pub fn endpoint(range: TimeRange) -> Endpoint {
    match range.upper {
        TimeBound::Excluded(at) => Endpoint::Time(at),
        TimeBound::Included(at) => Endpoint::Through(at),
        TimeBound::Unbounded => Endpoint::All,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "owner",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Route {
    Incoming(#[serde(with = "uuid_text")] Uuid),
    Direct(#[serde(with = "uuid_text")] Uuid),
    Subscribers(Address),
}
impl Route {
    pub fn from_key(key: &Key) -> Result<Self> {
        match key {
            Key::Incoming(id) => Ok(Self::Incoming(*id)),
            Key::Direct(id) => Ok(Self::Direct(*id)),
            Key::Subscribers(id) => Ok(Self::Subscribers(*id)),
            _ => Err(broken("not a route header")),
        }
    }
    pub fn key(self) -> Key {
        match self {
            Self::Incoming(id) => Key::Incoming(id),
            Self::Direct(id) => Key::Direct(id),
            Self::Subscribers(id) => Key::Subscribers(id),
        }
    }
    pub fn node_key(self, id: Address) -> Key {
        match self {
            Self::Incoming(_) => Key::IncomingNode(id),
            Self::Direct(_) => Key::DirectNode(id),
            Self::Subscribers(_) => Key::SubscriberNode(id),
        }
    }
    fn value<B: Binding>(self, header: Header) -> StoredValue<B> {
        match self {
            Self::Incoming(_) => StoredValue::Incoming(header),
            Self::Direct(_) => StoredValue::Direct(header),
            Self::Subscribers(_) => StoredValue::Subscribers(header),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub head: Option<Address>,
    pub len: u32,
    pub bounded: u32,
}
impl Header {
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Order {
    pub endpoint: Endpoint,
    pub member: Address,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub route: Route,
    pub key: Order,
    pub range: TimeRange,
    #[serde(with = "minimum_lower")]
    pub min_lower: Option<TimeBound>,
    pub left: Option<Address>,
    pub right: Option<Address>,
    pub height: u16,
}
// TimeBound::Unbounded encodes as null. Wrap present values so a subtree with
// an unbounded nonempty interval remains distinct from an all-empty subtree.
mod minimum_lower {
    use super::TimeBound;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Present {
        bound: TimeBound,
    }
    pub fn serialize<S: Serializer>(value: &Option<TimeBound>, s: S) -> Result<S::Ok, S::Error> {
        value.map(|bound| Present { bound }).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<TimeBound>, D::Error> {
        Ok(Option::<Present>::deserialize(d)?.map(|v| v.bound))
    }
}
fn minimum(a: Option<TimeBound>, b: Option<TimeBound>) -> Option<TimeBound> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if a.lower_cut() <= b.lower_cut() { a } else { b }),
        (a, b) => a.or(b),
    }
}

fn broken(detail: &str) -> Error {
    Error::new("corrupt_state", detail)
}
fn depth_check(depth: u16) -> Result<()> {
    if depth >= 64 {
        return Err(broken("reverse route path depth"));
    }
    Ok(())
}
fn value<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    key: &Key,
    original: bool,
) -> Result<Option<StoredValue<B>>> {
    if original {
        ws.original(key)
    } else {
        ws.get(key)
    }
}
pub fn header<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    route: Route,
    original: bool,
) -> Result<Option<Header>> {
    match value(ws, &route.key(), original)? {
        None => Ok(None),
        Some(StoredValue::Incoming(h) | StoredValue::Direct(h) | StoredValue::Subscribers(h)) => {
            Ok(Some(h))
        }
        _ => Err(broken("reverse route header type")),
    }
}
fn node<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    route: Route,
    id: Address,
    original: bool,
) -> Result<Node> {
    ws.charge("route", 1)?;
    match value(ws, &route.node_key(id), original)? {
        Some(StoredValue::RouteNode(n)) if n.route == route && n.key.member == id => Ok(n),
        _ => Err(broken("missing or cross-route registration")),
    }
}
fn height<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    route: Route,
    id: Option<Address>,
) -> Result<u16> {
    id.map(|id| node(ws, route, id, false).map(|n| n.height))
        .transpose()
        .map(|h| h.unwrap_or(0))
}
fn save<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    mut n: Node,
) -> Result<Node> {
    let left = n.left.map(|id| node(ws, n.route, id, false)).transpose()?;
    let right = n.right.map(|id| node(ws, n.route, id, false)).transpose()?;
    n.height = 1 + left
        .as_ref()
        .map_or(0, |n| n.height)
        .max(right.as_ref().map_or(0, |n| n.height));
    n.min_lower = minimum(
        (!n.range.is_empty()).then_some(n.range.lower),
        minimum(
            left.and_then(|n| n.min_lower),
            right.and_then(|n| n.min_lower),
        ),
    );
    depth_check(n.height)?;
    ws.put(
        n.route.node_key(n.key.member),
        Some(StoredValue::RouteNode(n.clone())),
    )?;
    Ok(n)
}
fn rotate<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    mut n: Node,
    left: bool,
) -> Result<Address> {
    let pivot =
        if left { n.right } else { n.left }.ok_or_else(|| broken("route rotation child"))?;
    let mut p = node(ws, n.route, pivot, false)?;
    if left {
        n.right = p.left;
        p.left = Some(n.key.member);
    } else {
        n.left = p.right;
        p.right = Some(n.key.member);
    }
    save(ws, n)?;
    save(ws, p)?;
    Ok(pivot)
}
fn balance<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    mut n: Node,
) -> Result<Address> {
    let difference =
        i32::from(height(ws, n.route, n.left)?) - i32::from(height(ws, n.route, n.right)?);
    if difference.abs() > 2 {
        return Err(broken("unbalanced reverse route"));
    }
    if difference > 1 {
        let l = node(
            ws,
            n.route,
            n.left.ok_or_else(|| broken("route left child"))?,
            false,
        )?;
        if height(ws, n.route, l.left)? < height(ws, n.route, l.right)? {
            n.left = Some(rotate(ws, l, true)?);
        }
        rotate(ws, n, false)
    } else if difference < -1 {
        let r = node(
            ws,
            n.route,
            n.right.ok_or_else(|| broken("route right child"))?,
            false,
        )?;
        if height(ws, n.route, r.right)? < height(ws, n.route, r.left)? {
            n.right = Some(rotate(ws, r, false)?);
        }
        rotate(ws, n, true)
    } else {
        Ok(save(ws, n)?.key.member)
    }
}
fn attach<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    route: Route,
    head: Option<Address>,
    key: Order,
    range: TimeRange,
    depth: u16,
) -> Result<Address> {
    depth_check(depth)?;
    let Some(head) = head else {
        save(
            ws,
            Node {
                route,
                key,
                range,
                min_lower: None,
                left: None,
                right: None,
                height: 1,
            },
        )?;
        return Ok(key.member);
    };
    let mut n = node(ws, route, head, false)?;
    if key < n.key {
        n.left = Some(attach(ws, route, n.left, key, range, depth + 1)?);
    } else if key > n.key {
        n.right = Some(attach(ws, route, n.right, key, range, depth + 1)?);
    } else {
        return Err(broken("duplicate reverse registration"));
    }
    balance(ws, n)
}
fn take_first<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    route: Route,
    head: Address,
    depth: u16,
) -> Result<(Option<Address>, Node)> {
    depth_check(depth)?;
    let mut n = node(ws, route, head, false)?;
    if let Some(left) = n.left {
        let (next, removed) = take_first(ws, route, left, depth + 1)?;
        n.left = next;
        Ok((Some(balance(ws, n)?), removed))
    } else {
        ws.put(route.node_key(head), None)?;
        Ok((n.right, n))
    }
}
fn detach<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    route: Route,
    head: Option<Address>,
    key: Order,
    depth: u16,
) -> Result<Option<Address>> {
    depth_check(depth)?;
    let head = head.ok_or_else(|| broken("missing reverse registration"))?;
    let mut n = node(ws, route, head, false)?;
    if key < n.key {
        n.left = detach(ws, route, n.left, key, depth + 1)?;
    } else if key > n.key {
        n.right = detach(ws, route, n.right, key, depth + 1)?;
    } else {
        ws.put(route.node_key(head), None)?;
        match (n.left, n.right) {
            (None, child) | (child, None) => return Ok(child),
            (Some(left), Some(right)) => {
                let (right, mut replacement) = take_first(ws, route, right, depth + 1)?;
                replacement.left = Some(left);
                replacement.right = right;
                n = replacement;
            }
        }
    }
    Ok(Some(balance(ws, n)?))
}

pub fn change<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    key: &Key,
    member: Address,
    range: TimeRange,
    add: bool,
) -> Result<()> {
    let route = Route::from_key(key)?;
    if !matches!(route, Route::Subscribers(_)) && range != TimeRange::ALL {
        return Err(broken("non-subscriber route window"));
    }
    let mut h = header(ws, route, false)?.ok_or_else(|| broken("missing reverse route header"))?;
    if !matches!(route, Route::Subscribers(_)) && h.bounded != 0 {
        return Err(broken("non-subscriber bounded route count"));
    }
    let order = Order {
        endpoint: endpoint(range),
        member,
    };
    let bounded = u32::from(range.lower != TimeBound::Unbounded);
    if add {
        if ws.get(&route.node_key(member))?.is_some() {
            return Err(broken("existing registration identity"));
        }
        h.head = Some(attach(ws, route, h.head, order, range, 0)?);
        h.len = h
            .len
            .checked_add(1)
            .ok_or_else(|| broken("route count overflow"))?;
    } else {
        let n = node(ws, route, member, false)?;
        if n.key != order || n.range != range {
            return Err(broken("reverse registration key mismatch"));
        }
        h.head = detach(ws, route, h.head, order, 0)?;
        h.len = h
            .len
            .checked_sub(1)
            .ok_or_else(|| broken("route count underflow"))?;
    }
    h.bounded = if add {
        h.bounded.checked_add(bounded)
    } else {
        h.bounded.checked_sub(bounded)
    }
    .ok_or_else(|| broken("bounded route count overflow or underflow"))?;
    if h.bounded > h.len {
        return Err(broken("bounded route count exceeds length"));
    }
    ws.put(key.clone(), Some(route.value(h)))
}

/// Bounds are on the read endpoint, not on UUID tie breakers. Original reads
/// traverse original headers *and* original nodes from this transaction snapshot.
pub fn select<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    key: &Key,
    lower: Bound<Endpoint>,
    upper: Bound<Endpoint>,
    original: bool,
) -> Result<Vec<Address>> {
    let route = Route::from_key(key)?;
    let mut stack = vec![];
    if let Some(head) = header(ws, route, original)?.and_then(|h| h.head) {
        stack.push(head);
    }
    let mut found = vec![];
    let mut seen = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            return Err(broken("reverse route traversal cycle"));
        }
        ws.charge("select", 1)?;
        let n = node(ws, route, id, original)?;
        let below = match lower {
            Bound::Included(v) => n.key.endpoint < v,
            Bound::Excluded(v) => n.key.endpoint <= v,
            Bound::Unbounded => false,
        };
        let above = match upper {
            Bound::Included(v) => n.key.endpoint > v,
            Bound::Excluded(v) => n.key.endpoint >= v,
            Bound::Unbounded => false,
        };
        if !below && !above {
            found.push(n.key.member);
        }
        if !below && let Some(left) = n.left {
            stack.push(left);
        }
        if !above && let Some(right) = n.right {
            stack.push(right);
        }
    }
    Ok(found)
}
pub fn collect<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    key: &Key,
    candidates: &mut BTreeSet<Uuid>,
) -> Result<()> {
    for original in [true, false] {
        candidates.extend(
            select(ws, key, Bound::Unbounded, Bound::Unbounded, original)?
                .into_iter()
                .map(|a| a.id),
        );
    }
    Ok(())
}

/// Discover registrations containing one complete timestamp. Both pruning
/// summaries and links come from the selected transaction snapshot.
pub fn stab<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>, B: Binding>(
    ws: &mut Attempt<L, B>,
    key: &Key,
    at: i64,
    original: bool,
) -> Result<Vec<Address>> {
    let route = Route::from_key(key)?;
    let mut stack = vec![];
    if let Some(head) = header(ws, route, original)?.and_then(|h| h.head) {
        stack.push(head);
    }
    let mut found = vec![];
    let mut seen = BTreeSet::new();
    let point = TimeBound::Included(at).lower_cut();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            return Err(broken("reverse route traversal cycle"));
        }
        ws.charge("select", 1)?;
        let n = node(ws, route, id, original)?;
        if n.min_lower.is_none_or(|lower| lower.lower_cut() > point) {
            continue;
        }
        if n.range.contains(at) {
            found.push(n.key.member);
        }
        // Every upper endpoint in the left subtree is <= this endpoint.
        // A through endpoint includes `at`, while a before endpoint does not.
        if n.key.endpoint > Endpoint::Time(at)
            && let Some(left) = n.left
        {
            stack.push(left);
        }
        if let Some(right) = n.right {
            stack.push(right);
        }
    }
    Ok(found)
}
