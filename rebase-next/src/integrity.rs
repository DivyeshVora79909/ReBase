//! Privileged complete-state checks. Expected memberships and scalar results
//! come from source scans; actual tree links/caches are checked independently.
//! No writer, rotation, query traversal or settlement function is called here.
use crate::{
    algebra::Summary,
    binding::{Binding, Calculation, NativeInput},
    index::{IndexCode, NativeIndex, TimeKey},
    indexes::standard::{Aggregate, FINANCIAL, Leaf, QUOTE, QuoteSummary, Standard},
    local::{self, KV, PUBLIC, RECEIPTS},
    local::{ReceiptResult, ReceiptValue, RuntimeHeader, Store},
    model::Visibility,
    native_codec::StoredValue,
    native_codec::{self, Address, Key, Stored},
    native_slice::{Calculated, Derived, Input, Query},
    native_slice::{Error, Result},
    native_slice::{Meta, ModelRecord},
    time_range::{TimeBound, TimeRange},
    tree::{FullKey, Node, Span},
};
use redb::ReadableTable;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub(crate) type Members = BTreeMap<Address, (Address, i64, Leaf)>;
pub(crate) type NativeMembers<I> =
    BTreeMap<Address, (Address, <I as NativeIndex>::Key, <I as NativeIndex>::Leaf)>;
type SourceAggregate<I> = dyn Fn(
    IndexCode,
    &[(<I as NativeIndex>::Key, <I as NativeIndex>::Leaf)],
) -> Result<<I as NativeIndex>::Summary>;
pub(crate) fn require(condition: bool, what: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::new("corrupt_state", what))
    }
}
// Independently enforce the model's bounded population contract; the codec
// only knows the outer runtime envelope, not this binding's declarations.
fn check_populations<B: Binding>(
    model: &crate::model::Prepared<B>,
    counts: &BTreeMap<u16, u16>,
    reservations: u16,
) -> Result<()> {
    let limits = B::limits();
    let mut public = 0u64;
    let mut private = 0u64;
    for (&code, &count) in counts {
        let declaration = model.contract(code)?;
        if declaration.visibility == Visibility::Engine {
            private += u64::from(count);
        } else {
            public += u64::from(count);
        }
        require(
            limits
                .per_contract
                .get(&code)
                .is_none_or(|limit| count <= *limit),
            "declared contract population limit",
        )?;
    }
    require(
        public <= u64::from(limits.public_records)
            && private <= u64::from(limits.outputs)
            && reservations <= limits.reservations,
        "declared model population limits",
    )
}
fn sum(values: impl IntoIterator<Item = i128>) -> Result<i128> {
    values.into_iter().try_fold(0i128, |a, b| {
        a.checked_add(b)
            .ok_or_else(|| Error::new("corrupt_state", "summary arithmetic overflow"))
    })
}
fn aggregate(kind: IndexCode, leaves: &[(TimeKey, Leaf)]) -> Result<Aggregate> {
    let first = leaves.first().map(|v| v.0.get());
    let last = leaves.last().map(|v| v.0.get());
    if kind == QUOTE {
        require(
            leaves
                .iter()
                .all(|(_, leaf)| matches!(leaf, Leaf::Quote(_))),
            "quote source leaves",
        )?;
        return Ok(Aggregate::Quote(QuoteSummary {
            count: leaves.len() as u64,
            first,
            last,
        }));
    }
    require(kind == FINANCIAL, "unknown standard source index")?;
    // Literal record-prefix and complete-time arithmetic; never call the
    // writer's singleton/combine or consume maintained caches for expectations.
    let (mut total, mut min, mut max) = (0i128, 0i128, 0i128);
    let mut boundaries = vec![];
    for (i, (at, leaf)) in leaves.iter().enumerate() {
        let Leaf::Financial(value) = leaf else {
            return Err(local::corrupt("mixed source leaves"));
        };
        total = total
            .checked_add(*value)
            .ok_or_else(|| local::corrupt("source sum overflow"))?;
        min = min.min(total);
        max = max.max(total);
        if i + 1 < leaves.len() && *at != leaves[i + 1].0 {
            boundaries.push(total);
        }
    }
    Ok(Aggregate::Financial(Summary {
        count: leaves.len() as u64,
        first,
        last,
        sum: total,
        min_prefix: min,
        max_prefix: max,
        boundary_min: boundaries.iter().copied().min(),
        boundary_max: boundaries.iter().copied().max(),
    }))
}

// This walker derives exact registration identities and augmentation from source
// queries. Its bound ordering and emptiness oracle are independent of the writer.
fn source_lower_order(bound: TimeBound) -> (i128, bool) {
    match bound {
        TimeBound::Unbounded => (i128::from(i64::MIN) - 1, false),
        TimeBound::Included(at) => (i128::from(at), false),
        TimeBound::Excluded(at) => (i128::from(at), true),
    }
}
fn source_route_order(order: crate::routes::Order) -> ((i128, bool), Address) {
    use crate::routes::Endpoint;
    let endpoint = match order.endpoint {
        Endpoint::Time(at) => (i128::from(at), false),
        Endpoint::Through(at) => (i128::from(at), true),
        Endpoint::All => (i128::from(i64::MAX) + 1, false),
    };
    (endpoint, order.member)
}
fn source_nonempty(range: TimeRange) -> bool {
    let lower = match range.lower {
        TimeBound::Unbounded => i128::from(i64::MIN),
        TimeBound::Included(at) => i128::from(at),
        TimeBound::Excluded(at) => i128::from(at) + 1,
    };
    let upper = match range.upper {
        TimeBound::Unbounded => i128::from(i64::MAX),
        TimeBound::Included(at) => i128::from(at),
        TimeBound::Excluded(at) => i128::from(at) - 1,
    };
    lower <= upper
}
#[derive(Default)]
struct RouteStats {
    height: u16,
    len: u32,
    bounded: u32,
    min_lower: Option<TimeBound>,
}
struct RouteWalk<'a, B: Binding> {
    all: &'a BTreeMap<Key, StoredValue<B>>,
    expected: BTreeMap<Key, (crate::routes::Route, crate::routes::Order, TimeRange)>,
    seen: BTreeSet<Key>,
}
impl<B: Binding> RouteWalk<'_, B> {
    fn visit(
        &mut self,
        route: crate::routes::Route,
        id: Option<Address>,
        lower: Option<crate::routes::Order>,
        upper: Option<crate::routes::Order>,
        depth: u16,
    ) -> Result<RouteStats> {
        let Some(id) = id else {
            return Ok(RouteStats::default());
        };
        require(depth < 64, "selector depth")?;
        let key = route.node_key(id);
        require(self.seen.insert(key.clone()), "selector repeated node")?;
        let Some(StoredValue::RouteNode(n)) = self.all.get(&key) else {
            return Err(local::corrupt("selector dangling link"));
        };
        let expected = self.expected.get(&key).copied();
        require(
            expected == Some((n.route, n.key, n.range)) && n.route == route,
            "selector exact source membership/bound",
        )?;
        let range = expected.expect("required source registration").2;
        require(
            lower.is_none_or(|k| source_route_order(k) < source_route_order(n.key))
                && upper.is_none_or(|k| source_route_order(n.key) < source_route_order(k)),
            "selector order",
        )?;
        let n = n.clone();
        let left = self.visit(route, n.left, lower, Some(n.key), depth + 1)?;
        let right = self.visit(route, n.right, Some(n.key), upper, depth + 1)?;
        require(
            left.height.abs_diff(right.height) <= 1
                && n.height == 1 + left.height.max(right.height),
            "selector balance/height",
        )?;
        let own = source_nonempty(range).then_some(range.lower);
        let min_lower = [own, left.min_lower, right.min_lower]
            .into_iter()
            .flatten()
            .min_by_key(|bound| source_lower_order(*bound));
        require(
            n.min_lower == min_lower,
            "selector exact minimum lower bound",
        )?;
        Ok(RouteStats {
            height: n.height,
            len: 1 + left.len + right.len,
            bounded: u32::from(range.lower != TimeBound::Unbounded) + left.bounded + right.bounded,
            min_lower,
        })
    }
}
fn check_routes<B: Binding>(
    all: &BTreeMap<Key, StoredValue<B>>,
    routes: &BTreeMap<Key, BTreeSet<Address>>,
    queries: &BTreeMap<Address, Query>,
) -> Result<BTreeSet<Key>> {
    use crate::routes::{Endpoint, Order, Route};
    let mut walk = RouteWalk {
        all,
        expected: BTreeMap::new(),
        seen: BTreeSet::new(),
    };
    for (key, addresses) in routes {
        let route = Route::from_key(key)?;
        for &member in addresses {
            let range = if let Route::Subscribers(root) = route {
                let q = queries
                    .get(&member)
                    .ok_or_else(|| local::corrupt("selector lacks expected query"))?;
                require(q.source == root, "selector query root")?;
                q.range
            } else {
                TimeRange::ALL
            };
            let endpoint = match range.upper {
                TimeBound::Included(at) => Endpoint::Through(at),
                TimeBound::Excluded(at) => Endpoint::Time(at),
                TimeBound::Unbounded => Endpoint::All,
            };
            require(
                walk.expected
                    .insert(
                        route.node_key(member),
                        (route, Order { endpoint, member }, range),
                    )
                    .is_none(),
                "duplicate selector identity",
            )?;
        }
    }
    for (key, addresses) in routes {
        let Some(StoredValue::Incoming(h) | StoredValue::Direct(h) | StoredValue::Subscribers(h)) =
            all.get(key)
        else {
            return Err(local::corrupt("missing selector header"));
        };
        let stats = walk.visit(Route::from_key(key)?, h.head, None, None, 0)?;
        require(
            stats.len as usize == addresses.len() && stats.len == h.len,
            "selector complete count",
        )?;
        require(stats.bounded == h.bounded, "selector exact bounded count")?;
    }
    require(
        walk.seen == walk.expected.keys().cloned().collect(),
        "selector disconnected registration",
    )?;
    walk.seen.extend(routes.keys().cloned());
    Ok(walk.seen)
}

struct Walk<'a, I: NativeIndex> {
    nodes: &'a BTreeMap<Address, Node<I>>,
    members: &'a NativeMembers<I>,
    aggregate: &'a SourceAggregate<I>,
    seen: BTreeSet<Address>,
}
impl<I: NativeIndex> Walk<'_, I> {
    fn visit(
        &mut self,
        id: Option<Address>,
        parent: Option<Address>,
        root: Address,
        kind: IndexCode,
        depth: u16,
    ) -> Result<(u16, Vec<Address>)> {
        let Some(id) = id else {
            return Ok((0, vec![]));
        };
        require(depth < 64, "tree path depth")?;
        require(self.seen.insert(id), "tree cycle or duplicate reachability")?;
        let node = self
            .nodes
            .get(&id)
            .ok_or_else(|| Error::new("corrupt_state", "missing linked node"))?;
        require(
            node.parent == parent && node.root == root && node.kind == kind,
            "node parent/root",
        )?;
        let expected = self
            .members
            .get(&id)
            .ok_or_else(|| Error::new("corrupt_state", "extra node"))?;
        require(
            *expected == (root, node.key.value.clone(), node.leaf.clone())
                && node.key.id == id.id
                && node.key.slot == id.slot,
            "source membership",
        )?;
        let (left_height, mut order) = self.visit(node.left, Some(id), root, kind, depth + 1)?;
        order.push(id);
        let (right_height, right) = self.visit(node.right, Some(id), root, kind, depth + 1)?;
        order.extend(right);
        require(
            left_height.abs_diff(right_height) <= 1
                && node.height == 1 + left_height.max(right_height),
            "AVL height/balance",
        )?;
        let leaves: Vec<_> = order
            .iter()
            .map(|id| {
                let (_, at, leaf) = &self.members[id];
                (at.clone(), leaf.clone())
            })
            .collect();
        require(
            node.summary == (self.aggregate)(kind, &leaves)?,
            "exact subtree summary",
        )?;
        require(
            node.span
                == Span {
                    first: leaves.first().unwrap().0.clone(),
                    last: leaves.last().unwrap().0.clone(),
                },
            "exact subtree span",
        )?;
        Ok((node.height, order))
    }
}
/// A complete bounded native snapshot. Model checkers derive semantic expectations
/// from `records`, then finish with the shared structural and authority checker.
pub(crate) struct Snapshot<'a, B: Binding> {
    store: &'a Store<B>,
    pub(crate) read: redb::ReadTransaction,
    pub(crate) meta: Meta,
    pub(crate) header: RuntimeHeader,
    pub(crate) all: BTreeMap<Key, StoredValue<B>>,
    pub(crate) records: BTreeMap<Uuid, ModelRecord<B>>,
    pub(crate) roots: BTreeMap<Address, crate::tree::Root<B::Index>>,
    pub(crate) nodes: BTreeMap<Address, Node<B::Index>>,
    pub(crate) graph: Option<crate::access::PreparedGraph>,
    pub(crate) expected_keys: BTreeSet<Key>,
    pub(crate) routes: BTreeMap<Key, BTreeSet<Address>>,
    public: BTreeMap<Vec<u8>, u16>,
    readers: BTreeMap<Vec<u8>, u16>,
}
impl<'a, B: Binding> Snapshot<'a, B> {
    pub(crate) fn load(store: &'a Store<B>) -> Result<Self> {
        let (read, meta, header) = store.read(store.model().identity())?;
        local::check_tables(&read)?;
        let table = read.open_table(KV).map_err(local::storage)?;
        let mut all = BTreeMap::new();
        for (i, row) in table.iter().map_err(local::storage)?.enumerate() {
            require(
                i < crate::binding::MAX_INVENTORY_ROWS,
                "integrity inventory budget",
            )?;
            let (key, value) = row.map_err(local::storage)?;
            let key = Key::decode(key.value())?;
            all.insert(
                key.clone(),
                native_codec::decode_for::<B>(&key, value.value())?,
            );
        }
        let records: BTreeMap<_, _> = all
            .iter()
            .filter_map(|(k, v)| match (k, v) {
                (Key::Record(id), StoredValue::Record(r)) => Some((*id, r.clone())),
                _ => None,
            })
            .collect();
        require(
            records.len() <= crate::binding::MAX_NATIVE_RECORDS,
            "integrity record budget",
        )?;
        let roots: BTreeMap<_, _> = all
            .iter()
            .filter_map(|(k, v)| match (k, v) {
                (Key::Root(id), StoredValue::Root(r)) => Some((*id, r.clone())),
                _ => None,
            })
            .collect();
        let nodes: BTreeMap<_, _> = all
            .iter()
            .filter_map(|(k, v)| match (k, v) {
                (Key::Node(id), StoredValue::Node(n)) => Some((*id, n.clone())),
                _ => None,
            })
            .collect();
        let graph = if store.secured {
            let auth = read
                .open_table(crate::security::AUTHORITY)
                .map_err(local::storage)?;
            let bytes = auth
                .get(b"graph".as_slice())
                .map_err(local::storage)?
                .ok_or_else(|| local::corrupt("missing graph"))?;
            let graph: crate::access::Graph = local::decode(bytes.value())?;
            let graph = graph.prepare()?;
            require(graph.graph.tenant == meta.tenant, "graph tenant")?;
            require(
                graph.scopes.contains_key(&meta.actor),
                "bootstrap principal identity",
            )?;
            let mut expected = BTreeMap::from([(b"graph".to_vec(), local::encode(&graph.graph)?)]);
            for (actor, scope) in &graph.scopes {
                let mut key = vec![b's'];
                key.extend_from_slice(actor.as_bytes());
                expected.insert(key, local::encode(scope)?);
            }
            let mut actual = BTreeMap::new();
            for row in auth.iter().map_err(local::storage)? {
                let (k, v) = row.map_err(local::storage)?;
                actual.insert(k.value().to_vec(), v.value().to_vec());
            }
            require(actual == expected, "exact authority scope inventory")?;
            Some(graph)
        } else {
            None
        };

        let mut counts: BTreeMap<_, u16> = store.model().contracts().map(|c| (c.code, 0)).collect();
        let mut public = BTreeMap::new();
        let mut readers = BTreeMap::new();
        let mut expected_keys = BTreeSet::from([Key::Meta]);
        let mut routes = BTreeMap::<Key, BTreeSet<Address>>::new();
        for (&id, r) in &records {
            require(
                r.contract == r.input.contract()
                    && r.tenant == meta.tenant
                    && r.version > 0
                    && r.version <= meta.revision,
                "record header",
            )?;
            store.model().validate(
                r.contract,
                &serde_json::to_value(&r.input).map_err(local::storage)?,
            )?;
            *counts.entry(r.contract).or_insert(0u16) += 1;
            expected_keys.insert(Key::Record(id));
            let contract = store.model().contract(r.contract)?;
            for (key, _) in crate::binding::headers(store.model(), id, &r.input, meta.revision)? {
                match key {
                    Key::Incoming(_) | Key::Direct(_) | Key::Subscribers(_) => {
                        routes.entry(key).or_default();
                    }
                    _ => {
                        expected_keys.insert(key);
                    }
                }
            }
            if contract.visibility == Visibility::Public {
                public.insert(id.as_bytes().to_vec(), r.contract);
                readers.insert(
                    crate::security::reader_key(r.reader, r.contract, id),
                    r.contract,
                );
            }
            for (target, _, slot) in r.input.references() {
                let target_record = records
                    .get(&target)
                    .ok_or_else(|| local::corrupt("missing reference"))?;
                let declaration = contract
                    .references
                    .iter()
                    .find(|r| r.slot == slot)
                    .ok_or_else(|| local::corrupt("undeclared reference"))?;
                require(
                    declaration.targets.contains(&target_record.contract),
                    "reference contract",
                )?;
                routes
                    .entry(Key::Incoming(target))
                    .or_default()
                    .insert(Address::new(id, slot));
            }
            if let Some(graph) = &graph {
                require(graph.scopes.contains_key(&r.owner), "principal owner")?;
                let expected = if let Some((producer, _)) = r.input.managed() {
                    records
                        .get(&producer)
                        .ok_or_else(|| local::corrupt("missing producer"))?
                        .reader
                } else {
                    let owners: Vec<_> = r
                        .input
                        .references()
                        .iter()
                        .filter(|(_, _, slot)| {
                            contract
                                .references
                                .iter()
                                .any(|r| r.slot == *slot && r.reader)
                        })
                        .map(|(target, _, _)| records[target].owner)
                        .collect();
                    graph.reader(&owners, r.owner)
                };
                require(r.reader == expected, "declared reader")?;
            } else {
                require(
                    r.owner == meta.actor && r.reader == meta.actor,
                    "local owner/reader",
                )?;
            }
        }
        let bindings: BTreeMap<_, _> = all
            .iter()
            .filter_map(|(key, value)| match (key, value) {
                (Key::Role(role), StoredValue::Role(binding)) => Some((*role, *binding)),
                _ => None,
            })
            .collect();
        let reserved: BTreeMap<_, _> = all
            .iter()
            .filter_map(|(key, value)| match (key, value) {
                (Key::Reserved(id), StoredValue::Reserved(role)) => Some((*id, *role)),
                _ => None,
            })
            .collect();
        require(
            bindings.len() == reserved.len() && bindings.len() == usize::from(meta.reserved),
            "reservation population",
        )?;
        for (role, binding) in &bindings {
            require(
                reserved.get(&binding.output) == Some(role),
                "reservation inverse",
            )?;
            require(
                !bindings.keys().any(|r| r.id == binding.output),
                "producer/output identity separation",
            )?;
            require(
                binding.retired != records.contains_key(&role.id),
                "retired producer lifecycle",
            )?;
            if let Some(producer) = records.get(&role.id) {
                let declaration = store
                    .model()
                    .contract(producer.contract)?
                    .outputs
                    .iter()
                    .find(|r| r.role == role.slot)
                    .ok_or_else(|| local::corrupt("undeclared output role"))?;
                if let Some(output) = records.get(&binding.output) {
                    require(
                        output.contract == declaration.contract
                            && output.input.managed() == Some((role.id, role.slot))
                            && output.owner == producer.owner
                            && output.reader == producer.reader,
                        "managed output provenance/authority",
                    )?;
                }
            } else {
                require(
                    !records.contains_key(&binding.output),
                    "retired output remains",
                )?;
                require(
                    store
                        .model()
                        .contracts()
                        .any(|c| c.outputs.iter().any(|r| r.role == role.slot)),
                    "undeclared retired role",
                )?;
            }
            expected_keys.insert(Key::Role(*role));
            expected_keys.insert(Key::Reserved(binding.output));
        }
        for (&id, record) in &records {
            if let Some((producer, slot)) = record.input.managed() {
                require(
                    bindings
                        .get(&Address::new(producer, slot))
                        .is_some_and(|b| !b.retired && b.output == id),
                    "unbound managed output",
                )?;
            }
        }
        require(counts == meta.counts, "record population")?;
        check_populations(store.model(), &counts, meta.reserved)?;
        Ok(Self {
            store,
            read,
            meta,
            header,
            all,
            records,
            roots,
            nodes,
            graph,
            expected_keys,
            routes,
            public,
            readers,
        })
    }
    pub(crate) fn finish(
        &self,
        expected_keys: BTreeSet<Key>,
        members: Members,
        routes: BTreeMap<Key, BTreeSet<Address>>,
        queries: BTreeMap<Address, Query>,
    ) -> Result<Value>
    where
        B: Binding<Index = Standard>,
    {
        for (address, root) in &self.roots {
            let owner = self
                .records
                .get(&address.id)
                .ok_or_else(|| local::corrupt("root owner missing"))?;
            let declaration = self
                .store
                .model()
                .contract(owner.contract)?
                .roots
                .iter()
                .find(|r| r.slot == address.slot)
                .ok_or_else(|| local::corrupt("undeclared root"))?;
            if declaration.invariant == Some("nonnegative complete-time prefixes") {
                let Aggregate::Financial(summary) = root.summary else {
                    return Err(local::corrupt("account kind"));
                };
                require(summary.complete_min() >= 0, "historical account floor")?;
            }
        }
        let members = members
            .into_iter()
            .map(|(id, (root, at, leaf))| (id, (root, TimeKey::new(at), leaf)))
            .collect();
        self.finish_native(expected_keys, members, routes, queries, &aggregate)
    }
    pub(crate) fn finish_native(
        &self,
        mut expected_keys: BTreeSet<Key>,
        members: NativeMembers<B::Index>,
        routes: BTreeMap<Key, BTreeSet<Address>>,
        queries: BTreeMap<Address, Query>,
        aggregate: &SourceAggregate<B::Index>,
    ) -> Result<Value> {
        let Self {
            store,
            read,
            meta,
            header,
            all,
            records,
            roots,
            nodes,
            graph,
            public,
            readers,
            ..
        } = self;
        expected_keys.extend(check_routes(all, &routes, &queries)?);
        for (id, query) in queries {
            let key = Key::Query(id);
            require(
                all.get(&key) == Some(&StoredValue::Query(query)),
                "exact ordered query",
            )?;
            expected_keys.insert(key);
        }
        require(nodes.len() == members.len(), "node inventory size")?;
        let mut walk = Walk {
            nodes,
            members: &members,
            aggregate,
            seen: BTreeSet::new(),
        };
        for (&address, root) in roots {
            require(
                expected_keys.contains(&Key::Root(address)) && root.revision <= meta.revision,
                "root inventory/version",
            )?;
            let owner = records
                .get(&address.id)
                .ok_or_else(|| local::corrupt("root owner missing"))?;
            let declaration = store
                .model()
                .contract(owner.contract)?
                .roots
                .iter()
                .find(|r| r.slot == address.slot)
                .ok_or_else(|| local::corrupt("undeclared root"))?;
            require(root.kind == declaration.kind, "root kind")?;
            let (height, order) = walk.visit(root.head, None, address, root.kind, 0)?;
            require(
                root.height == height
                    && root.first == order.first().copied()
                    && root.last == order.last().copied(),
                "root links/height",
            )?;
            let mut previous = None;
            for (i, id) in order.iter().enumerate() {
                let n = &nodes[id];
                require(
                    n.prev == i.checked_sub(1).map(|i| order[i])
                        && n.next == order.get(i + 1).copied(),
                    "neighbour links",
                )?;
                require(
                    previous.is_none_or(|p: &FullKey<_>| p < &n.key),
                    "tree order",
                )?;
                previous = Some(&n.key);
            }
            let leaves: Vec<_> = order
                .iter()
                .map(|id| {
                    let (_, at, leaf) = &members[id];
                    (at.clone(), leaf.clone())
                })
                .collect();
            require(
                root.summary == aggregate(root.kind, &leaves)?,
                "root summary",
            )?;
            let span = leaves.first().zip(leaves.last()).map(|(first, last)| Span {
                first: first.0.clone(),
                last: last.0.clone(),
            });
            require(root.span == span, "exact root span")?;
        }
        require(
            walk.seen == members.keys().copied().collect(),
            "disconnected membership",
        )?;
        expected_keys.extend(members.keys().map(|id| Key::Node(*id)));
        require(
            expected_keys == all.keys().cloned().collect(),
            "complete native inventory",
        )?;

        let index = read.open_table(PUBLIC).map_err(local::storage)?;
        let actual = index
            .iter()
            .map_err(local::storage)?
            .map(|r| {
                r.map(|(k, v)| (k.value().to_vec(), v.value()))
                    .map_err(local::storage)
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        require(actual == *public, "public identity index")?;
        if store.secured {
            let index = read
                .open_table(crate::security::READERS)
                .map_err(local::storage)?;
            let actual = index
                .iter()
                .map_err(local::storage)?
                .map(|r| {
                    r.map(|(k, v)| (k.value().to_vec(), v.value()))
                        .map_err(local::storage)
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            require(actual == *readers, "reader index inventory")?;
        }
        let receipts = read.open_table(RECEIPTS).map_err(local::storage)?;
        let effects =
            crate::effects::check(read, store.model(), meta, header, records, store.secured)?;
        let mut receipt_count = 0;
        for row in receipts.iter().map_err(local::storage)? {
            let (k, v) = row.map_err(local::storage)?;
            let r: ReceiptValue<B> = local::decode(v.value())?;
            receipt_count += 1;
            crate::security::check_operation_context(
                &r.context,
                header,
                crate::native_slice::Context {
                    tenant: meta.tenant,
                    actor: r.actor,
                },
                &meta.model,
            )?;
            require(
                graph
                    .as_ref()
                    .map_or(r.actor == meta.actor, |g| g.scopes.contains_key(&r.actor)),
                "receipt actor identity",
            )?;
            require(r.kind == r.result.kind(), "receipt kind/result")?;
            crate::effects::check_receipt(read, &r, header)?;
            if let ReceiptResult::Records(result) = &r.result {
                require(
                    result.records.len() <= 32
                        && result
                            .records
                            .iter()
                            .map(|r| r.id)
                            .collect::<BTreeSet<_>>()
                            .len()
                            == result.records.len(),
                    "receipt return inventory",
                )?;
                for returned in &result.records {
                    if let Some(record) = &returned.record {
                        require(
                            record.id == returned.id
                                && record.version > 0
                                && record.version <= result.revision,
                            "receipt record binding/version",
                        )?;
                        let contract = store.model.public_contract(record.contract)?;
                        store.model.validate(
                            record.contract,
                            &serde_json::to_value(&record.input).map_err(local::storage)?,
                        )?;
                        let expected: BTreeSet<_> =
                            contract.published.iter().map(|f| f.name).collect();
                        let actual: BTreeSet<_> = record
                            .derived
                            .as_ref()
                            .and_then(Value::as_object)
                            .map(|m| m.keys().map(String::as_str).collect())
                            .unwrap_or_default();
                        require(
                            expected == actual && (record.derived.is_none() == expected.is_empty()),
                            "receipt public projection fields",
                        )?;
                    }
                }
            }
            let expected = if store.secured {
                [
                    r.actor.as_bytes().as_slice(),
                    r.result.operation_id().as_bytes().as_slice(),
                ]
                .concat()
            } else {
                r.result.operation_id().as_bytes().to_vec()
            };
            require(
                k.value() == expected
                    && r.model == meta.model
                    && r.tenant == meta.tenant
                    && r.result.revision() > 0
                    && r.result.revision() <= meta.revision
                    && r.request_hash.len() == 64
                    && local::unhex(&r.request_hash).is_ok(),
                "receipt scope/shape",
            )?;
        }
        require(receipt_count == header.receipts, "receipt population")?;
        Ok(
            json!({"status":"valid","scope":"complete current state, indexes, links, calculations and receipt structure; not historical receipt truth",
            "store":header.store_id,"model":meta.model,"revision":meta.revision.to_string(),"records":records.len(),"roots":roots.len(),"nodes":nodes.len(),"rows":all.len(),"receipts":receipt_count,"effects":effects}),
        )
    }
}
pub(crate) fn check_calculation(store: &Store<Calculation>) -> Result<Value> {
    let snapshot = Snapshot::load(store)?;
    let all = &snapshot.all;
    let records = &snapshot.records;
    let meta = &snapshot.meta;
    let mut expected_keys = snapshot.expected_keys.clone();
    let mut members = Members::new();
    let mut routes = snapshot.routes.clone();
    let mut queries = BTreeMap::<Address, Query>::new();
    let mut causal_reads = BTreeMap::<Uuid, Vec<(Uuid, Option<i64>)>>::new();
    let mut emits = BTreeMap::<Address, (Uuid, i64, i128)>::new();
    let mut quote_times = BTreeSet::new();
    for (&id, r) in records {
        match &r.input {
            Input::Quote { curve, at, rate } => {
                require(quote_times.insert((*curve, *at)), "unique quote time")?;
                members.insert(
                    Address::new(id, 3),
                    (Address::new(*curve, 1), *at, Leaf::Quote(*rate)),
                );
            }
            Input::Entry {
                account,
                at,
                amount,
            }
            | Input::Output {
                account,
                at,
                amount,
                ..
            } => {
                members.insert(
                    Address::new(id, 1),
                    (Address::new(*account, 2), *at, Leaf::Financial(*amount)),
                );
            }
            Input::Posting {
                units,
                at,
                rule,
                curve,
                account,
                subsidiary,
            } => {
                let Input::Rule { c } = records[rule].input else {
                    return Err(local::corrupt("rule type"));
                };
                let Input::Curve {
                    native_unit,
                    reporting_unit,
                } = records[curve].input
                else {
                    return Err(local::corrupt("curve type"));
                };
                require(
                    records[account].input == Input::Account { native_unit }
                        && records[subsidiary].input == Input::Subsidiary { reporting_unit },
                    "posting unit compatibility",
                )?;
                let selected = records
                    .iter()
                    .filter_map(|(&qid, q)| match q.input {
                        Input::Quote {
                            curve: c,
                            at: q_at,
                            rate,
                        } if c == *curve && q_at <= *at => Some((q_at, qid, rate)),
                        _ => None,
                    })
                    .max_by_key(|v| v.0);
                let native = units
                    .checked_mul(i128::from(c))
                    .ok_or_else(|| local::corrupt("native overflow"))?;
                let reporting = native
                    .checked_mul(i128::from(selected.map_or(1, |v| v.2)))
                    .ok_or_else(|| local::corrupt("reporting overflow"))?;
                require(
                    r.derived
                        == Some(Calculated::Posting(Derived {
                            native_minor: native,
                            reporting_minor: reporting,
                        })),
                    "posting calculation",
                )?;
                members.insert(
                    Address::new(id, 1),
                    (Address::new(*account, 2), *at, Leaf::Financial(native)),
                );
                members.insert(
                    Address::new(id, 2),
                    (
                        Address::new(*subsidiary, 3),
                        *at,
                        Leaf::Financial(reporting),
                    ),
                );
                queries.insert(
                    Address::new(id, 1),
                    Query {
                        source: Address::new(*curve, 1),
                        operation: "latest".into(),
                        phase: "calculate".into(),
                        channel: "rate".into(),
                        range: TimeRange::through(*at),
                        selected: selected.map(|v| v.1),
                        result: i128::from(selected.map_or(1, |v| v.2)),
                    },
                );
                routes
                    .entry(Key::Direct(*rule))
                    .or_default()
                    .insert(Address::new(id, 7));
                routes
                    .entry(Key::Subscribers(Address::new(*curve, 1)))
                    .or_default()
                    .insert(Address::new(id, 1));
            }
            _ => {}
        }
        if !matches!(
            r.input,
            Input::Posting { .. } | Input::Adjustment { .. } | Input::Basis { .. }
        ) {
            require(r.derived.is_none(), "unexpected derived value")?;
        }
    }
    let account_sum = |account: Uuid, before: Option<i64>| -> Result<i128> {
        sum(members.values().filter_map(|(root, at, leaf)| match leaf {
            Leaf::Financial(amount)
                if *root == Address::new(account, 2) && before.is_none_or(|t| *at < t) =>
            {
                Some(*amount)
            }
            _ => None,
        }))
    };
    for (&id, r) in records {
        match &r.input {
            Input::Adjustment {
                account,
                moment,
                offset,
                target,
                post,
            } => {
                let Input::Moment { at } = records[moment].input else {
                    return Err(local::corrupt("moment type"));
                };
                let at = at
                    .checked_add(*offset)
                    .ok_or_else(|| local::corrupt("adjustment time overflow"))?;
                let before = account_sum(*account, Some(at))?;
                let delta = target
                    .checked_sub(before)
                    .ok_or_else(|| local::corrupt("delta overflow"))?;
                require(
                    r.derived == Some(Calculated::Adjustment { at, before, delta }) && before >= 0,
                    "adjustment calculation/invariant",
                )?;
                causal_reads.insert(id, vec![(*account, Some(at))]);
                if *post {
                    emits.insert(Address::new(id, 1), (*account, at, delta));
                }
                routes
                    .entry(Key::Direct(*moment))
                    .or_default()
                    .insert(Address::new(id, 6));
                for slot in [1, 2] {
                    let query = Address::new(id, slot);
                    routes
                        .entry(Key::Subscribers(Address::new(*account, 2)))
                        .or_default()
                        .insert(query);
                    queries.insert(
                        query,
                        Query {
                            source: Address::new(*account, 2),
                            operation: "sum".into(),
                            phase: if slot == 1 { "calculate" } else { "validate" }.into(),
                            channel: "amount".into(),
                            range: TimeRange::before(at),
                            selected: None,
                            result: before,
                        },
                    );
                }
            }
            Input::Basis {
                sources,
                factor,
                account,
                at,
                feedback,
            } => {
                let unit = &records[account].input;
                require(
                    sources
                        .iter()
                        .chain(feedback.iter().map(|f| &f.account))
                        .all(|id| &records[id].input == unit),
                    "basis unit compatibility",
                )?;
                let value = sum(sources
                    .iter()
                    .map(|source| account_sum(*source, None))
                    .collect::<Result<Vec<_>>>()?)?
                .checked_mul(i128::from(*factor))
                .ok_or_else(|| local::corrupt("basis overflow"))?;
                require(
                    r.derived == Some(Calculated::Basis { value }),
                    "basis calculation",
                )?;
                causal_reads.insert(id, sources.iter().map(|s| (*s, None)).collect());
                emits.insert(Address::new(id, 1), (*account, *at, value));
                if let Some(f) = feedback {
                    emits.insert(Address::new(id, 2), (f.account, f.at, 0));
                }
                for (i, &source) in sources.iter().enumerate() {
                    let q = Address::new(id, i as u16 + 1);
                    routes
                        .entry(Key::Subscribers(Address::new(source, 2)))
                        .or_default()
                        .insert(q);
                    queries.insert(
                        q,
                        Query {
                            source: Address::new(source, 2),
                            operation: "sum".into(),
                            phase: "calculate".into(),
                            channel: "amount".into(),
                            range: TimeRange::ALL,
                            selected: None,
                            result: account_sum(source, None)?,
                        },
                    );
                }
            }
            _ => {}
        }
    }
    // Complete expected final dependency edges, including zero contributions.
    let mut pending: BTreeMap<_, usize> = causal_reads.keys().map(|id| (*id, 0)).collect();
    let mut edges = BTreeMap::<Uuid, BTreeSet<Uuid>>::new();
    for (&consumer, reads) in &causal_reads {
        for (role, (account, at, _)) in &emits {
            if reads
                .iter()
                .any(|(r, b)| r == account && b.is_none_or(|bound| *at < bound))
                && edges.entry(role.id).or_default().insert(consumer)
            {
                *pending.get_mut(&consumer).unwrap() += 1;
            }
        }
    }
    let mut ready: BTreeSet<_> = pending
        .iter()
        .filter(|(_, v)| **v == 0)
        .map(|(id, _)| *id)
        .collect();
    let mut evaluated = 0;
    while let Some(id) = ready.pop_first() {
        evaluated += 1;
        for consumer in edges.get(&id).into_iter().flatten() {
            let p = pending.get_mut(consumer).unwrap();
            *p -= 1;
            if *p == 0 {
                ready.insert(*consumer);
            }
        }
    }
    require(evaluated == pending.len(), "final causal cycle")?;
    let mut bindings = BTreeMap::new();
    let mut reserved = BTreeMap::new();
    for (key, value) in all {
        match (key, value) {
            (Key::Role(role), Stored::Role(binding)) => {
                bindings.insert(*role, *binding);
            }
            (Key::Reserved(id), Stored::Reserved(role)) => {
                reserved.insert(*id, *role);
            }
            _ => {}
        }
    }
    require(
        bindings.len() == reserved.len() && bindings.len() == usize::from(meta.reserved),
        "reservation population",
    )?;
    require(
        reserved
            .keys()
            .all(|id| !bindings.keys().any(|role| role.id == *id)),
        "producer/output identity separation",
    )?;
    let mut outputs = BTreeSet::new();
    for (role, binding) in &bindings {
        require(
            matches!(role.slot, 1 | 2) && reserved.get(&binding.output) == Some(role),
            "reservation inverse",
        )?;
        require(
            binding.retired != records.contains_key(&role.id),
            "retired producer lifecycle",
        )?;
        if !binding.retired {
            require(
                records[&role.id].contract == 10
                    || records[&role.id].contract == 9 && role.slot == 1,
                "producer contract",
            )?;
        }
        if let Some(&(account, at, amount)) = emits.get(role) {
            let r = records
                .get(&binding.output)
                .ok_or_else(|| local::corrupt("missing managed output"))?;
            let producer = &records[&role.id];
            require(
                r.input
                    == Input::Output {
                        producer: role.id,
                        role: role.slot,
                        account,
                        at,
                        amount,
                    }
                    && r.owner == producer.owner
                    && r.reader == producer.reader,
                "managed output shape/authority",
            )?;
            outputs.insert(binding.output);
        } else {
            require(
                !records.contains_key(&binding.output),
                "inactive output remains",
            )?;
        }
        expected_keys.insert(Key::Role(*role));
        expected_keys.insert(Key::Reserved(binding.output));
    }
    require(
        emits.keys().all(|role| bindings.contains_key(role)),
        "unbound required output",
    )?;
    require(
        records
            .iter()
            .filter(|(_, r)| r.contract == 12)
            .map(|(id, _)| *id)
            .collect::<BTreeSet<_>>()
            == outputs,
        "complete output inventory",
    )?;
    snapshot.finish(expected_keys, members, routes, queries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalStore;
    use redb::ReadableDatabase;
    use std::sync::Arc;
    #[test]
    fn canonical_orphan_root_returns_corruption_at_check_startup_and_restore() {
        use crate::{
            identity::IdentityConfig,
            native_slice::Context,
            server::{self, ServerConfig},
            tree::Root,
        };
        use sha2::{Digest, Sha256};

        let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/integrity-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&directory).unwrap();
        let model = Arc::new(crate::model::PreparedModel::load().unwrap());
        let store = Arc::new(
            LocalStore::create_secured(
                directory.join("orphan.redb"),
                model.clone(),
                Context {
                    tenant: Uuid::from_u128(1),
                    actor: Uuid::from_u128(2),
                },
            )
            .unwrap(),
        );
        store.check_integrity().unwrap();
        let backup = directory.join("valid.json");
        store.backup(&backup).unwrap();

        // The row itself is canonical and well typed. Only the complete
        // source inventory establishes that its owner does not exist.
        let key = Key::Root(Address::new(Uuid::from_u128(1000), 2));
        let value = native_codec::encode(
            &key,
            &Stored::Root(Root::<Standard>::empty(FINANCIAL, 0).unwrap()),
        )
        .unwrap();
        let write = store.db.begin_write().unwrap();
        write
            .open_table(KV)
            .unwrap()
            .insert(key.encode().as_slice(), value.as_slice())
            .unwrap();
        write.commit().unwrap();
        let before = store.observe_for_verification().unwrap();
        let error = store.check_integrity().unwrap_err();
        assert_eq!(error.code, "corrupt_state");
        assert_eq!(error.detail, "root owner missing");
        let config = ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            identity: IdentityConfig {
                issuer: "integrity-test".into(),
                audience: "rebase-test".into(),
                public_keys: [(
                    "test".into(),
                    include_str!("../tests/fixtures/test-ed25519-public.pem").into(),
                )]
                .into(),
                max_token_seconds: 600,
            },
            max_inflight: 1,
            request_timeout_seconds: 5,
            effects: None,
        };
        assert_eq!(
            server::router(store.clone(), &config).unwrap_err().code,
            "corrupt_state"
        );
        assert_eq!(store.observe_for_verification().unwrap(), before);

        let mut image: Value = serde_json::from_slice(&std::fs::read(backup).unwrap()).unwrap();
        image["payload"]["tables"]["native_kv"]
            .as_array_mut()
            .unwrap()
            .push(
                json!({"key":native_codec::hex(&key.encode()),"value":native_codec::hex(&value)}),
            );
        image["sha256"] = json!(native_codec::hex(&Sha256::digest(
            local::encode(&image["payload"]).unwrap()
        )));
        let invalid_backup = directory.join("orphan.json");
        std::fs::write(&invalid_backup, serde_json::to_vec(&image).unwrap()).unwrap();
        let destination = directory.join("rejected.redb");
        assert_eq!(
            crate::lifecycle::restore(&invalid_backup, &destination, model)
                .unwrap_err()
                .code,
            "corrupt_state"
        );
        assert!(!destination.exists());
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn corrupt_data_chain_is_rejected_before_unbounded_recursion() {
        let root = Address::new(Uuid::from_u128(1000), 7);
        let ids: Vec<_> = (1..=256)
            .map(|n| Address::new(Uuid::from_u128(n), 17))
            .collect();
        let mut nodes = BTreeMap::new();
        let mut members = BTreeMap::new();
        for (i, &id) in ids.iter().enumerate() {
            let at = i as i64;
            let leaf = Leaf::Financial(1);
            members.insert(id, (root, TimeKey::new(at), leaf));
            nodes.insert(
                id,
                Node::<Standard> {
                    kind: FINANCIAL,
                    span: Span {
                        first: TimeKey::new(at),
                        last: TimeKey::new(at),
                    },
                    root,
                    key: FullKey {
                        value: TimeKey::new(at),
                        id: id.id,
                        slot: id.slot,
                    },
                    leaf,
                    parent: i.checked_sub(1).map(|p| ids[p]),
                    left: None,
                    right: ids.get(i + 1).copied(),
                    prev: i.checked_sub(1).map(|p| ids[p]),
                    next: ids.get(i + 1).copied(),
                    height: 1,
                    summary: Aggregate::Financial(Summary::leaf(at, Some(1))),
                },
            );
        }
        let mut walk = Walk {
            nodes: &nodes,
            members: &members,
            aggregate: &aggregate,
            seen: BTreeSet::new(),
        };
        let error = walk
            .visit(Some(ids[0]), None, root, FINANCIAL, 0)
            .unwrap_err();
        assert_eq!(error.code, "corrupt_state");
        assert_eq!(error.detail, "tree path depth");
        assert_eq!(walk.seen.len(), 64);
    }
    #[test]
    fn model_population_limits_are_checked_inside_codec_envelope() {
        use crate::{model::Prepared, models::equipment::Equipment};
        let equipment = Prepared::<Equipment>::load().unwrap();
        let limits = Equipment::limits();
        // Per-model limits remain checked independently of codec decoding.
        assert!(
            check_populations(
                &equipment,
                &BTreeMap::from([(101, limits.public_records)]),
                0
            )
            .is_ok()
        );
        assert!(
            check_populations(
                &equipment,
                &BTreeMap::from([(101, limits.public_records + 1)]),
                0
            )
            .is_err()
        );
        assert!(
            check_populations(
                &equipment,
                &BTreeMap::from([(900, limits.outputs)]),
                limits.reservations
            )
            .is_ok()
        );
        assert!(
            check_populations(
                &equipment,
                &BTreeMap::from([(900, limits.outputs + 1)]),
                limits.reservations
            )
            .is_err()
        );
        assert!(check_populations(&equipment, &BTreeMap::new(), limits.reservations + 1).is_err());
        let calculation = Prepared::<Calculation>::load().unwrap();
        let limit = Calculation::limits().per_contract[&3];
        assert!(check_populations(&calculation, &BTreeMap::from([(3, limit)]), 0).is_ok());
        assert!(check_populations(&calculation, &BTreeMap::from([(3, limit + 1)]), 0).is_err());
    }
    #[test]
    fn selector_checker_rejects_wrong_order_imbalance_and_disconnected_nodes() {
        use crate::routes::{Endpoint, Header, Order, Route};
        let root = Address::new(Uuid::from_u128(100), 2);
        let route = Route::Subscribers(root);
        let ids: Vec<_> = (1..=4)
            .map(|id| Address::new(Uuid::from_u128(id), 1))
            .collect();
        let bounds = [
            TimeRange::before(i64::MIN),
            TimeRange::through(0),
            TimeRange::before(i64::MAX),
            TimeRange::ALL,
        ];
        let queries: BTreeMap<_, _> = ids
            .iter()
            .zip(bounds.iter().cloned())
            .map(|(&id, range)| {
                (
                    id,
                    Query {
                        source: root,
                        operation: "sum".into(),
                        phase: "calculate".into(),
                        channel: "amount".into(),
                        range,
                        selected: None,
                        result: 0,
                    },
                )
            })
            .collect();
        let routes = BTreeMap::from([(route.key(), ids.iter().copied().collect())]);
        let mut all = BTreeMap::<Key, Stored>::new();
        for (i, &member) in ids.iter().enumerate() {
            let endpoint = match bounds[i].upper {
                TimeBound::Excluded(t) => Endpoint::Time(t),
                TimeBound::Included(t) => Endpoint::Through(t),
                TimeBound::Unbounded => Endpoint::All,
            };
            all.insert(
                route.node_key(member),
                Stored::RouteNode(crate::routes::Node {
                    route,
                    key: Order { endpoint, member },
                    range: bounds[i],
                    min_lower: if i == 0 {
                        None
                    } else {
                        Some(TimeBound::Unbounded)
                    },
                    left: None,
                    right: None,
                    height: 1,
                }),
            );
        }
        let configure = |all: &mut BTreeMap<Key, Stored>,
                         head: usize,
                         links: &[(Option<usize>, Option<usize>, u16)]| {
            all.insert(
                route.key(),
                Stored::Subscribers(Header {
                    head: Some(ids[head]),
                    len: 4,
                    bounded: 0,
                }),
            );
            for (i, &(left, right, height)) in links.iter().enumerate() {
                let Some(Stored::RouteNode(n)) = all.get_mut(&route.node_key(ids[i])) else {
                    unreachable!()
                };
                n.left = left.map(|i| ids[i]);
                n.right = right.map(|i| ids[i]);
                n.height = height;
            }
        };
        configure(
            &mut all,
            2,
            &[
                (None, None, 1),
                (Some(0), None, 2),
                (Some(1), Some(3), 3),
                (None, None, 1),
            ],
        );
        check_routes(&all, &routes, &queries).unwrap();
        configure(
            &mut all,
            1,
            &[
                (None, None, 1),
                (Some(0), Some(2), 3),
                (None, Some(3), 2),
                (None, None, 1),
            ],
        );
        check_routes(&all, &routes, &queries).unwrap();
        let valid = all.clone();
        configure(
            &mut all,
            1,
            &[
                (None, None, 1),
                (Some(2), Some(0), 3),
                (None, Some(3), 2),
                (None, None, 1),
            ],
        );
        assert_eq!(
            check_routes(&all, &routes, &queries).unwrap_err().detail,
            "selector order"
        );
        all = valid.clone();
        // All cached heights and ordering are exact, but this chain is not AVL.
        configure(
            &mut all,
            3,
            &[
                (None, None, 1),
                (Some(0), None, 2),
                (Some(1), None, 3),
                (Some(2), None, 4),
            ],
        );
        assert_eq!(
            check_routes(&all, &routes, &queries).unwrap_err().detail,
            "selector balance/height"
        );
        all = valid;
        configure(
            &mut all,
            1,
            &[
                (None, None, 1),
                (Some(0), None, 2),
                (None, Some(3), 2),
                (None, None, 1),
            ],
        );
        assert_eq!(
            check_routes(&all, &routes, &queries).unwrap_err().detail,
            "selector complete count"
        );
    }
    #[test]
    fn selector_checker_recomputes_empty_identity_minimum_and_bounded_count_from_sources() {
        use crate::routes::{Endpoint, Header, Order, Route};
        use TimeBound::{Excluded, Included, Unbounded};
        let root = Address::new(Uuid::from_u128(100), 2);
        let route = Route::Subscribers(root);
        let member = Address::new(Uuid::from_u128(1), 7);
        let cases = [
            (TimeRange::ALL, Some(Unbounded), 0),
            (TimeRange::before(i64::MIN), None, 0),
            (TimeRange::through(i64::MIN), Some(Unbounded), 0),
            (
                TimeRange {
                    lower: Excluded(i64::MAX),
                    upper: Unbounded,
                },
                None,
                1,
            ),
            (
                TimeRange {
                    lower: Excluded(0),
                    upper: Excluded(1),
                },
                None,
                1,
            ),
            (
                TimeRange {
                    lower: Included(0),
                    upper: Excluded(0),
                },
                None,
                1,
            ),
            (
                TimeRange {
                    lower: Excluded(0),
                    upper: Included(0),
                },
                None,
                1,
            ),
            (
                TimeRange {
                    lower: Included(0),
                    upper: Included(0),
                },
                Some(Included(0)),
                1,
            ),
            (
                TimeRange {
                    lower: Excluded(0),
                    upper: Included(1),
                },
                Some(Excluded(0)),
                1,
            ),
        ];
        let routes = BTreeMap::from([(route.key(), BTreeSet::from([member]))]);
        for (range, min_lower, bounded) in cases {
            let endpoint = match range.upper {
                Unbounded => Endpoint::All,
                Included(at) => Endpoint::Through(at),
                Excluded(at) => Endpoint::Time(at),
            };
            let queries = BTreeMap::from([(
                member,
                Query {
                    source: root,
                    operation: "sum".into(),
                    phase: "calculate".into(),
                    channel: "amount".into(),
                    range,
                    selected: None,
                    result: 0,
                },
            )]);
            let mut all = BTreeMap::from([
                (
                    route.key(),
                    Stored::Subscribers(Header {
                        head: Some(member),
                        len: 1,
                        bounded,
                    }),
                ),
                (
                    route.node_key(member),
                    Stored::RouteNode(crate::routes::Node {
                        route,
                        key: Order { endpoint, member },
                        range,
                        min_lower,
                        left: None,
                        right: None,
                        height: 1,
                    }),
                ),
            ]);
            check_routes(&all, &routes, &queries).unwrap();
            let valid = all.clone();
            let Some(Stored::RouteNode(n)) = all.get_mut(&route.node_key(member)) else {
                unreachable!()
            };
            n.min_lower = if min_lower.is_some() {
                None
            } else {
                Some(Unbounded)
            };
            assert_eq!(
                check_routes(&all, &routes, &queries).unwrap_err().detail,
                "selector exact minimum lower bound"
            );
            all = valid.clone();
            let Some(Stored::Subscribers(h)) = all.get_mut(&route.key()) else {
                unreachable!()
            };
            h.bounded = 1 - bounded;
            assert_eq!(
                check_routes(&all, &routes, &queries).unwrap_err().detail,
                "selector exact bounded count"
            );
            all = valid;
            let Some(Stored::RouteNode(n)) = all.get_mut(&route.node_key(member)) else {
                unreachable!()
            };
            n.range.lower = match range.lower {
                Unbounded => Included(0),
                _ => Unbounded,
            };
            assert_eq!(
                check_routes(&all, &routes, &queries).unwrap_err().detail,
                "selector exact source membership/bound"
            );
        }
    }
    #[test]
    fn source_inventory_and_structure_reject_corruption_without_writer_replay() {
        let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/integrity-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&directory).unwrap();
        let model = Arc::new(crate::model::PreparedModel::load().unwrap());
        crate::demo::run(&directory.join("demo"), model.clone()).unwrap();
        let store = LocalStore::open(directory.join("demo/demo.redb"), model).unwrap();
        store.check_integrity().unwrap();
        let read = store.db.begin_read().unwrap();
        let native = read.open_table(KV).unwrap();
        let mut changes = vec![];
        for row in native.iter().unwrap() {
            let (key, bytes) = row.unwrap();
            let key = Key::decode(key.value()).unwrap();
            let stored = native_codec::decode(&key, bytes.value()).unwrap();
            match stored {
                Stored::Node(mut n) => {
                    n.height += 1;
                    changes.push((key.clone(), Some(Stored::Node(n.clone()))));
                    n.parent = Some(Address::new(Uuid::nil(), 1));
                    changes.push((key.clone(), Some(Stored::Node(n))));
                }
                Stored::Query(mut q) => {
                    q.result += 1;
                    changes.push((key.clone(), Some(Stored::Query(q))));
                }
                Stored::Incoming(_) => changes.push((key.clone(), None)),
                Stored::RouteNode(mut n) => {
                    changes.push((key.clone(), None));
                    let mut wrong_height = n.clone();
                    wrong_height.height += 1;
                    changes.push((key.clone(), Some(Stored::RouteNode(wrong_height))));
                    if matches!(n.route, crate::routes::Route::Subscribers(_)) {
                        (n.key.endpoint, n.range.upper) = match n.key.endpoint {
                            crate::routes::Endpoint::All => {
                                (crate::routes::Endpoint::Time(0), TimeBound::Excluded(0))
                            }
                            _ => (crate::routes::Endpoint::All, TimeBound::Unbounded),
                        };
                        changes.push((key.clone(), Some(Stored::RouteNode(n))));
                    }
                }
                Stored::Record(mut r) if r.contract == 12 => {
                    if let Input::Output { amount, .. } = &mut r.input {
                        *amount += 1;
                    }
                    changes.push((key.clone(), Some(Stored::Record(r))));
                }
                Stored::Meta(mut m) => {
                    *m.counts.entry(1).or_default() += 1;
                    changes.push((key.clone(), Some(Stored::Meta(m))));
                }
                _ => {}
            }
        }
        drop(native);
        drop(read);
        assert!(changes.len() > 20);
        for (key, value) in changes {
            let original = {
                let read = store.db.begin_read().unwrap();
                read.open_table(KV)
                    .unwrap()
                    .get(key.encode().as_slice())
                    .unwrap()
                    .map(|v| v.value().to_vec())
            };
            let write = store.db.begin_write().unwrap();
            {
                let mut table = write.open_table(KV).unwrap();
                if let Some(value) = value {
                    table
                        .insert(
                            key.encode().as_slice(),
                            native_codec::encode(&key, &value).unwrap().as_slice(),
                        )
                        .unwrap();
                } else {
                    table.remove(key.encode().as_slice()).unwrap();
                }
            }
            write.commit().unwrap();
            assert!(store.check_integrity().is_err(), "accepted corrupt {key:?}");
            let write = store.db.begin_write().unwrap();
            {
                let mut table = write.open_table(KV).unwrap();
                if let Some(bytes) = original {
                    table
                        .insert(key.encode().as_slice(), bytes.as_slice())
                        .unwrap();
                } else {
                    table.remove(key.encode().as_slice()).unwrap();
                }
            }
            write.commit().unwrap();
        }
        store.check_integrity().unwrap();
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
