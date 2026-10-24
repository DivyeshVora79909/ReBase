//! Extraction seams: strict native envelopes, ordered financial algebra and a
//! non-time, non-Copy family using the same maintained tree and point codec.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound,
};

use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    algebra::Summary,
    binding::{Binding, Calculation},
    index::{IndexCode, IndexDescriptor, KeyRange, NativeIndex, SummaryRead, TimeKey},
    indexes::standard::{Aggregate, FINANCIAL, Leaf, QUOTE, Standard},
    local::Store,
    model::{Contract, Prepared},
    native_codec::{self, Address, Key, StoredValue},
    native_slice::{Attempt, Context, Error, Input, Model, ModelChange, Population, Result},
    time_range::TimeRange,
    tree::{self, FullKey, Node, Root, Span},
};

#[test]
fn index_codes_and_time_keys_are_strict_native_values() {
    for code in [1, 2, u16::MAX] {
        let value = IndexCode::new(code).unwrap();
        assert_eq!(value.get(), code);
        assert_eq!(serde_json::to_string(&value).unwrap(), code.to_string());
        assert_eq!(
            serde_json::from_str::<IndexCode>(&code.to_string()).unwrap(),
            value
        );
    }
    assert_eq!(IndexCode::new(0), None);
    for malformed in ["0", "-1", "65536", "1.0", "\"1\"", "null"] {
        assert!(serde_json::from_str::<IndexCode>(malformed).is_err());
    }
    let unknown = IndexCode::new(19).unwrap();
    assert!(Standard::descriptor(unknown).is_err());
    assert!(Standard::empty(unknown).is_err());
    assert!(Standard::validate_key(unknown, &TimeKey::new(0)).is_err());
    assert!(Standard::singleton(QUOTE, &TimeKey::new(0), &Leaf::Financial(1)).is_err());
    assert!(Standard::validate_leaf(QUOTE, &Leaf::Quote(0)).is_err());
    for at in [i64::MIN, -1, 0, 1, i64::MAX] {
        let key = TimeKey::new(at);
        let wire = format!("\"{at}\"");
        assert_eq!(serde_json::to_string(&key).unwrap(), wire);
        assert_eq!(serde_json::from_str::<TimeKey>(&wire).unwrap(), key);
    }
    for malformed in [
        "0",
        "\"-0\"",
        "\"01\"",
        "\"+1\"",
        "\"1e1\"",
        "\"9223372036854775808\"",
    ] {
        assert!(serde_json::from_str::<TimeKey>(malformed).is_err());
    }
    let key = FullKey {
        value: TimeKey::new(i64::MAX),
        id: Uuid::from_u128(7),
        slot: 2,
    };
    let wire = serde_json::to_value(key).unwrap();
    assert_eq!(wire["value"], i64::MAX.to_string());
}

#[test]
fn native_query_port_preserves_standard_scalar_wire_and_rejects_statistics() {
    use crate::native_slice::Query;
    let key = Key::Query(Address::new(Uuid::from_u128(2), 3));
    for (operation, channel, range, selected, result) in [
        ("sum", "amount", TimeRange::ALL, None, i128::MIN),
        (
            "latest",
            "rate",
            TimeRange::through(17),
            Some(Uuid::from_u128(3)),
            7,
        ),
    ] {
        let query = Query {
            source: Address::new(Uuid::from_u128(1), 2),
            operation: operation.into(),
            phase: "calculate".into(),
            channel: channel.into(),
            range,
            selected,
            result,
        };
        let stored = StoredValue::<Calculation>::Query(query);
        let bytes = native_codec::encode_for::<Calculation>(&key, &stored).unwrap();
        let expected = format!(
            "{{\"type\":\"query\",\"data\":{{\"source\":{{\"id\":\"{}\",\"slot\":2}},\"operation\":\"{operation}\",\"phase\":\"calculate\",\"channel\":\"{channel}\",\"range\":{},\"selected\":{},\"result\":\"{result}\"}}}}",
            Uuid::from_u128(1),
            serde_json::to_string(&range).unwrap(),
            serde_json::to_string(&selected).unwrap()
        );
        assert_eq!(bytes, expected.as_bytes());
        assert_eq!(
            native_codec::decode_for::<Calculation>(&key, &bytes).unwrap(),
            stored
        );
        let mut wrong: Value = serde_json::from_slice(&bytes).unwrap();
        wrong["data"]["result"] =
            json!({"count":0,"sum":"0","min":null,"max":null,"dimension":{"kind":"empty"}});
        assert!(
            native_codec::decode_for::<Calculation>(&key, &serde_json::to_vec(&wrong).unwrap())
                .is_err()
        );
    }
}

fn financial_scan(source: &[(i64, i128)]) -> Summary {
    let (mut total, mut low, mut high) = (0, 0, 0);
    let mut boundaries = vec![];
    for (position, (at, amount)) in source.iter().enumerate() {
        total += amount;
        low = low.min(total);
        high = high.max(total);
        if source.get(position + 1).is_some_and(|(next, _)| at != next) {
            boundaries.push(total);
        }
    }
    Summary {
        count: source.len() as u64,
        first: source.first().map(|(at, _)| *at),
        last: source.last().map(|(at, _)| *at),
        sum: total,
        min_prefix: low,
        max_prefix: high,
        boundary_min: boundaries.iter().copied().min(),
        boundary_max: boundaries.iter().copied().max(),
    }
}

fn every_parenthesization(source: &[(i64, i128)]) -> Vec<Aggregate> {
    match source.len() {
        0 => vec![Standard::empty(FINANCIAL).unwrap()],
        1 => vec![
            Standard::singleton(
                FINANCIAL,
                &TimeKey::new(source[0].0),
                &Leaf::Financial(source[0].1),
            )
            .unwrap(),
        ],
        size => (1..size)
            .flat_map(|split| {
                let right = every_parenthesization(&source[split..]);
                every_parenthesization(&source[..split])
                    .into_iter()
                    .flat_map(move |left| {
                        right
                            .clone()
                            .into_iter()
                            .map(move |right| Standard::combine(FINANCIAL, &left, &right).unwrap())
                    })
            })
            .collect(),
    }
}

#[test]
fn native_financial_algebra_matches_complete_time_source_scans() {
    for source in [
        vec![],
        vec![(0, -3)],
        vec![(0, -3), (0, 7), (1, -10), (2, 6), (2, 1)],
        vec![(i64::MIN, 2), (i64::MIN, -4), (0, 7), (i64::MAX, -3)],
        vec![(4, -9), (4, 5), (4, 7), (4, -1)],
    ] {
        let literal = financial_scan(&source);
        let expected = Aggregate::Financial(literal);
        let identity = Standard::empty(FINANCIAL).unwrap();
        for folded in every_parenthesization(&source) {
            assert_eq!(folded, expected);
            assert_eq!(
                Standard::combine(FINANCIAL, &identity, &folded).unwrap(),
                expected
            );
            assert_eq!(
                Standard::combine(FINANCIAL, &folded, &identity).unwrap(),
                expected
            );
            Standard::validate_summary(FINANCIAL, &folded).unwrap();
        }
        let mut groups = BTreeMap::<i64, i128>::new();
        for (at, amount) in source {
            *groups.entry(at).or_default() += amount;
        }
        let mut running = 0;
        let mut complete = vec![0];
        for value in groups.values() {
            running += value;
            complete.push(running);
        }
        assert_eq!(literal.complete_min(), *complete.iter().min().unwrap());
        assert_eq!(literal.complete_max(), *complete.iter().max().unwrap());
    }
    let a = Standard::singleton(FINANCIAL, &TimeKey::new(0), &Leaf::Financial(i128::MAX)).unwrap();
    let b = Standard::singleton(FINANCIAL, &TimeKey::new(1), &Leaf::Financial(1)).unwrap();
    assert_eq!(
        Standard::combine(FINANCIAL, &a, &b).unwrap_err().code,
        "overflow"
    );
    assert!(Standard::combine(FINANCIAL, &a, &Standard::empty(QUOTE).unwrap()).is_err());
}

const WORDS: IndexCode = IndexCode::new(19).unwrap();

#[derive(Clone, Debug, PartialEq, Eq)]
struct Words;

// This deliberately has no time, count, first, last or amount summary fields.
// It is a bounded test family, not a public string/composite query API.
impl NativeIndex for Words {
    type QueryResult = ();
    type Key = String;
    type Leaf = String;
    type Summary = String;

    fn descriptors() -> Vec<IndexDescriptor> {
        vec![IndexDescriptor {
            code: WORDS,
            name: "test_words",
            reads: vec!["summary"],
            key_schema: json!({"type":"string","pattern":"^[a-z]{1,8}$"}),
            leaf_schema: json!({"type":"string","pattern":"^[A-Z]$"}),
            summary_schema: json!({"type":"string","pattern":"^[A-Z]{0,64}$"}),
            result_schemas: json!({"summary":{"type":"string","pattern":"^[A-Z]{0,64}$"}}),
            time: false,
            financial: false,
            quote: false,
        }]
    }
    fn validate_key(code: IndexCode, key: &String) -> Result<()> {
        if code == WORDS
            && (1..=8).contains(&key.len())
            && key.bytes().all(|c| c.is_ascii_lowercase())
        {
            Ok(())
        } else {
            Err(Error::new("corrupt_state", "word key/code"))
        }
    }
    fn validate_leaf(code: IndexCode, leaf: &String) -> Result<()> {
        if code == WORDS && leaf.len() == 1 && leaf.bytes().all(|c| c.is_ascii_uppercase()) {
            Ok(())
        } else {
            Err(Error::new("corrupt_state", "word leaf/code"))
        }
    }
    fn validate_summary(code: IndexCode, summary: &String) -> Result<()> {
        if code == WORDS && summary.len() <= 64 && summary.bytes().all(|c| c.is_ascii_uppercase()) {
            Ok(())
        } else {
            Err(Error::new("corrupt_state", "word summary/code"))
        }
    }
    fn empty(code: IndexCode) -> Result<String> {
        Self::validate_summary(code, &String::new())?;
        Ok(String::new())
    }
    fn singleton(code: IndexCode, key: &String, leaf: &String) -> Result<String> {
        Self::validate_key(code, key)?;
        Self::validate_leaf(code, leaf)?;
        Ok(leaf.clone())
    }
    fn combine(code: IndexCode, left: &String, right: &String) -> Result<String> {
        let result = format!("{left}{right}");
        Self::validate_summary(code, &result)?;
        Ok(result)
    }
    fn project(code: IndexCode, read: SummaryRead, summary: &String) -> Result<Value> {
        Self::validate_summary(code, summary)?;
        if read != SummaryRead::Summary {
            return Err(Error::new("unsupported_query", "word projection"));
        }
        Ok(json!(summary))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WordBinding;

impl Binding for WordBinding {
    type Index = Words;
    type Input = Input;
    type Derived = <Calculation as Binding>::Derived;
    type Outcome = ();
    const NAME: &'static str = "test-native-words";
    const BEHAVIOR: &'static str = "words-1";
    fn declarations() -> Result<Vec<Contract>> {
        Ok(vec![])
    }
    fn engine() -> Result<Model> {
        Calculation::engine()
    }
    fn valid_derived(input: &Input, derived: Option<&Self::Derived>) -> bool {
        Calculation::valid_derived(input, derived)
    }
    fn published_shape(code: u16) -> Value {
        Calculation::published_shape(code)
    }
    fn settle_changes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        _ws: &mut Attempt<L, Self>,
        _model: &Prepared<Self>,
        _context: Context,
        _changes: &[ModelChange<Self>],
        _population: &mut Population,
        _revision: Uuid,
        _allocate: &mut dyn FnMut() -> Result<Uuid>,
    ) -> Result<()> {
        Err(Error::new("unsupported_query", "tree-only test binding"))
    }
    fn check(_store: &Store<Self>) -> Result<Value> {
        Err(Error::new("unsupported_query", "tree-only test binding"))
    }
}

type Bytes = BTreeMap<Vec<u8>, Vec<u8>>;
type Sources = BTreeMap<Address, (String, String)>;

fn address(id: u128, slot: u16) -> Address {
    Address::new(Uuid::from_u128(id), slot)
}

fn apply_words(
    store: &mut Bytes,
    owner: Address,
    id: Address,
    value: Option<(&str, &str)>,
) -> Result<()> {
    let mut ws = Attempt::<_, WordBinding>::new(|key: &[u8]| Ok(store.get(key).cloned()), 100_000);
    match value {
        Some((key, leaf)) => tree::insert(&mut ws, owner, id, key.to_string(), leaf.to_string())?,
        None => tree::remove(&mut ws, owner, id)?,
    }
    for (key, value) in ws.finish()? {
        if let Some(value) = value {
            store.insert(key, value);
        } else {
            store.remove(&key);
        }
    }
    Ok(())
}

fn word_scan(store: &Bytes, owner: Address, source: &Sources) -> Result<()> {
    let mut nodes = BTreeMap::new();
    let mut header = None;
    for (key, value) in store {
        let key = Key::decode(key)?;
        match native_codec::decode_for::<WordBinding>(&key, value)? {
            StoredValue::Root(root) => {
                assert_eq!(key, Key::Root(owner));
                header = Some(root);
            }
            StoredValue::Node(node) => {
                let Key::Node(address) = key else {
                    panic!("unexpected node address")
                };
                nodes.insert(address, node);
            }
            _ => panic!("unexpected tree-only row"),
        }
    }
    assert_eq!(
        nodes.keys().collect::<Vec<_>>(),
        source.keys().collect::<Vec<_>>()
    );
    let header = header.unwrap();
    struct Scan<'a> {
        nodes: &'a BTreeMap<Address, Node<Words>>,
        source: &'a Sources,
        seen: BTreeSet<Address>,
    }
    impl Scan<'_> {
        fn visit(
            &mut self,
            id: Option<Address>,
            parent: Option<Address>,
        ) -> (u16, Vec<FullKey<String>>) {
            let Some(id) = id else { return (0, vec![]) };
            assert!(self.seen.insert(id));
            let node = &self.nodes[&id];
            assert_eq!(node.parent, parent);
            assert_eq!(node.kind, WORDS);
            assert_eq!(
                (&node.key.value, &node.leaf),
                (&self.source[&id].0, &self.source[&id].1)
            );
            assert_eq!((node.key.id, node.key.slot), (id.id, id.slot));
            let (lh, mut keys) = self.visit(node.left, Some(id));
            keys.push(node.key.clone());
            let (rh, right) = self.visit(node.right, Some(id));
            keys.extend(right);
            assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
            assert_eq!(node.height, lh.max(rh) + 1);
            assert!(lh.abs_diff(rh) <= 1);
            assert_eq!(
                node.span,
                Span {
                    first: keys.first().unwrap().value.clone(),
                    last: keys.last().unwrap().value.clone()
                }
            );
            let expected: String = keys
                .iter()
                .map(|key| self.source[&Address::new(key.id, key.slot)].1.as_str())
                .collect();
            assert_eq!(node.summary, expected);
            (node.height, keys)
        }
    }
    let mut scan = Scan {
        nodes: &nodes,
        source,
        seen: BTreeSet::new(),
    };
    let (height, keys) = scan.visit(header.head, None);
    assert_eq!(scan.seen.len(), source.len());
    assert_eq!(header.height, height);
    assert_eq!(
        header.span,
        keys.first().zip(keys.last()).map(|(first, last)| Span {
            first: first.value.clone(),
            last: last.value.clone()
        })
    );
    let expected: String = keys
        .iter()
        .map(|key| source[&Address::new(key.id, key.slot)].1.as_str())
        .collect();
    assert_eq!(header.summary, expected);
    let ids: Vec<_> = keys
        .iter()
        .map(|key| Address::new(key.id, key.slot))
        .collect();
    assert_eq!(header.first, ids.first().copied());
    assert_eq!(header.last, ids.last().copied());
    for (position, id) in ids.iter().enumerate() {
        assert_eq!(nodes[id].prev, position.checked_sub(1).map(|i| ids[i]));
        assert_eq!(nodes[id].next, ids.get(position + 1).copied());
        assert_eq!(nodes[id].root, owner);
    }
    let bounds = [
        Bound::Unbounded,
        Bound::Included("b".to_string()),
        Bound::Excluded("b".to_string()),
        Bound::Included("d".to_string()),
        Bound::Excluded("d".to_string()),
        Bound::Included("z".to_string()),
    ];
    for lower in &bounds {
        for upper in &bounds {
            let range = KeyRange {
                lower: lower.clone(),
                upper: upper.clone(),
            };
            let expected: String = keys
                .iter()
                .filter(|key| {
                    let lower = match &range.lower {
                        Bound::Unbounded => true,
                        Bound::Included(v) => key.value >= *v,
                        Bound::Excluded(v) => key.value > *v,
                    };
                    let upper = match &range.upper {
                        Bound::Unbounded => true,
                        Bound::Included(v) => key.value <= *v,
                        Bound::Excluded(v) => key.value < *v,
                    };
                    lower && upper
                })
                .map(|key| source[&Address::new(key.id, key.slot)].1.as_str())
                .collect();
            let mut ws =
                Attempt::<_, WordBinding>::new(|key: &[u8]| Ok(store.get(key).cloned()), 100_000);
            assert_eq!(tree::range_keys(&mut ws, owner, &range)?, expected);
        }
    }
    Ok(())
}

#[test]
fn one_native_tree_supports_noncopy_nontime_values() -> Result<()> {
    let owner = address(100, 1);
    let key = Key::Root(owner);
    let root = Root::<Words>::empty(WORDS, Uuid::new_v4())?;
    let mut store: Bytes = [(
        key.encode(),
        native_codec::encode_for::<WordBinding>(&key, &StoredValue::Root(root))?,
    )]
    .into();
    let mut source = Sources::new();
    word_scan(&store, owner, &source)?;
    for (id, key, leaf) in [
        (9, "d", "D"),
        (3, "b", "B"),
        (12, "f", "F"),
        (1, "a", "A"),
        (5, "c", "C"),
        (10, "e", "E"),
        (4, "b", "X"),
        (2, "b", "Y"),
        (7, "c", "Z"),
    ] {
        let id = address(id, 1);
        apply_words(&mut store, owner, id, Some((key, leaf)))?;
        source.insert(id, (key.to_string(), leaf.to_string()));
        word_scan(&store, owner, &source)?;
    }
    // Same UUID, different member slot remains a distinct occurrence tie.
    let extra = address(3, 2);
    apply_words(&mut store, owner, extra, Some(("b", "S")))?;
    source.insert(extra, ("b".into(), "S".into()));
    word_scan(&store, owner, &source)?;
    let mut ws = Attempt::<_, WordBinding>::new(|key: &[u8]| Ok(store.get(key).cloned()), 100_000);
    tree::revalue(&mut ws, owner, extra, "Q".into())?;
    for (key, value) in ws.finish()? {
        store.insert(key, value.expect("revalue cannot delete"));
    }
    source.get_mut(&extra).unwrap().1 = "Q".into();
    word_scan(&store, owner, &source)?;
    for id in [
        address(9, 1),
        address(3, 1),
        address(12, 1),
        address(1, 1),
        address(5, 1),
        address(10, 1),
        address(4, 1),
        address(2, 1),
        address(7, 1),
        extra,
    ] {
        apply_words(&mut store, owner, id, None)?;
        source.remove(&id);
        word_scan(&store, owner, &source)?;
    }
    let mut ws = Attempt::<_, WordBinding>::new(|key: &[u8]| Ok(store.get(key).cloned()), 100_000);
    assert_eq!(
        tree::range(&mut ws, owner, TimeRange::ALL)
            .unwrap_err()
            .code,
        "unsupported_query"
    );
    assert_eq!(
        tree::prefix(&mut ws, owner, None).unwrap_err().code,
        "unsupported_query"
    );
    assert_eq!(
        tree::latest(&mut ws, owner, 0).unwrap_err().code,
        "unsupported_query"
    );
    Ok(())
}
