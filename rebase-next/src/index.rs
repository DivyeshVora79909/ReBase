//! A compiled model's native ordered values and bounded summary algebra.
//!
//! Tree structure, storage and occurrence ties belong to the engine. A family
//! owns its codebook, values, checked algebra and explicit query capabilities.

use std::{fmt::Debug, ops::Bound};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    algebra::Summary,
    native_codec::{Address, decimal},
    native_slice::{Error, Query, Result},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct IndexCode(u16);

impl IndexCode {
    pub const fn new(value: u16) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for IndexCode {
    type Error = &'static str;
    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        Self::new(value).ok_or("native index code must be nonzero")
    }
}

impl From<IndexCode> for u16 {
    fn from(value: IndexCode) -> Self {
        value.get()
    }
}

/// Canonical exact timestamp wire form, including inside generic node keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TimeKey(#[serde(with = "decimal")] pub i64);

impl TimeKey {
    pub const fn new(at: i64) -> Self {
        Self(at)
    }
    pub const fn get(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SummaryRead {
    Summary,
    Before,
    Range,
}

#[derive(Clone, Debug, Serialize)]
pub struct IndexDescriptor {
    pub code: IndexCode,
    pub name: &'static str,
    pub reads: Vec<&'static str>,
    pub key_schema: Value,
    pub leaf_schema: Value,
    pub summary_schema: Value,
    pub result_schemas: Value,
    pub time: bool,
    pub financial: bool,
    pub quote: bool,
}

/// An attempt-local ordered occurrence. A family projects the selected native
/// leaf into its query result; tree links and cached summaries stay private.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selected<I: NativeIndex> {
    pub member: Address,
    pub key: I::Key,
    pub leaf: I::Leaf,
}

/// Family implementations are trusted pure functions. Associativity, identity
/// and bounded arithmetic on the admitted input domain need source-oracle tests.
pub trait NativeIndex: Clone + Debug + Eq + Send + Sync + 'static {
    type Key: Ord + Clone + Debug + Serialize + DeserializeOwned + Send + Sync + 'static;
    type Leaf: Clone + Debug + Eq + Serialize + DeserializeOwned + Send + Sync + 'static;
    type Summary: Clone + Debug + Eq + Serialize + DeserializeOwned + Send + Sync + 'static;
    type QueryResult: Clone + Debug + Eq + Serialize + DeserializeOwned + Send + Sync + 'static;

    fn descriptors() -> Vec<IndexDescriptor>;
    fn descriptor(code: IndexCode) -> Result<IndexDescriptor> {
        Self::descriptors()
            .into_iter()
            .find(|descriptor| code.0 != 0 && descriptor.code == code)
            .ok_or_else(|| Error::new("corrupt_state", "unknown native index code"))
    }
    fn validate_key(code: IndexCode, key: &Self::Key) -> Result<()>;
    fn validate_leaf(code: IndexCode, leaf: &Self::Leaf) -> Result<()>;
    fn validate_summary(code: IndexCode, summary: &Self::Summary) -> Result<()>;
    fn empty(code: IndexCode) -> Result<Self::Summary>;
    fn singleton(code: IndexCode, key: &Self::Key, leaf: &Self::Leaf) -> Result<Self::Summary>;
    fn combine(
        code: IndexCode,
        left: &Self::Summary,
        right: &Self::Summary,
    ) -> Result<Self::Summary>;
    fn project(code: IndexCode, read: SummaryRead, summary: &Self::Summary) -> Result<Value>;

    /// A persisted formula value belongs to the compiled family. Public JSON
    /// projections are not the native input to a calculation.
    fn serialize_query_result<S: Serializer>(
        value: &Self::QueryResult,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        value.serialize(serializer)
    }
    fn deserialize_query_result<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self::QueryResult, D::Error> {
        Self::QueryResult::deserialize(deserializer)
    }
    fn supports_query(_code: IndexCode, _operation: &str, _phase: &str, _channel: &str) -> bool {
        false
    }
    fn causal_query(_operation: &str) -> bool {
        false
    }
    fn causal_index(_code: IndexCode) -> bool {
        false
    }
    fn validate_query(_query: &Query<Self>) -> Result<()> {
        Err(unsupported("native query result"))
    }
    fn query_result(
        _code: IndexCode,
        _operation: &str,
        _summary: &Self::Summary,
    ) -> Result<Self::QueryResult> {
        Err(unsupported("native summary query"))
    }
    fn selection_result(
        _code: IndexCode,
        _selected: Option<Selected<Self>>,
    ) -> Result<Self::QueryResult> {
        Err(unsupported("native selection query"))
    }
    /// The financial fast prefix and terminal floor are explicit capabilities;
    /// another family's statistics never become an amount by a numeric cast.
    fn financial_query_result(_sum: i128) -> Result<Self::QueryResult> {
        Err(unsupported("financial query result"))
    }
    fn validate_terminal(_result: &Self::QueryResult) -> Result<()> {
        Err(unsupported("terminal query validation"))
    }

    /// Optional business-key uniqueness. UUID/member-slot occurrence ties never
    /// establish business uniqueness by themselves.
    fn check_insert(_code: IndexCode, _key: &Self::Key, _existing: &Self::Key) -> Result<()> {
        Ok(())
    }
    fn time_key(_code: IndexCode, _at: i64) -> Result<Self::Key> {
        Err(unsupported("time key adapter"))
    }
    fn time(_code: IndexCode, _key: &Self::Key) -> Result<i64> {
        Err(unsupported("time key adapter"))
    }
    fn financial_leaf(_code: IndexCode, _leaf: &Self::Leaf) -> Result<i128> {
        Err(unsupported("financial leaf adapter"))
    }
    fn financial_summary(_code: IndexCode, _summary: &Self::Summary) -> Result<&Summary> {
        Err(unsupported("financial summary adapter"))
    }
    fn quote_leaf(_code: IndexCode, _leaf: &Self::Leaf) -> Result<u16> {
        Err(unsupported("quote leaf adapter"))
    }
    fn supports_quote(_code: IndexCode) -> bool {
        false
    }
}

fn unsupported(detail: &str) -> Error {
    Error::new("unsupported_query", detail)
}

/// Attempt-local native bounds. Public wire contracts remain family-owned;
/// this does not define composite-key prefix semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRange<K> {
    pub lower: Bound<K>,
    pub upper: Bound<K>,
}

impl<K: Ord> KeyRange<K> {
    pub fn contains(&self, key: &K) -> bool {
        !self.below(key) && !self.above(key)
    }
    pub fn below(&self, key: &K) -> bool {
        match &self.lower {
            Bound::Unbounded => false,
            Bound::Included(lower) => key < lower,
            Bound::Excluded(lower) => key <= lower,
        }
    }
    pub fn above(&self, key: &K) -> bool {
        match &self.upper {
            Bound::Unbounded => false,
            Bound::Included(upper) => key > upper,
            Bound::Excluded(upper) => key >= upper,
        }
    }
    pub fn is_empty(&self) -> bool {
        match (&self.lower, &self.upper) {
            (Bound::Unbounded, _) | (_, Bound::Unbounded) => false,
            (Bound::Included(a), Bound::Included(b)) => a > b,
            (Bound::Included(a) | Bound::Excluded(a), Bound::Included(b) | Bound::Excluded(b)) => {
                a >= b
            }
        }
    }
}
