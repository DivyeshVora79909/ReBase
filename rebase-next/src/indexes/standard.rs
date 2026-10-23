//! Reusable financial-history and quote values for compiled native models.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};

use crate::{
    algebra::Summary,
    index::{IndexCode, IndexDescriptor, NativeIndex, SummaryRead, TimeKey},
    native_codec::{decimal, optional_decimal, summary},
    native_slice::{Error, Query, Result},
    time_range::TimeBound,
};

pub const FINANCIAL: IndexCode = IndexCode::new(1).expect("nonzero index code");
pub const QUOTE: IndexCode = IndexCode::new(2).expect("nonzero index code");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Standard;

fn broken(detail: &str) -> Error {
    Error::new("corrupt_state", detail)
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
    pub fn kind(self) -> IndexCode {
        match self {
            Self::Financial(_) => FINANCIAL,
            Self::Quote(_) => QUOTE,
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
    pub fn kind(self) -> IndexCode {
        match self {
            Self::Financial(_) => FINANCIAL,
            Self::Quote(_) => QUOTE,
        }
    }
    pub fn empty(kind: IndexCode) -> Result<Self> {
        match kind {
            FINANCIAL => Ok(Self::Financial(Summary::default())),
            QUOTE => Ok(Self::Quote(QuoteSummary::default())),
            _ => Err(broken("unknown native index code")),
        }
    }
    pub fn leaf(at: i64, leaf: Leaf) -> Self {
        match leaf {
            Leaf::Financial(amount) => Self::Financial(Summary::leaf(at, Some(amount))),
            Leaf::Quote(_) => Self::Quote(QuoteSummary {
                count: 1,
                first: Some(at),
                last: Some(at),
            }),
        }
    }
    pub fn combine(self, other: Self) -> Result<Self> {
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

/// Schemas are supplied with the native family rather than repeated in tools.
pub fn time_schema() -> Value {
    json!({"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","format":"i64"})
}

fn amount_schema() -> Value {
    json!({"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","format":"i128"})
}

fn optional(schema: Value) -> Value {
    json!({"anyOf":[schema,{"type":"null"}]})
}

fn object(properties: Value) -> Value {
    let required: Vec<_> = properties
        .as_object()
        .expect("schema object")
        .keys()
        .cloned()
        .collect();
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}

fn tagged(kind: &str, value: Value) -> Value {
    object(json!({"kind":{"const":kind},"value":value}))
}

impl NativeIndex for Standard {
    type Key = TimeKey;
    type Leaf = Leaf;
    type Summary = Aggregate;
    type QueryResult = i128;

    fn serialize_query_result<S: Serializer>(
        value: &i128,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        decimal::serialize(value, serializer)
    }
    fn deserialize_query_result<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<i128, D::Error> {
        decimal::deserialize(deserializer)
    }
    fn supports_query(code: IndexCode, operation: &str, phase: &str, channel: &str) -> bool {
        matches!(
            (code, operation, phase, channel),
            (FINANCIAL, "sum", "calculate" | "validate", "amount")
                | (QUOTE, "latest", "calculate", "rate")
        )
    }
    fn causal_query(operation: &str) -> bool {
        operation == "sum"
    }
    fn causal_index(code: IndexCode) -> bool {
        code == FINANCIAL
    }
    fn validate_query(query: &Query<Self>) -> Result<()> {
        if (Self::supports_query(QUOTE, &query.operation, &query.phase, &query.channel)
            && query.range.lower == TimeBound::Unbounded
            && matches!(query.range.upper, TimeBound::Included(_)))
            || (Self::supports_query(FINANCIAL, &query.operation, &query.phase, &query.channel)
                && query.selected.is_none())
        {
            Ok(())
        } else {
            Err(broken("standard query binding"))
        }
    }
    fn query_result(code: IndexCode, operation: &str, summary: &Aggregate) -> Result<i128> {
        if operation != "sum" {
            return Err(Error::new("unsupported_query", "financial sum required"));
        }
        Ok(Self::financial_summary(code, summary)?.sum)
    }
    fn financial_query_result(sum: i128) -> Result<i128> {
        Ok(sum)
    }
    fn validate_terminal(result: &i128) -> Result<()> {
        if *result < 0 {
            Err(Error::new("invariant", "negative validation sum"))
        } else {
            Ok(())
        }
    }

    fn descriptors() -> Vec<IndexDescriptor> {
        let times = json!({"count":{"type":"integer","minimum":0},
            "first":optional(time_schema()),"last":optional(time_schema())});
        let mut financial = times.clone();
        let fields = financial.as_object_mut().expect("schema object");
        for field in ["sum", "min_prefix", "max_prefix"] {
            fields.insert(field.into(), amount_schema());
        }
        for field in ["boundary_min", "boundary_max"] {
            fields.insert(field.into(), optional(amount_schema()));
        }
        let mut projected = times.clone();
        let fields = projected.as_object_mut().expect("schema object");
        fields.insert("sum".into(), amount_schema());
        fields.insert("complete_min".into(), amount_schema());
        let projected = object(projected);
        vec![
            IndexDescriptor {
                code: FINANCIAL,
                name: "financial",
                reads: vec!["summary", "sum", "before", "range"],
                key_schema: time_schema(),
                leaf_schema: tagged("financial", amount_schema()),
                summary_schema: tagged("financial", object(financial)),
                result_schemas: json!({"summary":projected,"range":projected,
                    "sum":object(json!({"sum":amount_schema()})),
                    "before":object(json!({"sum":amount_schema()}))}),
                time: true,
                financial: true,
                quote: Self::supports_quote(FINANCIAL),
            },
            IndexDescriptor {
                code: QUOTE,
                name: "quote",
                reads: vec!["summary", "latest"],
                key_schema: time_schema(),
                leaf_schema: tagged(
                    "quote",
                    json!({"type":"string","pattern":"^[1-9][0-9]*$","format":"u16"}),
                ),
                summary_schema: tagged("quote", object(times.clone())),
                result_schemas: json!({"summary":object(times),"latest":{"anyOf":[
                    object(json!({"id":{"type":"string","format":"uuid"},
                        "rate":{"type":"string","pattern":"^[1-9][0-9]*$","format":"u16"}})),
                    {"type":"null"}]}}),
                time: true,
                financial: false,
                quote: Self::supports_quote(QUOTE),
            },
        ]
    }

    fn validate_key(code: IndexCode, _key: &TimeKey) -> Result<()> {
        match code {
            FINANCIAL | QUOTE => Ok(()),
            _ => Err(broken("unknown standard index code")),
        }
    }

    fn validate_leaf(code: IndexCode, leaf: &Leaf) -> Result<()> {
        if leaf.kind() != code || matches!(leaf, Leaf::Quote(0)) {
            return Err(broken("native leaf/code mismatch"));
        }
        Ok(())
    }

    fn validate_summary(code: IndexCode, summary: &Aggregate) -> Result<()> {
        if summary.kind() != code {
            return Err(broken("native summary/code mismatch"));
        }
        let (count, first, last) = match summary {
            Aggregate::Financial(value) => (value.count, value.first, value.last),
            Aggregate::Quote(value) => (value.count, value.first, value.last),
        };
        if count == 0 {
            if *summary != Aggregate::empty(code)? {
                return Err(broken("noncanonical empty native summary"));
            }
        } else if !matches!((first,last),(Some(first),Some(last)) if first <= last) {
            return Err(broken("native summary time endpoints"));
        }
        if let Aggregate::Financial(value) = summary
            && (value.min_prefix > value.sum.min(0)
                || value.max_prefix < value.sum.max(0)
                || value.boundary_min.is_some() != value.boundary_max.is_some()
                || value.boundary_min > value.boundary_max
                || (first == last && value.boundary_min.is_some())
                || (first != last && value.boundary_min.is_none())
                || value.boundary_min.is_some_and(|v| v < value.min_prefix)
                || value.boundary_max.is_some_and(|v| v > value.max_prefix))
        {
            return Err(broken("native financial extrema"));
        }
        Ok(())
    }

    fn empty(code: IndexCode) -> Result<Aggregate> {
        Aggregate::empty(code)
    }

    fn singleton(code: IndexCode, key: &TimeKey, leaf: &Leaf) -> Result<Aggregate> {
        Self::validate_key(code, key)?;
        Self::validate_leaf(code, leaf)?;
        Ok(Aggregate::leaf(key.0, *leaf))
    }

    fn combine(code: IndexCode, left: &Aggregate, right: &Aggregate) -> Result<Aggregate> {
        if left.kind() != code || right.kind() != code {
            return Err(broken("combined native summary/code mismatch"));
        }
        left.combine(*right)
    }

    fn project(code: IndexCode, read: SummaryRead, summary: &Aggregate) -> Result<Value> {
        Self::validate_summary(code, summary)?;
        match summary {
            Aggregate::Financial(s) => match read {
                SummaryRead::Before => Ok(json!({"sum":s.sum.to_string()})),
                SummaryRead::Summary | SummaryRead::Range => Ok(json!({
                    "count":s.count,"sum":s.sum.to_string(),"complete_min":s.complete_min().to_string(),
                    "first":s.first.map(|t|t.to_string()),"last":s.last.map(|t|t.to_string())})),
            },
            Aggregate::Quote(s) if read == SummaryRead::Summary => Ok(json!({
                "count":s.count,"first":s.first.map(|t|t.to_string()),"last":s.last.map(|t|t.to_string())})),
            _ => Err(Error::new(
                "unsupported_query",
                "unsupported native summary projection",
            )),
        }
    }

    fn check_insert(code: IndexCode, key: &TimeKey, existing: &TimeKey) -> Result<()> {
        if code == QUOTE && key == existing {
            return Err(Error::new("duplicate_time", "curve quote time"));
        }
        Ok(())
    }

    fn time_key(code: IndexCode, at: i64) -> Result<TimeKey> {
        Self::validate_key(code, &TimeKey(at))?;
        Ok(TimeKey(at))
    }

    fn time(code: IndexCode, key: &TimeKey) -> Result<i64> {
        Self::validate_key(code, key)?;
        Ok(key.0)
    }

    fn financial_leaf(code: IndexCode, leaf: &Leaf) -> Result<i128> {
        match (code, leaf) {
            (FINANCIAL, Leaf::Financial(amount)) => Ok(*amount),
            _ => Err(Error::new("unsupported_query", "financial leaf required")),
        }
    }

    fn financial_summary(code: IndexCode, summary: &Aggregate) -> Result<&Summary> {
        match (code, summary) {
            (FINANCIAL, Aggregate::Financial(summary)) => Ok(summary),
            _ => Err(Error::new(
                "unsupported_query",
                "financial summary required",
            )),
        }
    }

    fn quote_leaf(code: IndexCode, leaf: &Leaf) -> Result<u16> {
        match (code, leaf) {
            (QUOTE, Leaf::Quote(rate)) => Ok(*rate),
            _ => Err(Error::new("unsupported_query", "quote leaf required")),
        }
    }

    fn supports_quote(code: IndexCode) -> bool {
        code == QUOTE
    }
}
