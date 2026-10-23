//! Bounded dimensioned statistics, independent of the financial/quote family.
use crate::{
    index::{IndexCode, IndexDescriptor, NativeIndex, SummaryRead, TimeKey},
    native_codec::{decimal, optional_decimal},
    native_slice::{Error, Result},
};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use serde_json::{Value, json};
use std::{fmt, marker::PhantomData};

pub const STATISTICS: IndexCode = IndexCode::new(7).expect("nonzero statistics code");
pub const MAX_VALUE: i128 = 1_000_000_000_000;
pub const MAX_COUNT: u64 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statistics;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Dimension {
    #[default]
    Empty,
    Unit {
        code: u16,
    },
    Mixed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Observation {
    pub unit: u16,
    #[serde(with = "decimal")]
    pub value: i128,
}

// Deserialize only maps, including when invoked outside the native envelope.
fn object<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<T, D::Error> {
    struct Object<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Object<T> {
        type Value = T;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a complete native object")
        }
        fn visit_map<M: MapAccess<'de>>(self, map: M) -> std::result::Result<T, M::Error> {
            T::deserialize(MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Object(PhantomData))
}
impl<'de> Deserialize<'de> for Observation {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            unit: u16,
            #[serde(with = "decimal")]
            value: i128,
        }
        let w: Wire = object(d)?;
        Ok(Self {
            unit: w.unit,
            value: w.value,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub count: u64,
    #[serde(with = "decimal")]
    pub sum: i128,
    #[serde(with = "optional_decimal")]
    pub min: Option<i128>,
    #[serde(with = "optional_decimal")]
    pub max: Option<i128>,
    pub dimension: Dimension,
}
impl<'de> Deserialize<'de> for Summary {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            count: u64,
            #[serde(with = "decimal")]
            sum: i128,
            #[serde(with = "optional_decimal")]
            min: Option<i128>,
            #[serde(with = "optional_decimal")]
            max: Option<i128>,
            dimension: Dimension,
        }
        let w: Wire = object(d)?;
        Ok(Self {
            count: w.count,
            sum: w.sum,
            min: w.min,
            max: w.max,
            dimension: w.dimension,
        })
    }
}
fn corrupt(detail: &str) -> Error {
    Error::new("corrupt_state", detail)
}
fn kind(code: IndexCode) -> Result<()> {
    if code == STATISTICS {
        Ok(())
    } else {
        Err(corrupt("unknown measurement index code"))
    }
}
fn closed(properties: Value) -> Value {
    let required: Vec<_> = properties
        .as_object()
        .expect("authored schema")
        .keys()
        .collect();
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}
pub fn unit_schema() -> Value {
    json!({"type":"integer","minimum":1,"maximum":65535,"x-rebase-binding":"u16_code"})
}
pub fn value_schema() -> Value {
    json!({"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","x-rebase-range":[(-MAX_VALUE).to_string(),MAX_VALUE.to_string()]})
}
fn number_schema() -> Value {
    json!({"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","format":"i128"})
}
fn nullable(schema: Value) -> Value {
    json!({"anyOf":[schema,{"type":"null"}]})
}

impl NativeIndex for Statistics {
    type Key = TimeKey;
    type Leaf = Observation;
    type Summary = Summary;
    type QueryResult = Summary;
    fn supports_query(code: IndexCode, operation: &str, phase: &str, channel: &str) -> bool {
        code == STATISTICS
            && operation == "summary"
            && phase == "calculate"
            && channel == "statistics"
    }
    fn causal_query(operation: &str) -> bool {
        operation == "summary"
    }
    fn causal_index(code: IndexCode) -> bool {
        code == STATISTICS
    }
    fn validate_query(query: &crate::native_slice::Query<Self>) -> Result<()> {
        if !Self::supports_query(STATISTICS, &query.operation, &query.phase, &query.channel)
            || query.selected.is_some()
            || query.result.dimension == Dimension::Mixed
        {
            return Err(corrupt("measurement query binding"));
        }
        Self::validate_summary(STATISTICS, &query.result)
    }
    fn query_result(code: IndexCode, operation: &str, summary: &Summary) -> Result<Summary> {
        if !Self::supports_query(code, operation, "calculate", "statistics") {
            return Err(corrupt("measurement summary query"));
        }
        Self::validate_summary(code, summary)?;
        Ok(*summary)
    }
    fn descriptors() -> Vec<IndexDescriptor> {
        let projected = closed(
            json!({"count":{"type":"integer","minimum":0,"maximum":MAX_COUNT},
            "sum":number_schema(),"min":nullable(value_schema()),"max":nullable(value_schema()),"unit":nullable(unit_schema())}),
        );
        vec![IndexDescriptor {
            code: STATISTICS,
            name: "measurement_statistics",
            reads: vec!["summary", "before", "range"],
            key_schema: crate::indexes::standard::time_schema(),
            leaf_schema: closed(json!({"unit":unit_schema(),"value":value_schema()})),
            summary_schema: closed(
                json!({"count":{"type":"integer","minimum":0,"maximum":MAX_COUNT},
                "sum":number_schema(),"min":nullable(value_schema()),"max":nullable(value_schema()),
                "dimension":{"oneOf":[closed(json!({"kind":{"const":"empty"}})),
                    closed(json!({"kind":{"const":"unit"},"code":unit_schema()})),
                    closed(json!({"kind":{"const":"mixed"}}))]}}),
            ),
            result_schemas: json!({"summary":projected,"before":projected,"range":projected}),
            time: true,
            financial: false,
            quote: false,
        }]
    }
    fn validate_key(code: IndexCode, _key: &TimeKey) -> Result<()> {
        kind(code)
    }
    fn validate_leaf(code: IndexCode, leaf: &Observation) -> Result<()> {
        kind(code)?;
        if leaf.unit > 0 && (-MAX_VALUE..=MAX_VALUE).contains(&leaf.value) {
            Ok(())
        } else {
            Err(corrupt("measurement leaf bounds"))
        }
    }
    fn validate_summary(code: IndexCode, s: &Summary) -> Result<()> {
        kind(code)?;
        if s.count == 0 {
            return if *s == Summary::default() {
                Ok(())
            } else {
                Err(corrupt("nonempty measurement identity"))
            };
        }
        let (Some(min), Some(max)) = (s.min, s.max) else {
            return Err(corrupt("missing measurement extrema"));
        };
        let dimension = matches!(s.dimension, Dimension::Unit { code } if code > 0)
            || (s.count > 1 && s.dimension == Dimension::Mixed);
        if s.count <= MAX_COUNT
            && dimension
            && -MAX_VALUE <= min
            && min <= max
            && max <= MAX_VALUE
            && i128::from(s.count) * min <= s.sum
            && s.sum <= i128::from(s.count) * max
            && (s.count != 1 || min == max)
        {
            Ok(())
        } else {
            Err(corrupt("measurement summary bounds"))
        }
    }
    fn empty(code: IndexCode) -> Result<Summary> {
        kind(code)?;
        Ok(Summary::default())
    }
    fn singleton(code: IndexCode, key: &TimeKey, leaf: &Observation) -> Result<Summary> {
        Self::validate_key(code, key)?;
        Self::validate_leaf(code, leaf)?;
        Ok(Summary {
            count: 1,
            sum: leaf.value,
            min: Some(leaf.value),
            max: Some(leaf.value),
            dimension: Dimension::Unit { code: leaf.unit },
        })
    }
    fn combine(code: IndexCode, a: &Summary, b: &Summary) -> Result<Summary> {
        Self::validate_summary(code, a)?;
        Self::validate_summary(code, b)?;
        if a.count == 0 {
            return Ok(*b);
        }
        if b.count == 0 {
            return Ok(*a);
        }
        let s = Summary {
            count: a
                .count
                .checked_add(b.count)
                .ok_or_else(|| Error::new("overflow", "measurement count"))?,
            sum: a
                .sum
                .checked_add(b.sum)
                .ok_or_else(|| Error::new("overflow", "measurement sum"))?,
            min: a.min.into_iter().chain(b.min).min(),
            max: a.max.into_iter().chain(b.max).max(),
            dimension: if a.dimension == b.dimension {
                a.dimension
            } else {
                Dimension::Mixed
            },
        };
        Self::validate_summary(code, &s)?;
        Ok(s)
    }
    fn project(code: IndexCode, _read: SummaryRead, s: &Summary) -> Result<Value> {
        Self::validate_summary(code, s)?;
        let unit = match s.dimension {
            Dimension::Empty => None,
            Dimension::Unit { code } => Some(code),
            Dimension::Mixed => return Err(corrupt("mixed measurement dimension in settled root")),
        };
        Ok(
            json!({"count":s.count,"sum":s.sum.to_string(),"min":s.min.map(|v|v.to_string()),"max":s.max.map(|v|v.to_string()),"unit":unit}),
        )
    }
    fn time_key(code: IndexCode, at: i64) -> Result<TimeKey> {
        kind(code)?;
        Ok(TimeKey::new(at))
    }
    fn time(code: IndexCode, key: &TimeKey) -> Result<i64> {
        kind(code)?;
        Ok(key.get())
    }
}
