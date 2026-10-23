//! Exact complete-timestamp windows shared by query and reactive boundaries.
//! Neither UUID ties nor arithmetic timestamp sentinels affect membership.
use crate::native_codec::decimal;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TimeBound {
    #[default]
    Unbounded,
    Included(i64),
    Excluded(i64),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FiniteBound {
    Included(#[serde(with = "decimal")] i64),
    Excluded(#[serde(with = "decimal")] i64),
}

impl Serialize for TimeBound {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match *self {
            Self::Unbounded => None::<FiniteBound>,
            Self::Included(at) => Some(FiniteBound::Included(at)),
            Self::Excluded(at) => Some(FiniteBound::Excluded(at)),
        }
        .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for TimeBound {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match Option::<FiniteBound>::deserialize(deserializer)? {
            None => Self::Unbounded,
            Some(FiniteBound::Included(at)) => Self::Included(at),
            Some(FiniteBound::Excluded(at)) => Self::Excluded(at),
        })
    }
}

/// Cuts are positions between complete timestamp groups, not stored records.
/// Endpoint order includes the side of a timestamp and never adds/subtracts one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Cut {
    NegativeInfinity,
    Time(i64, Side),
    PositiveInfinity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Side {
    Before,
    After,
}

impl TimeBound {
    pub fn schema() -> serde_json::Value {
        let time = serde_json::json!({"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","x-rebase-binding":"i64","x-rebase-range":[i64::MIN.to_string(),i64::MAX.to_string()]});
        serde_json::json!({"oneOf":[
            {"type":"null"},
            {"type":"object","properties":{"included":time},"required":["included"],"additionalProperties":false},
            {"type":"object","properties":{"excluded":time},"required":["excluded"],"additionalProperties":false}
        ]})
    }
    pub(crate) fn lower_cut(self) -> Cut {
        match self {
            Self::Unbounded => Cut::NegativeInfinity,
            Self::Included(at) => Cut::Time(at, Side::Before),
            Self::Excluded(at) => Cut::Time(at, Side::After),
        }
    }
    pub(crate) fn upper_cut(self) -> Cut {
        match self {
            Self::Unbounded => Cut::PositiveInfinity,
            Self::Included(at) => Cut::Time(at, Side::After),
            Self::Excluded(at) => Cut::Time(at, Side::Before),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TimeRange {
    pub lower: TimeBound,
    pub upper: TimeBound,
}

impl<'de> Deserialize<'de> for TimeRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RangeVisitor;
        impl<'de> de::Visitor<'de> for RangeVisitor {
            type Value = TimeRange;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object with lower and upper time bounds")
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<TimeRange, A::Error> {
                let (mut lower, mut upper) = (None, None);
                while let Some(key) = map.next_key::<String>()? {
                    let field = match key.as_str() {
                        "lower" => &mut lower,
                        "upper" => &mut upper,
                        _ => return Err(de::Error::unknown_field(&key, &["lower", "upper"])),
                    };
                    if field.is_some() {
                        return Err(de::Error::custom(format!("duplicate field {key}")));
                    }
                    *field = Some(map.next_value::<TimeBound>()?);
                }
                Ok(TimeRange {
                    lower: lower.ok_or_else(|| de::Error::missing_field("lower"))?,
                    upper: upper.ok_or_else(|| de::Error::missing_field("upper"))?,
                })
            }
        }
        deserializer.deserialize_map(RangeVisitor)
    }
}

impl TimeRange {
    pub fn schema() -> serde_json::Value {
        serde_json::json!({"type":"object","properties":{"lower":TimeBound::schema(),"upper":TimeBound::schema()},"required":["lower","upper"],"additionalProperties":false})
    }
    pub const ALL: Self = Self {
        lower: TimeBound::Unbounded,
        upper: TimeBound::Unbounded,
    };
    pub const fn before(at: i64) -> Self {
        Self {
            lower: TimeBound::Unbounded,
            upper: TimeBound::Excluded(at),
        }
    }
    pub const fn through(at: i64) -> Self {
        Self {
            lower: TimeBound::Unbounded,
            upper: TimeBound::Included(at),
        }
    }
    pub fn contains(self, at: i64) -> bool {
        let lower = match self.lower {
            TimeBound::Unbounded => true,
            TimeBound::Included(value) => value <= at,
            TimeBound::Excluded(value) => value < at,
        };
        let upper = match self.upper {
            TimeBound::Unbounded => true,
            TimeBound::Included(value) => at <= value,
            TimeBound::Excluded(value) => at < value,
        };
        lower && upper
    }
    /// Includes empty discrete gaps such as (0, 1), and extreme open ends.
    pub fn is_empty(self) -> bool {
        use TimeBound::{Excluded, Included, Unbounded};
        match (self.lower, self.upper) {
            (Excluded(i64::MAX), _) | (_, Excluded(i64::MIN)) => true,
            (Unbounded, _) | (_, Unbounded) => false,
            (Included(a), Included(b)) => a > b,
            (Included(a), Excluded(b)) | (Excluded(a), Included(b)) => a >= b,
            (Excluded(a), Excluded(b)) => a >= b || a.abs_diff(b) == 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn closed_open_and_extreme_membership_matches_literal_predicates() {
        let points = [
            i64::MIN,
            i64::MIN + 1,
            -2,
            -1,
            0,
            1,
            2,
            i64::MAX - 1,
            i64::MAX,
        ];
        let mut bounds = vec![TimeBound::Unbounded];
        for at in points {
            bounds.extend([TimeBound::Included(at), TimeBound::Excluded(at)]);
        }
        for &lower in &bounds {
            for &upper in &bounds {
                let range = TimeRange { lower, upper };
                for at in points {
                    let minimum = match lower {
                        TimeBound::Unbounded => i128::from(i64::MIN),
                        TimeBound::Included(n) => i128::from(n),
                        TimeBound::Excluded(n) => i128::from(n) + 1,
                    };
                    let maximum = match upper {
                        TimeBound::Unbounded => i128::from(i64::MAX),
                        TimeBound::Included(n) => i128::from(n),
                        TimeBound::Excluded(n) => i128::from(n) - 1,
                    };
                    assert_eq!(
                        range.contains(at),
                        minimum <= i128::from(at) && i128::from(at) <= maximum
                    );
                    assert_eq!(range.is_empty(), minimum > maximum);
                }
            }
        }
        assert!(TimeRange::through(i64::MIN).contains(i64::MIN));
        assert!(TimeRange::before(i64::MIN).is_empty());
        assert!(TimeRange::ALL.contains(i64::MAX));
        assert!(TimeBound::Included(0).lower_cut() < TimeBound::Excluded(0).lower_cut());
        assert!(TimeBound::Excluded(0).upper_cut() < TimeBound::Included(0).upper_cut());
    }

    #[test]
    fn wire_is_canonical_closed_and_preserves_empty_window_identity() {
        let value = json!({"lower":{"included":"5"},"upper":{"excluded":"5"}});
        let range: TimeRange = serde_json::from_value(value.clone()).unwrap();
        assert!(range.is_empty());
        assert_eq!(serde_json::to_value(range).unwrap(), value);
        assert_eq!(
            serde_json::to_value(TimeRange::ALL).unwrap(),
            json!({"lower":null,"upper":null})
        );
        for value in [
            json!({"lower":{"included":0},"upper":null}),
            json!({"lower":{"included":"00"},"upper":null}),
            json!({"lower":{"included":"-0"},"upper":null}),
            json!({"lower":{"included":"9223372036854775808"},"upper":null}),
            json!({"lower":{"included":"0","excluded":"1"},"upper":null}),
            json!({"lower":null,"upper":null,"extra":true}),
            json!({"lower":null}),
            json!([null, null]),
        ] {
            assert!(
                serde_json::from_value::<TimeRange>(value.clone()).is_err(),
                "accepted {value}"
            );
        }
    }
}
