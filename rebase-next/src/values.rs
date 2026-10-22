//! Exact integer-minor-unit multiplication with an explicit rounding boundary.
//!
//! Native inputs are bounded by `i128`; the exact product needs at most 255
//! magnitude bits. Only the rounded final result must fit back into `i128`.

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{Signed, ToPrimitive, Zero};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, MapAccess, Visitor, value::MapAccessDeserializer},
};
use serde_json::{Value, json};

use crate::{
    model::SCHEMA_DIALECT,
    native_codec::decimal,
    native_slice::{Error, Result},
};

/// How an exact rational result is quantized to an integer minor unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rounding {
    TowardZero,
    Floor,
    Ceiling,
    HalfEven,
    HalfAwayFromZero,
    /// Reject a result that is not already an integer.
    Exact,
}

impl Rounding {
    const ALL: [Self; 6] = [
        Self::TowardZero,
        Self::Floor,
        Self::Ceiling,
        Self::HalfEven,
        Self::HalfAwayFromZero,
        Self::Exact,
    ];

    /// The same Serde names accepted by the native enum, for model catalogs.
    pub fn schema() -> Value {
        json!({"$schema":SCHEMA_DIALECT,"type":"string","enum":Self::ALL})
    }
}

/// A reduced rational with a positive denominator; zero is always `0/1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Rational {
    #[serde(with = "decimal")]
    numerator: i128,
    #[serde(with = "decimal")]
    denominator: i128,
}

impl Rational {
    pub fn new(numerator: i128, denominator: i128) -> Result<Self> {
        if denominator <= 0 {
            return Err(Error::new(
                "invalid_input",
                "rational denominator must be positive",
            ));
        }
        // BigInt also makes the magnitude of i128::MIN safe during reduction.
        let numerator = BigInt::from(numerator);
        let denominator = BigInt::from(denominator);
        let divisor = numerator.gcd(&denominator);
        let reduced = |value: BigInt| {
            value
                .to_i128()
                .ok_or_else(|| Error::new("overflow", "reduced rational component"))
        };
        Ok(Self {
            numerator: reduced(numerator / &divisor)?,
            denominator: reduced(denominator / divisor)?,
        })
    }

    pub fn numerator(self) -> i128 {
        self.numerator
    }

    pub fn denominator(self) -> i128 {
        self.denominator
    }

    /// Multiply exactly, then round once. Intermediate products cannot cause a
    /// false overflow; an out-of-range rounded result returns `overflow`.
    pub fn apply(self, amount_minor: i128, rounding: Rounding) -> Result<i128> {
        let product = BigInt::from(amount_minor) * BigInt::from(self.numerator);
        let negative = product.is_negative();
        let denominator = BigInt::from(self.denominator);
        let (mut quotient, remainder) = product.abs().div_rem(&denominator);
        if !remainder.is_zero() {
            let increment = match rounding {
                Rounding::TowardZero => false,
                Rounding::Floor => negative,
                Rounding::Ceiling => !negative,
                Rounding::HalfEven => {
                    let twice = &remainder * 2u8;
                    twice > denominator || (twice == denominator && quotient.is_odd())
                }
                Rounding::HalfAwayFromZero => &remainder * 2u8 >= denominator,
                Rounding::Exact => return Err(Error::new("inexact", "fractional minor unit")),
            };
            if increment {
                quotient += 1u8;
            }
        }
        let rounded = if negative { -quotient } else { quotient };
        rounded
            .to_i128()
            .ok_or_else(|| Error::new("overflow", "rounded minor-unit amount"))
    }

    /// Closed canonical integer-string fields. Native binding additionally
    /// enforces the bounds, positive denominator and reduced representation.
    pub fn schema() -> Value {
        json!({
            "$schema":SCHEMA_DIALECT,
            "type":"object",
            "additionalProperties":false,
            "required":["numerator","denominator"],
            "properties":{
                "numerator":{
                    "type":"string",
                    "pattern":"^(0|-?[1-9][0-9]{0,38})$",
                    "x-rebase-binding":"i128",
                    "x-rebase-range":[i128::MIN.to_string(),i128::MAX.to_string()]
                },
                "denominator":{
                    "type":"string",
                    "pattern":"^[1-9][0-9]{0,38}$",
                    "x-rebase-binding":"i128",
                    "x-rebase-range":["1",i128::MAX.to_string()]
                }
            }
        })
    }
}

impl<'de> Deserialize<'de> for Rational {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(with = "decimal")]
            numerator: i128,
            #[serde(with = "decimal")]
            denominator: i128,
        }
        // Derived struct deserializers also accept positional sequences. This
        // wire contract requires an object, while Wire retains duplicate-field
        // and unknown-field checks for its map entries.
        struct Object;
        impl<'de> Visitor<'de> for Object {
            type Value = Wire;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a rational object")
            }

            fn visit_map<M: MapAccess<'de>>(self, map: M) -> std::result::Result<Wire, M::Error> {
                Wire::deserialize(MapAccessDeserializer::new(map))
            }
        }
        let wire = deserializer.deserialize_map(Object)?;
        let value = Self::new(wire.numerator, wire.denominator).map_err(D::Error::custom)?;
        if value.numerator != wire.numerator || value.denominator != wire.denominator {
            return Err(D::Error::custom(
                "rational must be reduced; zero must be 0/1",
            ));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduction_and_canonical_wire_preserve_native_boundaries() {
        assert_eq!(Rational::new(6, 4).unwrap(), Rational::new(3, 2).unwrap());
        assert_eq!(
            Rational::new(0, i128::MAX).unwrap(),
            Rational::new(0, 1).unwrap()
        );
        let min = Rational::new(i128::MIN, 2).unwrap();
        assert_eq!(min.numerator(), -85070591730234615865843651857942052864);
        assert_eq!(min.denominator(), 1);
        for value in [
            Rational::new(i128::MIN, 1).unwrap(),
            Rational::new(1, i128::MAX).unwrap(),
            min,
        ] {
            let wire = serde_json::to_value(value).unwrap();
            assert_eq!(serde_json::from_value::<Rational>(wire).unwrap(), value);
        }
        assert_eq!(
            serde_json::to_value(Rational::new(6, 4).unwrap()).unwrap(),
            json!({"numerator":"3","denominator":"2"})
        );
        for denominator in [i128::MIN, -1, 0] {
            assert_eq!(
                Rational::new(1, denominator).unwrap_err().code,
                "invalid_input"
            );
        }
    }

    #[test]
    fn wire_rejects_noncanonical_or_unbounded_values() {
        for wire in [
            json!(["1", "2"]),
            json!(["0", "1"]),
            json!([]),
            json!(["1", "2", "3"]),
            json!({"numerator":"2","denominator":"4"}),
            json!({"numerator":"0","denominator":"2"}),
            json!({"numerator":"1","denominator":"0"}),
            json!({"numerator":"1","denominator":"-2"}),
            json!({"numerator":"-0","denominator":"1"}),
            json!({"numerator":"01","denominator":"1"}),
            json!({"numerator":"+1","denominator":"1"}),
            json!({"numerator":" 1","denominator":"1"}),
            json!({"numerator":"1e0","denominator":"1"}),
            json!({"numerator":"1.0","denominator":"1"}),
            json!({"numerator":"1","denominator":"01"}),
            json!({"numerator":1,"denominator":"1"}),
            json!({"numerator":null,"denominator":"1"}),
            json!({"numerator":"1"}),
            json!({"numerator":"1","denominator":"1","extra":true}),
            json!({"numerator":"170141183460469231731687303715884105728","denominator":"1"}),
            json!({"numerator":"-170141183460469231731687303715884105729","denominator":"1"}),
        ] {
            assert!(
                serde_json::from_value::<Rational>(wire.clone()).is_err(),
                "{wire}"
            );
        }
        assert!(
            serde_json::from_str::<Rational>(
                r#"{"numerator":"1","numerator":"1","denominator":"1"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn ties_and_directed_rounding_are_explicit_for_both_signs() {
        use Rounding::*;
        let half = Rational::new(1, 2).unwrap();
        for (amount, rounding, expected) in [
            (5, HalfEven, 2),
            (-5, HalfEven, -2),
            (7, HalfEven, 4),
            (-7, HalfEven, -4),
            (5, HalfAwayFromZero, 3),
            (-5, HalfAwayFromZero, -3),
            (5, TowardZero, 2),
            (-5, TowardZero, -2),
            (5, Floor, 2),
            (-5, Floor, -3),
            (5, Ceiling, 3),
            (-5, Ceiling, -2),
            (1, HalfEven, 0),
            (-1, HalfEven, 0),
        ] {
            assert_eq!(
                half.apply(amount, rounding).unwrap(),
                expected,
                "{amount} {rounding:?}"
            );
        }
        let third = Rational::new(1, 3).unwrap();
        for (amount, rounding, expected) in [
            (1, HalfEven, 0),
            (-1, HalfEven, 0),
            (2, HalfEven, 1),
            (-2, HalfEven, -1),
            (1, HalfAwayFromZero, 0),
            (-1, HalfAwayFromZero, 0),
            (2, HalfAwayFromZero, 1),
            (-2, HalfAwayFromZero, -1),
            (1, Ceiling, 1),
            (-1, Floor, -1),
        ] {
            assert_eq!(third.apply(amount, rounding).unwrap(), expected);
        }
        assert_eq!(half.apply(5, Exact).unwrap_err().code, "inexact");
        assert_eq!(half.apply(-5, Exact).unwrap_err().code, "inexact");
        assert_eq!(half.apply(6, Exact).unwrap(), 3);
        assert_eq!(
            Rational::new(-1, 2)
                .unwrap()
                .apply(5, HalfAwayFromZero)
                .unwrap(),
            -3
        );
    }

    #[test]
    fn intermediate_overflow_is_distinct_from_final_overflow() {
        use Rounding::*;
        let maximum = i128::MAX;
        for rounding in Rounding::ALL {
            assert_eq!(
                Rational::new(1, 1)
                    .unwrap()
                    .apply(i128::MIN, rounding)
                    .unwrap(),
                i128::MIN
            );
            assert_eq!(
                Rational::new(2, 2)
                    .unwrap()
                    .apply(maximum, rounding)
                    .unwrap(),
                maximum
            );
            assert_eq!(
                Rational::new(0, 1)
                    .unwrap()
                    .apply(i128::MIN, rounding)
                    .unwrap(),
                0
            );
            assert_eq!(
                Rational::new(-1, 1)
                    .unwrap()
                    .apply(i128::MIN, rounding)
                    .unwrap_err()
                    .code,
                "overflow"
            );
            assert_eq!(
                Rational::new(2, 1)
                    .unwrap()
                    .apply(maximum, rounding)
                    .unwrap_err()
                    .code,
                "overflow"
            );
        }
        // No numerator/denominator cancellation is possible before this product.
        let rate = Rational::new(maximum - 1, maximum).unwrap();
        assert_eq!(rate.apply(maximum - 1, HalfEven).unwrap(), maximum - 2);
        assert_eq!(rate.apply(maximum - 1, Ceiling).unwrap(), maximum - 1);
        assert_eq!(rate.apply(maximum - 1, Exact).unwrap_err().code, "inexact");
        // The exact value is MAX + 1/(MAX - 2): quantization decides whether
        // the final integer fits, rather than the unrounded rational value.
        let upper_edge = Rational::new(maximum - 1, maximum - 2).unwrap();
        assert_eq!(upper_edge.apply(maximum - 1, Floor).unwrap(), maximum);
        assert_eq!(upper_edge.apply(maximum - 1, HalfEven).unwrap(), maximum);
        assert_eq!(
            upper_edge.apply(maximum - 1, Ceiling).unwrap_err().code,
            "overflow"
        );
        // Here the exact value is MIN - 2/(MAX - 2).
        assert_eq!(upper_edge.apply(-maximum, Ceiling).unwrap(), i128::MIN);
        assert_eq!(upper_edge.apply(-maximum, HalfEven).unwrap(), i128::MIN);
        assert_eq!(
            upper_edge.apply(-maximum, Floor).unwrap_err().code,
            "overflow"
        );
        assert_eq!(
            Rational::new(i128::MIN, maximum)
                .unwrap()
                .apply(maximum, Exact)
                .unwrap(),
            i128::MIN
        );
        assert_eq!(
            Rational::new(i128::MIN, 1)
                .unwrap()
                .apply(i128::MIN, Exact)
                .unwrap_err()
                .code,
            "overflow"
        );
    }

    #[test]
    fn tax_fx_and_rounding_location_are_model_choices() {
        assert_eq!(
            Rational::new(825, 10000)
                .unwrap()
                .apply(10005, Rounding::HalfEven)
                .unwrap(),
            825
        );
        assert_eq!(
            Rational::new(107, 100)
                .unwrap()
                .apply(12345, Rounding::HalfEven)
                .unwrap(),
            13209
        );
        let half = Rational::new(1, 2).unwrap();
        assert_eq!(3 * half.apply(1, Rounding::HalfEven).unwrap(), 0);
        assert_eq!(half.apply(3, Rounding::HalfEven).unwrap(), 2);
    }

    #[test]
    fn schema_exports_the_wire_contract_and_rounding_names() {
        let schema = Rational::schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["numerator"]["x-rebase-range"][0],
            i128::MIN.to_string()
        );
        assert_eq!(
            schema["properties"]["denominator"]["x-rebase-range"][0],
            "1"
        );
        let names = json!([
            "toward_zero",
            "floor",
            "ceiling",
            "half_even",
            "half_away_from_zero",
            "exact"
        ]);
        assert_eq!(Rounding::schema()["enum"], names);
        for name in names.as_array().unwrap() {
            let rounding: Rounding = serde_json::from_value(name.clone()).unwrap();
            assert_eq!(serde_json::to_value(rounding).unwrap(), *name);
        }
        for invalid in [
            json!("up"),
            json!("half_up"),
            json!("HalfEven"),
            json!(null),
            json!(1),
        ] {
            assert!(serde_json::from_value::<Rounding>(invalid).is_err());
        }
    }
}
