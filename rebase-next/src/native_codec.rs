//! One strict point-key/value codec for the bounded native experiment.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    native_slice::{Error, Meta, Query, Record, Result},
    tree::{Node, Root},
};

pub const CODEC: &str = "native-slice-kv-1";

pub mod decimal {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use std::{fmt::Display, str::FromStr};

    pub fn serialize<T: Display, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr + Display,
        T::Err: Display,
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        let value = text.parse::<T>().map_err(D::Error::custom)?;
        if text != value.to_string() {
            return Err(D::Error::custom("noncanonical decimal string"));
        }
        Ok(value)
    }
}

pub mod optional_decimal {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use std::{fmt::Display, str::FromStr};

    pub fn serialize<T: Display, S: Serializer>(
        value: &Option<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        T: FromStr + Display,
        T::Err: Display,
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|text| {
                let value = text.parse::<T>().map_err(D::Error::custom)?;
                if text != value.to_string() {
                    return Err(D::Error::custom("noncanonical decimal string"));
                }
                Ok(value)
            })
            .transpose()
    }
}

pub mod uuid_text {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use uuid::Uuid;

    pub fn serialize<S: Serializer>(value: &Uuid, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Uuid, D::Error> {
        let text = String::deserialize(deserializer)?;
        let value = Uuid::parse_str(&text).map_err(D::Error::custom)?;
        if text != value.to_string() {
            return Err(D::Error::custom("noncanonical UUID"));
        }
        Ok(value)
    }
}

pub mod summary {
    use super::{decimal, optional_decimal};
    use crate::algebra::Summary;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        count: u64,
        #[serde(with = "optional_decimal")]
        first: Option<i64>,
        #[serde(with = "optional_decimal")]
        last: Option<i64>,
        #[serde(with = "decimal")]
        sum: i128,
        #[serde(with = "decimal")]
        min_prefix: i128,
        #[serde(with = "decimal")]
        max_prefix: i128,
        #[serde(with = "optional_decimal")]
        boundary_min: Option<i128>,
        #[serde(with = "optional_decimal")]
        boundary_max: Option<i128>,
    }

    pub fn serialize<S: Serializer>(s: &Summary, serializer: S) -> Result<S::Ok, S::Error> {
        Wire {
            count: s.count,
            first: s.first,
            last: s.last,
            sum: s.sum,
            min_prefix: s.min_prefix,
            max_prefix: s.max_prefix,
            boundary_min: s.boundary_min,
            boundary_max: s.boundary_max,
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Summary, D::Error> {
        let w = Wire::deserialize(deserializer)?;
        Ok(Summary {
            count: w.count,
            first: w.first,
            last: w.last,
            sum: w.sum,
            min_prefix: w.min_prefix,
            max_prefix: w.max_prefix,
            boundary_min: w.boundary_min,
            boundary_max: w.boundary_max,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Address {
    #[serde(with = "uuid_text")]
    pub id: Uuid,
    pub slot: u16,
}

impl Address {
    pub fn new(id: Uuid, slot: u16) -> Self {
        Self { id, slot }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Key {
    Meta,
    Record(Uuid),
    Root(Address),
    Node(Address),
    Query(Address),
    Incoming(Uuid),
    Direct(Uuid),
    Subscribers(Address),
}

impl Key {
    pub fn encode(&self) -> Vec<u8> {
        let (tag, id, slot) = match self {
            Self::Meta => return vec![0],
            Self::Record(id) => (1, *id, None),
            Self::Root(a) => (2, a.id, Some(a.slot)),
            Self::Node(a) => (3, a.id, Some(a.slot)),
            Self::Query(a) => (4, a.id, Some(a.slot)),
            Self::Incoming(id) => (5, *id, None),
            Self::Direct(id) => (6, *id, None),
            Self::Subscribers(a) => (7, a.id, Some(a.slot)),
        };
        let mut bytes = vec![tag];
        bytes.extend_from_slice(id.as_bytes());
        if let Some(slot) = slot {
            bytes.extend_from_slice(&slot.to_be_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let bad = || Error::new("corrupt_state", "invalid point key");
        if bytes == [0] {
            return Ok(Self::Meta);
        }
        let tag = *bytes.first().ok_or_else(bad)?;
        let length = match tag {
            1 | 5 | 6 => 17,
            2..=4 | 7 => 19,
            _ => return Err(bad()),
        };
        if bytes.len() != length {
            return Err(bad());
        }
        let id = Uuid::from_slice(&bytes[1..17]).map_err(|_| bad())?;
        let slot = if length == 19 {
            u16::from_be_bytes([bytes[17], bytes[18]])
        } else {
            0
        };
        if length == 19
            && !(if tag == 2 || tag == 3 {
                (1..=3).contains(&slot)
            } else {
                slot == 1
            })
        {
            return Err(bad());
        }
        let a = Address::new(id, slot);
        Ok(match tag {
            1 => Self::Record(id),
            2 => Self::Root(a),
            3 => Self::Node(a),
            4 => Self::Query(a),
            5 => Self::Incoming(id),
            6 => Self::Direct(id),
            7 => Self::Subscribers(a),
            _ => return Err(bad()),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Stored {
    Meta(Meta),
    Record(Record),
    Root(Root),
    Node(Node),
    Query(Query),
    Incoming(Vec<Address>),
    Direct(Vec<Address>),
    Subscribers(Vec<Address>),
}

pub fn encode(key: &Key, value: &Stored) -> Result<Vec<u8>> {
    validate(key, value)?;
    serde_json::to_vec(value).map_err(|e| Error::new("codec", e.to_string()))
}

pub fn decode(key: &Key, bytes: &[u8]) -> Result<Stored> {
    let value =
        serde_json::from_slice(bytes).map_err(|e| Error::new("corrupt_state", e.to_string()))?;
    if encode(key, &value)? != bytes {
        return Err(Error::new("corrupt_state", "noncanonical value bytes"));
    }
    Ok(value)
}

fn validate(key: &Key, value: &Stored) -> Result<()> {
    use crate::tree::Kind;
    let valid = match (key, value) {
        (Key::Meta, Stored::Meta(meta)) => {
            !meta.codec.is_empty()
                && !meta.model.is_empty()
                && meta.counts.iter().map(|n| u32::from(*n)).sum::<u32>() <= 64
                && meta.counts[2] <= 16
                && meta.counts[5] <= 16
        }
        (Key::Record(_), Stored::Record(r)) => {
            r.contract == r.input.contract()
                && r.input.validate().is_ok()
                && r.derived.is_some() == (r.contract == 6)
        }
        (Key::Root(a), Stored::Root(r)) => {
            matches!(
                (a.slot, r.kind),
                (1, Kind::Quote) | (2 | 3, Kind::Financial)
            ) && r.summary.kind() == r.kind
        }
        (Key::Node(a), Stored::Node(n)) => {
            n.key.id == a.id
                && n.key.slot == a.slot
                && matches!(
                    (a.slot, n.root.slot, n.leaf.kind()),
                    (1, 2, Kind::Financial) | (2, 3, Kind::Financial) | (3, 1, Kind::Quote)
                )
                && n.summary.kind() == n.leaf.kind()
        }
        (Key::Query(a), Stored::Query(q)) => {
            a.slot == 1
                && q.source.slot == 1
                && q.operation == "latest"
                && q.phase == "calculate"
                && q.channel == "rate"
                && q.lower == "negative_infinity"
                && (1..=1000).contains(&q.result)
        }
        (Key::Incoming(_), Stored::Incoming(rows))
        | (Key::Direct(_), Stored::Direct(rows))
        | (Key::Subscribers(_), Stored::Subscribers(rows)) => {
            rows.windows(2).all(|w| w[0] < w[1]) && rows.iter().all(|a| a.slot > 0)
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::new("corrupt_state", "key/value role mismatch"))
    }
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                char::from(DIGITS[usize::from(b >> 4)]),
                char::from(DIGITS[usize::from(b & 15)]),
            ]
        })
        .collect()
}
