use serde::{Deserialize, Serialize};

/// Fixed-scale exact units. Times are an already ordered nanosecond key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub count: u64,
    pub first: Option<i64>,
    pub last: Option<i64>,
    pub sum: i128,
    pub min_prefix: i128,
    pub max_prefix: i128,
    pub boundary_min: Option<i128>,
    pub boundary_max: Option<i128>,
}

fn add(a: i128, b: i128) -> Result<i128, &'static str> {
    a.checked_add(b).ok_or("exact amount overflow")
}

impl Summary {
    pub fn leaf(time: i64, amount: Option<i128>) -> Self {
        let sum = amount.unwrap_or(0);
        Self {
            count: 1,
            first: Some(time),
            last: Some(time),
            sum,
            min_prefix: sum.min(0),
            max_prefix: sum.max(0),
            boundary_min: None,
            boundary_max: None,
        }
    }

    pub fn combine(self, other: Self) -> Result<Self, &'static str> {
        if self.count == 0 {
            return Ok(other);
        }
        if other.count == 0 {
            return Ok(self);
        }
        if self.last > other.first {
            return Err("segments must be ordered");
        }
        let split = (self.last < other.first).then_some(self.sum);
        let right_min = other.boundary_min.map(|x| add(self.sum, x)).transpose()?;
        let right_max = other.boundary_max.map(|x| add(self.sum, x)).transpose()?;
        Ok(Self {
            count: self
                .count
                .checked_add(other.count)
                .ok_or("count overflow")?,
            first: self.first,
            last: other.last,
            sum: add(self.sum, other.sum)?,
            min_prefix: self.min_prefix.min(add(self.sum, other.min_prefix)?),
            max_prefix: self.max_prefix.max(add(self.sum, other.max_prefix)?),
            boundary_min: [self.boundary_min, right_min, split]
                .into_iter()
                .flatten()
                .min(),
            boundary_max: [self.boundary_max, right_max, split]
                .into_iter()
                .flatten()
                .max(),
        })
    }

    pub fn complete_min(self) -> i128 {
        self.sum.min(0).min(self.boundary_min.unwrap_or(0))
    }

    pub fn complete_max(self) -> i128 {
        self.sum.max(0).max(self.boundary_max.unwrap_or(0))
    }
}
