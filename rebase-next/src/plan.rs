use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub name: String,
    pub inputs: Vec<String>,
}

/// Ready ties retain declaration order; dependencies always precede consumers.
pub fn evaluation_order(fields: &[Field]) -> Result<Vec<usize>, String> {
    let mut names = BTreeMap::new();
    for (index, field) in fields.iter().enumerate() {
        if names.insert(&field.name, index).is_some() {
            return Err(format!("duplicate field {}", field.name));
        }
    }
    let mut pending = vec![0; fields.len()];
    let mut dependents = vec![Vec::new(); fields.len()];
    for (index, field) in fields.iter().enumerate() {
        for input in field.inputs.iter().collect::<BTreeSet<_>>() {
            let source = *names
                .get(input)
                .ok_or_else(|| format!("unknown input {input}"))?;
            pending[index] += 1;
            dependents[source].push(index);
        }
    }
    let mut ready: BTreeSet<_> = (0..fields.len()).filter(|&i| pending[i] == 0).collect();
    let mut order = Vec::new();
    while let Some(index) = ready.pop_first() {
        order.push(index);
        for &consumer in &dependents[index] {
            pending[consumer] -= 1;
            if pending[consumer] == 0 {
                ready.insert(consumer);
            }
        }
    }
    if order.len() != fields.len() {
        return Err("calculation cycle".into());
    }
    Ok(order)
}

/// Exact current scalar-reader fold; incomparable candidates keep first choice.
pub fn choose_reader<T: Copy>(
    candidates: &[T],
    fallback: T,
    dominates: impl Fn(T, T) -> bool,
) -> T {
    let Some((&first, rest)) = candidates.split_first() else {
        return fallback;
    };
    rest.iter().fold(first, |selected, &next| {
        if dominates(selected, next) {
            next
        } else {
            selected
        }
    })
}
