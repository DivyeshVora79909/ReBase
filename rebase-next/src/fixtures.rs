//! Offline, design-owned authored inputs. Execution always uses public mutation.

use crate::{
    model::PreparedModel,
    native_slice::{Command, Error, Result},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Recipe {
    pub name: String,
    pub tenant: Uuid,
    pub actor: Uuid,
    pub ids: BTreeMap<String, Uuid>,
    pub commands: Vec<Command>,
    pub expected: Value,
}

pub(crate) fn bundled() -> Result<Recipe> {
    serde_json::from_str(include_str!("../model/fixtures/causal-demo.json"))
        .map_err(|e| Error::new("fixture", e.to_string()))
}

pub fn catalog() -> Value {
    json!([{"name":"causal-diamond","source":"model/fixtures/causal-demo.json",
        "description":"Two moved prefix readers and a private-output reporting diamond",
        "identity":"UUIDv5(namespace, fixture-name/record-label)",
        "execution":"one ordinary records.mutate operation"}])
}

fn prepare(model: &PreparedModel, mut recipe: Recipe, namespace: Uuid) -> Result<Value> {
    let error = |message| Error::new("fixture", message);
    let original_ids: BTreeSet<_> = recipe.ids.values().copied().collect();
    let commands: BTreeSet<_> = recipe.commands.iter().map(Command::id).collect();
    if recipe.commands.is_empty()
        || recipe.commands.len() > 64
        || recipe.commands.len() != commands.len()
        || original_ids.len() != recipe.ids.len()
        || original_ids != commands
    {
        return Err(error("complete unique labelled source inventory required"));
    }
    let remap: BTreeMap<_, _> = recipe
        .ids
        .iter()
        .map(|(label, id)| {
            (
                *id,
                Uuid::new_v5(&namespace, format!("{}/{label}", recipe.name).as_bytes()),
            )
        })
        .collect();
    let mut inputs = BTreeMap::new();
    for command in &mut recipe.commands {
        let Command::Create {
            id,
            contract,
            fields,
        } = command
        else {
            return Err(error("a seed recipe contains only authored creates"));
        };
        let declaration = model.public_contract(*contract)?;
        model.validate(*contract, fields)?;
        for reference in &declaration.references {
            // These are prepared model field paths, never arbitrary client code.
            let pointer = format!(
                "/{}",
                reference
                    .field
                    .replace('[', "/")
                    .replace(']', "")
                    .replace('.', "/")
            );
            match fields.pointer_mut(&pointer) {
                Some(value) => {
                    let old = value
                        .as_str()
                        .and_then(|s| Uuid::parse_str(s).ok())
                        .ok_or_else(|| error("reference UUID required"))?;
                    *value = json!(
                        remap
                            .get(&old)
                            .ok_or_else(|| error("unlabelled reference"))?
                    );
                }
                None if reference.optional => {}
                None => return Err(error("missing required reference")),
            }
        }
        *id = remap[id];
        let input = model.validate(*contract, fields)?;
        if inputs.insert(*id, input).is_some() {
            return Err(error("fixture identity collision"));
        }
    }
    for input in inputs.values() {
        for (id, target, _) in input.references() {
            if inputs.get(&id).is_none_or(|r| r.contract() != target) {
                return Err(error(
                    "reference target does not satisfy the declared contract",
                ));
            }
        }
    }
    let ids: BTreeMap<_, _> = recipe
        .ids
        .iter()
        .map(|(label, id)| (label.clone(), remap[id]))
        .collect();
    let returning = ["P", "Q", "J"]
        .map(|label| {
            ids.get(label)
                .copied()
                .ok_or_else(|| error("missing returned label"))
        })
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    Ok(json!({"model":model.identity(),"commands":recipe.commands,
        "returning":returning,
        "fixture":{"name":recipe.name,"namespace":namespace,"ids":ids,"expected":recipe.expected}}))
}

pub fn plan(model: &PreparedModel, name: &str, namespace: Uuid) -> Result<Value> {
    let recipe = bundled()?;
    if name != recipe.name {
        return Err(Error::new("invalid_input", "unknown fixture name"));
    }
    prepare(model, recipe, namespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_remap_declared_references_and_reject_invalid_inventories() {
        let model = PreparedModel::load().unwrap();
        let namespace = Uuid::from_u128(123);
        let first = plan(&model, "causal-diamond", namespace).unwrap();
        assert_eq!(first, plan(&model, "causal-diamond", namespace).unwrap());
        let second = plan(&model, "causal-diamond", Uuid::from_u128(124)).unwrap();
        let ids: BTreeSet<_> = first["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap())
            .collect();
        assert!(
            second["commands"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| !ids.contains(c["id"].as_str().unwrap()))
        );
        assert!(model.public_catalog().get("fixtures").is_none());
        assert_eq!(model.developer_catalog()["fixtures"], catalog());

        let mut missing = bundled().unwrap();
        missing.commands.pop();
        assert!(prepare(&model, missing, namespace).is_err());
        let mut wrong = bundled().unwrap();
        let moment = wrong.ids["MP"];
        let Command::Create { fields, .. } = &mut wrong.commands[7] else {
            panic!()
        };
        fields["account"] = json!(moment);
        assert!(prepare(&model, wrong, namespace).is_err());
        let mut nested = bundled().unwrap();
        let account = nested.ids["A"];
        let Command::Create { fields, .. } = nested.commands.last_mut().unwrap() else {
            panic!()
        };
        fields["feedback"] = json!({"account":account,"at":"50"});
        let prepared = prepare(&model, nested, namespace).unwrap();
        assert_eq!(
            prepared["commands"][13]["fields"]["feedback"]["account"],
            prepared["fixture"]["ids"]["A"]
        );
    }
}
