//! Repeatable authored scenarios; execution uses ordinary public mutations.
use super::invoicing::Invoicing;
use crate::{
    model::Prepared,
    native_slice::{Error, Result},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use uuid::Uuid;

pub fn catalog() -> Value {
    json!([
        {"name":"invoice","description":"Fractional line pricing, base tax and tax-on-tax","source":"src/models/invoicing_fixtures.rs","identity":"UUIDv5(namespace, fixture-name/record-label)","execution":"one ordinary records.mutate operation"},
        {"name":"invoice-credit","description":"The same invoice with a linked monetary credit and later cumulative tax corrections","source":"src/models/invoicing_fixtures.rs","identity":"UUIDv5(namespace, fixture-name/record-label)","execution":"one ordinary records.mutate operation"}
    ])
}

pub fn plan(model: &Prepared<Invoicing>, name: &str, namespace: Uuid) -> Result<Value> {
    if !matches!(name, "invoice" | "invoice-credit") {
        return Err(Error::new("invalid_input", "unknown invoicing fixture"));
    }
    let corrected = name == "invoice-credit";
    let labels = [
        "Invoice", "Issue", "BaseRule", "NetRule", "BaseTax", "NetTax",
    ];
    let mut ids: BTreeMap<&str, Uuid> = labels
        .into_iter()
        .map(|label| {
            (
                label,
                Uuid::new_v5(&namespace, format!("{name}/{label}").as_bytes()),
            )
        })
        .collect();
    if corrected {
        for label in ["Credit", "BaseCorrection", "NetCorrection"] {
            ids.insert(
                label,
                Uuid::new_v5(&namespace, format!("{name}/{label}").as_bytes()),
            );
        }
    }
    let create = |label: &str, contract: u16, fields: Value| json!({"op":"create","id":ids[label],"contract":contract,"fields":fields});
    let mut commands = vec![
        create("Invoice", 101, json!({"currency":1})),
        create(
            "Issue",
            211,
            json!({"invoice":ids["Invoice"],"at":"0","quantity":{"numerator":"3","denominator":"2"},"unit_price_minor":"6670","rounding":"half_even"}),
        ),
        create(
            "BaseRule",
            401,
            json!({"invoice":ids["Invoice"],"kind":"base","rate":{"numerator":"1","denominator":"10"},"rounding":"half_even"}),
        ),
        create(
            "NetRule",
            401,
            json!({"invoice":ids["Invoice"],"kind":"net","rate":{"numerator":"1","denominator":"20"},"rounding":"half_even"}),
        ),
        create(
            "BaseTax",
            509,
            json!({"invoice":ids["Invoice"],"rule":ids["BaseRule"],"at":"10"}),
        ),
        create(
            "NetTax",
            509,
            json!({"invoice":ids["Invoice"],"rule":ids["NetRule"],"at":"20"}),
        ),
    ];
    if corrected {
        commands.extend([
            create("Credit",307,json!({"invoice":ids["Invoice"],"issue":ids["Issue"],"at":"50","amount_minor":"2001"})),
            create("BaseCorrection",509,json!({"invoice":ids["Invoice"],"rule":ids["BaseRule"],"at":"51"})),
            create("NetCorrection",509,json!({"invoice":ids["Invoice"],"rule":ids["NetRule"],"at":"52"})),
        ]);
    }
    for command in &commands {
        model.validate(
            command["contract"].as_u64().unwrap() as u16,
            &command["fields"],
        )?;
    }
    let returning: Vec<_> = commands.iter().map(|c| c["id"].clone()).collect();
    let expected = if corrected {
        json!({"base":"8004","gross":"9244","base_tax":"800","net_tax":"440"})
    } else {
        json!({"base":"10005","gross":"11555","base_tax":"1000","net_tax":"550"})
    };
    Ok(
        json!({"model":model.identity(),"commands":commands,"returning":returning,
        "fixture":{"name":name,"namespace":namespace,"ids":ids,"expected":expected}}),
    )
}
