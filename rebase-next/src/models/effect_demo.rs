//! The bounded fake-provider model. Inputs and invariants use the ordinary engine.
use crate::{
    binding::{Binding, Limits, NativeInput},
    effects::{ActionDeclaration, Template},
    indexes::standard::Standard,
    local::Store,
    model::{self, Contract, InputField, Prepared, Reference, Visibility},
    native_codec::{Address, Key, decimal, optional_decimal, uuid_text},
    native_slice::{Attempt, Context, Error, Meta, Model, ModelChange, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EffectDemo;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Input {
    Account {
        #[serde(with = "decimal")]
        balance: i128,
    },
    Dispatch {
        #[serde(with = "uuid_text")]
        account: Uuid,
        #[serde(with = "decimal")]
        units: i128,
        #[serde(with = "optional_decimal")]
        execute_at: Option<i64>,
        #[serde(with = "optional_decimal")]
        not_after: Option<i64>,
    },
}
impl NativeInput for Input {
    fn contract(&self) -> u16 {
        match self {
            Self::Account { .. } => 101,
            Self::Dispatch { .. } => 205,
        }
    }
    fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::Account { balance } => (-1_000_000..=1_000_000).contains(balance),
            Self::Dispatch { units, .. } => (1..=1_000_000).contains(units),
        };
        if valid {
            Ok(())
        } else {
            Err(Error::new("invalid_input", "effect-demo scalar bounds"))
        }
    }
    fn bind(code: u16, fields: Value) -> Result<Self> {
        let value: Self = serde_json::from_value(fields.clone())
            .map_err(|_| Error::new("invalid_input", "complete effect-demo input required"))?;
        value.validate()?;
        if value.contract() != code
            || serde_json::to_value(&value).map_err(crate::local::storage)? != fields
        {
            return Err(Error::new(
                "invalid_input",
                "canonical effect-demo input required",
            ));
        }
        Ok(value)
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        match self {
            Self::Dispatch { account, .. } => vec![(*account, 101, 1)],
            _ => vec![],
        }
    }
}
fn registrations(id: Uuid, input: Option<&Input>) -> BTreeSet<(Key, Address)> {
    input
        .into_iter()
        .flat_map(NativeInput::references)
        .map(|(target, _, slot)| (Key::Incoming(target), Address::new(id, slot)))
        .collect()
}
impl Binding for EffectDemo {
    type Input = Input;
    type Derived = ();
    type Index = Standard;
    const NAME: &'static str = "effect-demo";
    const BEHAVIOR: &'static str = "effect-demo-intent-1";
    fn engine() -> Result<Model> {
        Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
    }
    fn limits() -> Limits {
        Limits {
            public_records: 320,
            outputs: 0,
            reservations: 0,
            per_contract: BTreeMap::from([(101, 64), (205, 256)]),
        }
    }
    fn declarations() -> Result<Vec<Contract>> {
        let uuid = json!({"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","x-rebase-binding":"uuid"});
        let optional_time =
            json!({"anyOf":[crate::indexes::standard::time_schema(),{"type":"null"}]});
        let mut contracts = vec![];
        for (code, name, fields, names) in [
            (
                101,
                "Account",
                json!({"balance":{"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","x-rebase-range":["-1000000","1000000"]}}),
                vec!["balance"],
            ),
            (
                205,
                "Dispatch",
                json!({"account":uuid,"units":{"type":"string","pattern":"^[1-9][0-9]*$","x-rebase-range":["1","1000000"]},"execute_at":optional_time,"not_after":optional_time}),
                vec!["account", "units", "execute_at", "not_after"],
            ),
        ] {
            contracts.push(Contract {
                code, name, visibility: Visibility::Public,
                schema: json!({"$schema":model::SCHEMA_DIALECT,"type":"object","additionalProperties":false,"required":names,"properties":fields}),
                fields: names.into_iter().enumerate().map(|(i, name)| InputField { code: i as u16 + 1, name, mutable: code == 101 }).collect(),
                published: vec![], publication_inputs: vec![],
                references: if code == 205 { vec![Reference { slot: 1, field: "account", targets: vec![101], optional: false, direct_fields: vec![], on_delete: "reject", reader: true }] } else { vec![] },
                roots: vec![], memberships: vec![], queries: vec![], outputs: vec![], calculations: vec![], calculation_order: vec![],
                rules: if code == 101 { vec!["nonnegative settled balance"] } else { vec!["immutable external request"] },
                schema_source: "src/models/effect_demo.rs", behavior_source: "src/models/effect_demo.rs",
            });
        }
        Ok(contracts)
    }
    fn valid_derived(_input: &Input, derived: Option<&()>) -> bool {
        derived.is_none()
    }
    fn published_shape(_code: u16) -> Value {
        Value::Null
    }
    fn settle_changes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        _model: &Prepared<Self>,
        _context: Context,
        changes: &[ModelChange<Self>],
        _meta: &mut Meta,
        _revision: u64,
        _allocate: &mut dyn FnMut() -> Result<Uuid>,
    ) -> Result<()> {
        for change in changes {
            if matches!(change.new.as_ref().map(|r| &r.input), Some(Input::Account { balance }) if *balance < 0)
            {
                return Err(Error::new(
                    "invariant",
                    "account balance must be nonnegative",
                ));
            }
            let before = registrations(change.id, change.old.as_ref().map(|r| &r.input));
            let after = registrations(change.id, change.new.as_ref().map(|r| &r.input));
            for (key, address) in before.difference(&after) {
                crate::routes::change(ws, key, *address, crate::time_range::TimeRange::ALL, false)?;
            }
            for (key, address) in after.difference(&before) {
                crate::routes::change(ws, key, *address, crate::time_range::TimeRange::ALL, true)?;
            }
        }
        Ok(())
    }
    fn check(store: &Store<Self>) -> Result<Value> {
        let snapshot = crate::integrity::Snapshot::load(store)?;
        for record in snapshot.records.values() {
            crate::integrity::require(record.derived.is_none(), "effect-demo derived inventory")?;
            if let Input::Account { balance } = record.input {
                crate::integrity::require(balance >= 0, "nonnegative source account balance")?;
            }
        }
        snapshot.finish(
            snapshot.expected_keys.clone(),
            BTreeMap::new(),
            snapshot.routes.clone(),
            BTreeMap::new(),
        )
    }
    fn effect_action() -> Option<ActionDeclaration> {
        Some(ActionDeclaration {
            code: 1,
            name: "dispatch-units",
            version: "fake-units-1",
            source_contract: 205,
            reference_slot: 1,
            target_contract: 101,
            provider_account: "fake-account-1",
        })
    }
    fn effect_template(input: &Input) -> Result<Option<Template>> {
        Ok(match input {
            Input::Dispatch {
                account,
                execute_at,
                not_after,
                ..
            } => Some(Template {
                target: *account,
                execute_at: *execute_at,
                not_after: *not_after,
            }),
            _ => None,
        })
    }
    fn fixture_catalog() -> Value {
        json!([{"name":"atomic-intent","description":"Account 12 and immutable Dispatch 3; G5a dispatch is disabled"}])
    }
    fn fixture_plan(model: &Prepared<Self>, name: &str, namespace: Uuid) -> Result<Value> {
        if name != "atomic-intent" {
            return Err(Error::new("invalid_input", "unknown effect fixture"));
        }
        let account = Uuid::new_v5(&namespace, b"effect-demo/account");
        let dispatch = Uuid::new_v5(&namespace, b"effect-demo/dispatch");
        Ok(
            json!({"model":model.identity(),"fixture":{"name":name,"namespace":namespace,"ids":{"Account":account,"Dispatch":dispatch},"expected":{"balance":"12","units":"3","phase":"ready","dispatch_enabled":false}},
            "commands":[{"op":"create","id":account,"contract":101,"fields":{"balance":"12"}},
            {"op":"create","id":dispatch,"contract":205,"fields":{"account":account,"units":"3","execute_at":null,"not_after":null}}],"returning":[account,dispatch]}),
        )
    }
}
