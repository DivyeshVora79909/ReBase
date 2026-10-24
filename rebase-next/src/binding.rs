//! Compiled model boundary. Types remain native; selecting a model does not
//! install a parser, registry, dynamic plugin, or alternate transaction runner.
use crate::{
    local::Store,
    model::{Contract, Prepared},
    native_codec::{Key, StoredValue},
    native_slice::{Attempt, Context, Model, ModelChange, Population, Result},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{collections::BTreeMap, fmt::Debug};
use uuid::Uuid;

// Outer supported envelopes. Each compiled binding may declare smaller limits;
// command, transport, receipt and per-attempt work budgets remain independent.
pub const MAX_PUBLIC_RECORDS: u16 = 4096;
pub const MAX_OUTPUTS: u16 = 8192;
pub const MAX_RESERVATIONS: u16 = 16384;
pub const MAX_NATIVE_RECORDS: usize = MAX_PUBLIC_RECORDS as usize + MAX_OUTPUTS as usize;
pub const MAX_INVENTORY_ROWS: usize = 262144;

pub trait NativeInput:
    Clone + Debug + Eq + Serialize + DeserializeOwned + Send + Sync + 'static
{
    fn contract(&self) -> u16;
    fn validate(&self) -> Result<()>;
    fn bind(code: u16, fields: Value) -> Result<Self>;
    fn references(&self) -> Vec<(Uuid, u16, u16)>;
    fn managed(&self) -> Option<(Uuid, u16)> {
        None
    }
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub public_records: u16,
    pub outputs: u16,
    pub reservations: u16,
    pub per_contract: BTreeMap<u16, u16>,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            public_records: MAX_PUBLIC_RECORDS,
            outputs: MAX_OUTPUTS,
            reservations: MAX_RESERVATIONS,
            per_contract: BTreeMap::new(),
        }
    }
}

pub trait Binding: Copy + Clone + Debug + Eq + Send + Sync + 'static {
    type Index: crate::index::NativeIndex;
    type Input: NativeInput;
    type Derived: Clone + Debug + Eq + Serialize + DeserializeOwned + Send + Sync + 'static;
    type Outcome: Clone + Debug + Eq + Serialize + DeserializeOwned + Send + Sync + 'static;
    const NAME: &'static str;
    const BEHAVIOR: &'static str;
    fn declarations() -> Result<Vec<Contract>>;
    fn engine() -> Result<Model>;
    fn limits() -> Limits {
        Limits::default()
    }
    fn valid_derived(input: &Self::Input, derived: Option<&Self::Derived>) -> bool;
    fn published_shape(code: u16) -> Value;
    fn settle_changes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        model: &Prepared<Self>,
        context: Context,
        changes: &[ModelChange<Self>],
        population: &mut Population,
        revision: Uuid,
        allocate: &mut dyn FnMut() -> Result<Uuid>,
    ) -> Result<()>;
    fn check(store: &Store<Self>) -> Result<Value>;
    fn effect_action() -> Option<crate::effects::ActionDeclaration> {
        None
    }
    fn effect_template(_input: &Self::Input) -> Result<Option<crate::effects::Template>> {
        Ok(None)
    }
    fn effect_outcome(
        _request: &Self::Input,
        _execution: Uuid,
        _outcome: &Self::Outcome,
    ) -> Result<crate::effects::Disposition> {
        Err(crate::native_slice::Error::new(
            "unsupported_query",
            "model has no provider outcome",
        ))
    }
    fn effect_application(
        _request: &Self::Input,
        _outcome: &Self::Outcome,
        _target: &crate::native_slice::ModelRecord<Self>,
        _id: Uuid,
    ) -> Result<crate::native_slice::Command> {
        Err(crate::native_slice::Error::new(
            "unsupported_query",
            "model has no provider application",
        ))
    }
    fn effect_outcome_schema() -> Value {
        Value::Null
    }
    fn fixture_catalog() -> Value {
        serde_json::json!([])
    }
    fn fixture_plan(_model: &Prepared<Self>, _name: &str, _namespace: Uuid) -> Result<Value> {
        Err(crate::native_slice::Error::new(
            "invalid_input",
            "unknown fixture name",
        ))
    }
}

/// Default compiled calculation model. Its domain types remain model-owned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Calculation;

// Keep model-neutral headers in a single place. Routes with no active members
// exist only when a declared direct/query input can target this contract/root.
pub(crate) fn headers<B: Binding>(
    model: &Prepared<B>,
    id: Uuid,
    input: &B::Input,
    revision: Uuid,
) -> Result<Vec<(Key, StoredValue<B>)>> {
    let contract = model.contract(input.contract())?;
    let mut values = vec![(Key::Incoming(id), StoredValue::Incoming(Default::default()))];
    if model.contracts().any(|c| {
        c.references
            .iter()
            .any(|r| r.targets.contains(&contract.code) && c.uses_direct(r.slot))
    }) {
        values.push((Key::Direct(id), StoredValue::Direct(Default::default())));
    }
    for root in &contract.roots {
        let address = crate::native_codec::Address::new(id, root.slot);
        values.push((
            Key::Root(address),
            StoredValue::Root(crate::tree::Root::empty(root.kind, revision)?),
        ));
        if model.contracts().any(|c| {
            c.queries
                .iter()
                .any(|q| q.root_contract == contract.code && q.root_slot == root.slot)
        }) {
            values.push((
                Key::Subscribers(address),
                StoredValue::Subscribers(Default::default()),
            ));
        }
    }
    Ok(values)
}
