//! Binding for the original compiled calculation model.
pub use crate::binding::Calculation;
use crate::{
    binding::{Binding, Limits, NativeInput},
    local::Store,
    model::{Contract, Prepared},
    native_slice::{
        Attempt, Calculated, Context, Derived, Input, Meta, Model, ModelChange, Result,
    },
};
use serde_json::Value;
use uuid::Uuid;

impl NativeInput for Input {
    fn contract(&self) -> u16 {
        Input::contract(self)
    }
    fn validate(&self) -> Result<()> {
        Input::validate(self)
    }
    fn bind(code: u16, fields: Value) -> Result<Self> {
        Input::bind(code, fields)
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        Input::references(self)
    }
    fn managed(&self) -> Option<(Uuid, u16)> {
        match self {
            Self::Output { producer, role, .. } => Some((*producer, *role)),
            _ => None,
        }
    }
}

impl Binding for Calculation {
    type Input = Input;
    type Derived = Calculated;
    const NAME: &'static str = "rebase-next-local";
    const BEHAVIOR: &'static str = crate::native_slice::BEHAVIOR_CONTRACT;
    fn declarations() -> Result<Vec<Contract>> {
        crate::model::declarations()
    }
    fn engine() -> Result<Model> {
        Model::prepare()
    }
    fn limits() -> Limits {
        Limits {
            per_contract: [3, 6, 9, 10]
                .map(|code| (code, crate::binding::MAX_PUBLIC_RECORDS))
                .into(),
            ..Limits::default()
        }
    }
    fn valid_derived(input: &Input, derived: Option<&Calculated>) -> bool {
        matches!(
            (input.contract(), derived),
            (6, Some(Calculated::Posting(_)))
                | (9, Some(Calculated::Adjustment { .. }))
                | (10, Some(Calculated::Basis { .. }))
                | (1..=5 | 7 | 8 | 11 | 12, None)
        )
    }
    fn published_shape(code: u16) -> Value {
        let shape = match code {
            6 => Some(Calculated::Posting(Derived {
                native_minor: 0,
                reporting_minor: 0,
            })),
            9 => Some(Calculated::Adjustment {
                at: 0,
                before: 0,
                delta: 0,
            }),
            10 => Some(Calculated::Basis { value: 0 }),
            _ => None,
        };
        serde_json::to_value(shape).expect("native published shape serializes")
    }
    fn settle_changes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        model: &Prepared<Self>,
        context: Context,
        changes: &[ModelChange<Self>],
        meta: &mut Meta,
        revision: u64,
        allocate: &mut dyn FnMut() -> Result<Uuid>,
    ) -> Result<()> {
        crate::native_slice::settle_calculation_changes(
            ws, model, context, changes, meta, revision, allocate,
        )
    }
    fn check(store: &Store<Self>) -> Result<Value> {
        crate::integrity::check_calculation(store)
    }
    fn fixture_catalog() -> Value {
        crate::fixtures::catalog()
    }
    fn fixture_plan(model: &Prepared<Self>, name: &str, namespace: Uuid) -> Result<Value> {
        crate::fixtures::plan(model, name, namespace)
    }
}
