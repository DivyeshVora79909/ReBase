//! The bundled local model: authored schemas, explicit declarations and trusted
//! compiled behavior. This is preparation/inspection, not an extension language.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    binding::{Binding, Calculation as BindingCalculation, NativeInput},
    index::{IndexCode, IndexDescriptor, NativeIndex},
    indexes::standard::{FINANCIAL, QUOTE},
    native_codec,
    native_slice::{Error, Model, Result},
    plan::{Field, evaluation_order},
};

pub const MODEL_NAME: &str = "rebase-next-local";
pub const API_VERSION: &str = "rebase-local-api-4";
pub const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Public,
    Fixture,
    Engine,
}

#[derive(Clone, Debug, Serialize)]
pub struct InputField {
    pub code: u16,
    pub name: &'static str,
    pub mutable: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PublishedField {
    pub code: u16,
    pub name: &'static str,
    pub binding: &'static str,
}

/// Attempt-local publication inputs have their own slot namespace. They do not
/// allocate stored query rows or reuse membership/output-role addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct PublicationSlot(pub u16);

#[derive(Clone, Debug, Serialize)]
pub struct PublicationInput {
    pub slot: PublicationSlot,
    pub reference_slot: u16,
    pub field_code: u16,
    pub binding: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct Reference {
    pub slot: u16,
    pub field: &'static str,
    pub targets: Vec<u16>,
    pub optional: bool,
    pub direct_fields: Vec<&'static str>,
    pub on_delete: &'static str,
    pub reader: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RootDeclaration {
    pub slot: u16,
    pub name: &'static str,
    pub kind: IndexCode,
    pub reads: Vec<&'static str>,
    pub invariant: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Membership {
    pub slot: u16,
    pub through: &'static str,
    pub root_contract: u16,
    pub root_slot: u16,
    pub kind: IndexCode,
    pub key: &'static str,
    pub value: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct QueryDeclaration {
    pub slot: u16,
    pub through: &'static str,
    pub root_contract: u16,
    pub root_slot: u16,
    pub operation: &'static str,
    pub phase: &'static str,
    pub channel: &'static str,
    pub bound: &'static str,
    pub fallback: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OutputRole {
    pub role: u16,
    pub contract: u16,
    pub active: &'static str,
    pub account: &'static str,
    pub at: &'static str,
    pub amount: &'static str,
    pub depends_on: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Calculation {
    pub name: &'static str,
    pub inputs: Vec<&'static str>,
    pub expression: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct Contract {
    pub code: u16,
    pub name: &'static str,
    pub visibility: Visibility,
    pub schema: Value,
    pub fields: Vec<InputField>,
    pub published: Vec<PublishedField>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub publication_inputs: Vec<PublicationInput>,
    pub references: Vec<Reference>,
    pub roots: Vec<RootDeclaration>,
    pub memberships: Vec<Membership>,
    pub queries: Vec<QueryDeclaration>,
    pub outputs: Vec<OutputRole>,
    pub calculations: Vec<Calculation>,
    pub calculation_order: Vec<&'static str>,
    pub rules: Vec<&'static str>,
    pub schema_source: &'static str,
    pub behavior_source: &'static str,
}

impl Contract {
    /// One reverse registration covers all authored and published values read
    /// through a reference. Several publication inputs do not duplicate it.
    pub fn uses_direct(&self, reference_slot: u16) -> bool {
        self.references.iter().any(|reference| {
            reference.slot == reference_slot && !reference.direct_fields.is_empty()
        }) || self
            .publication_inputs
            .iter()
            .any(|input| input.reference_slot == reference_slot)
    }

    pub(crate) fn uses_causal_scheduler<I: NativeIndex>(&self) -> bool {
        !self.outputs.is_empty()
            || !self.publication_inputs.is_empty()
            || self
                .queries
                .iter()
                .any(|query| I::causal_query(query.operation))
    }
}

pub type PreparedModel = Prepared<BindingCalculation>;

pub struct Prepared<B: Binding> {
    binding: std::marker::PhantomData<B>,
    engine: Model,
    core_identity: String,
    contracts: BTreeMap<u16, Contract>,
    indexes: Vec<IndexDescriptor>,
    publication_targets: BTreeSet<u16>,
    validators: BTreeMap<u16, jsonschema::Validator>,
    field_validators: BTreeMap<(u16, &'static str), jsonschema::Validator>,
}

impl Prepared<BindingCalculation> {
    pub(crate) fn for_native_engine(engine: &Model) -> Result<Self> {
        let mut prepared = Self::load()?;
        prepared.engine = engine.clone();
        Ok(prepared)
    }
}

fn model_error(detail: impl Into<String>) -> Error {
    Error::new("model", detail)
}

fn unique(values: impl IntoIterator<Item = u16>, location: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|v| v == 0 || !seen.insert(v)) {
        return Err(model_error(format!("duplicate/zero code at {location}")));
    }
    Ok(())
}

fn self_contained(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            if map.contains_key("$ref") || map.contains_key("$dynamicRef") {
                return Err(model_error("bundled schemas must be self-contained"));
            }
            for value in map.values() {
                self_contained(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                self_contained(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

impl<B: Binding> Prepared<B> {
    pub fn load() -> Result<Self> {
        Self::prepare(B::declarations()?)
    }

    /// Prepare explicit declarations for this trusted compiled binding. This
    /// validates metadata; it does not load executable code from a document.
    pub fn prepare(mut declarations: Vec<Contract>) -> Result<Self> {
        unique(declarations.iter().map(|c| c.code), "contracts")?;
        if declarations
            .iter()
            .filter(|c| c.visibility == Visibility::Public)
            .count()
            .saturating_mul(crate::access::MAX_PRINCIPALS)
            > crate::query::MAX_EPOCHS
        {
            return Err(model_error(
                "query epoch inventory exceeds observation bound",
            ));
        }
        let indexes = B::Index::descriptors();
        unique(indexes.iter().map(|i| i.code.get()), "index codes")?;
        let mut index_names = BTreeSet::new();
        for index in &indexes {
            if index.name.is_empty()
                || !index_names.insert(index.name)
                || index.reads.is_empty()
                || index.reads.iter().collect::<BTreeSet<_>>().len() != index.reads.len()
                || index
                    .reads
                    .iter()
                    .any(|read| !matches!(*read, "summary" | "before" | "range" | "latest" | "sum"))
                || (index.reads.iter().any(|read| *read != "summary") && !index.time)
                || (index.financial && !index.time)
                || (index.quote && !index.time)
                || index.quote != B::Index::supports_quote(index.code)
                || (index.reads.contains(&"sum") && !index.financial)
                || (index.reads.contains(&"latest") && !index.quote)
            {
                return Err(model_error("invalid native index descriptor"));
            }
            let empty = B::Index::empty(index.code).map_err(|e| model_error(e.detail))?;
            B::Index::validate_summary(index.code, &empty).map_err(|e| model_error(e.detail))?;
            if index.time {
                for at in [i64::MIN, 0, i64::MAX] {
                    let key =
                        B::Index::time_key(index.code, at).map_err(|e| model_error(e.detail))?;
                    B::Index::validate_key(index.code, &key).map_err(|e| model_error(e.detail))?;
                    if B::Index::time(index.code, &key).map_err(|e| model_error(e.detail))? != at {
                        return Err(model_error("native time adapter disagreement"));
                    }
                }
            }
            if index.financial {
                B::Index::financial_summary(index.code, &empty)
                    .map_err(|e| model_error(e.detail))?;
            }
            let results = index
                .result_schemas
                .as_object()
                .ok_or_else(|| model_error("native result schemas must be an operation map"))?;
            if index.reads.iter().any(|read| !results.contains_key(*read))
                || results
                    .keys()
                    .any(|read| !index.reads.contains(&read.as_str()))
            {
                return Err(model_error("native read/result schema disagreement"));
            }
            for schema in [&index.key_schema, &index.leaf_schema, &index.summary_schema]
                .into_iter()
                .chain(results.values())
            {
                self_contained(schema)?;
                jsonschema::options()
                    .with_draft(jsonschema::Draft::Draft202012)
                    .should_validate_formats(false)
                    .build(schema)
                    .map_err(|error| model_error(error.to_string()))?;
            }
        }

        let limits = B::limits();
        if limits.public_records == 0
            || limits.public_records > crate::binding::MAX_PUBLIC_RECORDS
            || limits.outputs > crate::binding::MAX_OUTPUTS
            || limits.reservations > crate::binding::MAX_RESERVATIONS
            || limits
                .per_contract
                .keys()
                .any(|code| !declarations.iter().any(|c| c.code == *code))
        {
            return Err(model_error(
                "model limits exceed the supported bounded runtime or name an unknown contract",
            ));
        }
        let mut names = BTreeSet::new();
        let mut validators = BTreeMap::new();
        let mut field_validators = BTreeMap::new();
        for contract in &mut declarations {
            if !names.insert(contract.name) {
                return Err(model_error("duplicate contract name"));
            }
            if contract.schema["$schema"] != SCHEMA_DIALECT
                || contract.schema["type"] != "object"
                || contract.schema["additionalProperties"] != false
            {
                return Err(model_error(format!(
                    "closed schema required: {}",
                    contract.name
                )));
            }
            self_contained(&contract.schema)?;
            unique(contract.fields.iter().map(|f| f.code), contract.name)?;
            unique(
                contract
                    .fields
                    .iter()
                    .map(|f| f.code)
                    .chain(contract.published.iter().map(|f| f.code)),
                contract.name,
            )?;
            let properties = contract.schema["properties"]
                .as_object()
                .ok_or_else(|| model_error("schema properties"))?;
            let fields: BTreeSet<_> = contract.fields.iter().map(|f| f.name).collect();
            let required: BTreeSet<_> = contract.schema["required"]
                .as_array()
                .ok_or_else(|| model_error("complete required fields"))?
                .iter()
                .filter_map(Value::as_str)
                .collect();
            if fields.len() != contract.fields.len()
                || fields != properties.keys().map(String::as_str).collect()
                || fields != required
            {
                return Err(model_error(format!(
                    "field/schema disagreement: {}",
                    contract.name
                )));
            }
            for reference in &contract.references {
                let field = reference.field.split(['.', '[']).next().unwrap_or_default();
                if !fields.contains(field) || reference.targets.is_empty() {
                    return Err(model_error("reference has no authored field or target"));
                }
            }
            unique(
                contract.references.iter().map(|r| r.slot),
                "reference slots",
            )?;
            unique(contract.roots.iter().map(|r| r.slot), "root slots")?;
            unique(contract.memberships.iter().map(|m| m.slot), "member slots")?;
            unique(contract.queries.iter().map(|q| q.slot), "query slots")?;
            unique(contract.outputs.iter().map(|o| o.role), "output roles")?;
            unique(
                contract.publication_inputs.iter().map(|input| input.slot.0),
                "publication input slots",
            )?;
            let locals: Vec<_> = contract
                .calculations
                .iter()
                .map(|c| Field {
                    name: c.name.into(),
                    inputs: c.inputs.iter().map(|s| (*s).into()).collect(),
                })
                .collect();
            contract.calculation_order = evaluation_order(&locals)
                .map_err(model_error)?
                .iter()
                .map(|&i| contract.calculations[i].name)
                .collect();
            let validator = jsonschema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .should_validate_formats(false)
                .build(&contract.schema)
                .map_err(|e| model_error(e.to_string()))?;
            validators.insert(contract.code, validator);
            for field in &contract.fields {
                let schema = &properties[field.name];
                if matches!(
                    schema["type"].as_str(),
                    Some("string" | "integer" | "boolean")
                ) {
                    let validator = jsonschema::options()
                        .with_draft(jsonschema::Draft::Draft202012)
                        .should_validate_formats(false)
                        .build(schema)
                        .map_err(|e| model_error(e.to_string()))?;
                    field_validators.insert((contract.code, field.name), validator);
                }
            }
        }
        let contracts: BTreeMap<_, _> = declarations.into_iter().map(|c| (c.code, c)).collect();
        let mut publication_targets = BTreeSet::new();
        for contract in contracts.values() {
            let published_shape = B::published_shape(contract.code);
            if contract
                .published
                .iter()
                .any(|field| published_shape.get(field.name).is_none())
            {
                return Err(model_error("unknown published field"));
            }
            for root in &contract.roots {
                let index = indexes
                    .iter()
                    .find(|index| index.code == root.kind)
                    .ok_or_else(|| model_error("unknown root index code"))?;
                if root.reads.iter().any(|read| !index.reads.contains(read))
                    || root.reads.iter().collect::<BTreeSet<_>>().len() != root.reads.len()
                {
                    return Err(model_error("unsupported published root read"));
                }
            }
            for reference in &contract.references {
                for code in &reference.targets {
                    let target = contracts
                        .get(code)
                        .ok_or_else(|| model_error("unresolved reference target"))?;
                    if contract.visibility == Visibility::Public
                        && target.visibility != Visibility::Public
                    {
                        return Err(model_error("public input points at private contract"));
                    }
                    if reference
                        .direct_fields
                        .iter()
                        .any(|f| !target.fields.iter().any(|v| v.name == *f))
                    {
                        return Err(model_error("unresolved direct field"));
                    }
                }
            }
            if !contract.publication_inputs.is_empty()
                && contract
                    .queries
                    .iter()
                    .any(|query| !B::Index::causal_query(query.operation))
            {
                return Err(model_error(
                    "publication consumers must use shared causal settlement",
                ));
            }
            for input in &contract.publication_inputs {
                let reference = contract
                    .references
                    .iter()
                    .find(|reference| reference.slot == input.reference_slot)
                    .ok_or_else(|| model_error("unresolved publication reference"))?;
                if reference.optional || input.field_code == 0 || input.binding.is_empty() {
                    return Err(model_error(
                        "publication inputs require a mandatory typed reference",
                    ));
                }
                for code in &reference.targets {
                    let target = &contracts[code];
                    let field = target
                        .published
                        .iter()
                        .find(|field| field.code == input.field_code)
                        .ok_or_else(|| model_error("unresolved published input field"))?;
                    if field.binding != input.binding {
                        return Err(model_error("publication input binding mismatch"));
                    }
                    if target
                        .queries
                        .iter()
                        .any(|query| !B::Index::causal_query(query.operation))
                    {
                        return Err(model_error(
                            "publication parent must use shared causal settlement",
                        ));
                    }
                    publication_targets.insert(*code);
                }
            }
            let resolve = |code, slot| -> Result<&RootDeclaration> {
                contracts
                    .get(&code)
                    .and_then(|c| c.roots.iter().find(|r| r.slot == slot))
                    .ok_or_else(|| model_error("unresolved root declaration"))
            };
            for member in &contract.memberships {
                let target_resolves = if member.through == "self" {
                    member.root_contract == contract.code
                } else {
                    contract.references.iter().any(|r| {
                        r.field == member.through && r.targets.contains(&member.root_contract)
                    })
                };
                if !target_resolves || !contract.fields.iter().any(|f| f.name == member.key) {
                    return Err(model_error("unresolved member reference/key"));
                }
                if resolve(member.root_contract, member.root_slot)?.kind != member.kind {
                    return Err(model_error("member/root kind mismatch"));
                }
            }
            for query in &contract.queries {
                if !contract
                    .references
                    .iter()
                    .any(|r| r.field == query.through && r.targets.contains(&query.root_contract))
                {
                    return Err(model_error("unresolved query reference"));
                }
                let root = resolve(query.root_contract, query.root_slot)?;
                if !matches!(query.phase, "calculate" | "validate")
                    || !indexes.iter().any(|index| {
                        index.code == root.kind
                            && B::Index::supports_query(
                                root.kind,
                                query.operation,
                                query.phase,
                                query.channel,
                            )
                    })
                {
                    return Err(model_error("query/root operation mismatch"));
                }
            }
            for output in &contract.outputs {
                if contracts
                    .get(&output.contract)
                    .is_none_or(|c| c.visibility != Visibility::Engine)
                    || output
                        .depends_on
                        .iter()
                        .any(|name| !contract.calculations.iter().any(|c| c.name == *name))
                {
                    return Err(model_error("unresolved output contract/dependency"));
                }
            }
        }
        if let Some(action) = B::effect_action() {
            let source = contracts
                .get(&action.source_contract)
                .ok_or_else(|| model_error("unknown effect source contract"))?;
            let target = contracts
                .get(&action.target_contract)
                .ok_or_else(|| model_error("unknown effect target contract"))?;
            if action.code == 0
                || [action.name, action.version, action.provider_account]
                    .iter()
                    .any(|v| v.is_empty() || v.len() > 128 || !v.is_ascii())
                || source.visibility != Visibility::Public
                || target.visibility != Visibility::Public
                || source.fields.iter().any(|f| f.mutable)
                || action.application_fields.is_empty()
                || action
                    .application_fields
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != action.application_fields.len()
                || action
                    .application_fields
                    .iter()
                    .any(|name| !target.fields.iter().any(|f| f.name == *name && f.mutable))
                || !source.references.iter().any(|r| {
                    r.slot == action.reference_slot
                        && !r.optional
                        && r.targets == [action.target_contract]
                })
            {
                return Err(model_error("invalid immutable effect action declaration"));
            }
            let schema = B::effect_outcome_schema();
            self_contained(&schema)?;
            jsonschema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .should_validate_formats(false)
                .build(&schema)
                .map_err(|e| model_error(e.to_string()))?;
        }
        let mut engine = B::engine()?;
        let core_identity = engine.identity.clone();
        let mut semantic =
            serde_json::to_value(&contracts).map_err(|e| model_error(e.to_string()))?;
        for contract in semantic.as_object_mut().expect("contract map").values_mut() {
            let map = contract.as_object_mut().expect("contract");
            map.remove("schema_source");
            map.remove("behavior_source");
        }
        let semantic =
            serde_json::to_value((semantic, &indexes)).map_err(|e| model_error(e.to_string()))?;
        let bytes = serde_json::to_vec(&semantic).map_err(|e| model_error(e.to_string()))?;
        let mut hash = Sha256::new();
        hash.update(b"rebase-next-local-model-v1\0");
        for bytes in [
            B::NAME.as_bytes(),
            B::BEHAVIOR.as_bytes(),
            core_identity.as_bytes(),
            bytes.as_slice(),
        ] {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        // An absent action preserves the existing model identity exactly.
        if let Some(action) = B::effect_action() {
            let bytes = serde_json::to_vec(&(action, B::effect_outcome_schema()))
                .map_err(|e| model_error(e.to_string()))?;
            hash.update(b"rebase-effect-action-v1\0");
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        engine.identity = native_codec::hex(&hash.finalize());
        Ok(Self {
            binding: std::marker::PhantomData,
            engine,
            core_identity,
            contracts,
            indexes,
            publication_targets,
            validators,
            field_validators,
        })
    }

    pub fn identity(&self) -> &str {
        &self.engine.identity
    }
    pub fn engine(&self) -> &Model {
        &self.engine
    }
    pub fn contracts(&self) -> impl Iterator<Item = &Contract> {
        self.contracts.values()
    }

    pub fn contract(&self, code: u16) -> Result<&Contract> {
        self.contracts
            .get(&code)
            .ok_or_else(|| Error::new("invalid_input", "unknown contract"))
    }

    pub(crate) fn has_publication_dependents(&self, code: u16) -> bool {
        self.publication_targets.contains(&code)
    }

    pub fn public_contract(&self, code: u16) -> Result<&Contract> {
        let contract = self.contract(code)?;
        if contract.visibility != Visibility::Public {
            return Err(Error::new("forbidden", "private contract"));
        }
        Ok(contract)
    }

    pub fn validate(&self, code: u16, value: &Value) -> Result<B::Input> {
        self.contract(code)?;
        if !self.validators[&code].is_valid(value) {
            return Err(Error::new(
                "invalid_input",
                "input schema validation failed",
            ));
        }
        B::Input::bind(code, value.clone())
    }

    pub fn validate_predicate(&self, code: u16, field: &str, value: &Value) -> Result<()> {
        let contract = self.public_contract(code)?;
        let schema = contract.schema["properties"]
            .get(field)
            .ok_or_else(|| Error::new("invalid_input", "undeclared predicate field"))?;
        let validator = self
            .field_validators
            .get(&(code, field))
            .ok_or_else(|| Error::new("invalid_input", "unsupported predicate field"))?;
        if !validator.is_valid(value) {
            return Err(Error::new("invalid_input", "predicate type"));
        }
        // Scalar range extensions describe native limits, not JSON Schema keywords.
        match schema["x-rebase-binding"].as_str() {
            Some("u16_code") if value.as_u64().is_none_or(|n| !(1..=65535).contains(&n)) => {
                return Err(Error::new("invalid_input", "integer code predicate"));
            }
            Some("uuid") => {
                let text = value
                    .as_str()
                    .ok_or_else(|| Error::new("invalid_input", "UUID predicate"))?;
                let id = uuid::Uuid::parse_str(text)
                    .map_err(|_| Error::new("invalid_input", "UUID predicate"))?;
                if id.to_string() != text {
                    return Err(Error::new("invalid_input", "canonical UUID predicate"));
                }
            }
            _ => {}
        }
        if let Some(range) = schema.get("x-rebase-range").and_then(Value::as_array) {
            let number = value.as_str().and_then(|v| v.parse::<i128>().ok());
            let lower = range[0].as_str().and_then(|v| v.parse::<i128>().ok());
            let upper = range[1].as_str().and_then(|v| v.parse::<i128>().ok());
            if !matches!((number, lower, upper), (Some(n), Some(l), Some(u)) if l <= n && n <= u) {
                return Err(Error::new("invalid_input", "predicate range"));
            }
        }
        Ok(())
    }

    pub fn public_catalog(&self) -> Value {
        let contracts: Vec<_> = self
            .contracts
            .values()
            .filter(|c| c.visibility == Visibility::Public)
            .map(|c| {
                json!({"code":c.code,"name":c.name,"input_schema":c.schema,
                "fields":c.fields,"published":c.published,
                "predicate_fields":c.fields.iter().filter(|f|self.field_validators.contains_key(&(c.code,f.name))).map(|f|f.name).collect::<Vec<_>>(),
                "roots":c.roots.iter().map(|r| json!({"slot":r.slot,"name":r.name,
                    "kind":r.kind,"reads":r.reads})).collect::<Vec<_>>() })
            })
            .collect();
        json!({"name":B::NAME,"model":self.identity(),"api":API_VERSION,
            "codec":self.engine.codec,"schema_dialect":SCHEMA_DIALECT,
            "schema_formats":"disabled; canonical UUIDs use patterns and native binding",
            "exact_values":"canonical decimal strings plus native range binding",
            "indexes":self.indexes.iter().filter(|i| self.contracts.values().any(|c| c.visibility == Visibility::Public && c.roots.iter().any(|r| r.kind == i.code))).collect::<Vec<_>>(),
            "contracts":contracts,"capabilities":model_capabilities::<B>()})
    }

    pub fn developer_catalog(&self) -> Value {
        json!({"name":B::NAME,"model":self.identity(),"core_identity":self.core_identity,
            "behavior_contract":B::BEHAVIOR,
            "api":API_VERSION,"codec":self.engine.codec,
            "indexes":self.indexes,
            "contracts":self.contracts.values().collect::<Vec<_>>(),
            "capabilities":model_capabilities::<B>(),"authority":"local actor or transaction-scoped tenant principal DAG; separate owner and reader",
            "identity_policy":"retained private reservations; retired producers cannot be reused",
            "preparation":"bundled compiled model only; no arbitrary behavior loader",
            "fixtures":B::fixture_catalog()})
    }

    pub fn explain(&self, selector: &str) -> Result<Value> {
        let contract = self
            .contracts
            .values()
            .find(|c| c.name == selector || c.code.to_string() == selector)
            .ok_or_else(|| Error::new("invalid_input", "unknown contract name/code"))?;
        Ok(json!({"model":self.identity(),"contract":contract,
            "declarations":"src/model.rs","settlement":"one final atomic validation boundary"}))
    }
}

pub fn capabilities() -> Value {
    model_capabilities::<BindingCalculation>()
}

fn model_capabilities<B: Binding>() -> Value {
    let limits = B::limits();
    let mut methods = vec![
        "model.describe",
        "records.get",
        "records.mutate",
        "operations.status",
        "records.page",
        "records.exists",
        "roots.read",
        "session.describe",
        "access.describe",
        "access.replace",
    ];
    if B::effect_action().is_some() {
        methods.extend(["effects.status", "effects.cancel"]);
    }
    let mut catalog = json!({"methods":methods,
        "transport":"JSON-RPC 2.0 over stdio or authenticated HTTP /rpc; string request IDs; no batches/notifications",
        "path":{"name":"records.by_id","order":"UUID ascending","filter":"optional public contract and one declared scalar authored-field equality"},
        "limits":{"commands":64,"public_records":limits.public_records,"outputs":limits.outputs,"reservations":limits.reservations,"per_contract":limits.per_contract,
            "returning":32,"page_limit":32,"visit_budget":128,"receipts":1024,"request_bytes":65536},
        "cursor":"HMAC-SHA256; bound store/model/actor/query and scoped reader/contract epochs plus authority revision; unchanged scopes and true no-ops preserve cursors",
        "versions":"record/root/mutation revisions are opaque UUID tokens, never ordered; access revision is an administration-only counter; pages return a scoped digest",
        "updates":"set replaces complete fields; unset must be empty in this model",
        "receipt":"required actor/store/generation context from session.describe; same operation ID/content replays; offline archive advances its fence",
        "not_observed":"receipt absence does not prove failure"});
    if let Some(action) = B::effect_action() {
        catalog["effects"] = crate::effects::capabilities::<B>(&action);
    }
    catalog
}

fn reference(
    slot: u16,
    field: &'static str,
    targets: &[u16],
    optional: bool,
    direct: &[&'static str],
) -> Reference {
    Reference {
        slot,
        field,
        targets: targets.to_vec(),
        optional,
        direct_fields: direct.to_vec(),
        on_delete: "reject",
        reader: matches!(
            field,
            "account" | "subsidiary" | "sources[0]" | "sources[1]"
        ),
    }
}

fn member(
    slot: u16,
    through: &'static str,
    root_contract: u16,
    root_slot: u16,
    kind: IndexCode,
    value: &'static str,
) -> Membership {
    Membership {
        slot,
        through,
        root_contract,
        root_slot,
        kind,
        key: "at",
        value,
    }
}

fn calculation(
    name: &'static str,
    inputs: &[&'static str],
    expression: &'static str,
) -> Calculation {
    Calculation {
        name,
        inputs: inputs.to_vec(),
        expression,
    }
}

pub(crate) fn declarations() -> Result<Vec<Contract>> {
    type Source = (
        u16,
        &'static str,
        &'static str,
        &'static str,
        &'static [(u16, &'static str)],
    );
    let sources: &[Source] = &[
        (
            1,
            "Rule",
            "rule",
            include_str!("../model/schemas/rule.json"),
            &[(1, "c")],
        ),
        (
            2,
            "Curve",
            "curve",
            include_str!("../model/schemas/curve.json"),
            &[(1, "native_unit"), (2, "reporting_unit")],
        ),
        (
            3,
            "Quote",
            "quote",
            include_str!("../model/schemas/quote.json"),
            &[(1, "curve"), (2, "at"), (3, "rate")],
        ),
        (
            4,
            "Account",
            "account",
            include_str!("../model/schemas/account.json"),
            &[(1, "native_unit")],
        ),
        (
            5,
            "Subsidiary",
            "subsidiary",
            include_str!("../model/schemas/subsidiary.json"),
            &[(1, "reporting_unit")],
        ),
        (
            6,
            "Posting",
            "posting",
            include_str!("../model/schemas/posting.json"),
            &[
                (1, "units"),
                (2, "at"),
                (3, "rule"),
                (4, "curve"),
                (5, "account"),
                (6, "subsidiary"),
            ],
        ),
        (
            7,
            "Moment",
            "moment",
            include_str!("../model/schemas/moment.json"),
            &[(1, "at")],
        ),
        (
            8,
            "Entry",
            "entry",
            include_str!("../model/schemas/entry.json"),
            &[(1, "account"), (2, "at"), (3, "amount")],
        ),
        (
            9,
            "Adjustment",
            "adjustment",
            include_str!("../model/schemas/adjustment.json"),
            &[
                (1, "account"),
                (2, "moment"),
                (3, "offset"),
                (4, "target"),
                (5, "post"),
            ],
        ),
        (
            10,
            "Basis",
            "basis",
            include_str!("../model/schemas/basis.json"),
            &[
                (1, "sources"),
                (2, "factor"),
                (3, "account"),
                (4, "at"),
                (5, "feedback"),
            ],
        ),
        (
            11,
            "Pin",
            "pin",
            include_str!("../model/schemas/pin.json"),
            &[(1, "output")],
        ),
        (
            12,
            "Output",
            "output",
            include_str!("../model/schemas/output.json"),
            &[
                (1, "producer"),
                (2, "role"),
                (3, "account"),
                (4, "at"),
                (5, "amount"),
            ],
        ),
    ];
    let schema_paths = [
        "model/schemas/rule.json",
        "model/schemas/curve.json",
        "model/schemas/quote.json",
        "model/schemas/account.json",
        "model/schemas/subsidiary.json",
        "model/schemas/posting.json",
        "model/schemas/moment.json",
        "model/schemas/entry.json",
        "model/schemas/adjustment.json",
        "model/schemas/basis.json",
        "model/schemas/pin.json",
        "model/schemas/output.json",
    ];
    let mut contracts = Vec::new();
    for &(code, name, _, schema, fields) in sources {
        let mut c = Contract {
            code,
            name,
            visibility: match code {
                11 => Visibility::Fixture,
                12 => Visibility::Engine,
                _ => Visibility::Public,
            },
            schema: serde_json::from_str(schema).map_err(|e| model_error(e.to_string()))?,
            fields: fields
                .iter()
                .map(|&(code_field, name)| InputField {
                    code: code_field,
                    name,
                    mutable: matches!(code, 1 | 3 | 6 | 7 | 8 | 9 | 10),
                })
                .collect(),
            published: vec![],
            publication_inputs: vec![],
            references: vec![],
            roots: vec![],
            memberships: vec![],
            queries: vec![],
            outputs: vec![],
            calculations: vec![],
            calculation_order: vec![],
            rules: vec![],
            schema_source: schema_paths[usize::from(code - 1)],
            behavior_source: if matches!(code, 9 | 10 | 12) {
                "src/causal.rs"
            } else {
                "src/native_slice.rs"
            },
        };
        match code {
            2 | 4 | 5 => c.roots.push(RootDeclaration {
                slot: match code {
                    2 => 1,
                    4 => 2,
                    _ => 3,
                },
                name: if code == 2 { "quotes" } else { "history" },
                kind: if code == 2 { QUOTE } else { FINANCIAL },
                reads: match code {
                    2 => vec!["summary", "latest"],
                    4 => vec!["summary", "before", "range"],
                    _ => vec!["summary", "range"],
                },
                invariant: if code == 4 {
                    Some("nonnegative complete-time prefixes")
                } else {
                    None
                },
            }),
            3 => {
                c.references.push(reference(1, "curve", &[2], false, &[]));
                c.memberships.push(member(3, "curve", 2, 1, QUOTE, "rate"));
                c.rules.push("unique quote timestamp per curve");
            }
            6 => {
                c.references = vec![
                    reference(3, "rule", &[1], false, &["c"]),
                    reference(4, "curve", &[2], false, &[]),
                    reference(5, "account", &[4], false, &[]),
                    reference(6, "subsidiary", &[5], false, &[]),
                ];
                c.memberships = vec![
                    member(1, "account", 4, 2, FINANCIAL, "native_minor"),
                    member(2, "subsidiary", 5, 3, FINANCIAL, "reporting_minor"),
                ];
                c.queries.push(QueryDeclaration {
                    slot: 1,
                    through: "curve",
                    root_contract: 2,
                    root_slot: 1,
                    operation: "latest",
                    phase: "calculate",
                    channel: "rate",
                    bound: "at or earlier",
                    fallback: Some("1"),
                });
                c.published = vec![
                    PublishedField {
                        code: 101,
                        name: "native_minor",
                        binding: "i128",
                    },
                    PublishedField {
                        code: 102,
                        name: "reporting_minor",
                        binding: "i128",
                    },
                ];
                c.calculations = vec![
                    calculation("a_reporting", &["z_native", "rate"], "z_native * rate"),
                    calculation("z_native", &["units", "c"], "units * c"),
                    calculation("units", &[], "input.units"),
                    calculation("c", &[], "rule.c"),
                    calculation("rate", &[], "query[1].result"),
                ];
                c.rules.push("account.native_unit = curve.native_unit; subsidiary.reporting_unit = curve.reporting_unit");
            }
            8 => {
                c.references.push(reference(1, "account", &[4], false, &[]));
                c.memberships
                    .push(member(1, "account", 4, 2, FINANCIAL, "amount"));
            }
            9 => {
                c.references = vec![
                    reference(1, "account", &[4], false, &[]),
                    reference(2, "moment", &[7], false, &["at"]),
                ];
                for (slot, phase) in [(1, "calculate"), (2, "validate")] {
                    c.queries.push(QueryDeclaration {
                        slot,
                        through: "account",
                        root_contract: 4,
                        root_slot: 2,
                        operation: "sum",
                        phase,
                        channel: "amount",
                        bound: "strictly before moment.at + offset",
                        fallback: Some("0"),
                    });
                }
                c.published = vec![
                    PublishedField {
                        code: 101,
                        name: "at",
                        binding: "i64",
                    },
                    PublishedField {
                        code: 102,
                        name: "before",
                        binding: "i128",
                    },
                    PublishedField {
                        code: 103,
                        name: "delta",
                        binding: "i128",
                    },
                ];
                c.calculations = vec![
                    calculation("delta", &["target", "before"], "target - before"),
                    calculation("at", &["moment_at", "offset"], "checked moment_at + offset"),
                    calculation("before", &["at"], "query[1].result"),
                    calculation("target", &[], "input.target"),
                    calculation("moment_at", &[], "moment.at"),
                    calculation("offset", &[], "input.offset"),
                ];
                c.outputs.push(OutputRole {
                    role: 1,
                    contract: 12,
                    active: "post",
                    account: "account",
                    at: "at",
                    amount: "delta",
                    depends_on: vec!["delta"],
                });
                c.rules
                    .push("terminal validation query[2] >= 0; validation adds no calculation edge");
            }
            10 => {
                c.references = vec![
                    reference(1, "sources[0]", &[4], false, &[]),
                    reference(2, "sources[1]", &[4], true, &[]),
                    reference(3, "account", &[4], false, &[]),
                    reference(4, "feedback.account", &[4], true, &[]),
                ];
                for (slot, through) in [(1, "sources[0]"), (2, "sources[1]")] {
                    c.queries.push(QueryDeclaration {
                        slot,
                        through,
                        root_contract: 4,
                        root_slot: 2,
                        operation: "sum",
                        phase: "calculate",
                        channel: "amount",
                        bound: "whole root",
                        fallback: Some("0"),
                    });
                }
                c.published.push(PublishedField {
                    code: 101,
                    name: "value",
                    binding: "i128",
                });
                c.calculations = vec![
                    calculation("value", &["sum", "factor"], "sum * factor"),
                    calculation("sum", &[], "query[1] + optional query[2]"),
                    calculation("factor", &[], "input.factor"),
                ];
                c.outputs = vec![
                    OutputRole {
                        role: 1,
                        contract: 12,
                        active: "always",
                        account: "account",
                        at: "input.at",
                        amount: "value",
                        depends_on: vec!["value"],
                    },
                    OutputRole {
                        role: 2,
                        contract: 12,
                        active: "feedback != null",
                        account: "feedback.account",
                        at: "feedback.at",
                        amount: "0",
                        depends_on: vec!["value"],
                    },
                ];
                c.rules = vec![
                    "all source/output account units agree",
                    "repeated sources retain separate queries",
                    "zero feedback retains its dependency",
                ];
            }
            11 => c.references.push(reference(1, "output", &[12], false, &[])),
            12 => {
                c.references = vec![
                    reference(1, "producer", &[9, 10], false, &[]),
                    reference(2, "account", &[4], false, &[]),
                ];
                c.memberships
                    .push(member(1, "account", 4, 2, FINANCIAL, "amount"));
            }
            _ => {}
        }
        contracts.push(c);
    }
    Ok(contracts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_preparation_exports_public_schemas_without_private_roles() {
        let model = PreparedModel::load().unwrap();
        let public = model.public_catalog();
        assert_eq!(public["contracts"].as_array().unwrap().len(), 10);
        assert_eq!(
            model.developer_catalog()["contracts"]
                .as_array()
                .unwrap()
                .len(),
            12
        );
        for contract in public["contracts"].as_array().unwrap() {
            let code = contract["code"].as_u64().unwrap() as u16;
            assert_eq!(
                contract["input_schema"],
                model.contract(code).unwrap().schema
            );
            assert!(contract.get("outputs").is_none() && contract.get("references").is_none());
        }
        assert_eq!(model.identity(), PreparedModel::load().unwrap().identity());
        let order = &model.contract(6).unwrap().calculation_order;
        assert!(
            order.iter().position(|n| *n == "z_native")
                < order.iter().position(|n| *n == "a_reporting")
        );
        let native_names = ["a_reporting", "z_native", "units", "c", "rate"];
        assert!(
            model
                .validate_predicate(4, "native_unit", &json!(1.0))
                .is_err()
        );
        assert!(
            model
                .validate_predicate(4, "native_unit", &json!(1))
                .is_ok()
        );
        assert_eq!(
            *order,
            model
                .engine
                .order
                .iter()
                .map(|&i| native_names[i])
                .collect::<Vec<_>>()
        );
        assert!(
            model
                .validate(7, &json!({"at":"9223372036854775807"}))
                .is_ok()
        );
        for value in [
            json!({"at":"9223372036854775808"}),
            json!({"at":1}),
            json!({"at":"01"}),
            json!({"at":"-0"}),
            json!({"at":"1","derived":{}}),
        ] {
            assert!(model.validate(7, &value).is_err());
        }
    }

    #[test]
    fn preparation_rejects_ambiguous_or_inconsistent_declarations() {
        for corrupt in 0..11 {
            let mut d = declarations().unwrap();
            match corrupt {
                0 => d[1].code = 1,
                1 => d[5].fields[1].code = 1,
                2 => d[2].references[0].targets = vec![99],
                3 => d[5].memberships[0].kind = QUOTE,
                4 => d[5].calculations[1].inputs = vec!["a_reporting"],
                5 => d[8].queries[1].slot = 1,
                6 => {
                    d[0].schema["properties"]["c"]["$ref"] = json!("https://example.invalid/schema")
                }
                7 => d[5].memberships[0].through = "undeclared",
                8 => d[5].published[0].name = "private_or_missing_field",
                9 => d[3].roots[0].reads.push("latest"),
                _ => d[3].roots[0].kind = IndexCode::new(9).unwrap(),
            }
            assert!(PreparedModel::prepare(d).is_err(), "control {corrupt}");
        }
        let original = PreparedModel::load().unwrap();
        let mut d = declarations().unwrap();
        d[0].behavior_source = "presentation-only-location";
        assert_eq!(
            original.identity(),
            PreparedModel::prepare(d).unwrap().identity()
        );
        let mut d = declarations().unwrap();
        d[0].fields[0].mutable = false;
        assert_ne!(
            original.identity(),
            PreparedModel::prepare(d).unwrap().identity()
        );
    }
}
