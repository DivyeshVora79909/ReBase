//! Bounded invoice pricing and explicitly dated cumulative tax assessments.
//! Credits are monetary corrections. Assessments are authored facts; the model
//! does not invent tax adjustments, settle payments or claim tax-law compliance.
use crate::{
    binding::{Binding, Limits, NativeInput},
    causal::{Emit, ReactiveBinding, Read, Resolved, ResolvedShape},
    local::Store,
    model::{
        self, Contract, InputField, Membership, OutputRole, Prepared, PublishedField,
        QueryDeclaration, Reference, RootDeclaration, Visibility,
    },
    native_codec::{Address, Key, StoredValue, decimal, uuid_text},
    native_slice::{Attempt, Context, Error, Meta, Model, ModelChange, ModelRecord, Result},
    routes::{self, Endpoint},
    tree::{self, Aggregate, Kind, Leaf},
    values::{Rational, Rounding},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invoicing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaxKind {
    Base,
    Net,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Input {
    Invoice {
        currency: u16,
    },
    Issue {
        #[serde(with = "uuid_text")]
        invoice: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        quantity: Rational,
        #[serde(with = "decimal")]
        unit_price_minor: i128,
        rounding: Rounding,
    },
    Credit {
        #[serde(with = "uuid_text")]
        invoice: Uuid,
        #[serde(with = "uuid_text")]
        issue: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        amount_minor: i128,
    },
    TaxRule {
        #[serde(with = "uuid_text")]
        invoice: Uuid,
        kind: TaxKind,
        rate: Rational,
        rounding: Rounding,
    },
    Assessment {
        #[serde(with = "uuid_text")]
        invoice: Uuid,
        #[serde(with = "uuid_text")]
        rule: Uuid,
        #[serde(with = "decimal")]
        at: i64,
    },
    Output {
        #[serde(with = "uuid_text")]
        producer: Uuid,
        role: u16,
        #[serde(with = "uuid_text")]
        target: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        amount: i128,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Derived {
    Issue {
        #[serde(with = "decimal")]
        amount_minor: i128,
    },
    Assessment {
        #[serde(with = "decimal")]
        basis_minor: i128,
        #[serde(with = "decimal")]
        prior_minor: i128,
        #[serde(with = "decimal")]
        assessed_minor: i128,
        #[serde(with = "decimal")]
        delta_minor: i128,
    },
}

pub(crate) fn output_contract(role: u16) -> Result<u16> {
    match role {
        11 => Ok(901),
        13 => Ok(902),
        17 => Ok(903),
        19 => Ok(904),
        _ => Err(Error::new("invalid_input", "unknown invoicing output role")),
    }
}
pub(crate) fn output_slot(role: u16) -> Result<u16> {
    output_contract(role)?;
    Ok(role)
}
fn output_root(role: u16) -> Result<(u16, u16)> {
    match role {
        11 => Ok((101, 7)),
        13 => Ok((101, 13)),
        17 => Ok((211, 17)),
        19 => Ok((401, 19)),
        _ => Err(Error::new("invalid_input", "unknown invoicing output role")),
    }
}
impl NativeInput for Input {
    fn contract(&self) -> u16 {
        match self {
            Self::Invoice { .. } => 101,
            Self::Issue { .. } => 211,
            Self::Credit { .. } => 307,
            Self::TaxRule { .. } => 401,
            Self::Assessment { .. } => 509,
            Self::Output { role, .. } => output_contract(*role).unwrap_or(0),
        }
    }
    fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::Invoice { currency } => *currency > 0,
            Self::Issue {
                quantity,
                unit_price_minor,
                ..
            } => quantity.numerator() >= 0 && *unit_price_minor >= 0,
            Self::Credit { amount_minor, .. } => *amount_minor > 0,
            Self::TaxRule { rate, .. } => rate.numerator() >= 0,
            Self::Assessment { .. } => true,
            Self::Output { role, .. } => output_contract(*role).is_ok(),
        };
        if valid {
            Ok(())
        } else {
            Err(Error::new(
                "invalid_input",
                "invoicing value outside declared bounds",
            ))
        }
    }
    fn bind(code: u16, fields: Value) -> Result<Self> {
        let input: Self = serde_json::from_value(fields.clone())
            .map_err(|error| Error::new("invalid_input", error.to_string()))?;
        input.validate()?;
        if input.contract() != code
            || serde_json::to_value(&input)
                .map_err(|error| Error::new("codec", error.to_string()))?
                != fields
        {
            return Err(Error::new(
                "invalid_input",
                "complete canonical invoicing input required",
            ));
        }
        Ok(input)
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        match self {
            Self::Issue { invoice, .. } | Self::TaxRule { invoice, .. } => vec![(*invoice, 101, 1)],
            Self::Credit { invoice, issue, .. } => vec![(*invoice, 101, 1), (*issue, 211, 2)],
            Self::Assessment { invoice, rule, .. } => vec![(*invoice, 101, 1), (*rule, 401, 2)],
            Self::Output {
                producer,
                role,
                target,
                ..
            } => vec![
                (
                    *producer,
                    match role {
                        13 => 0,
                        19 => 509,
                        _ => 211,
                    },
                    1,
                ),
                (*target, output_root(*role).map_or(0, |(code, _)| code), 2),
            ],
            Self::Invoice { .. } => vec![],
        }
    }
    fn managed(&self) -> Option<(Uuid, u16)> {
        match self {
            Self::Output { producer, role, .. } => Some((*producer, *role)),
            _ => None,
        }
    }
}

fn reference(
    slot: u16,
    field: &'static str,
    targets: Vec<u16>,
    direct_fields: Vec<&'static str>,
) -> Reference {
    Reference {
        slot,
        field,
        targets,
        optional: false,
        direct_fields,
        on_delete: "reject",
        reader: field == "invoice" || field == "target",
    }
}
fn root(slot: u16, name: &'static str) -> RootDeclaration {
    RootDeclaration {
        slot,
        name,
        kind: Kind::Financial,
        reads: vec!["summary", "before"],
        invariant: Some("nonnegative complete-time prefixes"),
    }
}
fn member(
    slot: u16,
    through: &'static str,
    target: u16,
    root_slot: u16,
    value: &'static str,
) -> Membership {
    Membership {
        slot,
        through,
        root_contract: target,
        root_slot,
        kind: Kind::Financial,
        key: "at",
        value,
    }
}
fn query(slot: u16, through: &'static str, target: u16, root_slot: u16) -> QueryDeclaration {
    QueryDeclaration {
        slot,
        through,
        root_contract: target,
        root_slot,
        operation: "sum",
        phase: "calculate",
        channel: "amount",
        bound: "strictly before at",
        fallback: Some("0"),
    }
}
fn integer_schema(positive: bool) -> Value {
    json!({"type":"string","pattern":if positive{"^[1-9][0-9]{0,38}$"}else{"^(0|-?[1-9][0-9]{0,38})$"},"x-rebase-binding":"i128","x-rebase-range":[if positive{"1".into()}else{i128::MIN.to_string()},i128::MAX.to_string()]})
}
fn nonnegative_integer_schema() -> Value {
    let mut schema = integer_schema(false);
    schema["pattern"] = json!("^(0|[1-9][0-9]{0,38})$");
    schema["x-rebase-range"][0] = json!("0");
    schema
}
fn nonnegative_rational_schema() -> Value {
    let mut schema = Rational::schema();
    schema["properties"]["numerator"] = nonnegative_integer_schema();
    schema
}
fn declarations() -> Result<Vec<Contract>> {
    let uuid = json!({"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","x-rebase-binding":"uuid"});
    let time = json!({"type":"string","pattern":"^(0|-?[1-9][0-9]{0,18})$","x-rebase-binding":"i64","x-rebase-range":[i64::MIN.to_string(),i64::MAX.to_string()]});
    let mut declarations = vec![];
    for (code, name, properties, names) in [
        (
            101,
            "Invoice",
            json!({"currency":{"type":"integer","minimum":1,"maximum":65535,"x-rebase-binding":"u16_code"}}),
            vec!["currency"],
        ),
        (
            211,
            "Issue",
            json!({"invoice":uuid,"at":time,"quantity":nonnegative_rational_schema(),"unit_price_minor":nonnegative_integer_schema(),"rounding":Rounding::schema()}),
            vec!["invoice", "at", "quantity", "unit_price_minor", "rounding"],
        ),
        (
            307,
            "Credit",
            json!({"invoice":uuid,"issue":uuid,"at":time,"amount_minor":integer_schema(true)}),
            vec!["invoice", "issue", "at", "amount_minor"],
        ),
        (
            401,
            "TaxRule",
            json!({"invoice":uuid,"kind":{"type":"string","enum":["base","net"]},"rate":nonnegative_rational_schema(),"rounding":Rounding::schema()}),
            vec!["invoice", "kind", "rate", "rounding"],
        ),
        (
            509,
            "Assessment",
            json!({"invoice":uuid,"rule":uuid,"at":time}),
            vec!["invoice", "rule", "at"],
        ),
        (
            901,
            "InvoiceBaseOutput",
            json!({"producer":uuid,"role":{"const":11},"target":uuid,"at":time,"amount":integer_schema(false)}),
            vec!["producer", "role", "target", "at", "amount"],
        ),
        (
            902,
            "InvoiceGrossOutput",
            json!({"producer":uuid,"role":{"const":13},"target":uuid,"at":time,"amount":integer_schema(false)}),
            vec!["producer", "role", "target", "at", "amount"],
        ),
        (
            903,
            "IssueCapacityOutput",
            json!({"producer":uuid,"role":{"const":17},"target":uuid,"at":time,"amount":integer_schema(false)}),
            vec!["producer", "role", "target", "at", "amount"],
        ),
        (
            904,
            "TaxAssessedOutput",
            json!({"producer":uuid,"role":{"const":19},"target":uuid,"at":time,"amount":integer_schema(false)}),
            vec!["producer", "role", "target", "at", "amount"],
        ),
    ] {
        let mut c = Contract {
            code,
            name,
            visibility: if code >= 900 {
                Visibility::Engine
            } else {
                Visibility::Public
            },
            schema: json!({"$schema":model::SCHEMA_DIALECT,"type":"object","additionalProperties":false,"required":names,"properties":properties}),
            fields: names
                .iter()
                .enumerate()
                .map(|(index, &name)| InputField {
                    code: index as u16 + 1,
                    name,
                    mutable: code < 900
                        && code != 101
                        && !matches!(name, "invoice" | "issue" | "rule"),
                })
                .collect(),
            published: vec![],
            references: vec![],
            roots: vec![],
            memberships: vec![],
            queries: vec![],
            outputs: vec![],
            calculations: vec![],
            calculation_order: vec![],
            rules: vec![],
            schema_source: "src/models/invoicing.rs",
            behavior_source: "src/models/invoicing.rs",
        };
        match code {
            101 => c.roots = vec![root(7, "base"), root(13, "gross")],
            211 => {
                c.references
                    .push(reference(1, "invoice", vec![101], vec![]));
                c.roots.push(root(17, "credit_capacity"));
                c.published.push(PublishedField {
                    code: 101,
                    name: "amount_minor",
                    binding: "i128",
                });
                c.calculations.push(model::Calculation {
                    name: "amount_minor",
                    inputs: vec![],
                    expression: "quantity.apply(unit_price_minor,rounding)",
                });
                for (role, contract, account) in [
                    (11, 901, "invoice"),
                    (13, 902, "invoice"),
                    (17, 903, "self"),
                ] {
                    c.outputs.push(OutputRole {
                        role,
                        contract,
                        active: "always",
                        account,
                        at: "at",
                        amount: "amount_minor",
                        depends_on: vec!["amount_minor"],
                    });
                }
            }
            307 => {
                c.references = vec![
                    reference(1, "invoice", vec![101], vec![]),
                    reference(2, "issue", vec![211], vec![]),
                ];
                c.memberships = vec![
                    member(11, "invoice", 101, 7, "-amount_minor"),
                    member(13, "invoice", 101, 13, "-amount_minor"),
                    member(17, "issue", 211, 17, "-amount_minor"),
                ];
                c.rules = vec![
                    "issue.invoice equals invoice; monetary credit only; nonnegative chronological issue capacity",
                ];
            }
            401 => {
                c.references
                    .push(reference(1, "invoice", vec![101], vec![]));
                c.roots.push(root(19, "assessed"));
            }
            509 => {
                c.references = vec![
                    reference(1, "invoice", vec![101], vec![]),
                    reference(
                        2,
                        "rule",
                        vec![401],
                        vec!["invoice", "kind", "rate", "rounding"],
                    ),
                ];
                c.queries = vec![
                    query(31, "invoice", 101, 7),
                    query(37, "invoice", 101, 13),
                    query(41, "rule", 401, 19),
                ];
                c.published = [
                    (101, "basis_minor"),
                    (102, "prior_minor"),
                    (103, "assessed_minor"),
                    (104, "delta_minor"),
                ]
                .into_iter()
                .map(|(code, name)| PublishedField {
                    code,
                    name,
                    binding: "i128",
                })
                .collect();
                c.calculations.push(model::Calculation {name:"delta_minor",inputs:vec![],expression:"rate.apply(kind == base ? query[31] : query[37]-query[41],rounding)-query[41]"});
                for (role, contract, account) in [(13, 902, "invoice"), (19, 904, "rule")] {
                    c.outputs.push(OutputRole {
                        role,
                        contract,
                        active: "always",
                        account,
                        at: "at",
                        amount: "delta_minor",
                        depends_on: vec!["delta_minor"],
                    });
                }
                c.rules = vec![
                    "rule.invoice equals invoice; unique assessment timestamp per rule; repeated net assessments exclude this rule's prior assessed sum",
                ];
            }
            _ => {
                let role = match code {
                    901 => 11,
                    902 => 13,
                    903 => 17,
                    904 => 19,
                    _ => unreachable!(),
                };
                let (target, slot) = output_root(role)?;
                c.references = vec![
                    reference(
                        1,
                        "producer",
                        if role == 13 {
                            vec![211, 509]
                        } else if role == 19 {
                            vec![509]
                        } else {
                            vec![211]
                        },
                        vec![],
                    ),
                    reference(2, "target", vec![target], vec![]),
                ];
                c.memberships
                    .push(member(output_slot(role)?, "target", target, slot, "amount"));
            }
        }
        declarations.push(c);
    }
    Ok(declarations)
}

pub(crate) fn registrations(id: Uuid, input: Option<&Input>) -> BTreeSet<(Key, Address, Endpoint)> {
    let mut registrations = BTreeSet::new();
    if let Some(input) = input {
        for (target, _, slot) in input.references() {
            registrations.insert((Key::Incoming(target), Address::new(id, slot), Endpoint::All));
        }
        if let Input::Assessment { rule, .. } = input {
            registrations.insert((Key::Direct(*rule), Address::new(id, 2), Endpoint::All));
        }
    }
    registrations
}
pub(crate) fn credit_members(input: Option<&Input>) -> BTreeMap<u16, (Address, i64, Leaf)> {
    match input {
        Some(Input::Credit {
            invoice,
            issue,
            at,
            amount_minor,
        }) => [
            (
                11,
                (
                    Address::new(*invoice, 7),
                    *at,
                    Leaf::Financial(-amount_minor),
                ),
            ),
            (
                13,
                (
                    Address::new(*invoice, 13),
                    *at,
                    Leaf::Financial(-amount_minor),
                ),
            ),
            (
                17,
                (
                    Address::new(*issue, 17),
                    *at,
                    Leaf::Financial(-amount_minor),
                ),
            ),
        ]
        .into(),
        _ => BTreeMap::new(),
    }
}
fn required<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Attempt<L, Invoicing>,
    context: Context,
    id: Uuid,
    code: u16,
) -> Result<ModelRecord<Invoicing>> {
    ws.record(id)?
        .filter(|record| record.tenant == context.tenant && record.contract == code)
        .ok_or_else(|| Error::new("unavailable_reference", "invoicing parent unavailable"))
}

impl Binding for Invoicing {
    type Input = Input;
    type Derived = Derived;
    const NAME: &'static str = "invoice-assessments";
    const BEHAVIOR: &'static str = "invoice-assessments-1";
    fn declarations() -> Result<Vec<Contract>> {
        declarations()
    }
    fn engine() -> Result<Model> {
        Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
    }
    fn limits() -> Limits {
        Limits {
            public_records: 64,
            outputs: 256,
            reservations: 512,
            per_contract: BTreeMap::new(),
        }
    }
    fn valid_derived(input: &Input, derived: Option<&Derived>) -> bool {
        matches!(
            (input, derived),
            (Input::Issue { .. }, Some(Derived::Issue { .. }))
                | (Input::Assessment { .. }, Some(Derived::Assessment { .. }))
        ) || (!matches!(input, Input::Issue { .. } | Input::Assessment { .. }) && derived.is_none())
    }
    fn published_shape(code: u16) -> Value {
        match code {
            211 => json!({"kind":"issue","amount_minor":"0"}),
            509 => {
                json!({"kind":"assessment","basis_minor":"0","prior_minor":"0","assessed_minor":"0","delta_minor":"0"})
            }
            _ => Value::Null,
        }
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
        for change in changes {
            if let Some(record) = &change.new
                && let Input::Credit { invoice, issue, .. } = record.input
            {
                let Input::Issue {
                    invoice: parent_invoice,
                    ..
                } = required(ws, context, issue, 211)?.input
                else {
                    unreachable!()
                };
                if invoice != parent_invoice {
                    return Err(Error::new(
                        "unavailable_reference",
                        "credit issue belongs to another invoice",
                    ));
                }
            }
            let old = registrations(change.id, change.old.as_ref().map(|record| &record.input));
            let new = registrations(change.id, change.new.as_ref().map(|record| &record.input));
            for (key, address, endpoint) in old.difference(&new) {
                routes::change(ws, key, *address, *endpoint, false)?;
            }
            for (key, address, endpoint) in new.difference(&old) {
                routes::change(ws, key, *address, *endpoint, true)?;
            }
            let before = credit_members(change.old.as_ref().map(|record| &record.input));
            let after = credit_members(change.new.as_ref().map(|record| &record.input));
            for slot in [11, 13, 17] {
                crate::mutation::reconcile_member(
                    ws,
                    Address::new(change.id, slot),
                    before.get(&slot).copied(),
                    after.get(&slot).copied(),
                )?;
            }
        }
        crate::causal::settle(ws, model, context, changes, meta, revision, allocate)?;
        // Only an authored assessment timestamp can introduce a duplicate.
        // Its final managed node's neighbours decide uniqueness in bounded work.
        for change in changes {
            if let Some(ModelRecord {
                input: Input::Assessment { rule, at, .. },
                ..
            }) = &change.new
            {
                let Some(StoredValue::Role(binding)) =
                    ws.get(&Key::Role(Address::new(change.id, 19)))?
                else {
                    return Err(Error::new("corrupt_state", "missing assessment role"));
                };
                let root = Address::new(*rule, 19);
                let node = tree::node(ws, root, Address::new(binding.output, 19))?;
                for adjacent in [node.prev, node.next].into_iter().flatten() {
                    if tree::node(ws, root, adjacent)?.key.at == *at {
                        return Err(Error::new(
                            "invariant",
                            "assessment timestamps must be unique per rule",
                        ));
                    }
                }
            }
        }
        for address in ws.changed_roots() {
            let Aggregate::Financial(summary) = tree::root(ws, address)?.summary else {
                return Err(Error::new("corrupt_state", "invoicing root kind"));
            };
            if summary.complete_min() < 0 {
                return Err(Error::new(
                    "invariant",
                    "negative complete-time invoicing capacity",
                ));
            }
        }
        Ok(())
    }
    fn check(store: &Store<Self>) -> Result<Value> {
        super::invoicing_check::check(store)
    }
    fn fixture_catalog() -> Value {
        super::invoicing_fixtures::catalog()
    }
    fn fixture_plan(model: &Prepared<Self>, name: &str, namespace: Uuid) -> Result<Value> {
        super::invoicing_fixtures::plan(model, name, namespace)
    }
}

/// Authored rule fields captured once from the declared direct parent.
pub enum Parameters {
    Issue,
    Assessment {
        kind: TaxKind,
        rate: Rational,
        rounding: Rounding,
    },
}
impl ReactiveBinding for Invoicing {
    type Parameters = Parameters;
    fn resolve<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        context: Context,
        id: Uuid,
        record: &ModelRecord<Self>,
    ) -> Result<Resolved<Self::Parameters>> {
        match record.input {
            Input::Issue { invoice, at, .. } => Ok(Resolved {
                shape: ResolvedShape {
                    reads: vec![],
                    emits: vec![
                        Emit {
                            role: 11,
                            contract: 901,
                            root: Address::new(invoice, 7),
                            at,
                        },
                        Emit {
                            role: 13,
                            contract: 902,
                            root: Address::new(invoice, 13),
                            at,
                        },
                        Emit {
                            role: 17,
                            contract: 903,
                            root: Address::new(id, 17),
                            at,
                        },
                    ],
                },
                parameters: Parameters::Issue,
            }),
            Input::Assessment { invoice, rule, at } => {
                let Input::TaxRule {
                    invoice: parent_invoice,
                    kind,
                    rate,
                    rounding,
                } = required(ws, context, rule, 401)?.input
                else {
                    unreachable!()
                };
                if invoice != parent_invoice {
                    return Err(Error::new(
                        "unavailable_reference",
                        "assessment rule belongs to another invoice",
                    ));
                }
                let (slot, root_slot) = match kind {
                    TaxKind::Base => (31, 7),
                    TaxKind::Net => (37, 13),
                };
                Ok(Resolved {
                    shape: ResolvedShape {
                        reads: vec![
                            Read {
                                slot,
                                root: Address::new(invoice, root_slot),
                                before: Some(at),
                                validate: false,
                            },
                            Read {
                                slot: 41,
                                root: Address::new(rule, 19),
                                before: Some(at),
                                validate: false,
                            },
                        ],
                        emits: vec![
                            Emit {
                                role: 13,
                                contract: 902,
                                root: Address::new(invoice, 13),
                                at,
                            },
                            Emit {
                                role: 19,
                                contract: 904,
                                root: Address::new(rule, 19),
                                at,
                            },
                        ],
                    },
                    parameters: Parameters::Assessment {
                        kind,
                        rate,
                        rounding,
                    },
                })
            }
            _ => Err(Error::new(
                "corrupt_state",
                "nonreactive invoicing contract",
            )),
        }
    }
    fn evaluate(
        _id: Uuid,
        record: &ModelRecord<Self>,
        _shape: &ResolvedShape,
        parameters: &Self::Parameters,
        values: &[i128],
    ) -> Result<(Derived, BTreeMap<u16, i128>)> {
        match (&record.input, parameters) {
            (
                Input::Issue {
                    quantity,
                    unit_price_minor,
                    rounding,
                    ..
                },
                Parameters::Issue,
            ) => {
                let amount_minor = quantity.apply(*unit_price_minor, *rounding)?;
                Ok((
                    Derived::Issue { amount_minor },
                    [(11, amount_minor), (13, amount_minor), (17, amount_minor)].into(),
                ))
            }
            (
                Input::Assessment { .. },
                Parameters::Assessment {
                    kind,
                    rate,
                    rounding,
                },
            ) => {
                let [raw, prior_minor] = values else {
                    return Err(Error::new("internal", "assessment query values"));
                };
                let basis_minor = match kind {
                    TaxKind::Base => *raw,
                    TaxKind::Net => raw
                        .checked_sub(*prior_minor)
                        .ok_or_else(|| Error::new("overflow", "net tax basis"))?,
                };
                let assessed_minor = rate.apply(basis_minor, *rounding)?;
                let delta_minor = assessed_minor
                    .checked_sub(*prior_minor)
                    .ok_or_else(|| Error::new("overflow", "tax assessment difference"))?;
                Ok((
                    Derived::Assessment {
                        basis_minor,
                        prior_minor: *prior_minor,
                        assessed_minor,
                        delta_minor,
                    },
                    [(13, delta_minor), (19, delta_minor)].into(),
                ))
            }
            _ => Err(Error::new("internal", "invoicing parameter type mismatch")),
        }
    }
    fn output_input(producer: Uuid, emit: &Emit, amount: i128) -> Result<Input> {
        Ok(Input::Output {
            producer,
            role: emit.role,
            target: emit.root.id,
            at: emit.at,
            amount,
        })
    }
    fn output_member(input: &Input) -> Result<(Address, i64, Leaf)> {
        match input {
            Input::Output {
                role,
                target,
                at,
                amount,
                ..
            } => Ok((
                Address::new(*target, output_root(*role)?.1),
                *at,
                Leaf::Financial(*amount),
            )),
            _ => Err(Error::new("corrupt_state", "invoicing output contract")),
        }
    }
}
