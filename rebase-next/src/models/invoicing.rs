//! Bounded invoice pricing, dated tax reassessment and authored cash settlement.
//! Credits, payments and linked refunds are explicit facts. No tax adjustments
//! or external money transfers are invented by the model.
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
    routes,
    time_range::TimeRange,
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
    Treasury {
        currency: u16,
        name: String,
    },
    Payment {
        #[serde(with = "uuid_text")]
        invoice: Uuid,
        #[serde(with = "uuid_text")]
        treasury: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        amount_minor: i128,
    },
    Refund {
        #[serde(with = "uuid_text")]
        invoice: Uuid,
        #[serde(with = "uuid_text")]
        treasury: Uuid,
        #[serde(with = "uuid_text")]
        payment: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        amount_minor: i128,
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

struct OutputSpec {
    role: u16,
    contract: u16,
    name: &'static str,
    target: u16,
    root: u16,
    producers: &'static [u16],
}
const OUTPUTS: &[OutputSpec] = &[
    OutputSpec {
        role: 11,
        contract: 901,
        name: "InvoiceBaseOutput",
        target: 101,
        root: 7,
        producers: &[211],
    },
    OutputSpec {
        role: 13,
        contract: 902,
        name: "InvoiceGrossOutput",
        target: 101,
        root: 13,
        producers: &[211, 509],
    },
    OutputSpec {
        role: 17,
        contract: 903,
        name: "IssueCapacityOutput",
        target: 211,
        root: 17,
        producers: &[211],
    },
    OutputSpec {
        role: 19,
        contract: 904,
        name: "TaxAssessedOutput",
        target: 401,
        root: 19,
        producers: &[509],
    },
    OutputSpec {
        role: 23,
        contract: 905,
        name: "InvoiceBalanceOutput",
        target: 101,
        root: 23,
        producers: &[211, 509],
    },
    OutputSpec {
        role: 29,
        contract: 906,
        name: "InvoiceReceivableOutput",
        target: 101,
        root: 29,
        producers: &[211, 509],
    },
    OutputSpec {
        role: 31,
        contract: 907,
        name: "InvoicePayableOutput",
        target: 101,
        root: 31,
        producers: &[509],
    },
];
fn output_spec(role: u16) -> Result<&'static OutputSpec> {
    OUTPUTS
        .iter()
        .find(|s| s.role == role)
        .ok_or_else(|| Error::new("invalid_input", "unknown invoicing output role"))
}
pub(crate) fn output_contract(role: u16) -> Result<u16> {
    Ok(output_spec(role)?.contract)
}
pub(crate) fn output_slot(role: u16) -> Result<u16> {
    output_contract(role)?;
    Ok(role)
}
fn output_root(role: u16) -> Result<(u16, u16)> {
    let spec = output_spec(role)?;
    Ok((spec.target, spec.root))
}
impl NativeInput for Input {
    fn contract(&self) -> u16 {
        match self {
            Self::Invoice { .. } => 101,
            Self::Issue { .. } => 211,
            Self::Credit { .. } => 307,
            Self::TaxRule { .. } => 401,
            Self::Assessment { .. } => 509,
            Self::Treasury { .. } => 601,
            Self::Payment { .. } => 701,
            Self::Refund { .. } => 809,
            Self::Output { role, .. } => output_contract(*role).unwrap_or(0),
        }
    }
    fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::Invoice { currency } => *currency > 0,
            Self::Treasury { currency, name } => {
                *currency > 0 && (1..=80).contains(&name.chars().count())
            }
            Self::Issue {
                quantity,
                unit_price_minor,
                ..
            } => quantity.numerator() >= 0 && *unit_price_minor >= 0,
            Self::Credit { amount_minor, .. }
            | Self::Payment { amount_minor, .. }
            | Self::Refund { amount_minor, .. } => *amount_minor > 0,
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
            Self::Payment {
                invoice, treasury, ..
            } => vec![(*invoice, 101, 1), (*treasury, 601, 2)],
            Self::Refund {
                invoice,
                treasury,
                payment,
                ..
            } => vec![(*invoice, 101, 1), (*treasury, 601, 2), (*payment, 701, 3)],
            Self::Output {
                producer,
                role,
                target,
                ..
            } => vec![
                (
                    *producer,
                    output_spec(*role).map_or(0, |s| {
                        if s.producers.len() == 1 {
                            s.producers[0]
                        } else {
                            0
                        }
                    }),
                    1,
                ),
                (*target, output_root(*role).map_or(0, |(code, _)| code), 2),
            ],
            Self::Invoice { .. } | Self::Treasury { .. } => vec![],
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
        reads: vec!["summary", "before", "range"],
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
    let mut contracts = vec![
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
            601,
            "Treasury",
            json!({"currency":{"type":"integer","minimum":1,"maximum":65535,"x-rebase-binding":"u16_code"},"name":{"type":"string","minLength":1,"maxLength":80}}),
            vec!["currency", "name"],
        ),
        (
            701,
            "Payment",
            json!({"invoice":uuid,"treasury":uuid,"at":time,"amount_minor":integer_schema(true)}),
            vec!["invoice", "treasury", "at", "amount_minor"],
        ),
        (
            809,
            "Refund",
            json!({"invoice":uuid,"treasury":uuid,"payment":uuid,"at":time,"amount_minor":integer_schema(true)}),
            vec!["invoice", "treasury", "payment", "at", "amount_minor"],
        ),
    ];
    for spec in OUTPUTS {
        contracts.push((spec.contract, spec.name,
            json!({"producer":uuid,"role":{"const":spec.role},"target":uuid,"at":time,"amount":integer_schema(false)}),
            vec!["producer", "role", "target", "at", "amount"]));
    }
    for (code, name, properties, names) in contracts {
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
                        && !matches!(
                            name,
                            "currency" | "invoice" | "issue" | "rule" | "treasury" | "payment"
                        ),
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
            101 => {
                c.roots = vec![
                    root(7, "base"),
                    root(13, "gross"),
                    root(21, "paid"),
                    root(23, "balance"),
                    root(29, "receivable"),
                    root(31, "payable"),
                ]
            }
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
                    (23, 905, "invoice"),
                    (29, 906, "invoice"),
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
                    member(23, "invoice", 101, 23, "-amount_minor"),
                    member(31, "invoice", 101, 31, "amount_minor"),
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
                for (role, contract, account, amount) in [
                    (13, 902, "invoice", "delta_minor"),
                    (19, 904, "rule", "delta_minor"),
                    (23, 905, "invoice", "delta_minor"),
                    (29, 906, "invoice", "max(delta_minor,0)"),
                    (31, 907, "invoice", "max(-delta_minor,0)"),
                ] {
                    c.outputs.push(OutputRole {
                        role,
                        contract,
                        active: "always",
                        account,
                        at: "at",
                        amount,
                        depends_on: vec!["delta_minor"],
                    });
                }
                c.rules = vec![
                    "rule.invoice equals invoice; unique assessment timestamp per rule; repeated net assessments exclude this rule's prior assessed sum",
                ];
            }
            601 => c.roots.push(root(37, "cash")),
            701 => {
                c.references = vec![
                    reference(1, "invoice", vec![101], vec![]),
                    reference(2, "treasury", vec![601], vec![]),
                ];
                c.roots.push(root(41, "refund_capacity"));
                c.memberships = vec![
                    member(21, "invoice", 101, 21, "amount_minor"),
                    member(23, "invoice", 101, 23, "-amount_minor"),
                    member(31, "invoice", 101, 31, "amount_minor"),
                    member(37, "treasury", 601, 37, "amount_minor"),
                    member(41, "self", 701, 41, "amount_minor"),
                ];
                c.rules = vec![
                    "invoice.currency equals treasury.currency; nonnegative chronological invoice balance",
                ];
            }
            809 => {
                c.references = vec![
                    reference(1, "invoice", vec![101], vec![]),
                    reference(2, "treasury", vec![601], vec![]),
                    reference(3, "payment", vec![701], vec![]),
                ];
                c.memberships = vec![
                    member(21, "invoice", 101, 21, "-amount_minor"),
                    member(23, "invoice", 101, 23, "amount_minor"),
                    member(29, "invoice", 101, 29, "amount_minor"),
                    member(37, "treasury", 601, 37, "-amount_minor"),
                    member(41, "payment", 701, 41, "-amount_minor"),
                ];
                c.rules = vec![
                    "payment.invoice equals invoice; payment.treasury equals treasury; nonnegative chronological payment refund capacity",
                ];
            }
            _ => {
                let spec = OUTPUTS.iter().find(|s| s.contract == code).unwrap();
                let role = spec.role;
                let (target, slot) = output_root(role)?;
                c.references = vec![
                    reference(1, "producer", spec.producers.to_vec(), vec![]),
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

pub(crate) fn registrations(id: Uuid, input: Option<&Input>) -> BTreeSet<(Key, Address)> {
    let mut registrations = BTreeSet::new();
    if let Some(input) = input {
        for (target, _, slot) in input.references() {
            registrations.insert((Key::Incoming(target), Address::new(id, slot)));
        }
        if let Input::Assessment { rule, .. } = input {
            registrations.insert((Key::Direct(*rule), Address::new(id, 2)));
        }
    }
    registrations
}
fn authored_members(id: Uuid, input: Option<&Input>) -> BTreeMap<u16, (Address, i64, Leaf)> {
    let (at, entries) = match input {
        Some(Input::Credit {
            invoice,
            issue,
            at,
            amount_minor,
        }) => (
            *at,
            [
                (11, Address::new(*invoice, 7), -amount_minor),
                (13, Address::new(*invoice, 13), -amount_minor),
                (17, Address::new(*issue, 17), -amount_minor),
                (23, Address::new(*invoice, 23), -amount_minor),
                (31, Address::new(*invoice, 31), *amount_minor),
            ],
        ),
        Some(Input::Payment {
            invoice,
            treasury,
            at,
            amount_minor,
        }) => (
            *at,
            [
                (21, Address::new(*invoice, 21), *amount_minor),
                (23, Address::new(*invoice, 23), -amount_minor),
                (31, Address::new(*invoice, 31), *amount_minor),
                (37, Address::new(*treasury, 37), *amount_minor),
                (41, Address::new(id, 41), *amount_minor),
            ],
        ),
        Some(Input::Refund {
            invoice,
            treasury,
            payment,
            at,
            amount_minor,
        }) => (
            *at,
            [
                (21, Address::new(*invoice, 21), -amount_minor),
                (23, Address::new(*invoice, 23), *amount_minor),
                (29, Address::new(*invoice, 29), *amount_minor),
                (37, Address::new(*treasury, 37), -amount_minor),
                (41, Address::new(*payment, 41), -amount_minor),
            ],
        ),
        _ => return BTreeMap::new(),
    };
    entries
        .into_iter()
        .map(|(slot, root, amount)| (slot, (root, at, Leaf::Financial(amount))))
        .collect()
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
    const BEHAVIOR: &'static str = "invoice-assessments-3";
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
            if let Some(record) = &change.new {
                match record.input {
                    Input::Payment {
                        invoice, treasury, ..
                    } => {
                        let Input::Invoice { currency } =
                            required(ws, context, invoice, 101)?.input
                        else {
                            unreachable!()
                        };
                        if !matches!(required(ws, context, treasury, 601)?.input, Input::Treasury { currency: cash_currency, .. } if cash_currency == currency)
                        {
                            return Err(Error::new(
                                "unavailable_reference",
                                "invoice and treasury currencies differ",
                            ));
                        }
                    }
                    Input::Refund {
                        invoice,
                        treasury,
                        payment,
                        ..
                    } => {
                        let Input::Payment {
                            invoice: original_invoice,
                            treasury: original_treasury,
                            ..
                        } = required(ws, context, payment, 701)?.input
                        else {
                            unreachable!()
                        };
                        if original_invoice != invoice || original_treasury != treasury {
                            return Err(Error::new(
                                "unavailable_reference",
                                "refund disagrees with its payment",
                            ));
                        }
                    }
                    _ => {}
                }
            }
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
            for (key, address) in old.difference(&new) {
                routes::change(ws, key, *address, TimeRange::ALL, false)?;
            }
            for (key, address) in new.difference(&old) {
                routes::change(ws, key, *address, TimeRange::ALL, true)?;
            }
            let before =
                authored_members(change.id, change.old.as_ref().map(|record| &record.input));
            let after =
                authored_members(change.id, change.new.as_ref().map(|record| &record.input));
            let slots: BTreeSet<_> = before.keys().chain(after.keys()).copied().collect();
            for slot in slots {
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
                        Emit {
                            role: 23,
                            contract: 905,
                            root: Address::new(invoice, 23),
                            at,
                        },
                        Emit {
                            role: 29,
                            contract: 906,
                            root: Address::new(invoice, 29),
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
                                range: TimeRange::before(at),
                                validate: false,
                            },
                            Read {
                                slot: 41,
                                root: Address::new(rule, 19),
                                range: TimeRange::before(at),
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
                            Emit {
                                role: 23,
                                contract: 905,
                                root: Address::new(invoice, 23),
                                at,
                            },
                            Emit {
                                role: 29,
                                contract: 906,
                                root: Address::new(invoice, 29),
                                at,
                            },
                            Emit {
                                role: 31,
                                contract: 907,
                                root: Address::new(invoice, 31),
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
                    [
                        (11, amount_minor),
                        (13, amount_minor),
                        (17, amount_minor),
                        (23, amount_minor),
                        (29, amount_minor),
                    ]
                    .into(),
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
                let payable = if delta_minor < 0 {
                    delta_minor
                        .checked_neg()
                        .ok_or_else(|| Error::new("overflow", "tax payable claim"))?
                } else {
                    0
                };
                Ok((
                    Derived::Assessment {
                        basis_minor,
                        prior_minor: *prior_minor,
                        assessed_minor,
                        delta_minor,
                    },
                    [
                        (13, delta_minor),
                        (19, delta_minor),
                        (23, delta_minor),
                        (29, delta_minor.max(0)),
                        (31, payable),
                    ]
                    .into(),
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
