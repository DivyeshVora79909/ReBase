//! Exact-value integration through an intentionally test-only compiled model.
//! Currency is one immutable unit; each entry rounds before its integer posting.
use rebase_semantic_proof::{
    binding::{Binding, NativeInput},
    identity::{self, IdentityConfig, TokenRequest},
    local::Store,
    model::{
        self, Contract, InputField, Membership, Prepared, PublishedField, Reference,
        RootDeclaration, Visibility,
    },
    mutation::reconcile_member,
    native_codec::{Address, Key, StoredValue, decimal, uuid_text},
    native_slice::{Attempt, Context, Error, Meta, Model, ModelChange, Result},
    routes,
    server::{self, ServerConfig},
    time_range::TimeRange,
    tree::{Kind, Leaf},
    values::{Rational, Rounding},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactEntries;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum Input {
    Bucket {
        currency: u16,
    },
    Entry {
        #[serde(with = "uuid_text")]
        bucket: Uuid,
        #[serde(with = "decimal")]
        at: i64,
        #[serde(with = "decimal")]
        amount: i128,
        rate: Rational,
        rounding: Rounding,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Derived {
    #[serde(with = "decimal")]
    rounded: i128,
}

impl NativeInput for Input {
    fn contract(&self) -> u16 {
        match self {
            Self::Bucket { .. } => 11,
            Self::Entry { .. } => 29,
        }
    }
    fn validate(&self) -> Result<()> {
        if matches!(self, Self::Bucket { currency: 0 }) {
            return Err(Error::new("invalid_input", "currency code is positive"));
        }
        Ok(())
    }
    fn bind(code: u16, fields: Value) -> Result<Self> {
        let input: Self = serde_json::from_value(fields.clone())
            .map_err(|e| Error::new("invalid_input", e.to_string()))?;
        input.validate()?;
        if input.contract() != code || serde_json::to_value(&input).unwrap() != fields {
            return Err(Error::new(
                "invalid_input",
                "complete canonical input required",
            ));
        }
        Ok(input)
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        match self {
            Self::Entry { bucket, .. } => vec![(*bucket, 11, 1)],
            _ => vec![],
        }
    }
}

fn integer_schema() -> Value {
    json!({"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","x-rebase-binding":"i128","x-rebase-range":[i128::MIN.to_string(),i128::MAX.to_string()]})
}

impl Binding for ExactEntries {
    type Input = Input;
    type Derived = Derived;
    const NAME: &'static str = "test-exact-entries";
    const BEHAVIOR: &'static str = "test-exact-entries-1";
    fn engine() -> Result<Model> {
        Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
    }
    fn declarations() -> Result<Vec<Contract>> {
        let uuid = json!({"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$","x-rebase-binding":"uuid"});
        let mut declarations = vec![];
        for (code, name, properties, names) in [
            (
                11,
                "Bucket",
                json!({"currency":{"type":"integer","minimum":1,"maximum":65535}}),
                vec!["currency"],
            ),
            (
                29,
                "ScaledEntry",
                json!({"bucket":uuid,"at":{"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","x-rebase-binding":"i64","x-rebase-range":[i64::MIN.to_string(),i64::MAX.to_string()]},"amount":integer_schema(),"rate":Rational::schema(),"rounding":Rounding::schema()}),
                vec!["bucket", "at", "amount", "rate", "rounding"],
            ),
        ] {
            let mut contract = Contract {
                code,
                name,
                visibility: Visibility::Public,
                schema: json!({"$schema":model::SCHEMA_DIALECT,"type":"object","additionalProperties":false,"properties":properties,"required":names}),
                fields: names
                    .iter()
                    .enumerate()
                    .map(|(index, name)| InputField {
                        code: index as u16 + 1,
                        name,
                        mutable: code == 29,
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
                schema_source: "tests/exact_values.rs",
                behavior_source: "tests/exact_values.rs",
            };
            if code == 11 {
                contract.roots.push(RootDeclaration {
                    slot: 7,
                    name: "rounded_entries",
                    kind: Kind::Financial,
                    reads: vec!["summary", "before"],
                    invariant: None,
                });
            } else {
                contract.references.push(Reference {
                    slot: 1,
                    field: "bucket",
                    targets: vec![11],
                    optional: false,
                    direct_fields: vec![],
                    on_delete: "reject",
                    reader: true,
                });
                contract.memberships.push(Membership {
                    slot: 13,
                    through: "bucket",
                    root_contract: 11,
                    root_slot: 7,
                    kind: Kind::Financial,
                    key: "at",
                    value: "rounded",
                });
                contract.published.push(PublishedField {
                    code: 101,
                    name: "rounded",
                    binding: "i128",
                });
                contract.calculations.push(model::Calculation {
                    name: "rounded",
                    inputs: vec![],
                    expression: "rate.apply(amount, rounding)",
                });
            }
            declarations.push(contract);
        }
        Ok(declarations)
    }
    fn valid_derived(input: &Input, derived: Option<&Derived>) -> bool {
        matches!(
            (input, derived),
            (Input::Bucket { .. }, None) | (Input::Entry { .. }, Some(_))
        )
    }
    fn published_shape(code: u16) -> Value {
        if code == 29 {
            json!({"rounded":"0"})
        } else {
            Value::Null
        }
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
            let registrations = |record: Option<
                &rebase_semantic_proof::native_slice::ModelRecord<Self>,
            >| {
                record
                    .into_iter()
                    .flat_map(|r| r.input.references())
                    .map(|(target, _, slot)| (Key::Incoming(target), Address::new(change.id, slot)))
                    .collect::<std::collections::BTreeSet<_>>()
            };
            let before = registrations(change.old.as_ref());
            let after = registrations(change.new.as_ref());
            for (key, address) in before.difference(&after) {
                routes::change(ws, key, *address, TimeRange::ALL, false)?;
            }
            for (key, address) in after.difference(&before) {
                routes::change(ws, key, *address, TimeRange::ALL, true)?;
            }
            let member = |record: Option<
                &rebase_semantic_proof::native_slice::ModelRecord<Self>,
            >|
             -> Result<_> {
                match record.map(|r| &r.input) {
                    Some(Input::Entry {
                        bucket,
                        at,
                        amount,
                        rate,
                        rounding,
                    }) => Ok(Some((
                        Address::new(*bucket, 7),
                        *at,
                        Leaf::Financial(rate.apply(*amount, *rounding)?),
                    ))),
                    _ => Ok(None),
                }
            };
            let old = member(change.old.as_ref())?;
            let new = member(change.new.as_ref())?;
            if let Some(mut record) = change.new.clone()
                && let Some((_, _, Leaf::Financial(rounded))) = new
            {
                record.derived = Some(Derived { rounded });
                ws.put(Key::Record(change.id), Some(StoredValue::Record(record)))?;
            }
            reconcile_member(ws, Address::new(change.id, 13), old, new)?;
        }
        Ok(())
    }
    // This test binding checks its own projections. It does not claim a third
    // production model or a replacement for the complete bundled checkers.
    fn check(store: &Store<Self>) -> Result<Value> {
        let image = store.inspect()?;
        let mut sums = BTreeMap::<Uuid, i128>::new();
        for row in image["records"].as_array().unwrap() {
            let input: Input = serde_json::from_value(row["record"]["input"].clone()).unwrap();
            match input {
                Input::Bucket { .. } => {
                    sums.entry(Uuid::parse_str(row["id"].as_str().unwrap()).unwrap())
                        .or_default();
                }
                Input::Entry {
                    bucket,
                    amount,
                    rate,
                    rounding,
                    ..
                } => {
                    let rounded = rate.apply(amount, rounding)?;
                    if row["record"]["derived"]["rounded"] != rounded.to_string() {
                        return Err(Error::new("corrupt_state", "test entry projection"));
                    }
                    let total = sums.entry(bucket).or_default();
                    *total = total
                        .checked_add(rounded)
                        .ok_or_else(|| Error::new("overflow", "test source sum"))?;
                }
            }
        }
        for root in image["roots"].as_array().unwrap() {
            let bucket = Uuid::parse_str(root["root"]["id"].as_str().unwrap()).unwrap();
            if root["summary"]["value"]["sum"] != sums[&bucket].to_string() {
                return Err(Error::new("corrupt_state", "test root sum"));
            }
        }
        Ok(json!({"test_model":"valid"}))
    }
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/exact-value-tests")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn rpc(addr: SocketAddr, token: &str, method: &str, params: Value) -> Value {
    let token = token.to_owned();
    let body = serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":"exact-values","method":method,"params":params}),
    )
    .unwrap();
    tokio::task::spawn_blocking(move || {
        let mut stream=TcpStream::connect_timeout(&addr,Duration::from_secs(5)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(stream,"POST /rpc HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n",body.len()).unwrap();
        stream.write_all(&body).unwrap();
        let mut response=vec![]; stream.read_to_end(&mut response).unwrap();
        let boundary=response.windows(4).position(|part|part==b"\r\n\r\n").unwrap();
        assert_eq!(std::str::from_utf8(&response[..boundary]).unwrap().split_whitespace().nth(1),Some("200"));
        serde_json::from_slice(&response[boundary+4..]).unwrap()
    }).await.unwrap()
}
fn result(response: Value) -> Value {
    assert!(response.get("result").is_some(), "{response}");
    response["result"].clone()
}
fn entry(
    record: u128,
    bucket: u128,
    amount: &str,
    numerator: &str,
    denominator: &str,
    rounding: &str,
) -> Value {
    json!({"op":"create","id":id(record),"contract":29,"fields":{"bucket":id(bucket),"at":record.to_string(),"amount":amount,"rate":{"numerator":numerator,"denominator":denominator},"rounding":rounding}})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_values_cross_native_binding_http_receipts_and_reopening() {
    let directory = Directory::new();
    let path = directory.0.join("exact.redb");
    let model = Arc::new(Prepared::<ExactEntries>::load().unwrap());
    // Schema publication is composed from the primitive, not a copied rate schema.
    assert_eq!(
        model.contract(29).unwrap().schema["properties"]["rate"],
        Rational::schema()
    );
    assert_eq!(
        model.contract(29).unwrap().schema["properties"]["rounding"],
        Rounding::schema()
    );
    let store = Arc::new(
        Store::<ExactEntries>::create_secured(
            &path,
            model.clone(),
            Context {
                tenant: id(1),
                actor: id(2),
            },
        )
        .unwrap(),
    );
    let cfg = ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        identity: IdentityConfig {
            issuer: "https://identity.example.test".into(),
            audience: "rebase-exact-values".into(),
            public_keys: BTreeMap::from([(
                "test".into(),
                include_str!("fixtures/test-ed25519-public.pem").into(),
            )]),
            max_token_seconds: 600,
        },
        max_inflight: 4,
        request_timeout_seconds: 5,
    };
    let token = identity::issue(
        &cfg.identity,
        &TokenRequest {
            tenant: id(1),
            actor: id(2),
            epoch: 0,
            ttl: 300,
            key_id: "test".into(),
        },
        include_bytes!("fixtures/test-ed25519-private.pem"),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind(cfg.listen).await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = server::router(store.clone(), &cfg).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let session = result(rpc(address, &token, "session.describe", json!({})).await);
    let mutation = |operation, commands, returning| json!({"model":model.identity(),"context":session["operation_context"],"operation_id":id(operation),"commands":commands,"returning":returning});
    let seed = mutation(
        1000,
        json!([
            {"op":"create","id":id(10),"contract":11,"fields":{"currency":1}},
            {"op":"create","id":id(20),"contract":11,"fields":{"currency":1}},
            entry(11,10,"9007199254740993","3","2","half_even"),
            entry(12,10,"5","1","2","half_even"),
            entry(13,10,"-5","1","2","half_away_from_zero")
        ]),
        json!([id(11), id(12), id(13)]),
    );
    let committed = result(rpc(address, &token, "records.mutate", seed.clone()).await);
    assert_eq!(committed["replayed"], false);
    let returned = committed["result"]["records"].as_array().unwrap();
    for (row, expected) in returned.iter().zip(["13510798882111490", "2", "-3"]) {
        assert_eq!(row["record"]["derived"]["rounded"], expected);
    }
    assert_eq!(returned[0]["record"]["input"]["amount"], "9007199254740993");
    let replay = result(rpc(address, &token, "records.mutate", seed.clone()).await);
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["result"], committed["result"]);
    let root = result(
        rpc(
            address,
            &token,
            "roots.read",
            json!({"model":model.identity(),"owner":id(10),"slot":7,"read":{"kind":"summary"}}),
        )
        .await,
    );
    assert_eq!(root["value"]["sum"], "13510798882111489");
    store.check_integrity().unwrap();

    let mut array_rate = entry(37, 10, "1", "1", "2", "half_even");
    array_rate["fields"]["rate"] = json!(["1", "2"]);
    let invalid = vec![
        (entry(30, 10, "1", "2", "4", "half_even"), "invalid_input"),
        (entry(31, 10, "1", "0", "2", "half_even"), "invalid_input"),
        (entry(32, 10, "1", "1", "0", "half_even"), "invalid_input"),
        (entry(33, 10, "1", "1", "-2", "half_even"), "invalid_input"),
        (entry(34, 10, "1", "01", "2", "half_even"), "invalid_input"),
        (entry(35, 10, "1", "1", "2", "exact"), "inexact"),
        (array_rate, "invalid_input"),
        (
            entry(36, 10, &i128::MAX.to_string(), "2", "1", "half_even"),
            "overflow",
        ),
    ];
    let before = store.observe_for_verification().unwrap();
    let before_inspect = store.inspect().unwrap();
    for (index, (command, kind)) in invalid.into_iter().enumerate() {
        let operation = 1100 + index as u128;
        // A valid source is staged first: rejection must discard the entire batch.
        let request = mutation(
            operation,
            json!([
                entry(100 + index as u128, 10, "6", "1", "2", "exact"),
                command
            ]),
            json!([]),
        );
        let rejected = rpc(address, &token, "records.mutate", request).await;
        assert_eq!(rejected["error"]["data"]["kind"], kind, "{rejected}");
        assert_eq!(store.observe_for_verification().unwrap(), before);
        assert_eq!(store.inspect().unwrap(), before_inspect);
        let status=result(rpc(address,&token,"operations.status",json!({"model":model.identity(),"context":session["operation_context"],"operation_id":id(operation)})).await);
        assert_eq!(status["status"], "not_observed");
    }
    // Both values bind and quantize individually; the second tree insertion
    // overflows only while combining the settled financial aggregate.
    let rejected = rpc(
        address,
        &token,
        "records.mutate",
        mutation(
            1200,
            json!([
                entry(200, 20, &i128::MAX.to_string(), "1", "1", "exact"),
                entry(201, 20, "1", "1", "1", "exact")
            ]),
            json!([]),
        ),
    )
    .await;
    assert_eq!(rejected["error"]["data"]["kind"], "overflow", "{rejected}");
    assert_eq!(store.observe_for_verification().unwrap(), before);
    assert_eq!(store.inspect().unwrap(), before_inspect);
    let status=result(rpc(address,&token,"operations.status",json!({"model":model.identity(),"context":session["operation_context"],"operation_id":id(1200)})).await);
    assert_eq!(status["status"], "not_observed");

    stop.send(()).unwrap();
    serving.await.unwrap();
    drop(store);
    let reopened = Store::<ExactEntries>::open(&path, model.clone()).unwrap();
    assert_eq!(reopened.observe_for_verification().unwrap(), before);
    assert_eq!(reopened.inspect().unwrap(), before_inspect);
    reopened.check_integrity().unwrap();
    let seed: rebase_semantic_proof::local::Mutation = serde_json::from_value(seed).unwrap();
    let replay = reopened.mutate(&seed).unwrap();
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["result"], committed["result"]);
    assert_eq!(reopened.observe_for_verification().unwrap(), before);
}
