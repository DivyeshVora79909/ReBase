//! Local JSON-RPC selects typed operations, never authority, fixture mode or KV.

use crate::{
    json::{self, MAX_REQUEST_BYTES},
    local::{LocalStore, Mutation},
    native_codec::uuid_text,
    native_slice::{Error, Result},
    query::{ExistsRequest, PageRequest, RootRequest},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{BufRead, Read, Write};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    jsonrpc: String,
    id: String,
    method: String,
    params: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Get {
    model: String,
    #[serde(with = "uuid_text")]
    id: Uuid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    model: String,
    #[serde(with = "uuid_text")]
    operation_id: Uuid,
}

fn bind<T: for<'de> Deserialize<'de>>(params: Value) -> Result<T> {
    serde_json::from_value(params)
        .map_err(|_| Error::new("invalid_input", "invalid operation params"))
}

fn dispatch(store: &LocalStore, method: &str, params: Value) -> Result<Value> {
    match method {
        "model.describe" => {
            let _: Empty = bind(params)?;
            Ok(store.model().public_catalog())
        }
        "records.get" => {
            let p: Get = bind(params)?;
            serde_json::to_value(store.get(&p.model, p.id)?)
                .map_err(|e| Error::new("internal", e.to_string()))
        }
        "records.mutate" => {
            let p: Mutation = bind(params)?;
            store.mutate(&p)
        }
        "operations.status" => {
            let p: Status = bind(params)?;
            store.operation_status(&p.model, p.operation_id)
        }
        "records.page" => {
            let p: PageRequest = bind(params)?;
            serde_json::to_value(store.page(&p)?).map_err(|e| Error::new("internal", e.to_string()))
        }
        "records.exists" => {
            let p: ExistsRequest = bind(params)?;
            store.exists(&p)
        }
        "roots.read" => {
            let p: RootRequest = bind(params)?;
            store.root_read(&p)
        }
        _ => Err(Error::new("method_not_found", "unknown public method")),
    }
}

fn failure(id: Value, kind: &str) -> Value {
    let (code, message) = match kind {
        "parse_error" => (-32700, "Parse error"),
        "invalid_request" => (
            -32600,
            "A JSON-RPC 2.0 request with a string ID is required",
        ),
        "method_not_found" => (-32601, "Method not found"),
        "invalid_input" => (-32602, "Invalid operation input"),
        "outcome_unknown" => (
            -32001,
            "Commit outcome unknown; retain the operation ID and reconcile after reopening",
        ),
        "forbidden" => (-32000, "Operation is not permitted"),
        "not_found" => (-32000, "Record or root is unavailable"),
        "unavailable_reference" => (-32000, "A required identity is unavailable"),
        "already_exists" => (-32000, "Record already exists"),
        "stale_version" => (-32000, "Record changed; refresh before editing"),
        "model_mismatch" => (-32000, "Model or store format differs"),
        "invariant" => (-32000, "The settled state violates a declared rule"),
        "feedback" => (-32000, "The final calculation graph contains feedback"),
        "duplicate_time" => (-32000, "A quote already occupies that time"),
        "operation_conflict" => (-32000, "Operation ID is bound to different content"),
        "invalid_cursor" => (-32000, "Invalid cursor for this query or store"),
        "query_changed" => (-32000, "Query changed; restart pagination"),
        "unsupported_query" => (-32000, "Query path or operation is not declared"),
        "work_limit" | "state_limit" | "receipt_limit" | "request_limit" => {
            (-32000, "A declared local limit was reached")
        }
        "overflow" | "revision_exhausted" => (-32000, "An exact numeric limit was reached"),
        "allocation_collision" | "allocation_exhausted" => {
            (-32000, "Could not reserve an output identity")
        }
        _ => (-32603, "Local operation failed"),
    };
    let safe_kind = if code == -32603 { "internal" } else { kind };
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message,"data":{"kind":safe_kind}}})
}

pub fn handle(store: &LocalStore, bytes: &[u8]) -> Value {
    let value = match json::parse(bytes) {
        Ok(v) => v,
        Err(e) => return failure(Value::Null, e.code),
    };
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .map_or(Value::Null, |s| json!(s));
    let request = match serde_json::from_value::<Request>(value) {
        Ok(r)
            if r.jsonrpc == "2.0"
                && !r.id.is_empty()
                && r.id.len() <= 128
                && r.params.is_object() =>
        {
            r
        }
        _ => return failure(id, "invalid_request"),
    };
    match dispatch(store, &request.method, request.params) {
        Ok(result) => json!({"jsonrpc":"2.0","id":request.id,"result":result}),
        Err(error) => failure(json!(request.id), error.code),
    }
}

/// Oversize lines are drained without growing the buffer; framing resumes at
/// the next line. Parsing and method dispatch happen only after the byte limit.
pub fn serve(
    store: &LocalStore,
    mut input: impl BufRead,
    mut output: impl Write,
) -> std::io::Result<()> {
    loop {
        let mut bytes = vec![];
        let read = (&mut input)
            .take((MAX_REQUEST_BYTES + 1) as u64)
            .read_until(b'\n', &mut bytes)?;
        if read == 0 {
            return Ok(());
        }
        if bytes.len() > MAX_REQUEST_BYTES && bytes.last() != Some(&b'\n') {
            loop {
                let available = input.fill_buf()?;
                if available.is_empty() {
                    break;
                }
                let end = available.iter().position(|b| *b == b'\n');
                let count = end.map_or(available.len(), |i| i + 1);
                input.consume(count);
                if end.is_some() {
                    break;
                }
            }
        }
        serde_json::to_writer(&mut output, &handle(store, &bytes))?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
}
