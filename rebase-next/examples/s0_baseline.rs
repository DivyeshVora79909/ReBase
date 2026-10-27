//! Bounded primitive-adapter observer for the frozen S0 workload. The independent
//! Node checker derives ordered facts; this observer stops on frozen literal mismatches.
use rebase_semantic_proof::{
    binding::Calculation,
    diagnostics::{Recorder, error_outcome},
    local::{Mutation, Store},
    model::Prepared,
    native_codec::{self, Address, Key, Stored},
    native_slice::{
        Attempt, Command, Context, Error, Meta, Model, Population, Result, Work, settle_with_ids,
    },
    storage::{self, Database, ReadableTable, TableDefinition},
    time_range::{TimeBound, TimeRange},
    tree,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::BTreeSet,
    fs,
    io::{self, BufRead, Write},
    path::Path,
    sync::Arc,
    time::Instant,
};
use uuid::Uuid;
#[path = "s0_baseline/fingerprint.rs"]
mod fingerprint;

const INPUTS: &str = include_str!("../research/fixtures/s0-inputs.json");
const MANIFEST: &str = include_str!("../research/fixtures/s0-workload-manifest.json");
const KV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("native_kv");
const MAX_REPORT: usize = 64 * 1024 * 1024;
const ADMISSION_RESERVE: usize = 8 * 1024 * 1024;
const LIMIT: u64 = 100_000;
fn bad(detail: impl Into<String>) -> Error {
    Error::new("invalid_input", detail)
}
fn io_error(e: impl std::fmt::Display) -> Error {
    Error::new("storage", e.to_string())
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u64::MAX as u128) as u64
}
fn bounded_line(reader: impl BufRead, limit: usize) -> Result<String> {
    let mut line = String::new();
    reader
        .take((limit + 1) as u64)
        .read_line(&mut line)
        .map_err(io_error)?;
    if line.len() > limit || !line.ends_with('\n') {
        return Err(bad("missing or oversized bounded input line"));
    }
    Ok(line)
}
fn wire(request: &Request, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io_error)?;
    let total = request.wire_bytes.borrow().saturating_add(bytes.len() + 1);
    if total > MAX_REPORT {
        return Err(bad("cumulative probe wire bound exceeded"));
    }
    let mut output = io::stdout().lock();
    output.write_all(&bytes).map_err(io_error)?;
    output.write_all(b"\n").map_err(io_error)?;
    output.flush().map_err(io_error)?;
    *request.wire_bytes.borrow_mut() = total;
    Ok(())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Ack {
    action_id: String,
    cache_phase: String,
    #[serde(rename = "continue")]
    proceed: bool,
}
fn parse_ack(line: &str, sample: &Value) -> Result<bool> {
    let ack: Ack =
        serde_json::from_str(line).map_err(|_| bad("malformed checkpoint acknowledgement"))?;
    if ack.action_id != sample["actionId"].as_str().expect("sample action")
        || ack.cache_phase != sample["cachePhase"].as_str().expect("sample phase")
    {
        return Err(bad("checkpoint acknowledgement identity differs"));
    }
    Ok(ack.proceed)
}
// S0-only checkpoint: the independent Node checker and resource observer run
// while native execution is paused, including between traversals in one Attempt.
fn checkpoint(request: &Request, sample: &Value) -> Result<bool> {
    let frame = json!({"format":"rebase-s0-checkpoint-1","sample":sample});
    let frame_len = serde_json::to_vec(&frame).map_err(io_error)?.len() + 1;
    let sample_len = serde_json::to_vec(sample).map_err(io_error)?.len();
    *request.report_bytes.borrow_mut() += sample_len + 1;
    if request
        .wire_bytes
        .borrow()
        .saturating_add(frame_len)
        .saturating_add(*request.report_bytes.borrow())
        .saturating_add(256 * 1024)
        > MAX_REPORT
    {
        *request.checkpoint_stop.borrow_mut() = Some("checkpoint-wire-admission-bound".into());
        return Ok(false);
    }
    wire(request, &frame)?;
    let result = bounded_line(io::stdin().lock(), 1024).and_then(|line| parse_ack(&line, sample));
    let reason = match result {
        Ok(true) => return Ok(true),
        Ok(false) => "checkpoint-rejected",
        Err(_) => "checkpoint-acknowledgement-invalid",
    };
    *request.checkpoint_stop.borrow_mut() = Some(reason.into());
    Ok(false)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    format: String,
    backend: String,
    location: String,
    namespace: Option<String>,
    cluster_file: Option<String>,
    phase: String,
    cases: Vec<Selection>,
    samples: usize,
    trace: bool,
    manifest_sha256: String,
    inputs_sha256: String,
    #[serde(skip)]
    owned_targets: RefCell<Vec<String>>,
    #[serde(skip)]
    preserve_targets: RefCell<BTreeSet<String>>,
    #[serde(skip)]
    wire_bytes: RefCell<usize>,
    #[serde(skip)]
    report_bytes: RefCell<usize>,
    #[serde(skip)]
    checkpoint_stop: RefCell<Option<String>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    corpus: String,
    action: String,
}
fn validate(request: &Request, inputs: &Value) -> Result<()> {
    if request.format != "rebase-s0-probe-input-1"
        || request.manifest_sha256 != hash(MANIFEST.as_bytes())
        || request.inputs_sha256 != hash(INPUTS.as_bytes())
    {
        return Err(bad("request format or embedded fixture hash mismatch"));
    }
    if !matches!(
        request.phase.as_str(),
        "focused" | "pilot" | "baseline" | "overhead"
    ) || request.cases.is_empty()
        || request.cases.len() > 64
    {
        return Err(bad("invalid phase or cases"));
    }
    if request.samples == 0
        || request.samples > 30
        || (matches!(request.phase.as_str(), "pilot" | "focused") && request.samples != 1)
    {
        return Err(bad("invalid sample count"));
    }
    if !Path::new(&request.location).is_absolute()
        || fs::symlink_metadata(&request.location).is_ok()
    {
        return Err(bad("location must be an absent absolute owned directory"));
    }
    match request.backend.as_str() {
        "redb" => {}
        "surrealkv" => {
            if !cfg!(feature = "surrealkv") {
                return Err(bad("surrealkv feature not compiled"));
            }
        }
        "foundationdb-local" => {
            if !cfg!(feature = "foundationdb") {
                return Err(bad("foundationdb feature not compiled"));
            }
            let namespace = request
                .namespace
                .as_deref()
                .ok_or_else(|| bad("explicit namespace required"))?;
            if !namespace.starts_with("rebase-s0-")
                || namespace.len() > 128
                || !namespace
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(bad(
                    "namespace must be an explicit rebase-s0- ASCII identifier",
                ));
            }
            let cluster = request
                .cluster_file
                .as_deref()
                .ok_or_else(|| bad("explicit clusterFile required"))?;
            if !Path::new(cluster).is_absolute() || !Path::new(cluster).is_file() {
                return Err(bad("clusterFile must be an existing absolute file"));
            }
        }
        _ => return Err(bad("unsupported backend")),
    }
    let mut seen = BTreeSet::new();
    for selected in &request.cases {
        let corpus = find_corpus(inputs, &selected.corpus)?;
        find_action(corpus, &selected.action)?;
        if !seen.insert((&selected.corpus, &selected.action)) {
            return Err(bad("duplicate selected action"));
        }
        if request.phase == "overhead"
            && (selected.corpus != "entry-8" || selected.action != "prefix")
        {
            return Err(bad("overhead requires entry-8 prefix"));
        }
    }
    Ok(())
}
fn find_corpus<'a>(inputs: &'a Value, id: &str) -> Result<&'a Value> {
    inputs["corpora"]
        .as_array()
        .and_then(|v| v.iter().find(|c| c["id"] == id))
        .ok_or_else(|| bad("unknown corpus"))
}
fn find_action<'a>(corpus: &'a Value, id: &str) -> Result<&'a Value> {
    corpus["actions"]
        .as_array()
        .and_then(|v| v.iter().find(|c| c["id"] == id))
        .ok_or_else(|| bad("unknown action"))
}
fn context(corpus: &Value) -> Result<Context> {
    Ok(Context {
        tenant: serde_json::from_value(corpus["tenant"].clone()).map_err(io_error)?,
        actor: serde_json::from_value(corpus["actor"].clone()).map_err(io_error)?,
    })
}

fn connect(request: &Request, name: &str) -> Result<Database> {
    match request.backend.as_str() {
        "redb" => Database::create(Path::new(&request.location).join(format!("{name}.redb"))),
        #[cfg(feature = "surrealkv")]
        "surrealkv" => storage::surrealkv::connect(Path::new(&request.location).join(name)),
        #[cfg(feature = "foundationdb")]
        "foundationdb-local" => storage::foundationdb::connect(
            request.cluster_file.as_deref(),
            format!(
                "{}/{name}",
                request.namespace.as_deref().expect("validated")
            )
            .as_bytes(),
        ),
        _ => Err(bad("backend feature unavailable")),
    }
}
fn assert_empty(db: &Database) -> Result<()> {
    let read = db.begin_read()?;
    if read.list_tables()?.next().is_some() || read.has_multimap_tables()? {
        return Err(bad("owned namespace is not empty"));
    }
    Ok(())
}
fn claim(request: &Request, name: &str) -> Result<Database> {
    let db = connect(request, name)?;
    assert_empty(&db)?;
    Ok(db)
}
// Only targets verified empty by this process enter this guard. A preexisting
// namespace rejected by claim is never included in cleanup.
struct OwnedCleanup<'a> {
    request: &'a Request,
    disarmed: bool,
}
impl Drop for OwnedCleanup<'_> {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        let mut failed = false;
        for name in self.request.owned_targets.borrow().iter() {
            if self.request.preserve_targets.borrow().contains(name) {
                continue;
            }
            let result = connect(self.request, name).and_then(|db| clear(&db));
            if let Err(error) = result {
                failed = true;
                eprintln!("owned cleanup failed for {name}: {error}");
            }
        }
        if !failed
            && self.request.preserve_targets.borrow().is_empty()
            && let Err(error) = fs::remove_dir_all(&self.request.location)
        {
            eprintln!("owned directory cleanup failed: {error}");
        }
    }
}
fn clear(db: &Database) -> Result<()> {
    let read = db.begin_read()?;
    let tables: Vec<_> = read.list_tables()?.map(|t| t.name().to_owned()).collect();
    drop(read);
    let write = db.begin_write()?;
    for table in tables {
        if matches!(table.as_str(), "public_records" | "reader_records") {
            write.delete_table(TableDefinition::<&[u8], u16>::new(&table))?;
        } else {
            write.delete_table(TableDefinition::<&[u8], &[u8]>::new(&table))?;
        }
    }
    write.commit()
}
fn initialize(db: &Database, model: &Model, context: Context) -> Result<()> {
    assert_empty(db)?;
    let write = db.begin_write()?;
    if write.list_tables()?.next().is_some() {
        return Err(Error::new(
            "storage_exists",
            "destination changed before protected initialization",
        ));
    }
    {
        let mut table = write.open_table(KV)?;
        for (key, value) in [
            (
                Key::Meta,
                Stored::Meta(Meta {
                    model: model.identity.clone(),
                    codec: model.codec.clone(),
                    tenant: context.tenant,
                    actor: context.actor,
                }),
            ),
            (
                Key::Population,
                Stored::Population(Population {
                    counts: (1..=12).map(|c| (c, 0)).collect(),
                    reserved: 0,
                }),
            ),
        ] {
            table.insert(key.encode(), native_codec::encode(&key, &value)?.as_slice())?;
        }
    }
    write.commit()
}
fn snapshot(db: &Database) -> Result<Value> {
    let read = db.begin_read()?;
    let tables: Vec<_> = read.list_tables()?.map(|t| t.name().to_owned()).collect();
    if tables != ["native_kv"] || read.has_multimap_tables()? {
        return Err(bad("observation has unexpected application tables"));
    }
    let table = read.open_table(KV)?;
    let mut rows = Vec::new();
    for row in table.iter()? {
        let (key, value) = row?;
        let decoded = native_codec::decode(&Key::decode(key.value())?, value.value())?;
        rows.push(json!({"key":native_codec::hex(key.value()),"value":native_codec::hex(value.value()),"decoded":decoded}));
        if rows.len() > 4096 {
            return Err(bad("native snapshot row bound exceeded"));
        }
    }
    Ok(json!({"complete":true,"tables":tables,"rows":rows}))
}
fn deterministic_id(action: &str, counter: usize) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_OID,
        format!("s0-native-avl-1/{action}/{counter}").as_bytes(),
    )
}
fn allocate(
    action: &str,
    phase: &str,
    allocations: &mut Vec<Value>,
) -> impl FnMut() -> Result<Uuid> {
    let mut counter = 0usize;
    move || {
        let id = deterministic_id(action, counter);
        allocations.push(json!({"phase":phase,"counter":counter,"id":id}));
        counter += 1;
        Ok(id)
    }
}
fn publish(
    write: &storage::WriteTransaction,
    batch: &std::collections::BTreeMap<Vec<u8>, Option<Vec<u8>>>,
) -> Result<()> {
    let mut table = write.open_table(KV)?;
    for (key, value) in batch {
        match value {
            Some(value) => {
                table.insert(key, value.as_slice())?;
            }
            None => {
                table.remove(key)?;
            }
        }
    }
    Ok(())
}
fn setup(
    db: &Database,
    model: &Model,
    context: Context,
    commands: &Value,
    identity: &str,
    allocations: &mut Vec<Value>,
) -> Result<()> {
    let commands: Vec<Command> = serde_json::from_value(commands.clone()).map_err(io_error)?;
    let write = db.begin_write()?;
    let batch = {
        let table = write.open_table(KV)?;
        let mut ws = Attempt::<_, Calculation>::new(
            |key: &[u8]| table.get(key).map(|v| v.map(|v| v.value().to_vec())),
            LIMIT,
        );
        let allocation_identity = format!("{identity}/setup");
        let mut ids = allocate(&allocation_identity, "setup", allocations);
        // The frozen n=64 setup includes its owner/reference records as well
        // as 64 members. Keep the native per-call limit and one atomic setup.
        for commands in commands.chunks(64) {
            settle_with_ids(&mut ws, model, context, commands, &mut ids)?;
        }
        ws.finish()?
    };
    publish(&write, &batch)?;
    write.commit()
}
fn action_commands(action: &Value, before: &Value) -> Result<Value> {
    if action["kind"] == "native-create" {
        return Ok(action["commands"].clone());
    }
    let id = action["record"]
        .as_str()
        .ok_or_else(|| bad("missing mutation record"))?;
    let key = Key::Record(Uuid::parse_str(id).map_err(io_error)?).encode();
    let key = native_codec::hex(&key);
    let record = before["rows"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["key"] == key))
        .ok_or_else(|| bad("missing setup current version"))?;
    let version = &record["decoded"]["data"]["version"];
    if !version.is_string() {
        return Err(bad("missing actual setup version"));
    }
    Ok(if action["kind"] == "native-delete" {
        json!([{"op":"delete","id":id,"if_version":version}])
    } else {
        json!([{"op":"update","id":id,"if_version":version,"set":action["set"],"unset":[]}])
    })
}
fn query<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
    ws: &mut Attempt<L, Calculation>,
    corpus: &Value,
    action: &Value,
) -> Result<Value> {
    let root = &corpus["nByRoot"][0];
    let owner = Address::new(
        Uuid::parse_str(root["owner"].as_str().ok_or_else(|| bad("root owner"))?)
            .map_err(io_error)?,
        root["slot"].as_u64().ok_or_else(|| bad("root slot"))? as u16,
    );
    let number = |name: &str| -> Result<i64> {
        action[name]
            .as_str()
            .ok_or_else(|| bad("query bound"))?
            .parse()
            .map_err(io_error)
    };
    if action["kind"] == "tree-prefix" {
        Ok(json!(
            tree::prefix(ws, owner, Some(number("before")?))?.to_string()
        ))
    } else {
        serde_json::to_value(tree::range(
            ws,
            owner,
            TimeRange {
                lower: TimeBound::Included(number("from")?),
                upper: TimeBound::Excluded(number("until")?),
            },
        )?)
        .map_err(io_error)
    }
}
// A bounded admission guard over frozen literals, not an independent structural
// oracle. The Node checker still verifies every native row and the full fold.
fn literal_error(detail: &str) -> Error {
    Error::new("s0_correctness", detail)
}
fn observed(snapshot: &Value, key: Key) -> Result<&Value> {
    let encoded = native_codec::hex(&key.encode());
    snapshot["rows"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["key"] == encoded))
        .map(|row| &row["decoded"]["data"])
        .ok_or_else(|| literal_error("frozen expected native row is missing"))
}
fn literal_roots(snapshot: &Value, corpus: &Value, expectation: &Value) -> Result<()> {
    for (index, root) in corpus["nByRoot"]
        .as_array()
        .expect("frozen roots")
        .iter()
        .enumerate()
    {
        let address = Address::new(
            Uuid::parse_str(root["owner"].as_str().expect("frozen owner")).map_err(io_error)?,
            root["slot"].as_u64().expect("frozen slot") as u16,
        );
        let expected = if expectation["expectedSums"].is_array() {
            &expectation["expectedSums"][index]
        } else {
            &expectation["expectedSum"]
        };
        let actual = observed(snapshot, Key::Root(address))?;
        if !expected.is_string()
            || actual["summary"]["kind"] != "financial"
            || actual["summary"]["value"]["sum"] != *expected
        {
            return Err(literal_error(
                "observed root sum differs from frozen literal",
            ));
        }
    }
    Ok(())
}
fn literal_setup(snapshot: &Value, corpus: &Value) -> Result<()> {
    literal_roots(snapshot, corpus, corpus)?;
    for member in corpus["expectedMembers"]
        .as_array()
        .expect("frozen members")
    {
        let id =
            Uuid::parse_str(member["id"].as_str().expect("frozen member")).map_err(io_error)?;
        let node = observed(
            snapshot,
            Key::Node(Address::new(
                id,
                member["slot"].as_u64().expect("frozen slot") as u16,
            )),
        )?;
        if node["root"] != json!({"id":member["owner"],"slot":member["rootSlot"]})
            || node["key"]["value"] != member["key"]
            || node["leaf"] != json!({"kind":"financial","value":member["amount"]})
        {
            return Err(literal_error("setup member differs from frozen literal"));
        }
        let record = observed(snapshot, Key::Record(id))?;
        if record["contract"] == 6 {
            let field = if member["slot"] == 1 {
                "native_minor"
            } else {
                "reporting_minor"
            };
            if record["derived"][field] != member["amount"] {
                return Err(literal_error(
                    "setup Posting amount differs from frozen literal",
                ));
            }
        }
    }
    Ok(())
}
fn literal_query(result: &Value, action: &Value) -> Result<()> {
    let matches = if action["kind"] == "tree-prefix" {
        *result == action["expected"]
    } else {
        result["kind"] == "financial" && result["value"]["sum"] == action["expectedSum"]
    };
    if matches {
        Ok(())
    } else {
        Err(literal_error("query result differs from frozen literal"))
    }
}
fn literal_mutation(before: &Value, after: &Value, corpus: &Value, action: &Value) -> Result<()> {
    literal_roots(after, corpus, action)?;
    let mut changed = Vec::new();
    for command in corpus["setupCommands"].as_array().expect("frozen commands") {
        if command["contract"] == 6 {
            let id = Uuid::parse_str(command["id"].as_str().expect("frozen Posting"))
                .map_err(io_error)?;
            if observed(before, Key::Record(id))?["derived"]
                != observed(after, Key::Record(id))?["derived"]
            {
                changed.push(json!(id));
            }
        }
    }
    changed.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    let mut expected = action["expectedRecalculatedRecords"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    expected.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    if changed != expected {
        return Err(literal_error(
            "changed Posting closure differs from frozen literal",
        ));
    }
    Ok(())
}
fn delta(after: &Work, before: &Work) -> Result<Value> {
    let mut after = serde_json::to_value(after).map_err(io_error)?;
    let before = serde_json::to_value(before).map_err(io_error)?;
    for (key, value) in after.as_object_mut().expect("Work object") {
        *value = json!(
            value
                .as_u64()
                .expect("Work counter")
                .checked_sub(before[key].as_u64().expect("Work counter"))
                .ok_or_else(|| bad("Work counter regressed"))?
        );
    }
    Ok(after)
}
fn recorder(request: &Request, identity: &str, read_only: bool) -> Recorder {
    let backend = if request.backend == "foundationdb-local" {
        "foundationdb"
    } else {
        &request.backend
    };
    let trace = Recorder::new(
        identity,
        identity,
        backend,
        if read_only {
            "native-tree"
        } else {
            "native-settlement"
        },
        "attempt-first",
    );
    if !read_only {
        trace.mark_dependency_incomplete(
            "native record/route/causal key discovery is not fully instrumented",
        );
    }
    trace
}

struct SampleIdentity<'a> {
    index: usize,
    enabled: bool,
    pair: Option<usize>,
    identity: &'a str,
}
fn sample(
    request: &Request,
    model: &Model,
    corpus: &Value,
    action: &Value,
    sample: SampleIdentity<'_>,
    checkpoint_sample: &mut impl FnMut(&Request, &Value) -> Result<bool>,
) -> Result<Vec<Value>> {
    let SampleIdentity {
        index,
        enabled,
        pair,
        identity,
    } = sample;
    let db = claim(
        request,
        &format!(
            "sample-{identity_hash}",
            identity_hash = &hash(identity.as_bytes())[..24]
        ),
    )?;
    let context = context(corpus)?;
    let mut allocations = Vec::new();
    let start = Instant::now();
    let target = format!("sample-{}", &hash(identity.as_bytes())[..24]);
    initialize(&db, model, context).map_err(|error| {
        if error_outcome(&error) == "unknown" {
            request.preserve_targets.borrow_mut().insert(target.clone());
            return Error::new(error.code,json!({"stage":"protected-initialization","actionAdmitted":false,"actionId":identity,"target":target,"setupCommands":corpus["setupCommands"],"allocations":[],"error":error.detail}).to_string());
        }
        error
    })?;
    request.owned_targets.borrow_mut().push(target);
    let setup_result = setup(
        &db,
        model,
        context,
        &corpus["setupCommands"],
        identity,
        &mut allocations,
    );
    if let Err(error) = setup_result {
        if error_outcome(&error) == "unknown" {
            let target = format!("sample-{}", &hash(identity.as_bytes())[..24]);
            request.preserve_targets.borrow_mut().insert(target.clone());
            return Err(Error::new(error.code,json!({"stage":"unmeasured-setup","actionAdmitted":false,"actionId":identity,"target":target,"setupCommands":corpus["setupCommands"],"allocations":allocations,"error":error.detail,"observedAfter":snapshot(&db).ok()}).to_string()));
        }
        return Err(error);
    }
    let setup_ns = ns(start);
    let warmup_start = Instant::now();
    // Exactly one unmeasured traversal warms process state. It owns its own
    // transaction and Attempt and never supplies the measured Attempt cache.
    {
        let read = db.begin_read()?;
        let table = read.open_table(KV)?;
        let mut warm = Attempt::<_, Calculation>::new(
            |key: &[u8]| table.get(key).map(|v| v.map(|v| v.value().to_vec())),
            LIMIT,
        );
        let owner = &corpus["nByRoot"][0];
        if action["kind"]
            .as_str()
            .is_some_and(|kind| kind.starts_with("tree-"))
        {
            query(&mut warm, corpus, action)?;
        } else {
            tree::prefix(
                &mut warm,
                Address::new(
                    Uuid::parse_str(owner["owner"].as_str().expect("frozen")).map_err(io_error)?,
                    owner["slot"].as_u64().expect("frozen") as u16,
                ),
                Some(i64::MAX),
            )?;
        }
    }
    let warmup_ns = ns(warmup_start);
    let observation_start = Instant::now();
    let before = snapshot(&db)?;
    let before_observation_ns = ns(observation_start);
    literal_setup(&before, corpus).map_err(|error| Error::new(error.code,
        json!({"stage":"unmeasured-setup-literal-check","actionAdmitted":false,"actionId":identity,"target":format!("sample-{}", &hash(identity.as_bytes())[..24]),"setupCommands":corpus["setupCommands"],"allocations":allocations,"before":before,"error":error.detail}).to_string()))?;
    let read_only = action["kind"]
        .as_str()
        .is_some_and(|k| k.starts_with("tree-"));
    let trace = recorder(request, identity, read_only);
    if read_only {
        let root = &corpus["nByRoot"][0];
        trace.seed_invocation(
            &Key::Root(Address::new(
                Uuid::parse_str(root["owner"].as_str().expect("frozen")).map_err(io_error)?,
                root["slot"].as_u64().expect("frozen") as u16,
            ))
            .encode(),
        );
    }
    let commands = if read_only {
        json!([])
    } else {
        action_commands(action, &before)?
    };
    if !read_only {
        trace.seed_invocation(&Key::Meta.encode());
        trace.seed_invocation(&Key::Population.encode());
        for command in commands.as_array().expect("commands") {
            trace.seed_invocation(
                &Key::Record(
                    Uuid::parse_str(command["id"].as_str().expect("command id"))
                        .map_err(io_error)?,
                )
                .encode(),
            );
        }
    }
    let common = json!({"corpusId":corpus["id"],"action":action["id"],"actionId":identity,"operationId":if read_only {Value::Null}else{json!(deterministic_id(&format!("{identity}/operation"),0))},"sampleIndex":index,"pairIndex":pair,"traceEnabled":enabled,"readOnly":read_only,"setupCommands":corpus["setupCommands"],"setupCommandBatches":corpus["setupCommands"].as_array().expect("frozen setup commands").chunks(64).collect::<Vec<_>>(),"actionCommands":commands,"setupNs":setup_ns,"warmupNs":warmup_ns,"before":before});
    let mut samples = Vec::new();
    if read_only {
        let read = if enabled {
            db.begin_read_diagnostic(trace.clone())?
        } else {
            db.begin_read()?
        };
        let table = read.open_table(KV)?;
        let loader = |key: &[u8]| table.get(key).map(|v| v.map(|v| v.value().to_vec()));
        let mut ws = if enabled {
            Attempt::<_, Calculation>::new_diagnostic(loader, LIMIT, trace.clone())
        } else {
            Attempt::<_, Calculation>::new(loader, LIMIT)
        };
        for phase in ["attempt-first", "attempt-repeat"] {
            if phase == "attempt-repeat" {
                trace.reset_phase(phase);
            }
            let work_before = ws.work.clone();
            let started = Instant::now();
            let result = query(&mut ws, corpus, action);
            let elapsed = ns(started);
            let (outcome, result, error) = match result {
                Ok(value) => ("success", value, Value::Null),
                Err(e) => (
                    error_outcome(&e),
                    Value::Null,
                    json!({"code":e.code,"detail":e.detail}),
                ),
            };
            let mut s = common.clone();
            let obj = s.as_object_mut().expect("sample");
            obj.extend(json!({"cachePhase":phase,"result":result,"work":delta(&ws.work,&work_before)?,"operationNs":elapsed,"commitNs":null,"commitBoundaryNs":null,"outcome":outcome,"error":error,"trace":if enabled{serde_json::to_value(trace.snapshot(outcome,elapsed,None)).map_err(io_error)?}else{Value::Null}}).as_object().expect("sample fields").clone());
            if outcome == "success"
                && let Err(error) = literal_query(&result, action)
            {
                s["correctnessError"] = json!({"code":error.code,"detail":error.detail});
            }
            observe_sample(&db, &mut s, before_observation_ns, &allocations);
            let mismatch = !s["correctnessError"].is_null();
            let proceed = checkpoint_sample(request, &s)?;
            samples.push(s);
            if outcome != "success"
                || mismatch
                || !proceed
                || samples.last().expect("sample")["trace"]["complete"] == false
                || samples.last().expect("sample")["after"]["complete"] != true
            {
                break;
            }
        }
    } else {
        let write = if enabled {
            db.begin_write_diagnostic(trace.clone())?
        } else {
            db.begin_write()?
        };
        let table = write.open_table(KV)?;
        let loader = |key: &[u8]| table.get(key).map(|v| v.map(|v| v.value().to_vec()));
        let mut ws = if enabled {
            Attempt::<_, Calculation>::new_diagnostic(loader, LIMIT, trace.clone())
        } else {
            Attempt::<_, Calculation>::new(loader, LIMIT)
        };
        let commands: Vec<Command> = serde_json::from_value(commands).map_err(io_error)?;
        let started = Instant::now();
        let prepared = settle_with_ids(
            &mut ws,
            model,
            context,
            &commands,
            &mut allocate(&format!("{identity}/action"), "action", &mut allocations),
        )
        .and_then(|settled| ws.finish().map(|batch| (settled, batch)));
        let work = ws.work.clone();
        drop(ws);
        drop(table);
        let mut commit_ns = None;
        let result = match prepared {
            Ok((settled, batch)) => publish(&write, &batch).map(|()| (settled, write)),
            Err(e) => Err(e),
        };
        let operation_ns = ns(started);
        let result = match result {
            Ok((settled, write)) => {
                let start = Instant::now();
                let result = write.commit().map(|()| settled);
                commit_ns = Some(ns(start));
                result
            }
            Err(e) => Err(e),
        };
        let (outcome, result, error) = match result {
            Ok(settled) => (
                "success",
                serde_json::to_value(settled).map_err(io_error)?,
                Value::Null,
            ),
            Err(e) => (
                error_outcome(&e),
                Value::Null,
                json!({"code":e.code,"detail":e.detail}),
            ),
        };
        if outcome == "unknown" {
            request
                .preserve_targets
                .borrow_mut()
                .insert(format!("sample-{}", &hash(identity.as_bytes())[..24]));
        }
        let recorded = if enabled {
            serde_json::to_value(trace.snapshot(
                outcome,
                operation_ns,
                Some(deterministic_id(&format!("{identity}/operation"), 0).to_string()),
            ))
            .map_err(io_error)?
        } else {
            Value::Null
        };
        let traced_commit = if enabled {
            recorded["commitNs"].clone()
        } else {
            Value::Null
        };
        let mut s = common.clone();
        s.as_object_mut().expect("sample").extend(json!({"cachePhase":"attempt-first","result":result,"work":work,"operationNs":operation_ns,"commitNs":traced_commit,"commitBoundaryNs":commit_ns,"outcome":outcome,"error":error,"trace":recorded}).as_object().expect("sample fields").clone());
        samples.push(s);
    }
    if !read_only {
        let sample = &mut samples[0];
        observe_sample(&db, sample, before_observation_ns, &allocations);
        if sample["outcome"] == "success"
            && sample["after"]["complete"] == true
            && let Err(error) = literal_mutation(&before, &sample["after"], corpus, action)
        {
            sample["correctnessError"] = json!({"code":error.code,"detail":error.detail});
        }
        checkpoint_sample(request, sample)?;
    }
    drop(db);
    Ok(samples)
}
fn observe_sample(db: &Database, sample: &mut Value, before_ns: u64, allocations: &[Value]) {
    let started = Instant::now();
    sample["after"] = snapshot(db).unwrap_or_else(|error|
        json!({"complete":false,"tables":null,"rows":null,"observationError":{"code":error.code,"detail":error.detail}}));
    let after_ns = ns(started);
    sample["observationNs"] = json!(before_ns.saturating_add(after_ns));
    sample["beforeObservationNs"] = json!(before_ns);
    sample["afterObservationNs"] = json!(after_ns);
    sample["allocations"] = json!(allocations);
}

fn rollback_control(request: &Request) -> Result<Value> {
    let db = claim(request, "rollback-control")?;
    let model = Arc::new(Prepared::load()?);
    let context = Context {
        tenant: Uuid::from_u128(1),
        actor: Uuid::from_u128(2),
    };
    let store = Store::<Calculation>::create_backend_secured(
        db,
        model.clone(),
        context,
    ).map_err(|error|Error::new(error.code,json!({"stage":"control-store-initialization","target":"rollback-control","model":model.identity(),"context":{"tenant":context.tenant,"actor":context.actor},"operationId":null,"commands":[],"allocations":[],"error":error.detail}).to_string()))?;
    request
        .owned_targets
        .borrow_mut()
        .push("rollback-control".into());
    let request_for = |commands: Value, identity: &str| -> Result<Mutation> {
        serde_json::from_value(json!({"model":store.model().identity(),"context":store.operation_context(store.model().identity())?,"operation_id":deterministic_id(identity,0),"commands":commands,"returning":[]})).map_err(io_error)
    };
    let account = Uuid::from_u128(300);
    let seed = request_for(
        json!([{"op":"create","id":account,"contract":4,"fields":{"native_unit":1}},{"op":"create","id":Uuid::from_u128(301),"contract":8,"fields":{"account":account,"at":"0","amount":"10"}}]),
        "s0/rollback/seed",
    )?;
    let mut allocations = Vec::new();
    let seed_result = {
        let mut ids = allocate("s0/rollback/seed", "control-seed", &mut allocations);
        store.mutate_with_ids(&seed, &mut ids)
    };
    seed_result.map_err(|error|Error::new(error.code,json!({"stage":"control-seed","target":"rollback-control","operationId":seed.operation_id,"request":seed,"allocations":allocations,"observedAfter":store.observe_for_verification().ok(),"error":error.detail}).to_string()))?;
    let before = store.observe_for_verification()?;
    let invalid = request_for(
        json!([{"op":"create","id":Uuid::from_u128(302),"contract":8,"fields":{"account":account,"at":"1","amount":"-11"}}]),
        "s0/rollback/reject",
    )?;
    let rejected = {
        let mut ids = allocate("s0/rollback/reject", "control-reject", &mut allocations);
        store.mutate_with_ids(&invalid, &mut ids)
    };
    let error = match rejected {
        Err(error) => error,
        Ok(result) => return Err(Error::new("s0_correctness", json!({"stage":"control-unexpected-commit","target":"rollback-control","operationId":invalid.operation_id,"operationOutcome":"success","request":invalid,"seedRequest":seed,"allocations":allocations,"before":before,"observedAfter":store.observe_for_verification().ok(),"operationStatus":store.operation_status(&invalid.model,&invalid.context,invalid.operation_id).ok(),"mutationResult":result,"error":"tiny root invariant did not reject"}).to_string())),
    };
    if error.code != "invariant" {
        return Err(Error::new(error.code,json!({"stage":"control-reject","target":"rollback-control","operationId":invalid.operation_id,"request":invalid,"seedRequest":seed,"allocations":allocations,"observedAfter":store.observe_for_verification().ok(),"error":error.detail}).to_string()));
    }
    let after = store.observe_for_verification()?;
    let same = before == after;
    let status = store.operation_status(&invalid.model, &invalid.context, invalid.operation_id)?;
    if error.code != "invariant" || !same || status["status"] != "not_observed" {
        return Err(Error::new("s0_correctness", json!({"stage":"control-rollback-check","target":"rollback-control","operationId":invalid.operation_id,"operationOutcome":if status["status"]=="committed" {"success"} else {error_outcome(&error)},"request":invalid,"seedRequest":seed,"allocations":allocations,"before":before,"observedAfter":after,"operationStatus":status,"error":"tiny application rollback control failed"}).to_string()));
    }
    store.check_integrity()?;
    drop(store);
    let db = connect(request, "rollback-control")?;
    clear(&db)?;
    assert_empty(&db)?;
    drop(db);
    Ok(
        json!({"name":"calculation-root-complete-time-invariant-rollback","timed":false,"outcome":"success","unchanged":same,"errorCode":error.code,"operationStatus":status,"seedRequest":seed,"rejectedRequest":invalid,"allocations":allocations,"cleanup":"all owned control tables deleted with exact value kinds"}),
    )
}

fn finish_report(
    request: &Request,
    mut report: Value,
    cleanup: &mut OwnedCleanup<'_>,
) -> Result<Value> {
    let mut unknown_actions:Vec<Value>=report["samples"].as_array().expect("samples").iter().enumerate()
        .filter(|(_,sample)|sample["outcome"]=="unknown")
        .map(|(index,sample)|json!({"stage":"measured-action","sampleRef":index,"actionId":sample["actionId"],"operationId":sample["operationId"],"target":format!("sample-{}",&hash(sample["actionId"].as_str().expect("identity").as_bytes())[..24])})).collect();
    for kind in ["failedAction", "failedControl"] {
        if report[kind]["outcome"] == "unknown" {
            unknown_actions.push(json!({"failureRef":kind,"actionId":report[kind]["actionId"],"operationId":report[kind]["recovery"]["operationId"],"target":report[kind]["recovery"]["target"]}));
        }
    }
    let mut errors = Vec::new();
    for target in request.owned_targets.borrow().iter() {
        if request.preserve_targets.borrow().contains(target) {
            continue;
        }
        if let Err(error) = connect(request, target).and_then(|db| {
            clear(&db)?;
            assert_empty(&db)
        }) {
            request.preserve_targets.borrow_mut().insert(target.clone());
            errors.push(json!({"target":target,"code":error.code,"detail":error.detail}));
        }
    }
    let mut removed = false;
    if request.preserve_targets.borrow().is_empty() {
        match fs::remove_dir_all(&request.location) {
            Ok(()) => removed = true,
            Err(error) => {
                errors.push(json!({"target":request.location,"detail":error.to_string()}))
            }
        }
    }
    let complete = removed && errors.is_empty() && unknown_actions.is_empty();
    if !errors.is_empty() {
        report["complete"] = json!(false);
        report["incompleteReasons"]
            .as_array_mut()
            .expect("reasons")
            .push(json!("cleanup-failed"));
    }
    report["cleanup"] = json!({"complete":complete,"location":request.location,"namespace":request.namespace,"preservedTargets":request.preserve_targets.borrow().iter().cloned().collect::<Vec<_>>(),"unknownActions":unknown_actions,"errors":errors});
    cleanup.disarmed = true;
    Ok(report)
}

fn run(request: &Request, inputs: &Value) -> Result<Value> {
    let mut directory = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    directory.create(&request.location).map_err(io_error)?;
    let mut cleanup = OwnedCleanup {
        request,
        disarmed: false,
    };
    let started = Instant::now();
    let model = Model::prepare()?;
    let mut report = json!({"format":"rebase-s0-probe-report-1","backend":request.backend,"phase":request.phase,"trace":request.trace,"manifestSha256":hash(MANIFEST.as_bytes()),"inputsSha256":hash(INPUTS.as_bytes()),"sourceFingerprint":fingerprint::digest(),"scope":"primitive real-adapter/Attempt/tree-or-native-settlement; excludes authenticated HTTP and Store receipt/authority overhead","processWarmup":"one unmeasured separate Attempt/transaction traversal per fresh setup","storageCacheState":"uncontrolled OS/backend caches; new Attempt is not cold disk","controls":[],"samples":[],"complete":true,"incompleteReasons":[],"cleanup":null});
    match rollback_control(request) {
        Ok(control) => report["controls"]
            .as_array_mut()
            .expect("controls")
            .push(control),
        Err(error) => {
            let recovery: Value = serde_json::from_str(&error.detail).unwrap_or_else(
                |_| json!({"target":"rollback-control","stage":"unmeasured-rollback-control"}),
            );
            let outcome = recovery["operationOutcome"]
                .as_str()
                .unwrap_or_else(|| error_outcome(&error));
            if outcome == "unknown" {
                request
                    .preserve_targets
                    .borrow_mut()
                    .insert("rollback-control".into());
            }
            report["complete"] = json!(false);
            report["incompleteReasons"]
                .as_array_mut()
                .expect("reasons")
                .push(json!("control-failed"));
            report["failedControl"] = json!({"name":"calculation-root-complete-time-invariant-rollback","outcome":outcome,"error":{"code":error.code,"detail":error.detail},"recovery":recovery});
            return finish_report(request, report, &mut cleanup);
        }
    }
    if request.phase == "focused" {
        let observed = (|| -> Result<Value> {
            let db = claim(request, "adapter-control")?;
            let backend = if request.backend == "foundationdb-local" {
                "foundationdb"
            } else {
                &request.backend
            };
            let observed = storage::diagnostic_checks::run(&db, backend)?;
            request
                .owned_targets
                .borrow_mut()
                .push("adapter-control".into());
            clear(&db)?;
            assert_empty(&db)?;
            drop(db);
            Ok(observed)
        })();
        match observed {
            Ok(control) => report["controls"]
                .as_array_mut()
                .expect("controls")
                .push(control),
            Err(error) => {
                let outcome = error_outcome(&error);
                if error.code != "storage_exists" {
                    request
                        .preserve_targets
                        .borrow_mut()
                        .insert("adapter-control".into());
                }
                report["complete"] = json!(false);
                report["incompleteReasons"]
                    .as_array_mut()
                    .expect("reasons")
                    .push(json!("control-failed"));
                let recovery:Value=serde_json::from_str(&error.detail).unwrap_or_else(|_|json!({"stage":"unmeasured-adapter-control","target":"adapter-control","backend":request.backend,"namespace":request.namespace,"invocation":{"function":"storage::diagnostic_checks::run","backend":if request.backend=="foundationdb-local" {"foundationdb"}else{&request.backend},"definition":"exact compiled source in sourceFingerprint.files"},"operationId":null,"allocations":[],"observedAfter":null,"observationIncompleteReason":"failed primitive control destination preserved without issuing another transaction"}));
                report["failedControl"] = json!({"name":"adapter-control","outcome":outcome,"error":{"code":error.code,"detail":error.detail},"recovery":recovery});
                return finish_report(request, report, &mut cleanup);
            }
        }
    }
    let mut bytes = serde_json::to_vec(&report).map_err(io_error)?.len();
    *request.report_bytes.borrow_mut() = bytes;
    'admission: for index in 0..request.samples {
        for selected in &request.cases {
            let corpus = find_corpus(inputs, &selected.corpus)?;
            let action = find_action(corpus, &selected.action)?;
            let enabled: Vec<bool> = if request.phase == "overhead" {
                if index % 2 == 0 {
                    vec![false, true]
                } else {
                    vec![true, false]
                }
            } else {
                vec![request.trace]
            };
            for enabled in enabled {
                let reason = if started.elapsed().as_secs() >= 600 {
                    Some("backend-duration-bound")
                } else if request
                    .wire_bytes
                    .borrow()
                    .saturating_add(*request.report_bytes.borrow())
                    .saturating_add(ADMISSION_RESERVE)
                    > MAX_REPORT
                {
                    Some("report-size-admission-bound")
                } else {
                    None
                };
                if let Some(reason) = reason {
                    report["complete"] = json!(false);
                    report["incompleteReasons"]
                        .as_array_mut()
                        .expect("reasons")
                        .push(json!(reason));
                    break 'admission;
                }
                let identity = format!(
                    "{}/{}/{}/{index}/{enabled}",
                    request.phase, selected.corpus, selected.action
                );
                let observed = match sample(
                    request,
                    &model,
                    corpus,
                    action,
                    SampleIdentity {
                        index,
                        enabled,
                        pair: if request.phase == "overhead" {
                            Some(index)
                        } else {
                            None
                        },
                        identity: &identity,
                    },
                    &mut checkpoint,
                ) {
                    Ok(observed) => observed,
                    Err(error) => {
                        report["complete"] = json!(false);
                        report["incompleteReasons"]
                            .as_array_mut()
                            .expect("reasons")
                            .push(json!(if error.code == "s0_correctness" {
                                "correctness-mismatch"
                            } else {
                                "action-setup-or-observation-failed"
                            }));
                        let recovery:Value=serde_json::from_str(&error.detail).unwrap_or_else(|_|json!({"target":format!("sample-{}",&hash(identity.as_bytes())[..24])}));
                        report["failedAction"] = json!({"actionId":identity,"corpusId":selected.corpus,"action":selected.action,"sampleIndex":index,"outcome":error_outcome(&error),"error":{"code":error.code,"detail":error.detail},"recovery":recovery});
                        break 'admission;
                    }
                };
                for sample in observed {
                    let sample_bytes = serde_json::to_vec(&sample).map_err(io_error)?.len();
                    if bytes + sample_bytes > MAX_REPORT {
                        return Err(bad(
                            "reserved report bound exceeded; no truncation permitted",
                        ));
                    }
                    bytes += sample_bytes;
                    let stop = sample["outcome"] != "success"
                        || sample["trace"]["complete"] == false
                        || sample["after"]["complete"] != true
                        || !sample["correctnessError"].is_null()
                        || request.checkpoint_stop.borrow().is_some()
                        || !sample["cleanupError"].is_null();
                    let mismatch = !sample["correctnessError"].is_null();
                    report["samples"]
                        .as_array_mut()
                        .expect("samples")
                        .push(sample);
                    if stop {
                        report["complete"] = json!(false);
                        report["incompleteReasons"]
                            .as_array_mut()
                            .expect("reasons")
                            .push(json!(if mismatch {
                                "correctness-mismatch".to_owned()
                            } else {
                                request
                                    .checkpoint_stop
                                    .borrow()
                                    .clone()
                                    .unwrap_or_else(|| "action-outcome-or-trace-incomplete".into())
                            }));
                        break 'admission;
                    }
                }
            }
        }
    }
    finish_report(request, report, &mut cleanup)
}
fn main() -> Result<()> {
    let raw = bounded_line(io::stdin().lock(), 65536)?;
    let request: Request = serde_json::from_str(&raw).map_err(io_error)?;
    let inputs: Value = serde_json::from_str(INPUTS).map_err(io_error)?;
    validate(&request, &inputs)?;
    wire(
        &request,
        &json!({"format":"rebase-s0-start-1","sourceFingerprint":fingerprint::digest(),"backend":request.backend,"phase":request.phase,"manifestSha256":hash(MANIFEST.as_bytes()),"inputsSha256":hash(INPUTS.as_bytes())}),
    )?;
    #[cfg(feature = "foundationdb")]
    let _network = if request.backend == "foundationdb-local" {
        Some(unsafe { foundationdb::boot() })
    } else {
        None
    };
    let report = run(&request, &inputs)?;
    wire(&request, &report)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_literal_guards_and_checkpoint_ack_are_bounded() {
        let ack_sample = json!({"actionId":"fixture/action/0","cachePhase":"attempt-first"});
        assert!(
            parse_ack(
                r#"{"actionId":"fixture/action/0","cachePhase":"attempt-first","continue":true}"#,
                &ack_sample
            )
            .unwrap()
        );
        assert!(
            !parse_ack(
                r#"{"actionId":"fixture/action/0","cachePhase":"attempt-first","continue":false}"#,
                &ack_sample
            )
            .unwrap()
        );
        for line in [
            "continue",
            r#"{"actionId":"other","cachePhase":"attempt-first","continue":true}"#,
            r#"{"actionId":"fixture/action/0","cachePhase":"attempt-repeat","continue":true}"#,
            r#"{"actionId":"fixture/action/0","cachePhase":"attempt-first","continue":true,"extra":0}"#,
        ] {
            assert!(parse_ack(line, &ack_sample).is_err());
        }
        assert!(bounded_line(io::Cursor::new(b"12345\n"), 5).is_err());
        assert!(bounded_line(io::Cursor::new(b"12345"), 5).is_err());
        assert_eq!(
            bounded_line(io::Cursor::new(b"1234\nnext"), 5).unwrap(),
            "1234\n"
        );
        let inputs: Value = serde_json::from_str(INPUTS).unwrap();
        let model = Model::prepare().unwrap();
        let directory = std::env::temp_dir().join(format!("rebase-s0-literal-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        for corpus in inputs["corpora"].as_array().unwrap() {
            let id = corpus["id"].as_str().unwrap();
            let db = Database::create(directory.join(format!("{id}.redb"))).unwrap();
            let context = context(corpus).unwrap();
            initialize(&db, &model, context).unwrap();
            let mut allocations = Vec::new();
            setup(
                &db,
                &model,
                context,
                &corpus["setupCommands"],
                id,
                &mut allocations,
            )
            .unwrap();
            let before = snapshot(&db).unwrap();
            literal_setup(&before, corpus).unwrap();
            let mut wrong = corpus.clone();
            if wrong["expectedSums"].is_array() {
                wrong["expectedSums"][0] = json!("-999");
            } else {
                wrong["expectedSum"] = json!("-999");
            }
            assert_eq!(
                literal_setup(&before, &wrong).unwrap_err().code,
                "s0_correctness"
            );
            for action in corpus["actions"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|action| action["kind"] == "tree-prefix" || action["kind"] == "tree-range")
            {
                let read = db.begin_read().unwrap();
                let table = read.open_table(KV).unwrap();
                let mut attempt = Attempt::<_, Calculation>::new(
                    |key: &[u8]| {
                        table
                            .get(key)
                            .map(|value| value.map(|value| value.value().to_vec()))
                    },
                    LIMIT,
                );
                literal_query(&query(&mut attempt, corpus, action).unwrap(), action).unwrap();
                assert!(literal_query(&json!("-999"), action).is_err());
            }
            let action = corpus["actions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|action| !action["kind"].as_str().unwrap().starts_with("tree-"))
                .unwrap();
            let commands = action_commands(action, &before).unwrap();
            setup(
                &db,
                &model,
                context,
                &commands,
                &format!("{id}/mutation"),
                &mut allocations,
            )
            .unwrap();
            let after = snapshot(&db).unwrap();
            literal_mutation(&before, &after, corpus, action).unwrap();
            assert!(literal_mutation(&before, &before, corpus, action).is_err());
            drop(db);
        }
        let request: Request = serde_json::from_value(json!({
            "format":"rebase-s0-probe-input-1","backend":"redb","location":directory,
            "namespace":null,"clusterFile":null,"phase":"focused",
            "cases":[{"corpus":"entry-8","action":"prefix"}],"samples":1,"trace":true,
            "manifestSha256":hash(MANIFEST.as_bytes()),"inputsSha256":hash(INPUTS.as_bytes())
        }))
        .unwrap();
        let control = rollback_control(&request).unwrap();
        assert_eq!(control["operationStatus"]["status"], "not_observed");
        assert_eq!(control["unchanged"], true);
        for (corpus_id, action_id) in [("entry-8", "prefix"), ("posting-1", "revalue-posting")] {
            let corpus = find_corpus(&inputs, corpus_id).unwrap();
            let action = find_action(corpus, action_id).unwrap();
            for enabled in [false, true] {
                let identity = format!("focused/{corpus_id}/{action_id}/0/{enabled}");
                let mut checkpoints = Vec::new();
                let observed = sample(
                    &request,
                    &model,
                    corpus,
                    action,
                    SampleIdentity {
                        index: 0,
                        enabled,
                        pair: None,
                        identity: &identity,
                    },
                    &mut |_, sample| {
                        // These are the required assembled fields consumed by
                        // Node's shared checkpoint/final sample checker.
                        for field in [
                            "corpusId",
                            "action",
                            "actionId",
                            "operationId",
                            "sampleIndex",
                            "pairIndex",
                            "traceEnabled",
                            "readOnly",
                            "setupCommands",
                            "setupCommandBatches",
                            "actionCommands",
                            "setupNs",
                            "warmupNs",
                            "before",
                            "cachePhase",
                            "result",
                            "work",
                            "operationNs",
                            "commitNs",
                            "commitBoundaryNs",
                            "outcome",
                            "error",
                            "trace",
                            "observationNs",
                            "beforeObservationNs",
                            "afterObservationNs",
                            "after",
                            "allocations",
                        ] {
                            assert!(
                                sample.as_object().unwrap().contains_key(field),
                                "missing {field}"
                            );
                        }
                        assert_eq!(sample["outcome"], "success");
                        assert!(sample["correctnessError"].is_null());
                        if sample["readOnly"] == true {
                            assert!(sample["commitNs"].is_null());
                            assert!(sample["commitBoundaryNs"].is_null());
                            assert!(sample["operationId"].is_null());
                        } else {
                            assert!(sample["commitBoundaryNs"].is_u64());
                            assert!(sample["operationId"].is_string());
                        }
                        assert_eq!(sample["trace"].is_null(), !enabled);
                        checkpoints.push(sample.clone());
                        Ok(true)
                    },
                )
                .unwrap();
                assert_eq!(observed, checkpoints, "checkpoint and final samples differ");
                assert_eq!(observed.len(), if corpus_id == "entry-8" { 2 } else { 1 });
                if observed.len() == 2 {
                    assert_eq!(observed[1]["work"]["key_loads"], 0);
                }
            }
        }
        fs::remove_dir_all(directory).unwrap();
    }
}
