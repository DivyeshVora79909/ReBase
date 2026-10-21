//! Disposable real-redb adapter for the fixed native slice. Expected semantics
//! live in the independent Python oracle, never in this observer or writer.

use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
};

use rebase_semantic_proof::{
    native_codec::{self, Key, Stored},
    native_slice::{
        Command, Context, Error as NativeError, Meta, Model, Settled, Work, Workspace,
        settle_fixture, settle_with_ids,
    },
};
use redb::{
    Database, ReadTransaction, ReadableDatabase, ReadableTable, TableDefinition, TableHandle,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const KV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("native_kv");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixtures {
    format: String,
    tenant: Uuid,
    actor: Uuid,
    #[serde(rename = "ids")]
    _ids: Value,
    bases: BTreeMap<String, Value>,
    #[serde(default)]
    base_allocations: BTreeMap<String, Vec<Uuid>>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    base: String,
    operations: Vec<Operation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    commands: Value,
    work_limit: u64,
    #[serde(rename = "expect")]
    _expect: Value,
    actor: Option<Uuid>,
    tenant: Option<Uuid>,
    model: Option<String>,
    codec: Option<String>,
    abort_after: Option<Value>,
    allocations: Option<Vec<Uuid>>,
    #[serde(default)]
    trusted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Row {
    key: String,
    value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Snapshot {
    tables: Vec<String>,
    complete: bool,
    rows: Vec<Row>,
}

#[derive(Serialize)]
struct Attempt {
    status: &'static str,
    code: Option<&'static str>,
    detail: Option<String>,
    returned: Option<Settled>,
    work: Work,
    applied_writes: usize,
}

#[derive(Serialize)]
struct ObservedOperation {
    #[serde(flatten)]
    attempt: Attempt,
    after: Snapshot,
    old_snapshot_unchanged: bool,
}

#[derive(Serialize)]
struct ObservedCase {
    name: String,
    initial: Snapshot,
    operations: Vec<ObservedOperation>,
    reopened_equal: bool,
}

#[derive(Serialize)]
struct Report {
    format: &'static str,
    model: String,
    cases: Vec<ObservedCase>,
}

// The directory was just created by this run. No user-selected path or reset.
struct Temporary(Option<PathBuf>);
impl Temporary {
    fn remove(mut self) -> Result<()> {
        fs::remove_dir_all(self.0.as_ref().expect("owned directory"))?;
        self.0 = None;
        Ok(())
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn output_directory() -> Result<PathBuf> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).canonicalize()?;
    for component in ["target", "native-slice"] {
        path.push(component);
        match fs::create_dir(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if !fs::symlink_metadata(&path)?.file_type().is_dir() {
                    return Err("refusing an aliased output directory".into());
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    path.push(format!(
        "run-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    fs::create_dir(&path)?; // An existing path fails; no overwrite or reuse.
    Ok(path)
}

fn initialize(db: &Database, model: &Model, context: Context) -> Result<()> {
    let write = db.begin_write()?;
    {
        let mut table = write.open_table(KV)?;
        let bytes = native_codec::encode(
            &Key::Meta,
            &Stored::Meta(Meta {
                model: model.identity.clone(),
                codec: model.codec.clone(),
                tenant: context.tenant,
                actor: context.actor,
                revision: 0,
                counts: [0; 12],
                reserved: 0,
            }),
        )?;
        table.insert(Key::Meta.encode().as_slice(), bytes.as_slice())?;
    }
    write.commit()?;
    Ok(())
}

fn snapshot(read: &ReadTransaction) -> Result<Snapshot> {
    let mut tables: Vec<_> = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect();
    tables.sort();
    if tables != ["native_kv"] || read.list_multimap_tables()?.next().is_some() {
        return Err("unexpected application table; observation is not complete".into());
    }
    let table = read.open_table(KV)?;
    let mut rows = vec![];
    // Walk the whole physical table, including keys no engine route can reach.
    for entry in table.iter()? {
        let (key, value) = entry?;
        rows.push(Row {
            key: native_codec::hex(key.value()),
            value: native_codec::hex(value.value()),
        });
    }
    Ok(Snapshot {
        tables,
        complete: true,
        rows,
    })
}

fn apply(db: &Database, model: &Model, context: Context, operation: &Operation) -> Result<Attempt> {
    let mut requested = model.clone();
    if let Some(identity) = &operation.model {
        requested.identity.clone_from(identity);
    }
    if let Some(codec) = &operation.codec {
        requested.codec.clone_from(codec);
    }
    let context = Context {
        tenant: operation.tenant.unwrap_or(context.tenant),
        actor: operation.actor.unwrap_or(context.actor),
    };
    let write = db.begin_write()?;
    let (prepared, work) = {
        let table = write.open_table(KV)?;
        let mut workspace = Workspace::new(
            |key: &[u8]| {
                table
                    .get(key)
                    .map(|value| value.map(|v| v.value().to_vec()))
                    .map_err(|error| NativeError::new("storage", error.to_string()))
            },
            operation.work_limit,
        );
        let mut ids = operation
            .allocations
            .clone()
            .unwrap_or_default()
            .into_iter();
        let mut allocate = || {
            if operation.allocations.is_some() {
                ids.next().ok_or_else(|| {
                    NativeError::new("allocation_exhausted", "fixture identity pool exhausted")
                })
            } else {
                Ok(Uuid::new_v4())
            }
        };
        let prepared = serde_json::from_value::<Vec<Command>>(operation.commands.clone())
            .map_err(|error| NativeError::new("invalid_input", error.to_string()))
            .and_then(|commands| {
                if operation.trusted {
                    settle_fixture(
                        &mut workspace,
                        &requested,
                        context,
                        &commands,
                        &mut allocate,
                    )
                } else {
                    settle_with_ids(
                        &mut workspace,
                        &requested,
                        context,
                        &commands,
                        &mut allocate,
                    )
                }
            })
            .and_then(|settled| workspace.finish().map(|batch| (settled, batch)));
        (prepared, workspace.work.clone())
    };
    let (settled, batch) = match prepared {
        Ok(value) => value,
        Err(error) => {
            write.abort()?;
            // Corruption, adapter failures and internal defects are fatal. They
            // cannot count as a successful domain rejection in the report.
            if !matches!(
                error.code,
                "invalid_input"
                    | "already_exists"
                    | "unavailable_reference"
                    | "forbidden"
                    | "stale_version"
                    | "state_limit"
                    | "work_limit"
                    | "invariant"
                    | "duplicate_time"
                    | "model_mismatch"
                    | "revision_exhausted"
                    | "overflow"
                    | "feedback"
                    | "allocation_collision"
                    | "allocation_exhausted"
            ) {
                return Err(error.into());
            }
            return Ok(Attempt {
                status: "rejected",
                code: Some(error.code),
                detail: Some(error.detail),
                returned: None,
                work,
                applied_writes: 0,
            });
        }
    };
    let abort_after = match &operation.abort_after {
        None => None,
        Some(Value::String(value)) if value == "all" => Some(batch.len()),
        Some(Value::Number(value)) => {
            Some(usize::try_from(value.as_u64().ok_or("bad abort count")?)?)
        }
        _ => return Err("bad abort hook".into()),
    };
    if abort_after.is_some_and(|count| count == 0 || count > batch.len()) {
        return Err("abort hook would not execute after writes".into());
    }
    let mut applied_writes = 0;
    {
        let mut table = write.open_table(KV)?;
        for (key, value) in &batch {
            if let Some(value) = value {
                table.insert(key.as_slice(), value.as_slice())?;
            } else {
                table.remove(key.as_slice())?;
            }
            applied_writes += 1;
            if abort_after == Some(applied_writes) {
                break;
            }
        }
    }
    if abort_after == Some(applied_writes) {
        write.abort()?;
        return Ok(Attempt {
            status: "rejected",
            code: Some("injected_abort"),
            detail: None,
            returned: None,
            work,
            applied_writes,
        });
    }
    // A real commit error escapes as fatal/unknown, never a validation rejection
    // and never an automatic retry. Release the private result only after Ok.
    write.commit()?;
    Ok(Attempt {
        status: "committed",
        code: None,
        detail: None,
        returned: Some(settled),
        work,
        applied_writes,
    })
}

fn run_case(
    directory: &Path,
    index: usize,
    case: &Case,
    fixtures: &Fixtures,
    model: &Model,
) -> Result<ObservedCase> {
    let directory = directory.join(format!("case-{index:03}"));
    fs::create_dir(&directory)?;
    let temporary = Temporary(Some(directory.clone()));
    let path = directory.join("store.redb");
    let db = Database::create(&path)?;
    let context = Context {
        tenant: fixtures.tenant,
        actor: fixtures.actor,
    };
    initialize(&db, model, context)?;
    let commands = fixtures
        .bases
        .get(&case.base)
        .ok_or("unknown fixture base")?;
    if !commands
        .as_array()
        .ok_or("base commands must be an array")?
        .is_empty()
    {
        let base = Operation {
            commands: commands.clone(),
            work_limit: 100_000,
            _expect: Value::Null,
            actor: None,
            tenant: None,
            model: None,
            codec: None,
            abort_after: None,
            allocations: fixtures.base_allocations.get(&case.base).cloned(),
            trusted: false,
        };
        let result = apply(&db, model, context, &base)?;
        if result.status != "committed" {
            return Err(format!("base {} rejected: {:?}", case.base, result.detail).into());
        }
    }
    let initial = snapshot(&db.begin_read()?)?;
    let mut operations = vec![];
    let mut last = initial.clone();
    for operation in &case.operations {
        let old_read = db.begin_read()?;
        let before = snapshot(&old_read)?;
        let attempt = apply(&db, model, context, operation)?;
        let after = snapshot(&db.begin_read()?)?;
        let old_snapshot_unchanged = snapshot(&old_read)? == before;
        last = after.clone();
        operations.push(ObservedOperation {
            attempt,
            after,
            old_snapshot_unchanged,
        });
    }
    drop(db);
    let reopened = Database::open(&path)?;
    let reopened_equal = snapshot(&reopened.begin_read()?)? == last;
    drop(reopened);
    temporary.remove()?;
    Ok(ObservedCase {
        name: case.name.clone(),
        initial,
        operations,
        reopened_equal,
    })
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let source = match args.as_slice() {
        [] => include_str!("../research/fixtures/native-slice.json").to_owned(),
        [flag, path] if flag == "--fixtures" => fs::read_to_string(path)?,
        _ => return Err("usage: native_slice [--fixtures PATH]".into()),
    };
    let fixtures: Fixtures = serde_json::from_str(&source)?;
    if fixtures.format != "native-slice-cases-v1" {
        return Err("unknown fixture format".into());
    }
    let model = Model::prepare()?;
    let directory = output_directory()?;
    let mut report = Report {
        format: "native-slice-run-v1",
        model: model.identity.clone(),
        cases: vec![],
    };
    for (index, case) in fixtures.cases.iter().enumerate() {
        report.cases.push(
            run_case(&directory, index, case, &fixtures, &model)
                .map_err(|error| format!("case {}: {error}", case.name))?,
        );
    }
    let path = directory.join("native-observations.json");
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    serde_json::to_writer(file, &report)?;
    println!(
        "Observed {} cases / {} operations; independent verification still required.\n{}",
        report.cases.len(),
        report
            .cases
            .iter()
            .map(|case| case.operations.len())
            .sum::<usize>(),
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::MultimapTableDefinition;

    #[test]
    fn raw_observer_includes_unreachable_rows_and_refuses_other_tables() -> Result<()> {
        let directory = output_directory()?;
        let temporary = Temporary(Some(directory.clone()));
        let db = Database::create(directory.join("observer.redb"))?;
        initialize(
            &db,
            &Model::prepare()?,
            Context {
                tenant: Uuid::nil(),
                actor: Uuid::nil(),
            },
        )?;
        let write = db.begin_write()?;
        {
            let mut table = write.open_table(KV)?;
            table.insert([255].as_slice(), b"unreachable".as_slice())?;
        }
        write.commit()?;
        let raw = snapshot(&db.begin_read()?)?;
        assert_eq!(raw.rows.len(), 2);
        assert_eq!(
            raw.rows[1],
            Row {
                key: "ff".into(),
                value: native_codec::hex(b"unreachable")
            }
        );

        const HIDDEN: TableDefinition<&[u8], &[u8]> = TableDefinition::new("hidden");
        const MULTI: MultimapTableDefinition<&[u8], &[u8]> =
            MultimapTableDefinition::new("hidden_multi");
        let write = db.begin_write()?;
        write.open_table(HIDDEN)?;
        write.commit()?;
        assert!(snapshot(&db.begin_read()?).is_err());
        let write = db.begin_write()?;
        write.delete_table(HIDDEN)?;
        write.open_multimap_table(MULTI)?;
        write.commit()?;
        assert!(snapshot(&db.begin_read()?).is_err());
        drop(db);
        temporary.remove()?;
        Ok(())
    }
}
