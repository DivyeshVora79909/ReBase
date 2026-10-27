//! Unmeasured bounded adapter controls for the S0 native probe.
use super::{Database, ReadableTable, Result, StorageError, TableDefinition};
use crate::diagnostics::{Recorder, Trace};
use serde_json::{Value, json};
use std::{collections::BTreeMap, ops::Bound};

const DATA: TableDefinition<&[u8], &[u8]> = TableDefinition::new("s0_diagnostic_data");
const TEMP: TableDefinition<&[u8], &[u8]> = TableDefinition::new("s0_diagnostic_temporary");
const ROWS: u64 = 131;
const VALUE_BYTES: usize = 8192;
fn require(ok: bool, detail: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(StorageError::new("diagnostic_control", detail))
    }
}
fn trace_recorder(backend: &str, action: &str) -> Recorder {
    Recorder::new(
        action,
        "adapter-control",
        backend,
        "Store-control",
        "control",
    )
}
fn metrics(trace: &Trace) -> Result<()> {
    if trace.backend == "foundationdb" {
        let sdk = trace
            .counters
            .sdk
            .as_ref()
            .ok_or_else(|| StorageError::new("diagnostic_control", "SDK metrics missing"))?;
        require(
            Some(sdk.call_get) == trace.counters.binding_get,
            "successful GET calls disagree with SDK",
        )?;
        require(
            Some(sdk.call_set) == trace.counters.binding_set,
            "SET calls disagree with SDK",
        )?;
        require(
            Some(sdk.call_clear) == trace.counters.binding_clear,
            "CLEAR calls disagree with SDK",
        )?;
        require(
            Some(sdk.call_clear_range) == trace.counters.binding_clear_range,
            "CLEAR_RANGE calls disagree with SDK",
        )?;
        require(
            sdk.rows_fetched == trace.counters.returned_rows,
            "returned rows disagree with SDK",
        )?;
        require(
            sdk.retries == 0 && trace.counters.retry_count == 0,
            "diagnostics introduced retries",
        )?;
    }
    Ok(())
}
fn image(db: &Database) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    db.begin_read()?
        .open_table(DATA)?
        .iter()?
        .map(|row| {
            let (k, v) = row?;
            Ok((k.value().to_vec(), v.value().to_vec()))
        })
        .collect()
}

/// `db` must be an isolated empty owned destination. Values are generated public
/// control bytes, not application data; no control runs inside measured spans.
pub fn run(db: &Database, backend: &str) -> Result<Value> {
    let mut expected = BTreeMap::new();
    let setup = db.begin_write()?;
    if setup.list_tables()?.next().is_some() {
        return Err(StorageError::new(
            "storage_exists",
            "adapter control destination must be empty",
        ));
    }
    {
        let mut data = setup.open_table(DATA)?;
        for n in 0..ROWS {
            let key = n.to_be_bytes().to_vec();
            let value = vec![n as u8; VALUE_BYTES];
            data.insert(key.as_slice(), value.as_slice())?;
            expected.insert(key, value);
        }
        setup
            .open_table(TEMP)?
            .insert(b"temporary", b"temporary-value".as_slice())?;
    }
    commit_control(
        setup,
        backend,
        "setup",
        json!({"function":"seed-generated-byte-tables","dataTable":DATA.name(),"rows":ROWS,"keyEncoding":"u64 big-endian n for 0 <= n < rows","valueGenerator":{"length":VALUE_BYTES,"byte":"n modulo 256"},"temporaryTable":TEMP.name(),"temporaryKey":"temporary","temporaryValue":"temporary-value"}),
    )?;
    let recorder = trace_recorder(backend, "adapter-range");
    let read = db.begin_read_diagnostic(recorder.clone())?;
    let observed: BTreeMap<Vec<u8>, Vec<u8>> = read
        .open_table(DATA)?
        .iter()?
        .map(|row| {
            let (k, v) = row?;
            Ok((k.value().to_vec(), v.value().to_vec()))
        })
        .collect::<Result<_>>()?;
    require(observed == expected, "paged scan changed generated rows")?;
    require(
        read.open_table(DATA)?
            .get(b"missing-control-key")?
            .is_none(),
        "negative GET unexpectedly found a row",
    )?;
    drop(read);
    let range_trace = recorder.snapshot("success", 0, None);
    require(
        range_trace.counters.facade_scan >= 3,
        "facade did not visit all bounded pages",
    )?;
    if backend == "foundationdb" {
        require(
            range_trace.counters.binding_get_range.unwrap_or(0) >= 3,
            "binding range calls missing",
        )?;
    }
    metrics(&range_trace)?;

    let recorder = recorder_for_mutation(backend);
    let write = db.begin_write_diagnostic(recorder.clone())?;
    write
        .open_table(DATA)?
        .insert(b"mutation-control", b"new-control-value".as_slice())?;
    require(
        write
            .open_table(DATA)?
            .remove(0u64.to_be_bytes().as_slice())?
            .is_some(),
        "remove lost seeded old value",
    )?;
    require(write.delete_table(TEMP)?, "temporary table was not deleted")?;
    commit_control(
        write,
        backend,
        "mutation",
        json!({"table":DATA.name(),"writes":[{"operation":"put","key":"mutation-control","value":"new-control-value"},{"operation":"remove","keyHex":"0000000000000000"},{"operation":"delete-table","table":TEMP.name()}]}),
    )?;
    expected.remove(0u64.to_be_bytes().as_slice());
    expected.insert(b"mutation-control".to_vec(), b"new-control-value".to_vec());
    require(
        image(db)? == expected,
        "diagnostic mutation changed complete bytes",
    )?;
    let mutation_trace = recorder.snapshot("success", 0, None);
    metrics(&mutation_trace)?;
    require(
        mutation_trace
            .events
            .iter()
            .filter(|e| e.layer == "commit")
            .count()
            == 1,
        "diagnostic commit event count changed",
    )?;
    if backend == "foundationdb" {
        require(
            mutation_trace.counters.binding_set.unwrap_or(0) > 0
                && mutation_trace.counters.binding_clear.unwrap_or(0) > 0
                && mutation_trace.counters.binding_clear_range.unwrap_or(0) > 0
                && mutation_trace.counters.binding_approximate_size == Some(1),
            "mutation binding calls missing",
        )?;
    }

    let mut conflicts = Vec::new();
    if backend != "redb" {
        for (action, key, range) in [
            (
                "negative-read-conflict",
                b"negative-control-key".as_slice(),
                false,
            ),
            ("empty-range-conflict", b"range-middle".as_slice(), true),
        ] {
            let recorder = trace_recorder(backend, action);
            let loser = db.begin_write_diagnostic(recorder.clone())?;
            {
                let mut table = loser.open_table(DATA)?;
                if range {
                    require(
                        table
                            .range::<&[u8]>((
                                Bound::Included(b"range-a".as_slice()),
                                Bound::Excluded(b"range-z".as_slice()),
                            ))?
                            .next()
                            .is_none(),
                        "protected control range was not empty",
                    )?;
                } else {
                    require(
                        table.get(key)?.is_none(),
                        "protected negative read found a value",
                    )?;
                }
                table.insert(action.as_bytes(), b"must-not-publish".as_slice())?;
            }
            let winner = db.begin_write()?;
            winner.open_table(DATA)?.insert(key, b"winner".as_slice())?;
            commit_control(
                winner,
                backend,
                "protected-read-winner",
                json!({"action":action,"table":DATA.name(),"writes":[{"operation":"put","key":String::from_utf8_lossy(key),"value":"winner"}]}),
            )?;
            let error = match commit_control(
                loser,
                backend,
                "protected-read-loser",
                json!({"action":action,"table":DATA.name(),"protectedRead":if range{json!({"operation":"scan","lowerIncluded":"range-a","upperExcluded":"range-z"})}else{json!({"operation":"get","key":String::from_utf8_lossy(key)})},"writes":[{"operation":"put","key":action,"value":"must-not-publish"}]}),
            ) {
                Err(error) => error,
                Ok(()) => {
                    return Err(StorageError::new(
                        "diagnostic_control",
                        "protected stale commit unexpectedly succeeded",
                    ));
                }
            };
            if error.code != "transaction_conflict" {
                return Err(error);
            }

            expected.insert(key.to_vec(), b"winner".to_vec());
            require(
                image(db)? == expected,
                "conflicting diagnostic attempt partially published",
            )?;
            let trace = recorder.snapshot("conflict", 0, None);
            metrics(&trace)?;
            require(
                trace.events.iter().filter(|e| e.layer == "commit").count() == 1,
                "conflict was retried or lacked real commit",
            )?;
            conflicts.push(json!({"action":action,"outcome":"conflict","completeBytesPreserved":true,"trace":trace}));
        }
    }
    Ok(
        json!({"format":"rebase-s0-adapter-control-1","rows":ROWS,"valueBytes":VALUE_BYTES,"exactRowsVerified":true,"rangeTrace":range_trace,"mutationTrace":mutation_trace,"protectedReadControls":{"executed":backend!="redb","unavailableReason":if backend=="redb"{Some("serialized embedded writer cannot overlap two write transactions")}else{None},"cases":conflicts}}),
    )
}
fn recorder_for_mutation(backend: &str) -> Recorder {
    trace_recorder(backend, "adapter-mutation")
}

// Preserve exact generated transaction facts when a submitted commit is uncertain.
// Reconciliation uses this saved invocation; this control never retries it.
fn commit_control(
    write: super::WriteTransaction,
    backend: &str,
    stage: &str,
    transaction: Value,
) -> Result<()> {
    write.commit().map_err(|error|StorageError::new(error.code,json!({"stage":stage,"target":"adapter-control","operationId":null,"allocations":[],"invocation":{"function":"storage::diagnostic_checks::run","backend":backend},"transaction":transaction,"error":{"code":error.code,"detail":error.detail}}).to_string()))
}
