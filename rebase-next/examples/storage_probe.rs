//! Real storage transaction-contract controls; no domain model or mock writer.
use rebase_semantic_proof::{
    native_slice::Result,
    storage::{self, ReadableTable, TableDefinition},
};
use serde_json::json;
use std::ops::Bound;

const DATA: TableDefinition<&[u8], &[u8]> = TableDefinition::new("probe_data");
const RECEIPTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("probe_receipts");

fn controls(db: &storage::Database, concurrent: bool) -> Result<Vec<&'static str>> {
    let mut passed = vec![];
    let write = db.begin_write()?;
    {
        write.open_table(DATA)?.insert(b"a", b"old".as_slice())?;
        write
            .open_table(RECEIPTS)?
            .insert(b"operation", b"old".as_slice())?;
    }
    write.commit()?;
    let old = db.begin_read()?;
    assert_eq!(old.open_table(DATA)?.get(b"a")?.unwrap().value(), b"old");
    let write = db.begin_write()?;
    {
        write.open_table(DATA)?.insert(b"a", b"new".as_slice())?;
        write
            .open_table(RECEIPTS)?
            .insert(b"operation", b"new".as_slice())?;
    }
    write.commit()?;
    assert_eq!(old.open_table(DATA)?.get(b"a")?.unwrap().value(), b"old");
    let read = db.begin_read()?;
    assert_eq!(read.open_table(DATA)?.get(b"a")?.unwrap().value(), b"new");
    assert_eq!(
        read.open_table(RECEIPTS)?
            .get(b"operation")?
            .unwrap()
            .value(),
        b"new"
    );
    passed.push("atomic-spaces-and-stable-read-snapshot");
    {
        let write = db.begin_write()?;
        write
            .open_table(DATA)?
            .insert(b"a", b"aborted".as_slice())?;
        write
            .open_table(RECEIPTS)?
            .insert(b"abort", b"absent".as_slice())?;
    }
    let read = db.begin_read()?;
    assert_eq!(read.open_table(DATA)?.get(b"a")?.unwrap().value(), b"new");
    assert!(read.open_table(RECEIPTS)?.get(b"abort")?.is_none());
    passed.push("drop-aborts-all-spaces");

    if concurrent {
        let first = db.begin_write()?;
        assert!(first.open_table(DATA)?.get(b"missing")?.is_none());
        let second = db.begin_write()?;
        second
            .open_table(DATA)?
            .insert(b"missing", b"inserted".as_slice())?;
        second.commit()?;
        first
            .open_table(DATA)?
            .insert(b"decision", b"stale".as_slice())?;
        assert_eq!(first.commit().unwrap_err().code, "transaction_conflict");
        assert!(
            db.begin_read()?
                .open_table(DATA)?
                .get(b"decision")?
                .is_none()
        );
        passed.push("absent-point-read-protects-decision");

        let first = db.begin_write()?;
        {
            let table = first.open_table(DATA)?;
            assert_eq!(
                table
                    .range::<&[u8]>((
                        Bound::Included(b"x".as_slice()),
                        Bound::Excluded(b"y".as_slice())
                    ))?
                    .count(),
                0
            );
        }
        let second = db.begin_write()?;
        second
            .open_table(DATA)?
            .insert(b"x-child", b"inserted".as_slice())?;
        second.commit()?;
        first
            .open_table(DATA)?
            .insert(b"range-decision", b"stale".as_slice())?;
        assert_eq!(first.commit().unwrap_err().code, "transaction_conflict");
        passed.push("empty-range-phantom-protects-decision");

        let first = db.begin_write()?;
        let second = db.begin_write()?;
        assert!(first.open_table(DATA)?.get(b"independent-1")?.is_none());
        assert!(second.open_table(DATA)?.get(b"independent-2")?.is_none());
        first
            .open_table(DATA)?
            .insert(b"independent-1", b"one".as_slice())?;
        second
            .open_table(DATA)?
            .insert(b"independent-2", b"two".as_slice())?;
        first.commit()?;
        second.commit()?;
        passed.push("disjoint-read-write-attempts-both-commit");
    }

    let write = db.begin_write()?;
    {
        let mut table = write.open_table(DATA)?;
        for value in 0_u16..130 {
            table.insert(
                format!("page-{value:03}").as_bytes(),
                value.to_be_bytes().as_slice(),
            )?;
        }
        let rows: Vec<_> = table
            .range::<&[u8]>((
                Bound::Included(b"page-".as_slice()),
                Bound::Excluded(b"page.".as_slice()),
            ))?
            .map(|row| row.map(|(key, _)| key.value().to_vec()))
            .collect::<Result<_>>()?;
        assert_eq!(rows.len(), 130);
        assert!(rows.windows(2).all(|rows| rows[0] < rows[1]));
    }
    write.commit()?;
    passed.push("staged-writes-merge-through-64-row-pages");
    Ok(passed)
}

fn main() -> Result<()> {
    let backend = std::env::args().nth(1).expect("backend argument required");
    let location = std::env::args()
        .nth(2)
        .expect("cluster file or fresh database path required");
    #[cfg(feature = "foundationdb")]
    let _network = if backend == "foundationdb" {
        Some(unsafe { foundationdb::boot() })
    } else {
        None
    };
    let namespace = format!("rebase-g7-probe-{}", uuid::Uuid::new_v4());
    let db = match backend.as_str() {
        "redb" => storage::Database::from_redb(redb::Database::create(&location).unwrap()),
        #[cfg(feature = "foundationdb")]
        "foundationdb" => storage::foundationdb::connect(Some(&location), namespace.as_bytes())?,
        #[cfg(feature = "surrealkv")]
        "surrealkv" => storage::surrealkv::connect(&location)?,
        _ => panic!("backend not compiled: {backend}"),
    };
    let concurrent = backend != "redb";
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let cases = runtime.block_on(async move {
        tokio::task::spawn_blocking(move || controls(&db, concurrent))
            .await
            .unwrap()
    })?;
    println!(
        "{}",
        json!({"status":"passed","backend":backend,"namespace":namespace,"cases":cases,
        "concurrent_schedule_scope": if concurrent { "optimistic snapshot conflicts" } else { "serialized writers; concurrent controls supplied separately" },
        "scope":"storage/runtime contract only; application integration and unknown-response recovery are later gates"})
    );
    Ok(())
}
