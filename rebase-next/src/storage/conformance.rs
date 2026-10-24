//! Deterministic storage schedules with an independent complete-table oracle.
//!
//! These controls exercise the byte boundary. The application acceptance suite
//! separately checks native settlement, reader repair and effect publication.
use super::{
    Database, ReadTransaction, ReadableTable, Result, StorageError, TableDefinition,
    WriteTransaction,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, ops::Bound};

type Definition = TableDefinition<'static, &'static [u8], &'static [u8]>;
type Image = BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>;
const DATA: Definition = TableDefinition::new("conformance_data");
const INDEX: Definition = TableDefinition::new("conformance_index");
const RECEIPTS: Definition = TableDefinition::new("conformance_receipts");
const ROOTS: Definition = TableDefinition::new("conformance_roots");
const REFERENCES: Definition = TableDefinition::new("conformance_references");
const AUTHORITY: Definition = TableDefinition::new("conformance_authority");
const TABLES: [Definition; 6] = [DATA, INDEX, RECEIPTS, ROOTS, REFERENCES, AUTHORITY];

fn check(condition: bool, detail: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(StorageError::new("conformance_failed", detail))
    }
}
fn expected_put(image: &mut Image, table: Definition, key: &[u8], value: &[u8]) {
    image
        .get_mut(table.name())
        .expect("oracle table")
        .insert(key.to_vec(), value.to_vec());
}
fn expected_remove(image: &mut Image, table: Definition, key: &[u8]) {
    image
        .get_mut(table.name())
        .expect("oracle table")
        .remove(key);
}
fn put(write: &WriteTransaction, table: Definition, key: &[u8], value: &[u8]) -> Result<()> {
    write.open_table(table)?.insert(key, value)?;
    Ok(())
}
fn image(read: &ReadTransaction) -> Result<Image> {
    let mut image = Image::new();
    let mut actual_tables = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<Vec<_>>();
    let mut expected_tables = TABLES.map(|table| table.name().to_owned()).to_vec();
    actual_tables.sort();
    expected_tables.sort();
    check(
        actual_tables == expected_tables,
        "unexpected complete table inventory",
    )?;
    for table in TABLES {
        let rows = read
            .open_table(table)?
            .iter()?
            .map(|row| {
                let (key, value) = row?;
                Ok((key.value().to_vec(), value.value().to_vec()))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        image.insert(table.name().into(), rows);
    }
    Ok(image)
}
fn verify(db: &Database, expected: &Image, case: &str) -> Result<()> {
    let observed = image(&db.begin_read()?)?;
    check(
        &observed == expected,
        format!("complete table image differs after {case}"),
    )
}
fn record(cases: &mut Vec<Value>, name: &str, predicate: &str, outcome: &str, receipt: bool) {
    cases.push(json!({"name":name,"predicate":predicate,"expected_outcome":outcome,
        "expected_attempt_receipt":receipt,"complete_tables_checked":TABLES.map(|table|table.name().to_owned())}));
}
fn conflict(write: WriteTransaction, case: &str) -> Result<()> {
    match write.commit() {
        Err(error) if error.code == "transaction_conflict" => Ok(()),
        Err(error) => Err(StorageError::new(
            "conformance_failed",
            format!("{case}: expected transaction_conflict, received {error}"),
        )),
        Ok(()) => Err(StorageError::new(
            "conformance_failed",
            format!("{case}: stale attempt committed"),
        )),
    }
}
fn stage_stale(write: &WriteTransaction, name: &str) -> Result<()> {
    // A losing decision must publish none of its related logical spaces.
    for table in TABLES {
        put(write, table, name.as_bytes(), b"loser-must-be-absent")?;
    }
    Ok(())
}
fn range(
    write: &WriteTransaction,
    table: Definition,
    lower: &[u8],
    upper: &[u8],
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    write
        .open_table(table)?
        .range::<&[u8]>((Bound::Included(lower), Bound::Excluded(upper)))?
        .map(|row| {
            let (key, value) = row?;
            Ok((key.value().to_vec(), value.value().to_vec()))
        })
        .collect()
}
fn commit_winner(
    db: &Database,
    expected: &mut Image,
    table: Definition,
    key: &[u8],
    value: Option<&[u8]>,
    case: &str,
) -> Result<()> {
    let write = db.begin_write()?;
    if let Some(value) = value {
        put(&write, table, key, value)?;
        expected_put(expected, table, key, value);
    } else {
        write.open_table(table)?.remove(key)?;
        expected_remove(expected, table, key);
    }
    put(&write, RECEIPTS, case.as_bytes(), b"winner-committed")?;
    expected_put(expected, RECEIPTS, case.as_bytes(), b"winner-committed");
    write.commit()
}

fn limited(error: StorageError, case: &str) -> Result<()> {
    check(
        error.code == "transaction_limit",
        format!("{case}: expected transaction_limit, received {error}"),
    )
}

fn limit_controls(db: &Database, expected: &Image, cases: &mut Vec<Value>) -> Result<()> {
    let limits = db.limits();
    if let Some(maximum) = limits.max_key_bytes {
        let write = db.begin_write()?;
        put(&write, RECEIPTS, b"key-limit-attempt", b"staged")?;
        match put(&write, DATA, &vec![b'k'; maximum + 1], b"value") {
            Err(error) => limited(error, "encoded key limit")?,
            Ok(()) => {
                return Err(StorageError::new(
                    "conformance_failed",
                    "oversized encoded key accepted",
                ));
            }
        }
        drop(write);
        verify(db, expected, "encoded key limit")?;
        record(
            cases,
            "encoded-key-limit-aborts-staged-receipt",
            "physical namespace/table/key bytes count toward key limit",
            "transaction_limit",
            false,
        );
    }
    if let Some(maximum) = limits.max_value_bytes {
        let write = db.begin_write()?;
        put(&write, RECEIPTS, b"value-limit-attempt", b"staged")?;
        match put(&write, DATA, b"too-large-value", &vec![b'v'; maximum + 1]) {
            Err(error) => limited(error, "value limit")?,
            Ok(()) => {
                return Err(StorageError::new(
                    "conformance_failed",
                    "oversized value accepted",
                ));
            }
        }
        drop(write);
        verify(db, expected, "value limit")?;
        record(
            cases,
            "value-limit-aborts-staged-receipt",
            "complete encoded value bytes",
            "transaction_limit",
            false,
        );
    }
    if let (Some(maximum), Some(value_maximum)) =
        (limits.max_transaction_bytes, limits.max_value_bytes)
    {
        let write = db.begin_write()?;
        put(&write, RECEIPTS, b"transaction-limit-attempt", b"staged")?;
        let value = vec![b'v'; value_maximum];
        let mut rejected = false;
        for n in 0..=maximum / value_maximum + 1 {
            let key = format!("large/{n:06}");
            match put(&write, DATA, key.as_bytes(), &value) {
                Ok(()) => {}
                Err(error) => {
                    limited(error, "transaction size limit")?;
                    rejected = true;
                    break;
                }
            }
        }
        if rejected {
            drop(write);
        } else {
            match write.commit() {
                Err(error) => limited(error, "transaction size limit")?,
                Ok(()) => {
                    return Err(StorageError::new(
                        "conformance_failed",
                        "oversized transaction committed",
                    ));
                }
            }
        }
        verify(db, expected, "transaction size limit")?;
        record(
            cases,
            "transaction-byte-limit-aborts-all-staged-writes",
            "coalesced writes plus native conflict ranges",
            "transaction_limit",
            false,
        );
    }
    if let (Some(maximum), Some(key_maximum)) = (limits.max_transaction_bytes, limits.max_key_bytes)
    {
        // Values and final writes alone fit. Long protected absent-key reads
        // push the native conflict-range estimate above the transaction budget.
        let write = db.begin_write()?;
        put(&write, RECEIPTS, b"conflict-byte-limit-attempt", b"staged")?;
        let key_size = key_maximum.saturating_sub(512);
        check(
            key_size > 0,
            "key limit too small for conflict-byte control",
        )?;
        let count = maximum / (2 * key_size) + 8;
        let table = write.open_table(DATA)?;
        let mut rejected = false;
        for n in 0..count {
            let mut key = vec![b'q'; key_size];
            key[..8].copy_from_slice(&(n as u64).to_be_bytes());
            match table.get(&key) {
                Ok(value) => check(
                    value.is_none(),
                    "conflict-byte control requires absent long keys",
                )?,
                Err(error) => {
                    check(
                        error.detail.contains("size") || error.detail.contains("(2101)"),
                        format!("conflict-range control reached a different limit: {error}"),
                    )?;
                    limited(error, "conflict-range byte limit")?;
                    rejected = true;
                    break;
                }
            }
        }
        drop(table);
        if rejected {
            drop(write);
        } else {
            match write.commit() {
                Err(error) => {
                    check(
                        error.detail.contains("size") || error.detail.contains("(2101)"),
                        format!("conflict-range control reached a different limit: {error}"),
                    )?;
                    limited(error, "conflict-range byte limit")?;
                }
                Ok(()) => {
                    return Err(StorageError::new(
                        "conformance_failed",
                        "oversized protected-read conflict ranges committed",
                    ));
                }
            }
        }
        verify(db, expected, "conflict-range byte limit")?;
        record(
            cases,
            "native-conflict-range-byte-limit",
            "read values excluded; protected keys/ranges included by native estimate",
            "transaction_limit",
            false,
        );
    }
    Ok(())
}

/// Execute deterministic transaction interleavings. Each call owns six fresh
/// logical tables; use a fresh embedded path or a unique distributed namespace.
pub fn run(db: &Database, optimistic: bool) -> Result<Value> {
    let mut expected = Image::new();
    let mut cases = Vec::new();
    let create = db.begin_write()?;
    for table in TABLES {
        create.open_table(table)?;
        expected.insert(table.name().into(), BTreeMap::new());
    }
    create.commit()?;
    verify(db, &expected, "empty inventory")?;

    let write = db.begin_write()?;
    for (table, key, value) in [
        (DATA, b"record".as_slice(), b"old".as_slice()),
        (INDEX, b"record", b"indexed-old"),
        (RECEIPTS, b"initial-operation", b"old"),
        (ROOTS, b"balance", b"10"),
        (REFERENCES, b"refs/existing", b"record"),
        (AUTHORITY, b"actor", b"allowed"),
    ] {
        put(&write, table, key, value)?;
        expected_put(&mut expected, table, key, value);
    }
    write.commit()?;
    let old = db.begin_read()?;
    check(image(&old)? == expected, "initial snapshot")?;
    let prior = expected.clone();
    let write = db.begin_write()?;
    for (table, key, value) in [
        (DATA, b"record".as_slice(), b"new".as_slice()),
        (INDEX, b"record", b"indexed-new"),
        (RECEIPTS, b"initial-operation", b"new"),
    ] {
        put(&write, table, key, value)?;
        expected_put(&mut expected, table, key, value);
    }
    write.commit()?;
    check(
        image(&old)? == prior,
        "old snapshot changed after atomic publication",
    )?;
    verify(db, &expected, "atomic publication")?;
    drop(old);
    record(
        &mut cases,
        "atomic-publication-old-new-snapshots",
        "one snapshot across every table",
        "committed",
        true,
    );

    for boundary in 1..=TABLES.len() {
        let write = db.begin_write()?;
        for table in TABLES.into_iter().take(boundary) {
            put(&write, table, b"partial-abort", b"staged-only")?;
        }
        // Dropping the attempt is the abort boundary, including after receipt.
        drop(write);
        verify(db, &expected, "partial table-family abort")?;
        record(
            &mut cases,
            &format!("abort-after-table-family-{boundary}"),
            "all staged tables share commit",
            "aborted",
            false,
        );
    }

    let seed = db.begin_write()?;
    for n in 0_u16..150 {
        let key = format!("page/{n:03}");
        let value = n.to_be_bytes();
        put(&seed, DATA, key.as_bytes(), &value)?;
        expected_put(&mut expected, DATA, key.as_bytes(), &value);
    }
    seed.commit()?;
    let write = db.begin_write()?;
    for n in 0..70 {
        let key = format!("page/{n:03}");
        write.open_table(DATA)?.remove(key.as_bytes())?;
        expected_remove(&mut expected, DATA, key.as_bytes());
    }
    for n in 70_u16..90 {
        let key = format!("page/{n:03}");
        put(&write, DATA, key.as_bytes(), b"replacement")?;
        expected_put(&mut expected, DATA, key.as_bytes(), b"replacement");
    }
    for n in 0_u16..30 {
        let key = format!("page/{n:03}a");
        put(&write, DATA, key.as_bytes(), b"inserted")?;
        expected_put(&mut expected, DATA, key.as_bytes(), b"inserted");
    }
    let expected_range: BTreeMap<_, _> = expected[DATA.name()]
        .iter()
        .filter(|(key, _)| {
            key.as_slice() >= b"page/".as_slice() && key.as_slice() < b"page0".as_slice()
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    check(
        expected_range.len() > 64,
        "overlay must span multiple lazy pages",
    )?;
    let observed_range = range(&write, DATA, b"page/", b"page0")?;
    check(
        observed_range == expected_range,
        format!(
            "staged range overlay differs: expected {} rows, observed {}; first missing key {:?}",
            expected_range.len(),
            observed_range.len(),
            expected_range
                .keys()
                .find(|key| !observed_range.contains_key(*key))
                .map(|key| crate::native_codec::hex(key))
        ),
    )?;
    write.commit()?;
    verify(db, &expected, "range overlay commit")?;
    record(
        &mut cases,
        "paged-staged-range-insert-replace-delete",
        "half-open ordered range with over 64 results and over 64 tombstones",
        "committed",
        false,
    );

    if optimistic {
        let stale = db.begin_write()?;
        {
            let table = stale.open_table(DATA)?;
            check(
                table
                    .range::<&[u8]>((
                        Bound::Included(b"page/".as_slice()),
                        Bound::Excluded(b"page0".as_slice()),
                    ))?
                    .next()
                    .transpose()?
                    .is_some(),
                "populated lazy page setup",
            )?;
        }
        commit_winner(
            db,
            &mut expected,
            DATA,
            b"page/149",
            Some(b"edited-beyond-first-page"),
            "late-page-winner",
        )?;
        stage_stale(&stale, "late-page-loser")?;
        conflict(stale, "full predicate beyond first lazy page")?;
        verify(db, &expected, "full predicate beyond first lazy page")?;
        record(
            &mut cases,
            "limited-page-protects-far-later-range-edit",
            "complete requested range remains protected after first lazy page",
            "transaction_conflict",
            false,
        );

        let stale = db.begin_write()?;
        check(stale.delete_table(DATA)?, "populated table deletion setup")?;
        commit_winner(
            db,
            &mut expected,
            DATA,
            b"page/149",
            Some(b"edited-during-table-delete"),
            "table-delete-winner",
        )?;
        for table in TABLES.into_iter().skip(1) {
            put(&stale, table, b"table-delete-loser", b"must-not-publish")?;
        }
        conflict(stale, "populated table deletion predicate")?;
        verify(db, &expected, "populated table deletion predicate")?;
        record(
            &mut cases,
            "table-delete-protects-far-later-edit",
            "entire table prefix read conflict before range clear",
            "transaction_conflict",
            false,
        );

        let first = db.begin_write()?;
        let second = db.begin_write()?;
        put(&first, DATA, b"independent-a", b"a")?;
        put(&second, DATA, b"independent-b", b"b")?;
        first.commit()?;
        second.commit()?;
        expected_put(&mut expected, DATA, b"independent-a", b"a");
        expected_put(&mut expected, DATA, b"independent-b", b"b");
        verify(db, &expected, "disjoint point commits")?;
        record(
            &mut cases,
            "disjoint-points-both-commit",
            "disjoint exact keys; fixed keys occupy different SurrealKV guard buckets",
            "both_committed",
            false,
        );

        let stale = db.begin_write()?;
        check(
            stale.open_table(DATA)?.get(b"unique-absent")?.is_none(),
            "uniqueness setup",
        )?;
        commit_winner(
            db,
            &mut expected,
            DATA,
            b"unique-absent",
            Some(b"created"),
            "unique-winner",
        )?;
        stage_stale(&stale, "unique-loser")?;
        conflict(stale, "absent uniqueness")?;
        verify(db, &expected, "absent uniqueness")?;
        record(
            &mut cases,
            "absent-key-uniqueness",
            "tracked exact absence",
            "transaction_conflict",
            false,
        );

        let stale = db.begin_write()?;
        check(
            range(&stale, DATA, b"phantom/", b"phantom0")?.is_empty(),
            "phantom insertion setup",
        )?;
        commit_winner(
            db,
            &mut expected,
            DATA,
            b"phantom/child",
            Some(b"new"),
            "range-insert-winner",
        )?;
        stage_stale(&stale, "range-insert-loser")?;
        conflict(stale, "range insertion")?;
        verify(db, &expected, "range insertion")?;
        record(
            &mut cases,
            "empty-range-insertion-phantom",
            "tracked empty half-open range",
            "transaction_conflict",
            false,
        );

        let stale = db.begin_write()?;
        check(
            range(&stale, DATA, b"phantom/", b"phantom0")?.len() == 1,
            "phantom deletion setup",
        )?;
        commit_winner(
            db,
            &mut expected,
            DATA,
            b"phantom/child",
            None,
            "range-delete-winner",
        )?;
        stage_stale(&stale, "range-delete-loser")?;
        conflict(stale, "range deletion")?;
        verify(db, &expected, "range deletion")?;
        record(
            &mut cases,
            "range-deletion-phantom",
            "tracked populated half-open range",
            "transaction_conflict",
            false,
        );

        for (name, no_op) in [("root-invariant", false), ("no-op-root-guard", true)] {
            let stale = db.begin_write()?;
            let prior = stale
                .open_table(ROOTS)?
                .get(b"balance")?
                .expect("root seeded")
                .value()
                .to_vec();
            if no_op {
                put(&stale, ROOTS, b"balance", &prior)?;
            }
            commit_winner(
                db,
                &mut expected,
                ROOTS,
                b"balance",
                Some(if no_op { b"6" } else { b"7" }),
                &format!("{name}-winner"),
            )?;
            if !no_op {
                put(&stale, ROOTS, b"balance", b"8")?;
            }
            stage_stale(&stale, &format!("{name}-loser"))?;
            conflict(stale, name)?;
            verify(db, &expected, name)?;
            record(
                &mut cases,
                name,
                "tracked business-root value, including unchanged staged guard",
                "transaction_conflict",
                false,
            );
        }

        let stale = db.begin_write()?;
        // insert returns the prior value, so the facade makes this a protected
        // read-modify-write even though the caller did not call get separately.
        put(&stale, ROOTS, b"balance", b"facade-first")?;
        commit_winner(
            db,
            &mut expected,
            ROOTS,
            b"balance",
            Some(b"facade-second"),
            "blind-write-winner",
        )?;
        stage_stale(&stale, "blind-write-loser")?;
        conflict(stale, "protected facade put")?;
        verify(db, &expected, "protected facade put")?;
        record(
            &mut cases,
            "facade-put-protects-prior-value",
            "put tracks old value; native blind-write semantics are not assumed",
            "transaction_conflict",
            false,
        );

        let stale = db.begin_write()?;
        check(
            range(&stale, REFERENCES, b"refs/new/", b"refs/new0")?.is_empty(),
            "reverse discovery setup",
        )?;
        commit_winner(
            db,
            &mut expected,
            REFERENCES,
            b"refs/new/child",
            Some(b"record"),
            "reverse-winner",
        )?;
        stale.open_table(DATA)?.remove(b"record")?;
        stage_stale(&stale, "reverse-loser")?;
        conflict(stale, "reverse discovery")?;
        verify(db, &expected, "reverse discovery")?;
        record(
            &mut cases,
            "reverse-discovery-reference-insertion",
            "tracked reverse-reference range before parent deletion",
            "transaction_conflict",
            false,
        );

        let stale = db.begin_write()?;
        check(
            stale.open_table(DATA)?.get(b"record")?.is_some(),
            "reference parent setup",
        )?;
        commit_winner(
            db,
            &mut expected,
            DATA,
            b"record",
            None,
            "parent-delete-winner",
        )?;
        put(&stale, REFERENCES, b"refs/to-deleted", b"record")?;
        stage_stale(&stale, "parent-delete-loser")?;
        conflict(stale, "reference parent deletion")?;
        verify(db, &expected, "reference parent deletion")?;
        record(
            &mut cases,
            "reference-target-deletion",
            "tracked exact target before reference creation",
            "transaction_conflict",
            false,
        );

        let authorized = db.begin_read()?;
        check(
            authorized
                .open_table(AUTHORITY)?
                .get(b"actor")?
                .expect("authority seeded")
                .value()
                == b"allowed",
            "snapshot authority setup",
        )?;
        let stale = db.begin_write()?;
        check(
            stale
                .open_table(AUTHORITY)?
                .get(b"actor")?
                .expect("authority seeded")
                .value()
                == b"allowed",
            "write authority setup",
        )?;
        commit_winner(
            db,
            &mut expected,
            AUTHORITY,
            b"actor",
            Some(b"revoked"),
            "revocation-winner",
        )?;
        stage_stale(&stale, "revocation-loser")?;
        conflict(stale, "authority revocation")?;
        check(
            authorized
                .open_table(AUTHORITY)?
                .get(b"actor")?
                .expect("old authority")
                .value()
                == b"allowed",
            "authorized old snapshot was changed",
        )?;
        drop(authorized);
        verify(db, &expected, "authority revocation")?;
        record(
            &mut cases,
            "write-authority-revocation",
            "tracked authority point through commit",
            "transaction_conflict",
            false,
        );
        record(
            &mut cases,
            "snapshot-authorized-read-after-revocation",
            "read snapshot retains its authority facts",
            "snapshot_allowed",
            false,
        );
    }

    limit_controls(db, &expected, &mut cases)?;
    verify(db, &expected, "final inventory")?;
    let bytes = serde_json::to_vec(
        &expected
            .iter()
            .map(|(name, rows)| {
                (
                    name.clone(),
                    rows.iter()
                        .map(|(key, value)| {
                            (
                                crate::native_codec::hex(key),
                                crate::native_codec::hex(value),
                            )
                        })
                        .collect::<BTreeMap<_, _>>(),
                )
            })
            .collect::<BTreeMap<_, _>>(),
    )
    .map_err(|error| StorageError::new("codec", error.to_string()))?;
    Ok(
        json!({"status":"passed","cases":cases,"tables":TABLES.map(|table|table.name().to_owned()),
        "final_rows":expected.values().map(BTreeMap::len).sum::<usize>(),
        "final_image_sha256":crate::native_codec::hex(&Sha256::digest(bytes)),
        "optimistic_schedules":optimistic,
        "scope":"byte-boundary schedules; engine/application integration is checked separately"}),
    )
}

/// Fingerprint for reopening controls. Uses the same complete six-table image
/// serialization as `run`, with no database-specific physical bytes.
pub fn fingerprint(db: &Database) -> Result<String> {
    let observed = image(&db.begin_read()?)?;
    let bytes = serde_json::to_vec(
        &observed
            .iter()
            .map(|(name, rows)| {
                (
                    name.clone(),
                    rows.iter()
                        .map(|(key, value)| {
                            (
                                crate::native_codec::hex(key),
                                crate::native_codec::hex(value),
                            )
                        })
                        .collect::<BTreeMap<_, _>>(),
                )
            })
            .collect::<BTreeMap<_, _>>(),
    )
    .map_err(|error| StorageError::new("codec", error.to_string()))?;
    Ok(crate::native_codec::hex(&Sha256::digest(bytes)))
}
