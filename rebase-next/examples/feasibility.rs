use std::{collections::BTreeMap, error::Error, fs, path::PathBuf};

use rebase_semantic_proof::{
    algebra::Summary,
    plan::{Field, evaluation_order},
    staging::Overlay,
};
use redb::{Database, ReadableDatabase, ReadableTable, StorageError, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const KV: TableDefinition<&[u8], &[u8]> = TableDefinition::new("kv");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Design {
    contract_code: u16,
    input_schema: Value,
    fields: Vec<Field>,
    memberships: Vec<Membership>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Membership {
    slot: u16,
    root_slot: u16,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    id: Uuid,
    tenant: Uuid,
    owner: Uuid,
    account: Uuid,
    effective_ns: String,
    quantity: u32,
    unit_price: String,
}

#[derive(Serialize, Deserialize)]
struct Record {
    contract: u16,
    input: Input,
    amount_units: i128,
}

#[derive(Serialize)]
struct Node {
    root_record: Uuid,
    root_slot: u16,
    value: Summary,
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// Point-address namespaces; this is not an order-preserving business-key codec.
fn key(namespace: u8, record: Uuid, slot: Option<u16>) -> Vec<u8> {
    let mut key = vec![namespace];
    key.extend_from_slice(record.as_bytes());
    if let Some(slot) = slot {
        key.extend_from_slice(&slot.to_be_bytes());
    }
    key
}

fn units(price: &str) -> Result<i128> {
    let (whole, cents) = price
        .split_once('.')
        .ok_or("price needs two decimal places")?;
    if cents.len() != 2 || !cents.bytes().all(|x| x.is_ascii_digit()) {
        return Err("invalid cents".into());
    }
    let whole: i128 = whole.parse()?;
    let cents: i128 = cents.parse()?;
    whole
        .checked_mul(100)
        .and_then(|x| x.checked_add(cents))
        .ok_or_else(|| "price overflow".into())
}

// Trusted ordinary behavior uses the prepared dependency order.
fn calculate(design: &Design, order: &[usize], input: &Input) -> Result<i128> {
    let mut values = BTreeMap::new();
    for &index in order {
        let field = &design.fields[index];
        let value = match field.name.as_str() {
            "quantity" => i128::from(input.quantity),
            "unit_price" => units(&input.unit_price)?,
            "z_price_units" => values["unit_price"],
            "a_amount" => values["quantity"]
                .checked_mul(values["z_price_units"])
                .ok_or("amount overflow")?,
            _ => return Err("unregistered demonstration field".into()),
        };
        values.insert(field.name.as_str(), value);
    }
    Ok(values["a_amount"])
}

fn snapshot(db: &Database) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    let read = db.begin_read()?;
    let table = read.open_table(KV)?;
    let mut rows = BTreeMap::new();
    for entry in table.iter()? {
        let (key, value) = entry?;
        rows.insert(key.value().to_vec(), value.value().to_vec());
    }
    Ok(rows)
}

fn main() -> Result<()> {
    let design: Design = serde_json::from_str(include_str!("demo.json"))?;
    let validator = jsonschema::options()
        .offline()
        .should_validate_formats(true)
        .build(&design.input_schema)?;
    let order = evaluation_order(&design.fields)?;
    let input = json!({
        "id": "10000000-0000-4000-8000-000000000001",
        "tenant": "10000000-0000-4000-8000-000000000002",
        "owner": "10000000-0000-4000-8000-000000000003",
        "account": "10000000-0000-4000-8000-000000000004",
        "effective_ns": "1234567890123456789", "quantity": 2, "unit_price": "2.00"
    });
    assert!(validator.is_valid(&input));
    let mut bad = input.clone();
    bad["unit_price"] = json!(2.01);
    assert!(!validator.is_valid(&bad), "exact wire values are strings");
    bad = input.clone();
    bad["protected_amount"] = json!(10);
    assert!(
        !validator.is_valid(&bad),
        "client cannot supply calculated output"
    );
    bad = input.clone();
    bad["owner"] = json!("not-a-uuid");
    assert!(
        !validator.is_valid(&bad),
        "format checks are explicitly enabled"
    );
    let mut input: Input = serde_json::from_value(input)?;
    let time: i64 = input.effective_ns.parse()?;

    let dir = std::env::temp_dir().join(format!(
        "rebase-proof-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    fs::create_dir(&dir)?;
    let temporary = Temporary(dir);
    let file = temporary.0.join("proof.redb");
    let db = Database::create(&file)?;
    let root_keys: Vec<_> = design
        .memberships
        .iter()
        .map(|m| key(1, input.account, Some(m.root_slot)))
        .collect();
    let node_keys: Vec<_> = design
        .memberships
        .iter()
        .map(|m| key(2, input.id, Some(m.slot)))
        .collect();
    let record_key = key(0, input.id, None);
    let initialize = db.begin_write()?;
    {
        let mut table = initialize.open_table(KV)?;
        let empty = serde_json::to_vec(&Summary::default())?;
        for key in &root_keys {
            table.insert(key.as_slice(), empty.as_slice())?;
        }
    }
    initialize.commit()?;
    let old_read = db.begin_read()?;
    let old_table = old_read.open_table(KV)?;
    let write = db.begin_write()?;
    let mut overlay = Overlay::default();
    let final_summary;
    {
        let mut table = write.open_table(KV)?;
        let load = |key: &[u8]| -> std::result::Result<Option<Vec<u8>>, StorageError> {
            Ok(table.get(key)?.map(|value| value.value().to_vec()))
        };
        assert!(
            overlay.read(&record_key, || load(&record_key))?.is_none(),
            "create-if-absent"
        );
        // Single-leaf publications only: this demonstrates staging, not AVL mutation.
        for quantity in [2, 3] {
            input.quantity = quantity;
            let amount = calculate(&design, &order, &input)?;
            overlay.stage(
                &record_key,
                Some(serde_json::to_vec(&Record {
                    contract: design.contract_code,
                    input: input.clone(),
                    amount_units: amount,
                })?),
                || load(&record_key),
            )?;
            for (index, membership) in design.memberships.iter().enumerate() {
                let summary = Summary::leaf(time, Some(amount));
                overlay.stage(
                    &node_keys[index],
                    Some(serde_json::to_vec(&Node {
                        root_record: input.account,
                        root_slot: membership.root_slot,
                        value: summary,
                    })?),
                    || load(&node_keys[index]),
                )?;
                overlay.stage(
                    &root_keys[index],
                    Some(serde_json::to_vec(&summary)?),
                    || load(&root_keys[index]),
                )?;
            }
        }
        assert!(
            table.get(record_key.as_slice())?.is_none(),
            "staging does not write storage"
        );
        let staged = overlay.read(&record_key, || load(&record_key))?.unwrap();
        let record: Record = serde_json::from_slice(&staged)?;
        assert_eq!(record.amount_units, 600, "read own final derived output");
        final_summary = Summary::leaf(time, Some(record.amount_units));
        assert!(final_summary.complete_min() >= 0);
        assert_eq!(overlay.reads, 5, "five touched keys loaded once each");
        let batch = overlay.finish();
        assert_eq!(
            batch.len(),
            5,
            "ten staged patches become five final writes"
        );
        for (key, value) in batch {
            match value {
                Some(value) => {
                    table.insert(key.as_slice(), value.as_slice())?;
                }
                None => {
                    table.remove(key.as_slice())?;
                }
            }
        }
    }
    write.commit()?;
    assert!(
        old_table.get(record_key.as_slice())?.is_none(),
        "old snapshot remains unchanged"
    );
    let old_summary: Summary =
        serde_json::from_slice(old_table.get(root_keys[0].as_slice())?.unwrap().value())?;
    assert_eq!(old_summary.count, 0);
    drop(old_table);
    drop(old_read);
    let before = snapshot(&db)?;
    let settled: Record = serde_json::from_slice(&before[&record_key])?;
    assert_eq!(settled.amount_units, 600);
    for key in &root_keys {
        assert_eq!(
            serde_json::from_slice::<Summary>(&before[key])?,
            final_summary
        );
    }
    let rejected = db.begin_write()?;
    {
        let mut table = rejected.open_table(KV)?;
        table.insert(record_key.as_slice(), b"invalid source".as_slice())?;
        let invalid = Summary::leaf(time, Some(-1));
        assert!(invalid.complete_min() < 0);
        for key in &root_keys {
            let bytes = serde_json::to_vec(&invalid)?;
            table.insert(key.as_slice(), bytes.as_slice())?;
        }
    }
    rejected.abort()?;
    assert_eq!(
        snapshot(&db)?,
        before,
        "abort restores the complete keyspace"
    );
    drop(db);
    let reopened = Database::open(&file)?;
    assert_eq!(
        snapshot(&reopened)?,
        before,
        "committed bytes survive reopen"
    );
    drop(reopened);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "passed": ["reused strict JSON Schema", "exact string input and nanosecond binding", "dependency order", "one fact with two separately stored slots", "read your writes", "coalesced final writes", "old snapshot isolation", "atomic abort", "durable reopen"],
            "field_order": order.iter().map(|&i| &design.fields[i].name).collect::<Vec<_>>(),
            "snapshot_key_loads": 5, "staged_patches": 10, "final_dirty_keys": 5, "amount_minor_units": 600,
            "scope": "single-leaf embedded staging proof; no full tree/dependency/authorization runtime"
        }))?
    );
    Ok(())
}
