//! Bounded operation retention without a globally rewritten allocation header.
//! Each slot and its receipt are published by the caller's application transaction.
use crate::{
    binding::Binding,
    local::{self, MAX_RECEIPTS, RECEIPTS, ReceiptValue},
    native_slice::{Error, Result},
    storage::{ReadTransaction, ReadableTable, TableDefinition, WriteTransaction},
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const SLOTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("receipt_slots");

pub(crate) fn start_slot(receipt_key: &[u8]) -> u16 {
    let mut hash = Sha256::new();
    hash.update(b"rebase-receipt-slot-1\0");
    hash.update(receipt_key);
    let digest = hash.finalize();
    u16::from_be_bytes([digest[0], digest[1]]) % MAX_RECEIPTS
}

/// Call only after the original operation's replay check. Every occupied or
/// absent slot is a tracked read; the chosen pointer is staged immediately.
/// A collision probes all remaining slots, so capacity is never stranded in
/// another bucket. An aborted attempt retains neither pointer nor receipt.
pub(crate) fn allocate(write: &WriteTransaction, receipt_key: &[u8]) -> Result<u16> {
    if !matches!(receipt_key.len(), 16 | 32) {
        return Err(local::corrupt("receipt key length"));
    }
    if write.open_table(RECEIPTS)?.get(receipt_key)?.is_some() {
        return Err(local::corrupt("receipt allocation before replay check"));
    }
    let mut slots = write.open_table(SLOTS)?;
    let start = start_slot(receipt_key);
    for offset in 0..MAX_RECEIPTS {
        let slot = (start + offset) % MAX_RECEIPTS;
        let key = slot.to_be_bytes();
        if let Some(pointer) = slots.get(key)? {
            if pointer.value() == receipt_key {
                return Err(local::corrupt("receipt slot has no receipt"));
            }
        } else {
            slots.insert(key, receipt_key)?;
            return Ok(slot);
        }
    }
    Err(Error::new("receipt_limit", "receipt retention exhausted"))
}

pub(crate) fn publish<B: Binding>(
    write: &WriteTransaction,
    receipt_key: &[u8],
    receipt: &ReceiptValue<B>,
) -> Result<()> {
    let operation = receipt.result.operation_id();
    let key_matches = match receipt_key.len() {
        16 => receipt_key == operation.as_bytes(),
        32 => {
            receipt_key[..16] == *receipt.actor.as_bytes()
                && receipt_key[16..] == *operation.as_bytes()
        }
        _ => false,
    };
    if !key_matches {
        return Err(local::corrupt("receipt operation key binding"));
    }
    let slots = write.open_table(SLOTS)?;
    if receipt.slot >= MAX_RECEIPTS
        || slots
            .get(receipt.slot.to_be_bytes())?
            .is_none_or(|pointer| pointer.value() != receipt_key)
    {
        return Err(local::corrupt("receipt allocation binding"));
    }
    let mut receipts = write.open_table(RECEIPTS)?;
    if receipts.get(receipt_key)?.is_some() {
        return Err(local::corrupt("receipt overwrite"));
    }
    receipts.insert(receipt_key, local::encode(receipt)?.as_slice())?;
    Ok(())
}

/// Independent complete inventory: slot keys, unique pointers, receipt identity
/// and both directions of the bijection. Historical result truth is checked
/// separately from this structural obligation.
pub(crate) fn check<B: Binding>(read: &ReadTransaction, secured: bool) -> Result<u16> {
    let slots = read.open_table(SLOTS)?;
    let receipts = read.open_table(RECEIPTS)?;
    let mut pointers = BTreeMap::new();
    for (index, row) in slots.iter()?.enumerate() {
        if index >= usize::from(MAX_RECEIPTS) {
            return Err(local::corrupt("receipt slot capacity"));
        }
        let (key, value) = row?;
        let slot = u16::from_be_bytes(
            key.value()
                .try_into()
                .map_err(|_| local::corrupt("receipt slot key"))?,
        );
        if slot >= MAX_RECEIPTS
            || value.value().len() != if secured { 32 } else { 16 }
            || pointers.insert(value.value().to_vec(), slot).is_some()
        {
            return Err(local::corrupt("receipt slot pointer"));
        }
    }
    let mut observed = BTreeSet::new();
    for (index, row) in receipts.iter()?.enumerate() {
        if index >= usize::from(MAX_RECEIPTS) {
            return Err(local::corrupt("receipt capacity"));
        }
        let (key, value) = row?;
        let receipt: ReceiptValue<B> = local::decode(value.value())?;
        let expected = if secured {
            [
                receipt.actor.as_bytes().as_slice(),
                receipt.result.operation_id().as_bytes().as_slice(),
            ]
            .concat()
        } else {
            receipt.result.operation_id().as_bytes().to_vec()
        };
        if key.value() != expected
            || pointers.get(key.value()) != Some(&receipt.slot)
            || !observed.insert(key.value().to_vec())
        {
            return Err(local::corrupt("receipt slot/operation bijection"));
        }
    }
    if observed.len() != pointers.len() {
        return Err(local::corrupt("orphan receipt slot"));
    }
    Ok(observed.len() as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        binding::Calculation,
        local::{CommittedValue, ReceiptKind, ReceiptResult},
        storage::Database,
    };
    use uuid::Uuid;

    struct Fixture {
        db: Database,
        path: std::path::PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("rebase-receipts-{}.redb", Uuid::new_v4()));
            let db = Database::create(&path).unwrap();
            let write = db.begin_write().unwrap();
            write.open_table(RECEIPTS).unwrap();
            write.open_table(SLOTS).unwrap();
            write.commit().unwrap();
            Self { db, path }
        }
        fn image(&self) -> Vec<Vec<crate::storage::Row>> {
            let read = self.db.begin_read().unwrap();
            [RECEIPTS, SLOTS]
                .into_iter()
                .map(|definition| {
                    read.open_table(definition)
                        .unwrap()
                        .iter()
                        .unwrap()
                        .map(|row| {
                            let (key, value) = row.unwrap();
                            (key.value().to_vec(), value.value().to_vec())
                        })
                        .collect()
                })
                .collect()
        }
        fn count(&self) -> u16 {
            check::<Calculation>(&self.db.begin_read().unwrap(), false).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
    fn receipt(operation: Uuid, slot: u16) -> ReceiptValue<Calculation> {
        ReceiptValue {
            slot,
            kind: ReceiptKind::Records,
            context: "probe".into(),
            model: "probe".into(),
            tenant: Uuid::from_u128(1),
            actor: Uuid::from_u128(2),
            request_hash: "probe".into(),
            result: ReceiptResult::Records(CommittedValue {
                operation_id: operation,
                revision: Uuid::new_v4(),
                records: vec![],
                executions: vec![],
            }),
        }
    }

    #[test]
    fn slot_collision_probes_and_partial_publication_aborts() {
        let fixture = Fixture::new();
        let mut by_start = BTreeMap::new();
        let (first, second) = (1..=u128::from(MAX_RECEIPTS) + 1)
            .find_map(|number| {
                let id = Uuid::from_u128(number);
                by_start
                    .insert(start_slot(id.as_bytes()), id)
                    .map(|prior| (prior, id))
            })
            .expect("1025 candidates must collide in 1024 slots");
        let write = fixture.db.begin_write().unwrap();
        let first_slot = allocate(&write, first.as_bytes()).unwrap();
        publish(&write, first.as_bytes(), &receipt(first, first_slot)).unwrap();
        let second_slot = allocate(&write, second.as_bytes()).unwrap();
        publish(&write, second.as_bytes(), &receipt(second, second_slot)).unwrap();
        assert_eq!(first_slot, start_slot(first.as_bytes()));
        assert_eq!(second_slot, (first_slot + 1) % MAX_RECEIPTS);
        write.commit().unwrap();
        assert_eq!(fixture.count(), 2);

        let before = fixture.image();
        let write = fixture.db.begin_write().unwrap();
        allocate(&write, Uuid::from_u128(u128::MAX).as_bytes()).unwrap();
        drop(write); // failure after the pointer write, before receipt publication
        assert_eq!(fixture.image(), before);
        assert_eq!(fixture.count(), 2);
    }

    #[test]
    fn exact_capacity_uses_last_slot_and_full_rejection_preserves_tables() {
        let fixture = Fixture::new();
        let last_free = 937;
        let write = fixture.db.begin_write().unwrap();
        for slot in 0..MAX_RECEIPTS {
            if slot == last_free {
                continue;
            }
            let id = Uuid::from_u128(10_000 + u128::from(slot));
            write
                .open_table(SLOTS)
                .unwrap()
                .insert(slot.to_be_bytes(), id.as_bytes().as_slice())
                .unwrap();
            publish(&write, id.as_bytes(), &receipt(id, slot)).unwrap();
        }
        write.commit().unwrap();
        assert_eq!(fixture.count(), MAX_RECEIPTS - 1);

        let write = fixture.db.begin_write().unwrap();
        let final_id = Uuid::from_u128(20_000);
        let slot = allocate(&write, final_id.as_bytes()).unwrap();
        assert_eq!(slot, last_free);
        publish(&write, final_id.as_bytes(), &receipt(final_id, slot)).unwrap();
        write.commit().unwrap();
        assert_eq!(fixture.count(), MAX_RECEIPTS);

        let before = fixture.image();
        let write = fixture.db.begin_write().unwrap();
        assert_eq!(
            allocate(&write, Uuid::from_u128(20_001).as_bytes())
                .unwrap_err()
                .code,
            "receipt_limit"
        );
        drop(write);
        assert_eq!(fixture.image(), before);
    }

    #[test]
    fn slot_inventory_rejects_orphan_duplicate_and_mismatched_bindings() {
        for corruption in 0..5 {
            let fixture = Fixture::new();
            let write = fixture.db.begin_write().unwrap();
            let operation = Uuid::from_u128(900);
            let slot = allocate(&write, operation.as_bytes()).unwrap();
            publish(&write, operation.as_bytes(), &receipt(operation, slot)).unwrap();
            match corruption {
                0 => {
                    write
                        .open_table(RECEIPTS)
                        .unwrap()
                        .remove(operation.as_bytes())
                        .unwrap();
                }
                1 => {
                    write
                        .open_table(SLOTS)
                        .unwrap()
                        .remove(slot.to_be_bytes())
                        .unwrap();
                }
                2 => {
                    write
                        .open_table(SLOTS)
                        .unwrap()
                        .insert(
                            ((slot + 1) % MAX_RECEIPTS).to_be_bytes(),
                            operation.as_bytes().as_slice(),
                        )
                        .unwrap();
                }
                3 => {
                    write
                        .open_table(RECEIPTS)
                        .unwrap()
                        .insert(
                            operation.as_bytes(),
                            local::encode(&receipt(operation, (slot + 1) % MAX_RECEIPTS))
                                .unwrap()
                                .as_slice(),
                        )
                        .unwrap();
                }
                4 => {
                    write
                        .open_table(SLOTS)
                        .unwrap()
                        .insert(MAX_RECEIPTS.to_be_bytes(), operation.as_bytes().as_slice())
                        .unwrap();
                }
                _ => unreachable!(),
            }
            write.commit().unwrap();
            assert_eq!(
                check::<Calculation>(&fixture.db.begin_read().unwrap(), false)
                    .unwrap_err()
                    .code,
                "corrupt_state",
                "case {corruption}"
            );
        }
    }
}
