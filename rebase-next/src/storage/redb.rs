//! Legacy file adapter. Typed redb codecs stay within this module.
use super::*;
use ::redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableHandle};
pub(super) struct Redb(pub ::redb::Database);
pub(super) struct Read(pub ::redb::ReadTransaction);
struct Write(::redb::WriteTransaction);
fn error(e: impl std::fmt::Display) -> StorageError {
    failure(e.to_string())
}
impl Backend for Redb {
    fn begin_read(&self) -> Result<Box<dyn ReadView>> {
        Ok(Box::new(Read(self.0.begin_read().map_err(error)?)))
    }
    fn begin_write(&self) -> Result<Box<dyn WriteView>> {
        Ok(Box::new(Write(self.0.begin_write().map_err(error)?)))
    }
}
// The two transaction types expose different table handles; keep their local
// codec dispatch together without exposing either handle to the engine.
macro_rules! readable {
    ($ty:ty) => {
        impl ReadView for $ty {
            fn table_exists(&self, spec: &TableSpec) -> Result<bool> {
                Ok(self.list_tables()?.iter().any(|n| n == &spec.name))
            }
            fn list_tables(&self) -> Result<Vec<String>> {
                self.0
                    .list_tables()
                    .map_err(error)?
                    .map(|t| Ok(t.name().to_owned()))
                    .collect()
            }
            fn len(&self, spec: &TableSpec) -> Result<u64> {
                match spec.value {
                    ValueKind::Bytes => self
                        .0
                        .open_table(::redb::TableDefinition::<&[u8], &[u8]>::new(&spec.name))
                        .map_err(error)?
                        .len()
                        .map_err(error),
                    ValueKind::U16 => self
                        .0
                        .open_table(::redb::TableDefinition::<&[u8], u16>::new(&spec.name))
                        .map_err(error)?
                        .len()
                        .map_err(error),
                }
            }
            fn get(&self, spec: &TableSpec, key: &[u8]) -> Result<Option<Vec<u8>>> {
                match spec.value {
                    ValueKind::Bytes => {
                        let table = self
                            .0
                            .open_table(::redb::TableDefinition::<&[u8], &[u8]>::new(&spec.name))
                            .map_err(error)?;
                        Ok(table.get(key).map_err(error)?.map(|v| v.value().to_vec()))
                    }
                    ValueKind::U16 => {
                        let table = self
                            .0
                            .open_table(::redb::TableDefinition::<&[u8], u16>::new(&spec.name))
                            .map_err(error)?;
                        Ok(table
                            .get(key)
                            .map_err(error)?
                            .map(|v| v.value().to_be_bytes().to_vec()))
                    }
                }
            }
            fn scan(
                &self,
                spec: &TableSpec,
                start: Bound<Vec<u8>>,
                end: Bound<Vec<u8>>,
                limit: usize,
            ) -> Result<Vec<Row>> {
                let bounds = (
                    start.as_ref().map(Vec::as_slice),
                    end.as_ref().map(Vec::as_slice),
                );
                match spec.value {
                    ValueKind::Bytes => {
                        let table = self
                            .0
                            .open_table(::redb::TableDefinition::<&[u8], &[u8]>::new(&spec.name))
                            .map_err(error)?;
                        table
                            .range::<&[u8]>(bounds)
                            .map_err(error)?
                            .take(limit)
                            .map(|row| {
                                let (k, v) = row.map_err(error)?;
                                Ok((k.value().to_vec(), v.value().to_vec()))
                            })
                            .collect()
                    }
                    ValueKind::U16 => {
                        let table = self
                            .0
                            .open_table(::redb::TableDefinition::<&[u8], u16>::new(&spec.name))
                            .map_err(error)?;
                        table
                            .range::<&[u8]>(bounds)
                            .map_err(error)?
                            .take(limit)
                            .map(|row| {
                                let (k, v) = row.map_err(error)?;
                                Ok((k.value().to_vec(), v.value().to_be_bytes().to_vec()))
                            })
                            .collect()
                    }
                }
            }
        }
    };
}
readable!(Read);
readable!(Write);
impl WriteView for Write {
    fn create_table(&mut self, spec: &TableSpec) -> Result<()> {
        match spec.value {
            ValueKind::Bytes => {
                self.0
                    .open_table(::redb::TableDefinition::<&[u8], &[u8]>::new(&spec.name))
                    .map_err(error)?;
            }
            ValueKind::U16 => {
                self.0
                    .open_table(::redb::TableDefinition::<&[u8], u16>::new(&spec.name))
                    .map_err(error)?;
            }
        }
        Ok(())
    }
    fn delete_table(&mut self, spec: &TableSpec) -> Result<bool> {
        match spec.value {
            ValueKind::Bytes => self
                .0
                .delete_table(::redb::TableDefinition::<&[u8], &[u8]>::new(&spec.name))
                .map_err(error),
            ValueKind::U16 => self
                .0
                .delete_table(::redb::TableDefinition::<&[u8], u16>::new(&spec.name))
                .map_err(error),
        }
    }
    fn put(&mut self, spec: &TableSpec, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        match spec.value {
            ValueKind::Bytes => {
                let mut t = self
                    .0
                    .open_table(::redb::TableDefinition::<&[u8], &[u8]>::new(&spec.name))
                    .map_err(error)?;
                Ok(t.insert(key, value)
                    .map_err(error)?
                    .map(|v| v.value().to_vec()))
            }
            ValueKind::U16 => {
                let value = u16::from_be_bytes(
                    value
                        .try_into()
                        .map_err(|_| failure("invalid u16 storage value"))?,
                );
                let mut t = self
                    .0
                    .open_table(::redb::TableDefinition::<&[u8], u16>::new(&spec.name))
                    .map_err(error)?;
                Ok(t.insert(key, value)
                    .map_err(error)?
                    .map(|v| v.value().to_be_bytes().to_vec()))
            }
        }
    }
    fn remove(&mut self, spec: &TableSpec, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match spec.value {
            ValueKind::Bytes => {
                let mut t = self
                    .0
                    .open_table(::redb::TableDefinition::<&[u8], &[u8]>::new(&spec.name))
                    .map_err(error)?;
                Ok(t.remove(key).map_err(error)?.map(|v| v.value().to_vec()))
            }
            ValueKind::U16 => {
                let mut t = self
                    .0
                    .open_table(::redb::TableDefinition::<&[u8], u16>::new(&spec.name))
                    .map_err(error)?;
                Ok(t.remove(key)
                    .map_err(error)?
                    .map(|v| v.value().to_be_bytes().to_vec()))
            }
        }
    }
    fn commit(self: Box<Self>) -> Result<()> {
        self.0
            .commit()
            .map_err(|error| StorageError::new("outcome_unknown", error.to_string()))
    }
}
