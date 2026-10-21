use std::collections::BTreeMap;

pub type Batch = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// A point-read overlay owned by one backend transaction attempt.
/// Range overlays and conflict obligations are intentionally outside this proof.
#[derive(Default)]
pub struct Overlay {
    before: Batch,
    after: Batch,
    pub reads: usize,
}

impl Overlay {
    pub fn read<E>(
        &mut self,
        key: &[u8],
        load: impl FnOnce() -> Result<Option<Vec<u8>>, E>,
    ) -> Result<Option<Vec<u8>>, E> {
        if let Some(value) = self.after.get(key).or_else(|| self.before.get(key)) {
            return Ok(value.clone());
        }
        let value = load()?;
        self.reads += 1;
        self.before.insert(key.to_vec(), value.clone());
        Ok(value)
    }

    pub fn stage<E>(
        &mut self,
        key: &[u8],
        value: Option<Vec<u8>>,
        load: impl FnOnce() -> Result<Option<Vec<u8>>, E>,
    ) -> Result<(), E> {
        self.read(key, load)?;
        self.after.insert(key.to_vec(), value);
        Ok(())
    }

    /// Original reads remain conceptually protected by the owning transaction.
    /// Omitting a no-op business write must not omit a separately required guard.
    pub fn finish(self) -> Batch {
        self.after
            .into_iter()
            .filter(|(key, value)| self.before.get(key) != Some(value))
            .collect()
    }
}
