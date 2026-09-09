function readerFieldTargets(field, systemTables) {
  const targets = field?.recordType?.targets || [];
  if (!targets.length) return [];
  // Derived record shadows are calculation inputs, not authorization edges.
  // A schema author can opt a field into reader inheritance explicitly with
  // @rebase-readers; ordinary VALUE/COMPUTED fields remain opaque to the
  // reader graph even when their type is a record.
  if (field.derived && !field.inheritReaders) return [];
  if (targets.some((target) => systemTables.has(target))) return [];
  if (field.recordType.isArray && !field.inheritReaders) return [];
  return targets;
}

function contributesReaders(field, systemTables) {
  return readerFieldTargets(field, systemTables).length > 0;
}

module.exports = { contributesReaders, readerFieldTargets };
