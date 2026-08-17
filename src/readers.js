function readerFieldTargets(field, systemTables) {
  const targets = field?.recordType?.targets || [];
  if (!targets.length) return [];
  if (targets.some((target) => systemTables.has(target))) return [];
  if (field.recordType.isArray && !field.inheritReaders) return [];
  return targets;
}

function contributesReaders(field, systemTables) {
  return readerFieldTargets(field, systemTables).length > 0;
}

module.exports = { contributesReaders, readerFieldTargets };
