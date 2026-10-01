function readerFieldTargets(field, systemTables) {
  if (field?.treeRoot || field?.treeNode || field?.system) return [];
  if (!field?.inheritReaders) return [];
  const targets = field?.recordType?.targets || [];
  if (!targets.length) return [];
  // Derived values and arrays participate only when their field is explicitly
  // marked; the marker is the complete reader-edge contract.
  if (targets.some((target) => systemTables.has(target))) return [];
  return targets;
}

function contributesReaders(field, systemTables) {
  return readerFieldTargets(field, systemTables).length > 0;
}

module.exports = { contributesReaders, readerFieldTargets };
