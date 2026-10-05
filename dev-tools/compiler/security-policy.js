function actorAccess(actor = "$auth") {
  return `${actor}.parent_groups`;
}

function ownerPredicate({ actor = "$auth", row = "", includeSelf = true } = {}) {
  const owner = row ? `${row}.owned_by` : "owned_by";
  return includeSelf
    ? `fn::rebase::can_access(${actor}, ${owner})`
    : `(${owner} = ${actor} OR fn::rebase::dominates(${actor}, ${owner}))`;
}

function readPredicate({ actor = "$auth", row = "", includeReaders = true } = {}) {
  const prefix = row ? `${row}.` : "";
  const owner = ownerPredicate({ actor, row, includeSelf: true });
  const readers = includeReaders
    ? ` OR array::any(${prefix}readers_index ?? [], |$reader| fn::rebase::can_access(${actor}, $reader))`
    : "";
  return `(${actor} != NONE AND ${prefix}tenant = ${actor}.tenant AND (${owner}${readers}))`;
}

function tableSelectPredicate(table, options = {}) {
  return `'${table}_select' IN $auth.permissions AND ${readPredicate({
    ...options,
    includeReaders: options.selectPolicy !== "owner",
  })}`;
}

module.exports = { actorAccess, ownerPredicate, readPredicate, tableSelectPredicate };
