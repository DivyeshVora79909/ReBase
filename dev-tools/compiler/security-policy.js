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
  const target = includeReaders ? `(${prefix}read_by ?? ${prefix}owned_by)` : `${prefix}owned_by`;
  return `(${actor} != NONE AND ${prefix}tenant = ${actor}.tenant AND fn::rebase::can_access(${actor}, ${target}))`;
}

function tableSelectPredicate(table, options = {}) {
  return `'${table}_select' IN $auth.permissions AND ${readPredicate({
    ...options,
    includeReaders: options.selectPolicy !== "owner",
  })}`;
}

module.exports = { actorAccess, ownerPredicate, readPredicate, tableSelectPredicate };
