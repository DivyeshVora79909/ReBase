function actorAccess(actor = "$auth") {
  return `${actor}.z_access_index`;
}

function ownerPredicate({ actor = "$auth", row = "", includeSelf = true } = {}) {
  const owner = row ? `${row}.owned_by` : "owned_by";
  const access = actorAccess(actor);
  return includeSelf ? `<string>${owner} IN ${access}` : `(${owner} = ${actor} OR ${owner} IN ${actor}.dominates)`;
}

function readPredicate({ actor = "$auth", row = "", includeReaders = true } = {}) {
  const prefix = row ? `${row}.` : "";
  const owner = ownerPredicate({ actor, row, includeSelf: true });
  const visibility = `!!${prefix}visibility`;
  const readers = includeReaders ? ` OR ${prefix}readers_index CONTAINS <string>${actor}.id` : "";
  return `(${visibility}${readers} OR ${owner})`;
}

function tableSelectPredicate(table, options = {}) {
  return `'${table}_select' IN $auth.permissions AND ${readPredicate({
    ...options,
    includeReaders: options.selectPolicy !== "owner",
  })}`;
}

module.exports = { actorAccess, ownerPredicate, readPredicate, tableSelectPredicate };
