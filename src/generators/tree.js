'use strict';
const { KEY_TYPES } = require('../tree-contract');
const { fieldSelectPolicy } = require('../fields');
const { tableSelectPredicate } = require('../security-policy');

const quote = value => `'${value.replaceAll("'", "\\'")}'`;
const list = values => `[${values.map(quote).join(', ')}]`;
const rootDefault = '{ height: 0, revision: 0, refreshing: false, summary: fn::tree::empty() }';
const matches = (link, target) => `(record::tb(${link}.rid) = '${target.table}' AND ${link}.slot = '${target.slot}')`;

function summaryFields(table, field, keyType) {
  return `
DEFINE FIELD OVERWRITE ${field} ON ${table} TYPE object;
DEFINE FIELD OVERWRITE ${field}.count ON ${table} TYPE int ASSERT $value >= 0;
DEFINE FIELD OVERWRITE ${field}.dependents ON ${table} TYPE int ASSERT $value >= 0 AND $value <= $this.${field}.count;
DEFINE FIELD OVERWRITE ${field}.first ON ${table} TYPE option<${keyType}>;
DEFINE FIELD OVERWRITE ${field}.last ON ${table} TYPE option<${keyType}>;
DEFINE FIELD OVERWRITE ${field}.measures ON ${table} TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE ${field}.measures.* ON ${table} TYPE { sum: decimal, min_prefix: decimal, max_prefix: decimal, min: decimal, max: decimal, boundary_min: option<decimal>, boundary_max: option<decimal>, instant_min: decimal, instant_max: decimal };
DEFINE FIELD OVERWRITE ${field}.tags ON ${table} TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE ${field}.tags.* ON ${table} TYPE { value: record | string | int | bool, uniform: bool };
DEFINE FIELD OVERWRITE ${field}.spans ON ${table} TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE ${field}.spans.* ON ${table} TYPE { min: datetime, max: datetime };
`;
}

function linkFields(table, field, targets, optional = true) {
  // Keep exact table/slot pairs without a deep OR expression per slot: large
  // composed profiles otherwise exhaust SurrealDB's computation depth mid-write.
  const byTable = new Map();
  for (const target of targets) {
    if (!byTable.has(target.table)) byTable.set(target.table, new Set());
    byTable.get(target.table).add(target.slot);
  }
  const pairs = [...byTable].map(([name, slots]) => `(record::tb($value.rid) = '${name}' AND $value.slot IN ${list([...slots])})`);
  const type = `{ rid: record<${[...byTable.keys()].join(' | ')}>, slot: string }`;
  return `DEFINE FIELD OVERWRITE ${field} ON ${table} TYPE ${optional ? `option<${type}>` : type}
ASSERT ${optional ? '$value = NONE OR ' : ''}(${pairs.join(' OR ')});\n`;
}

function treeFields(trees) {
  let sql = '';
  for (const root of trees.roots) {
    const { table, slot: name, field } = root, keyType = KEY_TYPES[root.keyType];
    sql += `DEFINE FIELD OVERWRITE ${name} ON ${table} TYPE object DEFAULT ${rootDefault}
VALUE IF $before = NONE THEN ${rootDefault} ELSE $value END PERMISSIONS FOR select ${fieldSelectPolicy(field)} FOR create WHERE true FOR update NONE;\n`;
    sql += linkFields(table, `${name}.root`, root.nodes);
    sql += `DEFINE FIELD OVERWRITE ${name}.height ON ${table} TYPE int ASSERT $value >= 0;
DEFINE FIELD OVERWRITE ${name}.revision ON ${table} TYPE int ASSERT $value >= 0;
DEFINE FIELD OVERWRITE ${name}.refreshing ON ${table} TYPE bool;
DEFINE FIELD OVERWRITE ${name}.dirty ON ${table} TYPE option<${keyType}>;
DEFINE FIELD OVERWRITE ${name}.cursor ON ${table} TYPE option<${keyType}>;\n`;
    sql += summaryFields(table, `${name}.summary`, keyType);
  }
  for (const node of trees.nodes) {
    const { table, slot: name, field } = node, keyType = KEY_TYPES[node.keyType];
    sql += `DEFINE FIELD OVERWRITE ${name} ON ${table} TYPE option<object> PERMISSIONS FOR select ${fieldSelectPolicy(field)} FOR create, update NONE;\n`;
    sql += linkFields(table, `${name}.owner`, node.owners, false);
    sql += linkFields(table, `${name}.parent`, [...node.owners, ...node.peers], false);
    for (const side of ['left', 'right', 'prev', 'next']) sql += linkFields(table, `${name}.${side}`, node.peers);
    sql += `DEFINE FIELD OVERWRITE ${name}.key ON ${table} TYPE ${keyType};
DEFINE FIELD OVERWRITE ${name}.height ON ${table} TYPE int ASSERT $value >= 1;\n`;
    sql += summaryFields(table, `${name}.value`, keyType);
    sql += summaryFields(table, `${name}.summary`, keyType);
  }
  return sql;
}

function treeAdapters(trees) {
  const roots = trees.roots.map(root => matches('$link', root)).join(' OR ') || 'false';
  const keyTypes = trees.roots.map(root => `IF ${matches('$link', root)} { RETURN '${root.keyType}'; };`).join('\n');
  // Group by source table so membership checks do not test every source slot.
  const byTable = new Map();
  for (const node of trees.nodes) {
    if (!byTable.has(node.table)) byTable.set(node.table, []);
    byTable.get(node.table).push(node);
  }
  const allowed = [...byTable].map(([table, nodes]) => {
    const slots = nodes.map(node => `($link.slot = '${node.slot}' AND (${node.owners.map(root => matches('$owner', root)).join(' OR ')}))`);
    return `IF record::tb($link.rid) = '${table}' { RETURN ${slots.join(' OR ')}; };`;
  }).join('\n');
  return `DEFINE FUNCTION OVERWRITE fn::rebase::root_allowed($link: object) { RETURN ${roots}; } PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::rebase::root_key_type($link: object) {
${keyTypes}
THROW 'TREE_UNKNOWN_ROOT'; } PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::rebase::membership_allowed($link: object, $owner: object) {
${allowed}
RETURN false; } PERMISSIONS NONE;\n`;
}

function queryFunction(trees, options) {
  if (!trees.roots.length) return '';
  const checks = trees.roots.map(root => {
    const predicate = tableSelectPredicate(root.table, { selectPolicy: options.selectPolicy })
      .replace(/\b(visibility|readers_index|owned_by)\b/g, '$owner.$1');
    return `(record::tb($owner) = '${root.table}' AND $slot = '${root.slot}' AND (${predicate}))`;
  });
  return `DEFINE FUNCTION OVERWRITE fn::tree::read($owner: record, $slot: string, $operation: string, $argument: array) {
    IF $auth != NONE AND !(${checks.join(' OR ')}) { THROW 'Tree read not allowed'; };
    LET $link = { rid: $owner, slot: $slot };
    LET $key_type = fn::rebase::root_key_type($link);
    IF $operation = 'summary' {
        IF array::len($argument) != 0 { THROW 'TREE_READ_ARGUMENT'; };
        RETURN fn::tree::get($link).summary;
    };
    IF $operation IN ['before', 'rank'] {
        IF !fn::tree::valid_key($argument, $key_type, false) { THROW 'TREE_READ_KEY'; };
        LET $prefix = fn::tree::before($link, $argument);
        RETURN IF $operation = 'rank' THEN $prefix.count + 1 ELSE $prefix END;
    };
    IF $operation = 'range' {
        IF array::len($argument) != 2 OR !fn::tree::valid_key($argument[0], $key_type, false)
            OR !fn::tree::valid_key($argument[1], $key_type, false) { THROW 'TREE_READ_KEY'; };
        RETURN fn::tree::range($link, $argument[0], $argument[1]);
    };
    IF $operation = 'select' {
        IF array::len($argument) != 1 OR !type::is_int($argument[0]) { THROW 'TREE_READ_ARGUMENT'; };
        RETURN fn::tree::select($link, $argument[0], false);
    };
    IF $operation = 'percentile' {
        IF array::len($argument) != 1 OR !type::is_number($argument[0]) { THROW 'TREE_READ_ARGUMENT'; };
        LET $p = $argument[0];
        IF !($p >= 0 AND $p <= 1) { THROW 'TREE_PERCENTILE_RANGE'; };
        LET $n = fn::tree::get($link).summary.count;
        RETURN fn::tree::select($link, <int>math::max([1, math::ceil($p * $n)]), false);
    };
    THROW 'TREE_UNKNOWN_OPERATION';
} PERMISSIONS WHERE $auth != NONE;\n`;
}

module.exports = { treeFields, treeAdapters, queryFunction };
