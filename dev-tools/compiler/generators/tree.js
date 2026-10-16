'use strict';
const { keyStorageType } = require('../tree-contract');
const { fieldSelectPolicy } = require('../fields');

const quote = value => `'${value.replaceAll("'", "\\'")}'`;
const list = values => `[${values.map(quote).join(', ')}]`;
const rootDefault = '{ height: 0, revision: 0, summary: fn::tree::empty() }';
const matches = (link, target) => `(record::tb(${link}.rid) = '${target.table}' AND ${link}.slot = '${target.slot}')`;

function summaryFields(table, field, keyType) {
  return `
DEFINE FIELD OVERWRITE ${field} ON ${table} TYPE object;
DEFINE FIELD OVERWRITE ${field}.count ON ${table} TYPE int ASSERT $value >= 0;
DEFINE FIELD OVERWRITE ${field}.first ON ${table} TYPE option<${keyType}>;
DEFINE FIELD OVERWRITE ${field}.last ON ${table} TYPE option<${keyType}>;
DEFINE FIELD OVERWRITE ${field}.interval ON ${table} TYPE option<object>;
DEFINE FIELD OVERWRITE ${field}.interval.upper ON ${table} TYPE option<array>;
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

function readNodeStatement(link, owner, variable) {
  const row = `$${variable}`;
  return `LET ${row} = IF ${link} = NONE THEN NONE ELSE (SELECT VALUE type::field(${link}.slot) FROM ONLY ${link}.rid) END;
    IF ${link} != NONE AND (${row} = NONE OR ${row}.owner = NONE
        OR ${row}.owner.rid != ${owner}.rid OR ${row}.owner.slot != ${owner}.slot) {
      THROW 'Tree read not allowed';
    };`;
}

function readHeadStatement(owner, variable) {
  return `LET $${variable} = (SELECT VALUE type::field(${owner}.slot) FROM ONLY ${owner}.rid);`;
}

function selectTraversal(prefix, owner, head, keyExpression) {
  const rootNode = `${prefix}_root_node`, node = `${prefix}_node`, left = `${prefix}_left_node`;
  return `${readNodeStatement(`${head}.root`, owner, rootNode)}
    LET $${prefix}_k = ${keyExpression};
    LET $${prefix}_selected = IF $${prefix}_k < 1 OR $${prefix}_k > ($${rootNode}.summary.count ?? 0) THEN NONE ELSE
      array::range(0, ($${rootNode}.height ?? 0) + 1).fold(
        { cursor: ${head}.root, k: $${prefix}_k, found: NONE }, |$state, $_| {
          IF $state.found != NONE OR $state.cursor = NONE { RETURN $state; };
          ${readNodeStatement('$state.cursor', owner, node)}
          ${readNodeStatement(`$${node}.left`, owner, left)}
          LET $${prefix}_left_count = $${left}.summary.count ?? 0;
          IF $state.k = $${prefix}_left_count + 1 { RETURN { cursor: NONE, k: 0, found: $state.cursor }; };
          RETURN IF $state.k <= $${prefix}_left_count
            THEN { cursor: $${node}.left, k: $state.k, found: NONE }
            ELSE { cursor: $${node}.right, k: $state.k - $${prefix}_left_count - 1, found: NONE } END;
        }).found END;
    IF $${prefix}_selected != NONE AND !fn::rebase::tree_link_select_allowed($${prefix}_selected, ${owner}) {
      THROW 'Tree read not allowed';
    };`;
}

function seekTraversal(prefix, owner, head, keyExpression, reverseExpression, inclusiveExpression) {
  const rootNode = `${prefix}_root_node`, node = `${prefix}_node`;
  return `${readNodeStatement(`${head}.root`, owner, rootNode)}
    LET $${prefix}_seek = array::range(0, ($${rootNode}.height ?? 0) + 1).fold(
      { cursor: ${head}.root, found: NONE }, |$state, $_| {
        IF $state.cursor = NONE { RETURN $state; };
        ${readNodeStatement('$state.cursor', owner, node)}
        LET $${prefix}_match = IF (${reverseExpression})
          THEN $${node}.key < ${keyExpression} OR ((${inclusiveExpression}) AND $${node}.key = ${keyExpression})
          ELSE $${node}.key > ${keyExpression} OR ((${inclusiveExpression}) AND $${node}.key = ${keyExpression}) END;
        RETURN { cursor: IF (${reverseExpression}) = $${prefix}_match THEN $${node}.right ELSE $${node}.left END,
          found: IF $${prefix}_match THEN $state.cursor ELSE $state.found END };
      });
    IF $${prefix}_seek.cursor != NONE { THROW 'AVL_SEEK_BUDGET'; };
    LET $${prefix}_found = $${prefix}_seek.found;
    IF $${prefix}_found != NONE AND !fn::rebase::tree_link_select_allowed($${prefix}_found, ${owner}) {
      THROW 'Tree read not allowed';
    };`;
}

function readOperations(trees) {
  const beforeHead = readHeadStatement('$link', 'before_head');
  const beforeRoot = readNodeStatement('$before_head.root', '$link', 'before_root_node');
  const before = `IF $operation IN ['before', 'rank'] {
        IF !fn::tree::valid_key($argument, $key_type, false) { THROW 'TREE_READ_KEY'; };
        ${beforeHead}
        ${beforeRoot}
        LET $before_result = array::range(0, ($before_root_node.height ?? 0) + 1).fold(
          { cursor: $before_head.root, summary: fn::tree::empty() }, |$state, $_| {
            IF $state.cursor = NONE { RETURN $state; };
            ${readNodeStatement('$state.cursor', '$link', 'before_node')}
            IF $before_node.key >= $argument { RETURN { cursor: $before_node.left, summary: $state.summary }; };
            ${readNodeStatement('$before_node.left', '$link', 'before_left_node')}
            LET $before_left = $before_left_node.summary ?? fn::tree::empty();
            RETURN { cursor: $before_node.right,
              summary: fn::tree::combine(fn::tree::combine($state.summary, $before_left), $before_node.value) };
          });
        IF $before_result.cursor != NONE { THROW 'AVL_PREFIX_BUDGET'; };
        RETURN IF $operation = 'rank' THEN $before_result.summary.count + 1 ELSE $before_result.summary END;
    };`;
  const range = `IF $operation = 'range' {
        IF array::len($argument) != 2 OR ($argument[0] != NONE AND !fn::tree::valid_key($argument[0], $key_type, false))
            OR ($argument[1] != NONE AND !fn::tree::valid_key($argument[1], $key_type, false)) { THROW 'TREE_READ_KEY'; };
        ${readHeadStatement('$link', 'range_head')}
        IF $argument[0] = NONE AND $argument[1] = NONE { RETURN $range_head.summary ?? fn::tree::empty(); };
        ${readNodeStatement('$range_head.root', '$link', 'range_root_node')}
        IF ($argument[0] != NONE AND $argument[1] != NONE AND $argument[0] >= $argument[1])
            OR $range_head.root = NONE { RETURN fn::tree::empty(); };
        LET $range_result = array::range(0, 6 * $range_root_node.height + 3).fold(
          { stack: [{ link: $range_head.root }], summary: fn::tree::empty() }, |$state, $_| {
            IF array::len($state.stack) = 0 { RETURN $state; };
            LET $range_task = array::last($state.stack);
            LET $range_rest = array::slice($state.stack, 0, array::len($state.stack) - 1);
            IF $range_task.value != NONE {
              RETURN { stack: $range_rest, summary: fn::tree::combine($state.summary, $range_task.value) };
            };
            ${readNodeStatement('$range_task.link', '$link', 'range_node')}
            IF $range_node = NONE OR ($argument[0] != NONE AND $range_node.summary.last < $argument[0])
                OR ($argument[1] != NONE AND $range_node.summary.first >= $argument[1]) {
              RETURN { stack: $range_rest, summary: $state.summary };
            };
            IF ($argument[0] = NONE OR $range_node.summary.first >= $argument[0])
                AND ($argument[1] = NONE OR $range_node.summary.last < $argument[1]) {
              RETURN { stack: $range_rest, summary: fn::tree::combine($state.summary, $range_node.summary) };
            };
            LET $range_own = IF ($argument[0] = NONE OR $range_node.key >= $argument[0])
                AND ($argument[1] = NONE OR $range_node.key < $argument[1])
              THEN [{ value: $range_node.value }] ELSE [] END;
            RETURN { stack: array::concat($range_rest, [{ link: $range_node.right }], $range_own, [{ link: $range_node.left }]),
              summary: $state.summary };
          });
        IF array::len($range_result.stack) != 0 { THROW 'TREE_RANGE_BUDGET'; };
        RETURN $range_result.summary;
    };`;
  const seek = `IF $operation = 'seek' {
        IF array::len($argument) < 1 OR array::len($argument) > 3
            OR (array::len($argument) > 1 AND !type::is_bool($argument[1]))
            OR (array::len($argument) > 2 AND !type::is_bool($argument[2]))
            OR !fn::tree::valid_key($argument[0], $key_type, false) { THROW 'TREE_READ_KEY'; };
        ${readHeadStatement('$link', 'seek_head')}
        ${seekTraversal('seek', '$link', '$seek_head', '$argument[0]', '$argument[1] ?? false', '$argument[2] ?? true')}
        RETURN $seek_found;
    };`;
  const find = `IF $operation = 'find' {
        IF !fn::tree::valid_key($argument, $key_type, false)
            OR array::len($argument) != array::len(string::split($key_type, ',')) { THROW 'TREE_READ_KEY'; };
        ${readHeadStatement('$link', 'find_head')}
        ${seekTraversal('find', '$link', '$find_head', '$argument', 'false', 'true')}
        IF $find_found = NONE { RETURN NONE; };
        ${readNodeStatement('$find_found', '$link', 'find_candidate_node')}
        RETURN IF fn::tree::business_key($find_candidate_node.key) = $argument THEN $find_found ELSE NONE END;
    };`;
  const select = `IF $operation = 'select' {
        IF array::len($argument) != 1 OR !type::is_int($argument[0]) { THROW 'TREE_READ_ARGUMENT'; };
        ${readHeadStatement('$link', 'select_head')}
        ${selectTraversal('select', '$link', '$select_head', '$argument[0]')}
        RETURN $select_selected;
    };`;
  const percentile = `IF $operation = 'percentile' {
        IF array::len($argument) != 1 OR !type::is_number($argument[0]) { THROW 'TREE_READ_ARGUMENT'; };
        LET $percentile_p = $argument[0];
        IF !($percentile_p >= 0 AND $percentile_p <= 1) { THROW 'TREE_PERCENTILE_RANGE'; };
        ${readHeadStatement('$link', 'percentile_head')}
        LET $percentile_k = <int>math::max([1, math::ceil($percentile_p * ($percentile_head.summary.count ?? 0))]);
        ${selectTraversal('percentile', '$link', '$percentile_head', '$percentile_k')}
        RETURN $percentile_selected;
    };`;
  const page = `IF $operation = 'page' {
        IF array::len($argument) < 1 OR array::len($argument) > 3
            OR (array::len($argument) > 2 AND !type::is_bool($argument[2])) { THROW 'TREE_READ_ARGUMENT'; };
        IF !type::is_int($argument[0]) OR $argument[0] < 1 OR $argument[0] > 200 { THROW 'TREE_PAGE_LIMIT'; };
        IF array::len($argument) > 1 AND $argument[1] != NONE AND !fn::tree::valid_key($argument[1], $key_type, false) { THROW 'TREE_READ_KEY'; };
        ${readHeadStatement('$link', 'page_head')}
        LET $page_reverse = $argument[2] ?? false;
        LET $page_after = $argument[1] ?? NONE;
        LET $page_key = IF $page_after = NONE
          THEN IF $page_reverse THEN $page_head.summary.last ELSE $page_head.summary.first END
          ELSE $page_after END;
        LET $page_inclusive = $page_after = NONE;
        ${seekTraversal('page_start', '$link', '$page_head', '$page_key', '$page_reverse', '$page_inclusive')}
        LET $page = array::range(0, $argument[0] + 1).fold({ cursor: $page_start_found, items: [] }, |$state, $_| {
          IF $state.cursor = NONE { RETURN $state; };
          IF !fn::rebase::tree_link_select_allowed($state.cursor, $link) { THROW 'Tree read not allowed'; };
          ${readNodeStatement('$state.cursor', '$link', 'page_node')}
          RETURN { cursor: IF $page_reverse THEN $page_node.prev ELSE $page_node.next END,
            items: array::append($state.items, { link: $state.cursor, key: $page_node.key }) };
        });
        LET $page_items = array::slice($page.items, 0, $argument[0]);
        RETURN { items: $page_items, revision: $page_head.revision,
          next: IF array::len($page.items) > $argument[0] THEN array::last($page_items).key ELSE NONE END };
    };`;
  return { before, range, seek, find, select, percentile, page };
}

function treeFields(trees) {
  let sql = '';
  for (const root of trees.roots) {
    const { table, slot: name, field } = root, keyType = keyStorageType(root.keyType);
    sql += `DEFINE FIELD OVERWRITE ${name} ON ${table} TYPE object DEFAULT ${rootDefault}
VALUE IF $before = NONE THEN ${rootDefault} ELSE $value END PERMISSIONS FOR select ${fieldSelectPolicy(field)} FOR create WHERE true FOR update NONE;\n`;
    sql += linkFields(table, `${name}.root`, root.nodes);
    sql += `DEFINE FIELD OVERWRITE ${name}.height ON ${table} TYPE int ASSERT $value >= 0;
DEFINE FIELD OVERWRITE ${name}.revision ON ${table} TYPE int ASSERT $value >= 0;
\n`;
    sql += summaryFields(table, `${name}.summary`, keyType);
  }
  for (const node of trees.nodes) {
    const { table, slot: name, field } = node, keyType = keyStorageType(node.keyType);
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
  const unique = trees.roots.map(root => `IF ${matches('$link', root)} { RETURN ${root.unique}; };`).join('\n');
  const coalesce = trees.roots.filter(root => !root.coalesce).map(root => matches('$link', root)).join(' OR ') || 'false';
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
  const rootReadChecks = trees.roots.map((root) => {
    return `IF ${matches('$root_link', root)} {
    -- System sessions have no record $auth. Calling the private getter makes
    -- native function permissions distinguish them from anonymous queries.
    LET $root_slot = IF $auth = NONE THEN fn::tree::get($root_link)
        ELSE (SELECT VALUE type::field($root_link.slot) FROM ONLY $root_link.rid) END;
    RETURN $root_slot != NONE;
};`;
  }).join('\n');
  const memberReadChecks = trees.nodes.map((node) => `IF ${matches('$link', node)} {
    LET $node = (SELECT VALUE type::field($link.slot) FROM ONLY $link.rid);
    RETURN $node != NONE AND $node.owner.rid = $root_link.rid
        AND $node.owner.slot = $root_link.slot
        AND fn::rebase::tree_root_select_allowed($root_link);
};`).join('\n');
  return `DEFINE FUNCTION OVERWRITE fn::rebase::root_allowed($link: object) { RETURN ${roots}; } PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::rebase::root_key_type($link: object) {
${keyTypes}
THROW 'TREE_UNKNOWN_ROOT'; } PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::rebase::root_unique($link: object) {
${unique}
THROW 'TREE_UNKNOWN_ROOT'; } PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::rebase::root_coalesces($link: object) { RETURN !(${coalesce}); } PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::rebase::tree_root_select_allowed($root_link: option<object>) {
    IF $root_link = NONE { RETURN false; };
${rootReadChecks}
    RETURN false;
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::rebase::tree_link_select_allowed($link: option<object>, $root_link: option<object>) {
    IF $link = NONE { RETURN true; };
    IF $root_link = NONE { RETURN false; };
    IF $link.rid = $root_link.rid AND $link.slot = $root_link.slot {
        RETURN fn::rebase::tree_root_select_allowed($root_link);
    };
${memberReadChecks}
    RETURN false;
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::rebase::membership_allowed($link: object, $owner: object) {
${allowed}
RETURN false; } PERMISSIONS NONE;\n`;
}

function queryFunction(trees, options) {
  if (!trees.roots.length) return '';
  const operations = readOperations(trees);
  return `DEFINE FUNCTION OVERWRITE fn::tree::intervals_from($cursor: option<object>, $owner: object, $key: array, $budget: int) {
    IF !fn::rebase::tree_root_select_allowed($owner) { THROW 'Tree read not allowed'; };
    IF $cursor = NONE { RETURN []; };
    IF $budget <= 0 { THROW 'TREE_INTERVAL_BUDGET'; };
    ${readNodeStatement('$cursor', '$owner', 'interval_node')}
    IF $interval_node.summary.interval = NONE
        OR ($interval_node.summary.interval.upper != NONE AND $interval_node.summary.interval.upper <= $key)
        OR fn::tree::business_key($interval_node.summary.first) > $key { RETURN []; };
    LET $matches = $interval_node.value.interval != NONE
        AND fn::tree::business_key($interval_node.key) <= $key
        AND ($interval_node.value.interval.upper = NONE OR $key < $interval_node.value.interval.upper);
    IF $matches AND !fn::rebase::tree_link_select_allowed($cursor, $owner) { THROW 'Tree read not allowed'; };
    RETURN array::concat(
        fn::tree::intervals_from($interval_node.left, $owner, $key, $budget - 1),
        IF $matches THEN [$cursor] ELSE [] END,
        fn::tree::intervals_from($interval_node.right, $owner, $key, $budget - 1));
} PERMISSIONS FULL;
DEFINE FUNCTION OVERWRITE fn::tree::read($owner: record, $slot: string, $operation: string, $argument: array) {
    LET $link = { rid: $owner, slot: $slot };
    IF !fn::rebase::tree_root_select_allowed($link) { THROW 'Tree read not allowed'; };
    LET $key_type = fn::rebase::root_key_type($link);
    IF $operation = 'summary' {
        IF array::len($argument) != 0 { THROW 'TREE_READ_ARGUMENT'; };
        ${readHeadStatement('$link', 'summary_head')}
        RETURN $summary_head.summary ?? fn::tree::empty();
    };
    IF $operation = 'value' {
        IF array::len($argument) != 1 { THROW 'TREE_READ_ARGUMENT'; };
        ${readNodeStatement('$argument[0]', '$link', 'value_node')}
        IF $argument[0] != NONE AND !fn::rebase::tree_link_select_allowed($argument[0], $link) { THROW 'Tree read not allowed'; };
        RETURN $value_node.value;
    };
    IF $operation = 'intervals' {
        IF !fn::tree::valid_key($argument, $key_type, false) { THROW 'TREE_READ_KEY'; };
        ${readHeadStatement('$link', 'interval_head')}
        RETURN fn::tree::intervals_from($interval_head.root, $link, $argument, $interval_head.height + 1);
    };
    ${operations.before}
    ${operations.range}
    ${operations.find}
    ${operations.seek}
    ${operations.page}
    ${operations.select}
    ${operations.percentile}
    THROW 'TREE_UNKNOWN_OPERATION';
} PERMISSIONS FULL;\n`;
}

module.exports = { treeFields, treeAdapters, queryFunction };
