'use strict';
const assert = require('node:assert/strict');
const { parseSchema } = require('../../src/schema');
const { resolveTreeContract } = require('../../src/tree-contract');

function main() {
  const root = "@rebase-tree-root @rebase-tree-key int";
  const node = "@rebase-tree-node @rebase-tree-key int @rebase-tree-owner board.rb_rank";
  const source = `
    DEFINE TABLE board SCHEMAFULL;
    DEFINE FIELD rb_rank ON board TYPE object COMMENT '${root}';
    DEFINE TABLE fact SCHEMAFULL COMMENT '@rebase-members fn::fixture::members';
    DEFINE FIELD rb_rank ON fact TYPE option<object> COMMENT '${node}';
  `;
  const resolve = sql => resolveTreeContract(parseSchema(sql, ''));
  const contract = resolve(source);
  assert.equal(contract.roots[0].keyType, 'int');
  assert.deepEqual(contract.nodes[0].owners.map(owner => owner.name), ['board.rb_rank']);
  const cases = [
    ['missing root key', s => s.replace(root, '@rebase-tree-root'), /requires explicit/],
    ['missing node key', s => s.replace(node, node.replace(' @rebase-tree-key int', '')), /requires explicit/],
    ['missing owner', s => s.replace(' @rebase-tree-owner board.rb_rank', ''), /explicit.*owner/],
    ['missing key argument', s => s.replace(root, '@rebase-tree-root @rebase-tree-key'), /requires a value/],
    ['missing owner argument', s => s.replace('owner board.rb_rank', 'owner'), /requires a value/],
    ['datetime alias', s => s.replace(root, root.replace('int', 'temporal')), /expected datetime or int/],
    ['int alias', s => s.replace(root, root.replace('int', 'ordinal')), /expected datetime or int/],
    ['deferred decimal', s => s.replace(root, root.replace('int', 'decimal')), /expected datetime or int/],
    ['incompatible keys', s => s.replace(root, root.replace('int', 'datetime')), /incompatible/],
    ['unknown table', s => s.replace('owner board.', 'owner missing.'), /unknown tree owner/],
    ['unknown slot', s => s.replace('owner board.rb_rank', 'owner board.rb_missing'), /unknown tree owner/],
    ['malformed target', s => s.replace('owner board.rb_rank', 'owner board.*'), /requires table.root_field/],
    ['duplicate target', s => s.replace(node, node + ' @rebase-tree-owner board.rb_rank'), /duplicate.*owner/],
    ['duplicate key', s => s.replace(root, root + ' @rebase-tree-key int'), /key only once/],
    ['duplicate root', s => s.replace(root, root + ' @rebase-tree-root'), /root only once/],
    ['duplicate node', s => s.replace(node, node + ' @rebase-tree-node'), /node only once/],
    ['root and node', s => s.replace(root, root + ' @rebase-tree-node'), /both.*root and node/],
    ['unknown marker', s => s.replace(root, root + ' @rebase-tree-comparator numeric'), /unknown @rebase-tree/],
    ['key without storage', s => s.replace(root, '@rebase-tree-key int'), /requires @rebase-tree-root/],
    ['owner on root', s => s.replace(root, root + ' @rebase-tree-owner board.rb_rank'), /belongs on a node/],
    ['table marker', s => s.replace('board SCHEMAFULL;', `board SCHEMAFULL COMMENT '${root}';`), /belong on fields/],
    ['missing member function', s => s.replace("COMMENT '@rebase-members fn::fixture::members'", ''), /requires @rebase-members/],
    ['missing node', s => s.replace(`COMMENT '${node}'`, ''), /requires at least one tree node/],
    ['duplicate field', s => s + `DEFINE FIELD rb_rank ON board TYPE object COMMENT '${root}';`, /declare tree storage only once/],
    ['overwritten field', s => s + 'DEFINE FIELD OVERWRITE rb_rank ON board TYPE object;', /declare tree storage only once/],
    ['nested node', s => s.replace('rb_rank ON fact', 'nested.rb_rank ON fact'), /top-level named field/],
    ['wrong storage type', s => s.replace('TYPE option<object>', 'TYPE object'), /requires TYPE option<object>/],
    ['source value on storage', s => s.replace('TYPE option<object>', 'TYPE option<object> VALUE $value'), /tree storage is generated/],
    ['source default on storage', s => s.replace('TYPE object COMMENT', 'TYPE object DEFAULT {} COMMENT'), /tree storage is generated/],
    ['source assertion on storage', s => s.replace('TYPE object COMMENT', 'TYPE object ASSERT true COMMENT'), /tree storage is generated/],
  ];
  for (const [label, change, expected] of cases) assert.throws(() => resolve(change(source)), expected, label);
  console.log(`PASS explicit tree contracts and ${cases.length} invalid declaration diagnostics`);
  return cases.length;
}

if (require.main === module) main();
module.exports = { main };
