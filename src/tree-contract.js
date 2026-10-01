'use strict';
const { extractClauseExpression, findTopLevelKeyword } = require('./surql');

// Compile-time contracts only. No persisted registry or runtime comparator code.
const KEY_TYPES = Object.freeze({
  datetime: '[datetime, string, string]',
  int: '[int, string, string]',
});
const KNOWN_MARKERS = new Set(['root', 'node', 'key', 'owner']);

function argumentsFor(comment, marker, name) {
  const occurrences = [...comment.matchAll(new RegExp(`@rebase-tree-${marker}\\b`, 'gi'))];
  const values = [...comment.matchAll(new RegExp(`@rebase-tree-${marker}\\s+([^\\s@]+)`, 'gi'))].map(m => m[1]);
  if (occurrences.length !== values.length) throw new Error(`${name}: @rebase-tree-${marker} requires a value`);
  return values;
}

function resolveTreeContract(schema) {
  const roots = [], nodes = [];
  for (const table of schema.tables.values()) {
    if (/@rebase-tree-\w+/i.test(table.comment || '')) {
      throw new Error(`${table.name}: tree markers belong on fields, not tables`);
    }
    for (const field of table.fields.values()) {
      const name = `${table.name}.${field.name}`, comment = field.comment || '';
      const definitions = field.definitions || [field.definition];
      if (definitions.length > 1 && definitions.some(definition => /@rebase-tree-/i.test(definition))) {
        throw new Error(`${name}: declare tree storage only once`);
      }
      const markers = [...comment.matchAll(/@rebase-tree-([\w-]+)/gi)].map(m => m[1].toLowerCase());
      for (const marker of markers) {
        if (!KNOWN_MARKERS.has(marker)) throw new Error(`${name}: unknown @rebase-tree-${marker}`);
      }
      if (!markers.length) continue;
      for (const marker of ['root', 'node']) {
        if (markers.filter(value => value === marker).length > 1) throw new Error(`${name}: declare @rebase-tree-${marker} only once`);
      }
      if (!field.treeRoot && !field.treeNode) throw new Error(`${name}: tree key/owner requires @rebase-tree-root or @rebase-tree-node`);
      if (field.treeRoot && field.treeNode) throw new Error(`${name}: a field cannot be both a tree root and node`);
      const type = extractClauseExpression(field.definition, 'TYPE', ['DEFAULT', 'VALUE', 'ASSERT', 'REFERENCE', 'READONLY', 'PERMISSIONS', 'COMMENT', 'FLEXIBLE']);
      const expected = field.treeRoot ? 'object' : 'option<object>';
      if (type?.replace(/\s/g, '').toLowerCase() !== expected) throw new Error(`${name}: tree storage requires TYPE ${expected}`);
      if (field.reactive || field.computed || ['DEFAULT', 'VALUE', 'ASSERT', 'REFERENCE', 'READONLY', 'FLEXIBLE']
        .some(clause => findTopLevelKeyword(field.definition, clause) >= 0)) {
        throw new Error(`${name}: tree storage is generated; put defaults, values and validation on business fields or @rebase-validate`);
      }
      const keys = argumentsFor(comment, 'key', name).map(value => value.toLowerCase());
      if (keys.length > 1) throw new Error(`${name}: declare @rebase-tree-key only once`);
      if (!keys.length) throw new Error(`${name}: requires explicit @rebase-tree-key datetime or int`);
      const keyType = keys[0];
      if (!Object.hasOwn(KEY_TYPES, keyType)) throw new Error(`${name}: unsupported tree key '${keyType}'; expected datetime or int`);
      const owners = argumentsFor(comment, 'owner', name);
      if (new Set(owners).size !== owners.length) throw new Error(`${name}: duplicate @rebase-tree-owner target`);
      for (const owner of owners) {
        if (!/^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$/.test(owner)) {
          throw new Error(`${name}: @rebase-tree-owner requires table.root_field, received '${owner}'`);
        }
      }
      if (field.treeRoot && owners.length) throw new Error(`${name}: @rebase-tree-owner belongs on a node field`);
      if (field.treeNode && !owners.length) {
        throw new Error(`${name}: nodes require an explicit @rebase-tree-owner table.root_field`);
      }
      if (field.treeNode && !table.treeMembers) throw new Error(`${table.name} requires @rebase-members fn::...`);
      (field.treeRoot ? roots : nodes).push({ name, table: table.name, slot: field.name, field, keyType, ownerNames: owners });
    }
    if (table.treeMembers && !nodes.some(node => node.table === table.name)) throw new Error(`${table.name}: @rebase-members requires at least one tree node field`);
  }
  if (!roots.length && !nodes.length) return { roots, nodes };
  if (!roots.length || !nodes.length) throw new Error('Trees require both owner and membership fields');
  const byName = new Map(roots.map(root => [root.name, root]));
  for (const node of nodes) {
    node.owners = node.ownerNames.map(name => {
      const root = byName.get(name);
      if (!root) throw new Error(`${node.name}: unknown tree owner '${name}'`);
      if (root.keyType !== node.keyType) throw new Error(`${node.name}: ${node.keyType} key is incompatible with ${name} (${root.keyType})`);
      return root;
    });
  }
  for (const root of roots) {
    root.nodes = nodes.filter(node => node.owners.includes(root));
    if (!root.nodes.length) throw new Error(`${root.name}: no membership slot targets this root`);
  }
  for (const node of nodes) {
    node.peers = nodes.filter(peer => peer.owners.some(owner => node.owners.includes(owner)));
  }
  return { roots, nodes };
}

module.exports = { KEY_TYPES, resolveTreeContract };
