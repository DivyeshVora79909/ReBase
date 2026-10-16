'use strict';

const { extractClauseExpression, sqlCode } = require('./surql');
const { parseSchema } = require('./schema');

const OPERATIONS = Object.freeze(['range', 'latest', 'next', 'exact']);
const PREFIX = '__rebase_dependency_';
const ROOT_PREFIX = '__rebase_dependents_';
const quote = value => `'${value.replaceAll("'", "\\'")}'`;
const sqlObject = value => `{ ${Object.entries(value).map(([key, item]) => `${key}: ${quote(item)}`).join(', ')} }`;

function resolveDependencies(schema) {
  const declarations = [];
  const groups = new Map();
  for (const table of schema.tables.values()) {
    for (const field of table.fields.values()) {
      const name = `${table.name}.${field.name}`;
      if (field.name.startsWith(PREFIX) || field.name.startsWith(ROOT_PREFIX)) {
        throw new Error(`${name}: field name is reserved for generated dependency indexes`);
      }
      const markers = [...(field.comment || '').matchAll(/@rebase-dependency([\w-]*)/g)].map(match => match[1]);
      for (const marker of markers) {
        if (!['', '-source', '-validate'].includes(marker)) throw new Error(`${name}: unknown @rebase-dependency${marker}`);
      }
      if (!markers.length) continue;
      if (field.auditPolicy?.marked) {
        throw new Error(`${name}: dependency descriptors are private maintained state and cannot be audited`);
      }
      const operations = [...field.comment.matchAll(/@rebase-dependency\s+([\w-]+)/g)].map(match => match[1]);
      if (markers.filter(marker => marker === '').length !== 1 || operations.length !== 1 || !OPERATIONS.includes(operations[0])) {
        throw new Error(`${name}: declare one @rebase-dependency ${OPERATIONS.join(', ')}`);
      }
      const type = extractClauseExpression(field.definition, 'TYPE', ['DEFAULT', 'VALUE', 'ASSERT', 'REFERENCE', 'READONLY', 'PERMISSIONS', 'COMMENT', 'FLEXIBLE']);
      if (type?.replace(/\s/g, '') !== 'option<object>' || field.computed || !field.derived || field.treeRoot || field.treeNode) {
        throw new Error(`${name}: dependency queries require TYPE option<object> FLEXIBLE and a pure VALUE`);
      }
      if (!/\bFLEXIBLE\b/i.test(sqlCode(field.definition))) throw new Error(`${name}: dependency query objects require FLEXIBLE`);
      const sourceNames = [...field.comment.matchAll(/@rebase-dependency-source\s+([A-Za-z_][\w]*\.[A-Za-z_][\w]*)/g)].map(match => match[1]);
      if (!sourceNames.length || sourceNames.length !== markers.filter(marker => marker === '-source').length
          || new Set(sourceNames).size !== sourceNames.length) {
        throw new Error(`${name}: declare distinct @rebase-dependency-source table.root_field targets`);
      }
      const kind = operations[0];
      const sources = sourceNames.map(sourceName => {
        const [target, slot] = sourceName.split('.');
        const root = schema.tables.get(target)?.fields.get(slot);
        if (!root?.treeRoot) throw new Error(`${name}: unknown dependency source root ${sourceName}`);
        const key = /@rebase-tree-key\s+([^\s@]+)/.exec(root.comment)?.[1];
        const index = `${ROOT_PREFIX}${slot}_${kind}`;
        const group = { table: target, slot, index, kind, key };
        groups.set(`${sourceName}/${kind}`, group);
        return group;
      });
      if (new Set(sources.map(source => source.key)).size !== 1) throw new Error(`${name}: dependency sources must use the same key types`);
      field.reactive = true;
      field.privateDependency = true;
      field.dependency = { name, table: table.name, field: field.name, node: `${PREFIX}${field.name}`, kind,
        phase: markers.includes('-validate') ? 'validate' : 'refresh', sources,
        location: field.location || null };
      declarations.push(field.dependency);
    }
  }
  // Generated index slots use the same typed tree contract. Their tuple contains
  // a source-tree boundary (including an empty tuple for negative infinity).
  const inject = (tableName, fieldName, definition, properties) => {
    const table = schema.tables.get(tableName);
    if (table.fields.has(fieldName)) throw new Error(`${tableName}.${fieldName}: duplicate generated dependency field`);
    const field = parseSchema(definition, '').tables.get(tableName).fields.get(fieldName);
    Object.assign(field, { internal: true, system: true }, properties);
    table.fields.set(fieldName, field);
  };
  for (const group of groups.values()) {
    inject(group.table, group.index, `DEFINE FIELD ${group.index} ON ${group.table} TYPE object PERMISSIONS NONE
      COMMENT '@rebase-tree-root @rebase-tree-key tuple @rebase-tree-duplicates';`, { dependencyIndex: true });
  }
  for (const declaration of declarations) {
    inject(declaration.table, declaration.node, `DEFINE FIELD ${declaration.node} ON ${declaration.table} TYPE option<object> PERMISSIONS NONE
      COMMENT '@rebase-tree-node @rebase-tree-key tuple @rebase-tree-no-reader ${declaration.sources.map(source => `@rebase-tree-owner ${source.table}.${source.index}`).join(' ')}';`,
    { dependencyIndex: true });
  }
  return { declarations, groups: [...groups.values()] };
}

function dependencyExpression(expression, field, live) {
  if (!field.dependency) return expression;
  const { kind, phase, sources } = field.dependency;
  const targets = sources.map(({ table, slot, index }) => sqlObject({ table, slot, index }));
  return `fn::dependency::resolve((${expression}), '${kind}', '${phase}', [${targets.join(', ')}], ${live})`;
}

function dependencyAdapters(schema, model, routes) {
  const { declarations, groups } = model;
  const byTable = new Map();
  for (const declaration of declarations) {
    if (!byTable.has(declaration.table)) byTable.set(declaration.table, []);
    byTable.get(declaration.table).push(declaration);
  }
  const indexedTables = [...new Set(groups.map(group => group.table))];
  const fencedTables = [...new Set([...indexedTables, ...routes.map(route => route.target)])].sort();
  for (const table of fencedTables) {
    if (schema.tables.get(table).fields.has('rebase_dependency_revision')) {
      throw new Error(`${table}.rebase_dependency_revision: field name is reserved for source fences`);
    }
  }
  const definitions = fencedTables.map(table => `DEFINE FIELD OVERWRITE rebase_dependency_revision ON ${table} TYPE int DEFAULT 0
VALUE IF $before = NONE THEN 0 ELSE $value END PERMISSIONS FOR select NONE FOR create WHERE true FOR update NONE;`).join('\n');
  const bindings = [...byTable].map(([table, fields]) => `IF record::tb($row.id) = '${table}' {
    RETURN [${fields.map(field => `{ reader: $row.id, link: { rid: $row.id, slot: '${field.node}' }, field: '${field.field}', query: $row.${field.field} }`).join(',\n')}]
        .filter(|$binding| $binding.query != NONE AND ($phase = NONE OR $binding.query.phase = $phase));
};`).join('\n');
  const binding = [...byTable].map(([table, fields]) => `IF record::tb($link.rid) = '${table}' {
    ${fields.map(field => `IF $link.slot = '${field.node}' { RETURN {
        reader: $link.rid, link: $link, field: '${field.field}', query: (SELECT VALUE ${field.field} FROM ONLY $link.rid)
    }; };`).join('\n')}
};`).join('\n');
  const sourceGroups = indexedTables.map(table => `IF record::tb($rid) = '${table}' {
    RETURN [${groups.filter(group => group.table === table).map(({ slot, index, kind }) => sqlObject({ slot, index, kind })).join(', ')}];
};`).join('\n');
  const slots = [...byTable].map(([table, fields]) => `IF record::tb($rid) = '${table}' {
    RETURN [${fields.map(field => quote(field.node)).join(', ')}];
};`).join('\n');
  const ownerChanged = indexedTables.map(table => {
    const fields = [...schema.tables.get(table).fields.values()].filter(field => !field.system && !field.treeRoot
      && !field.treeNode && !field.computed && !field.privateDependency).map(field => field.name);
    return `IF record::tb($after.id) = '${table}' { RETURN ${[...new Set([...fields, 'owned_by'])].map(field => `$before.${field} != $after.${field}`).join(' OR ') || 'false'}; };`;
  }).join('\n');
  return `${definitions}
DEFINE FUNCTION OVERWRITE fn::dependency::bindings($row: option<object>, $phase: option<string>) {
    IF $row = NONE { RETURN []; };
    ${bindings}
    RETURN [];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::dependency::binding($link: object) {
    ${binding}
    THROW 'REBASE_DEPENDENCY_SLOT';
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::dependency::groups($rid: record) {
    ${sourceGroups}
    RETURN [];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::dependency::slots($rid: record) {
    ${slots}
    RETURN [];
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::dependency::owner_changed($before: option<object>, $after: object) {
    ${ownerChanged}
    RETURN false;
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::dependency::fence_sources($row: option<object>) {
    IF $row = NONE { RETURN NONE; };
    LET $sources = array::distinct(array::concat(fn::rebase::direct_sources($row),
        fn::dependency::bindings($row, NONE).map(|$binding| $binding.query.source)));
    FOR $source IN $sources {
        LET $record = SELECT * FROM ONLY $source;
        LET $tenant = IF record::tb($source) = 'rebase_tenant' THEN $source ELSE $record.tenant END;
        IF $record = NONE OR $tenant != $row.tenant { THROW 'REBASE_DEPENDENCY_TENANT'; };
        UPDATE $source SET rebase_dependency_revision = ($record.rebase_dependency_revision ?? 0) + 1 RETURN NONE;
    };
} PERMISSIONS NONE;`;
}

module.exports = { OPERATIONS, resolveDependencies, dependencyExpression, dependencyAdapters };
