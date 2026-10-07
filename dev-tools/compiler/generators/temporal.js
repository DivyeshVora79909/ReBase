const fs = require('node:fs');
const path = require('node:path');
const { businessFields, changedFields, valueExpression, fieldSelectPolicy } = require('../fields');
const { resolveDerivedOrder } = require('../derived-order');
const { resolveTreeContract } = require('../tree-contract');
const { treeFields, treeAdapters, queryFunction } = require('./tree');
const { extractClauseExpression, mapSqlCode, sqlCode } = require('../surql');

const quote = (s) => `'${s.replaceAll("'", "\\'")}'`;
const list = (xs) => `[${xs.map(quote).join(', ')}]`;
const marked = (table, property) => [...table.fields.values()].filter((f) => f[property]);
const selectCreate = 'PERMISSIONS FOR select, create WHERE true FOR update NONE';

function dependencies(schema) {
  const routes = new Map();
  for (const table of schema.tables.values()) {
    for (const field of marked(table, 'reactive')) {
      const expression = valueExpression(field);
      if (!expression) throw new Error(`${table.name}.${field.name}: @rebase-derived requires VALUE`);
      const explicit = [...field.comment.matchAll(/@rebase-depends\s+([A-Za-z_][A-Za-z0-9_.]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_.]*)*)/g)]
        .flatMap((m) => m[1].split(/\s*,\s*/));
      const inferred = [...sqlCode(expression).matchAll(/\$this\.([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)/g)].map((m) => m[1]);
      for (const dependency of new Set([...explicit, ...inferred])) {
        const [reference, ...tail] = dependency.split('.');
        const source = table.fields.get(reference);
        if (!source?.recordType) {
          if (explicit.includes(dependency)) throw new Error(`${table.name}.${field.name}: ${reference} is not a record reference`);
          continue;
        }
        if (!tail.length || !source.recordType.targets.length || source.recordType.isArray) {
          throw new Error(`${table.name}.${field.name}: dependencies require a typed scalar reference and a consumed field`);
        }
        if (!/\bREFERENCE\b/i.test(source.definition)) throw new Error(`${table.name}.${reference}: reactive references require REFERENCE`);
        for (const target of source.recordType.targets) {
          const remote = schema.tables.get(target)?.fields.get(tail[0]);
          if (!remote && !['owned_by', 'read_by', 'tenant'].includes(tail[0])) {
            throw new Error(`${table.name}.${field.name}: unknown dependency ${target}.${tail[0]}`);
          }
          if (remote?.recordType && tail.length > 1) {
            throw new Error(`${table.name}.${field.name}: materialize ${dependency} one reference hop at a time`);
          }
          if (remote?.treeNode || remote?.treeRoot && (tail[1] !== 'summary' || table.treeMembers)) {
            throw new Error(`${table.name}.${field.name}: consume published summaries outside their contributing trees; use a prefix member for temporal rules`);
          }
          const key = `${target}/${table.name}/${reference}`;
          if (!routes.has(key)) routes.set(key, { target, table: table.name, reference, fields: new Set() });
          routes.get(key).fields.add(tail.join('.'));
        }
      }
    }
  }
  return [...routes.values()];
}

function helperName(index) {
  return `__rebase_derived_${String(index).padStart(4, '0')}`;
}

function initialDerivedExpression(field, table, helperNames) {
  const expression = valueExpression(field);
  return mapSqlCode(expression, code => code.replace(/\$this\.([A-Za-z_][A-Za-z0-9_]*)\b/g,
    (match, name) => {
      if (helperNames.get(name)) return `$this.${helperNames.get(name)}`;
      const dependency = table.fields.get(name);
      const type = extractClauseExpression(dependency?.definition || '', 'TYPE',
        ['DEFAULT', 'VALUE', 'COMPUTED', 'ASSERT', 'REFERENCE', 'READONLY', 'PERMISSIONS', 'COMMENT', 'FLEXIBLE']);
      const defaultValue = extractClauseExpression(dependency?.definition || '', 'DEFAULT',
        ['VALUE', 'COMPUTED', 'ASSERT', 'REFERENCE', 'READONLY', 'PERMISSIONS', 'COMMENT', 'FLEXIBLE']);
      const literalDefault = /^(?:NONE|NULL|true|false|-?\d+(?:\.\d+)?(?:dec|f)?|'(?:\\.|[^'\\])*'|d'(?:\\.|[^'\\])*'|[A-Za-z_][A-Za-z0-9_]*:[A-Za-z_][A-Za-z0-9_]*)$/i;
      if (defaultValue && !/^option\s*</i.test(type || '') && literalDefault.test(defaultValue)) {
        return `($this.${name} ?? (${defaultValue}))`;
      }
      return match;
    }));
}

function derivedFields(schema, derivedOrder, derivedHelpers) {
  let sql = '';
  for (const table of schema.tables.values()) {
    const fields = derivedOrder.get(table.name) || [];
    if (!fields.length) continue;
    const helperNames = derivedHelpers.get(table.name);
    fields.forEach((field, index) => {
      const name = helperNames.get(field.name);
      const type = extractClauseExpression(field.definition, 'TYPE',
        ['DEFAULT', 'VALUE', 'COMPUTED', 'ASSERT', 'REFERENCE', 'READONLY', 'PERMISSIONS', 'COMMENT', 'FLEXIBLE']);
      if (!type) throw new Error(`${table.name}.${field.name}: @rebase-derived requires an explicit TYPE`);
      const expression = initialDerivedExpression(field, table, helperNames);
      // The numbered private fields give SurrealQL a native, topologically
      // ordered CREATE path. Each formula appears once, with no interpreter.
      sql += `DEFINE FIELD OVERWRITE ${name} ON ${table.name} TYPE ${type}
VALUE IF $before = NONE THEN (${expression}) ELSE $value END
PERMISSIONS FOR select NONE FOR create WHERE true FOR update NONE COMMENT '@rebase-system';\n`;
    });
    sql += `DEFINE FIELD OVERWRITE rebase_derived_ready ON ${table.name} TYPE bool DEFAULT false
VALUE IF $before = NONE THEN false ELSE $value END ${selectCreate};\n`;
    for (const field of fields) {
      const helper = helperNames.get(field.name);
      // Topological helper fields supply initial shadows. Later values are
      // written only by the private refresh.
      sql += `ALTER FIELD ${field.name} ON ${table.name} VALUE
IF $this.rebase_derived_ready = true THEN $value ELSE $this.${helper} END
PERMISSIONS FOR select ${fieldSelectPolicy(field)} FOR create WHERE true FOR update NONE;\n`;
    }
  }
  return sql;
}

function requiredOutputContract(schema) {
  const sources = [...schema.tables.values()].filter(table => table.requiredOutputs);
  const outputs = [...schema.tables.values()].filter(table => table.managedOutput);
  if (sources.length && !outputs.length) throw new Error('Required-output recipes need at least one @rebase-managed-output table');
  if (outputs.length && !sources.length) throw new Error('@rebase-managed-output needs a source @rebase-required-outputs recipe');
  for (const output of outputs) {
    if (!/\bPERMISSIONS\s+NONE\b/i.test(output.definition || '')) {
      throw new Error(`${output.name}: @rebase-managed-output tables require PERMISSIONS NONE`);
    }
    if (output.requiredOutputs) throw new Error(`${output.name}: managed outputs cannot own another recipe in C2c`);
    const source = output.fields.get('rebase_managed_source');
    const role = output.fields.get('rebase_managed_role');
    if (!source || !/\bTYPE\s+string\b/i.test(source.definition) || !source.system) {
      throw new Error(`${output.name}.rebase_managed_source must be a string field marked @rebase-system`);
    }
    if (!role || !/\bTYPE\s+string\b/i.test(role.definition) || !role.system) {
      throw new Error(`${output.name}.rebase_managed_role must be a string field marked @rebase-system`);
    }
  }
  return { sources, outputs: managedOutputOrder(outputs) };
}

function managedOutputOrder(outputs) {
  const names = new Set(outputs.map(table => table.name));
  const prerequisites = new Map(outputs.map(table => [table.name, new Set()]));
  for (const output of outputs) {
    for (const field of output.fields.values()) {
      if (!field.recordType || !/\bREFERENCE\b/i.test(field.definition)) continue;
      for (const target of field.recordType.targets) {
        if (names.has(target)) prerequisites.get(output.name).add(target);
      }
    }
  }

  const state = new Map(), stack = [], ordered = [];
  const visit = name => {
    if (state.get(name) === 2) return;
    if (state.get(name) === 1) {
      const start = stack.indexOf(name);
      throw new Error(`Managed-output reference dependency cycle is not supported: ${[...stack.slice(start), name].join(' -> ')}`);
    }
    state.set(name, 1); stack.push(name);
    for (const prerequisite of [...prerequisites.get(name)].sort()) visit(prerequisite);
    stack.pop(); state.set(name, 2); ordered.push(name);
  };
  for (const name of [...names].sort()) visit(name);
  const tables = new Map(outputs.map(table => [table.name, table]));
  return ordered.map(name => tables.get(name));
}

function refreshExpression(expression, table, row) {
  // Traversal can reuse the outer event's document image after a nested PATCH.
  // An explicit record selection reads the transaction's latest stored shadow.
  return mapSqlCode(expression, (code) => code.replace(/\$this\.([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)/g,
    (match, reference, field) => table.fields.get(reference)?.recordType
      ? `(SELECT VALUE ${field} FROM ONLY ${row}.${reference})`
      : match.replaceAll('$this', row)).replaceAll('$this', row));
}

function adapters(schema, routes, trees, derivedOrder, options, systemTables, managedOutputs) {
  const tables = [...schema.tables.values()];
  let sql = treeAdapters(trees);
  sql += 'DEFINE FUNCTION OVERWRITE fn::rebase::slots($rid: record) {\n';
  for (const table of tables) {
    const slots = marked(table, 'treeNode').map((f) => f.name);
    if (slots.length) sql += `IF record::tb($rid) = '${table.name}' { RETURN ${list(slots)}; };\n`;
  }
  // Pure schema metadata is also used by the caller's generated VALUE fields.
  sql += 'RETURN []; } PERMISSIONS FULL;\n';
  // Readers follow the maintained memberships, after derived values have been
  // calculated and coalescing has selected the stored representatives.
  sql += `DEFINE FUNCTION OVERWRITE fn::rebase::tree_roots($row: object) {
${tables.map(table => {
    const slots = marked(table, 'treeNode').filter(field => !field.treeNoReader).map(field => field.name);
    return slots.length ? `IF record::tb($row.id) = '${table.name}' { RETURN array::distinct(${list(slots)}.map(|$slot| $row[$slot].owner.rid).filter(|$root| $root != NONE)); };` : '';
  }).filter(Boolean).join('\n')}
RETURN [];
} PERMISSIONS FULL;\n`;
  sql += 'DEFINE FUNCTION OVERWRITE fn::rebase::members($row: option<object>) {\nIF $row = NONE { RETURN []; };\n';
  for (const table of tables) {
    if (table.treeMembers) sql += `IF record::tb($row.id) = '${table.name}' { RETURN ${table.treeMembers}($row); };\n`;
  }
  sql += 'RETURN []; } PERMISSIONS NONE;\n';
  sql += 'DEFINE FUNCTION OVERWRITE fn::rebase::validate($row: object) {\n';
  for (const table of tables) {
    if (table.validate) sql += `IF record::tb($row.id) = '${table.name}' { ${table.validate}($row); };\n`;
  }
  sql += '} PERMISSIONS NONE;\n';
  const recipes = tables.filter(table => table.requiredOutputs);
  sql += 'DEFINE FUNCTION OVERWRITE fn::rebase::has_required_outputs($rid: record) {\n';
  sql += `RETURN record::tb($rid) IN ${recipes.length ? list(recipes.map(table => table.name)) : '[]'};\n} PERMISSIONS NONE;\n`;
  sql += 'DEFINE FUNCTION OVERWRITE fn::rebase::required_outputs($row: option<object>) {\nIF $row = NONE { RETURN []; };\n';
  for (const table of recipes) {
    sql += `IF record::tb($row.id) = '${table.name}' { RETURN ${table.requiredOutputs}($row); };\n`;
  }
  sql += 'RETURN []; } PERMISSIONS NONE;\n';
  sql += 'DEFINE FUNCTION OVERWRITE fn::rebase::is_managed_output_table($name: string) {\n';
  sql += `RETURN $name IN ${managedOutputs.length ? list(managedOutputs.map(table => table.name)) : '[]'};\n} PERMISSIONS NONE;\n`;
  sql += 'DEFINE FUNCTION OVERWRITE fn::rebase::order_required_outputs($outputs: array) {\n';
  if (managedOutputs.length) {
    const ordered = managedOutputs.map(table => `$outputs.filter(|$output| record::tb($output.id) = '${table.name}')`);
    sql += `RETURN array::concat(${ordered.join(', ')});\n`;
  } else sql += 'RETURN [];\n';
  sql += '} PERMISSIONS NONE;\n';
  sql += 'DEFINE FUNCTION OVERWRITE fn::rebase::managed_outputs($source: record) {\n';
  if (managedOutputs.length) {
    managedOutputs.forEach((table, index) => {
      sql += `LET $outputs_${index} = SELECT * FROM ${table.name} WHERE rebase_managed_source = <string>$source;\n`;
    });
    sql += `RETURN array::concat(${managedOutputs.map((_, index) => `$outputs_${index}`).join(', ')});\n`;
  } else sql += 'RETURN [];\n';
  sql += '} PERMISSIONS NONE;\n';
  sql += 'DEFINE FUNCTION OVERWRITE fn::rebase::managed_outputs_reverse($source: record) {\n';
  if (managedOutputs.length) {
    const reverse = [...managedOutputs].reverse();
    reverse.forEach((table, index) => {
      sql += `LET $outputs_${index} = SELECT * FROM ${table.name} WHERE rebase_managed_source = <string>$source;\n`;
    });
    sql += `RETURN array::concat(${reverse.map((_, index) => `$outputs_${index}`).join(', ')});\n`;
  } else sql += 'RETURN [];\n';
  sql += '} PERMISSIONS NONE;\n';
  sql += 'DEFINE FUNCTION OVERWRITE fn::rebase::derive($row: object) {\n';
  for (const table of tables) {
    const fields = derivedOrder.get(table.name) || [];
    if (!fields.length) continue;
    sql += `IF record::tb($row.id) = '${table.name}' {\nLET $r0 = $row;\n`;
    fields.forEach((field, i) => {
      const input = valueExpression(field);
      for (const match of sqlCode(input).matchAll(/\$this\.([A-Za-z_][A-Za-z0-9_]*)/g)) {
        const local = table.fields.get(match[1]);
        if (local?.treeRoot || local?.treeNode) {
          throw new Error(`${table.name}.${field.name}: stored shadows cannot consume local tree storage; use a prefix query or a COMPUTED publication field`);
        }
      }
      const expression = refreshExpression(input, table, `$r${i}`);
      if (/\$(?:value|before|after|input)\b/.test(sqlCode(expression))) throw new Error(`${table.name}.${field.name}: derived VALUE must be a pure expression of $this and declared references`);
      sql += `LET $r${i + 1} = object::extend($r${i}, { ${field.name}: (${expression}) });\n`;
    });
    sql += `RETURN object::extend(object::from_entries(${list(fields.map((f) => f.name))}.map(|$k| [$k, $r${fields.length}[$k]])), { rebase_derived_ready: true });\n};\n`;
  }
  sql += 'RETURN {}; } PERMISSIONS NONE;\n';
  sql += 'DEFINE FUNCTION OVERWRITE fn::rebase::dependents($before: option<object>, $after: option<object>) {\nLET $rid = $after.id ?? $before.id;\n';
  const byTarget = new Map();
  for (const route of routes) {
    if (!byTarget.has(route.target)) byTarget.set(route.target, []);
    byTarget.get(route.target).push(route);
  }
  for (const [target, entries] of byTarget) {
    const sources = entries.map((entry) => `IF ${changedFields(entry.fields)} THEN $rid<~(${entry.table} FIELD ${entry.reference}) ELSE [] END`);
    sql += `IF record::tb($rid) = '${target}' { RETURN array::distinct(array::flatten([${sources.join(',\n')}])); };\n`;
  }
  sql += 'RETURN []; } PERMISSIONS NONE;\n';
  return sql;
}

function events(schema, routes, systemTables) {
  const targets = new Set(routes.map((r) => r.target));
  let sql = '';
  for (const table of schema.tables.values()) {
    if (systemTables.has(table.name) && !targets.has(table.name) && !table.treeMembers
        && !marked(table, 'treeRoot').length && !table.validate) continue;
    if (!table.treeMembers && !table.validate && !table.requiredOutputs && !table.managedOutput
        && !marked(table, 'reactive').length && !targets.has(table.name) && !marked(table, 'treeRoot').length) continue;
    const nativeOutputs = routes.filter((r) => r.target === table.name).flatMap((r) => [...r.fields]).filter((name) => {
      const field = table.fields.get(name.split('.')[0]);
      return !field?.reactive && !field?.treeRoot && !field?.treeNode;
    });
    const changed = changedFields([...businessFields(table), ...nativeOutputs, 'owned_by']);
    // Use current node summaries: the public root summary is published only
    // after all required outputs settle and may still count removed children.
    // Every remaining contribution must be a cached slot on this deleted row.
    const ownSlots = list(marked(table, 'treeNode').map((field) => field.name));
    const deleteGuards = marked(table, 'treeRoot').map((field) =>
      `IF (fn::tree::load($before.${field.name}.root, { rid: $before.id, slots: $before }).summary.count ?? 0)
        != array::len(${ownSlots}.filter(|$slot| $before[$slot].owner = { rid: $before.id, slot: '${field.name}' })) { THROW 'TREE_OWNER_NOT_EMPTY'; };`).join('\n');
    const finish = 'fn::rebase::finish(fn::rebase::refresh($after.id ?? $before.id, $before_image, true));';
    const independentFinish = table.managedOutput
      ? `IF ($after.rebase_managed_source ?? $before.rebase_managed_source) = NONE { ${finish} };`
      : finish;
    sql += `DEFINE EVENT OVERWRITE rebase_refresh ON ${table.name}
WHEN $event != 'UPDATE' OR (${changed}) OR $before.system_ping != $after.system_ping THEN {
    IF $event = 'DELETE' { ${deleteGuards} };
    LET $before_image = IF $event = 'CREATE' THEN NONE ELSE $before END;
    ${independentFinish}
};\n`;
  }
  return sql;
}

function resolveTemporalModel(schema, systemTables) {
  const required = requiredOutputContract(schema);
  const trees = resolveTreeContract(schema);
  const derivedOrder = new Map([...schema.tables.values()].map(table => [table.name, resolveDerivedOrder(table)]));
  const derivedHelpers = new Map();
  for (const [tableName, fields] of derivedOrder) {
    if (!fields.length) continue;
    const names = new Map(fields.map((field, index) => [field.name, helperName(index)]));
    for (const helper of names.values()) {
      if (schema.tables.get(tableName).fields.has(helper)) {
        throw new Error(`${tableName}.${helper}: field name is reserved for generated derived values`);
      }
    }
    derivedHelpers.set(tableName, names);
  }
  const enabled = [...schema.tables.values()].some((t) => t.treeMembers || t.validate || t.requiredOutputs || t.managedOutput
    || marked(t, 'treeRoot').length || marked(t, 'reactive').length);
  const routes = dependencies(schema);
  return { trees, derivedOrder, derivedHelpers, routes, enabled, systemTables, managedOutputs: required.outputs };
}

function generateTemporal(schema, options, systemTables, resolved = resolveTemporalModel(schema, systemTables)) {
  const { trees, derivedOrder, derivedHelpers, routes, enabled, managedOutputs } = resolved;
  if (!enabled) return { sql: '', routes: [], trees, derivedOrder, derivedHelpers };
  const sourceFields = new Map();
  for (const route of routes) {
    if (!sourceFields.has(route.table)) sourceFields.set(route.table, new Set());
    sourceFields.get(route.table).add(route.reference);
  }
  const sources = [...sourceFields].map(([table, fields]) =>
    `REMOVE FIELD IF EXISTS rebase_dependency_sources.* ON ${table};\nDEFINE FIELD OVERWRITE rebase_dependency_sources ON ${table} TYPE array<record> COMPUTED array::distinct([${[...fields].map((f) => `$this.${f}`).join(', ')}]).filter(|$r| $r != NONE) PERMISSIONS NONE;`).join('\n');
  const sql = [fs.readFileSync(path.join(__dirname, '..', 'temporal.surql'), 'utf8'),
    treeFields(trees), sources, adapters(schema, routes, trees, derivedOrder, options, systemTables, managedOutputs), derivedFields(schema, derivedOrder, derivedHelpers),
    events(schema, routes, systemTables), queryFunction(trees, options)].join('\n');
  return { sql, routes, trees, derivedOrder, derivedHelpers };
}

module.exports = { generateTemporal, dependencies, resolveTemporalModel };
