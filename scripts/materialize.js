function identifier(value, label) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value || "")) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
  return value;
}

function parsePath(value) {
  if (typeof value !== "string" || !value.trim())
    throw new Error("Relation paths must be non-empty strings");
  return value.split(".").map((part) => ({
    key: identifier(part.replace(/\[\]$/, ""), "path segment"),
    array: part.endsWith("[]"),
  }));
}

function splitPath(value) {
  const [dataset, ...tokens] = parsePath(value);
  if (!dataset || dataset.array || !tokens.length)
    throw new Error(`Relation path requires dataset.field: ${value}`);
  return { dataset: dataset.key, tokens };
}

function tableFor(dataset, tables) {
  const mapping = tables?.[dataset];
  return identifier(
    typeof mapping === "string" ? mapping : mapping?.table || dataset,
    "table",
  );
}

function cardinality(value, arrayTarget) {
  if (value == null)
    return arrayTarget ? { min: 1, max: 1 } : { min: 1, max: 1 };
  if (Number.isInteger(value) && value >= 0) return { min: value, max: value };
  if (
    !value ||
    !Number.isInteger(value.min) ||
    !Number.isInteger(value.max) ||
    value.min < 0 ||
    value.max < value.min
  ) {
    throw new Error(`Invalid relation cardinality: ${JSON.stringify(value)}`);
  }
  if (!arrayTarget && value.max > 1)
    throw new Error("Scalar relation cardinality cannot exceed one");
  return value;
}

function relationGroups(config, dataset) {
  const groups = new Map();
  for (const relation of config.relations || []) {
    const from = splitPath(relation.from);
    const to = splitPath(relation.to);
    if (to.dataset !== dataset) continue;
    if (!config.datasets[from.dataset])
      throw new Error(`Unknown source dataset: ${from.dataset}`);
    if (to.tokens.length !== 1) {
      throw new Error(
        `Surreal materialization currently requires a top-level target field: ${relation.to}`,
      );
    }
    const key = `${to.tokens[0].key}${to.tokens[0].array ? "[]" : ""}`;
    if (!groups.has(key))
      groups.set(key, { target: to.tokens[0], relations: [] });
    groups.get(key).relations.push({ ...relation, from });
  }
  return [...groups.values()];
}

function sourceSelect(relation, tables) {
  const table = tableFor(relation.from.dataset, tables);
  const path = relation.from.tokens.map((token) => token.key).join(".");
  const select = `(SELECT VALUE ${path} FROM ${table})`;
  return relation.from.tokens.some((token) => token.array)
    ? `array::flatten(${select})`
    : select;
}

function anchorValues(group, anchors) {
  return group.relations.flatMap(
    (relation) => anchors?.[relation.from.dataset] || [],
  );
}

function recordLiteral(value) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*:.+$/.test(value || ""))
    throw new Error(`Invalid anchor record: ${value}`);
  return `type::record(${JSON.stringify(value)})`;
}

function buildBatch({
  config,
  dataset,
  rows,
  tables = {},
  anchors = config.anchors || {},
}) {
  if (!config?.datasets?.[dataset])
    throw new Error(`Unknown dataset: ${dataset}`);
  if (!Array.isArray(rows))
    throw new Error(`Rows for ${dataset} must be an array`);
  const table = tableFor(dataset, tables);
  const groups = relationGroups(config, dataset);
  const statements = [];
  statements.push("BEGIN TRANSACTION;");
  const fields = [];

  groups.forEach((group, index) => {
    const pool = `$pool_${index}`;
    const sources = group.relations.map((relation) =>
      sourceSelect(relation, tables),
    );
    const literals = anchorValues(group, anchors).map(recordLiteral);
    statements.push(
      `LET ${pool} = array::distinct(array::flatten([${[...sources, literals].join(", ")}])).filter(|$value| $value != NONE);`,
    );

    const settings = cardinality(
      group.relations[0].cardinality,
      group.target.array,
    );
    if (
      group.relations.some(
        (relation) =>
          JSON.stringify(
            cardinality(relation.cardinality, group.target.array),
          ) !== JSON.stringify(settings),
      )
    ) {
      throw new Error(
        `Relations targeting ${dataset}.${group.target.key} must share cardinality`,
      );
    }
    if (settings.min > 0) {
      statements.push(
        `IF array::len(${pool}) < ${settings.min} { THROW ${JSON.stringify(`No earlier values available for required relation ${dataset}.${group.target.key}`)}; };`,
      );
    }
    if (group.relations.some((relation) => relation.strictCardinality)) {
      statements.push(
        `IF array::len(${pool}) < ${settings.max} { THROW ${JSON.stringify(`Insufficient earlier values for strict relation ${dataset}.${group.target.key}`)}; };`,
      );
    }

    if (!group.target.array) {
      fields.push(
        `${group.target.key}: IF array::len(${pool}) { rand::enum(${pool}) } ELSE { NONE }`,
      );
      return;
    }
    const count =
      settings.min === settings.max
        ? `${settings.min}`
        : `rand::int(${settings.min}, ${settings.max})`;
    fields.push(
      `${group.target.key}: IF array::len(${pool}) { LET $count = math::min([${count}, array::len(${pool})]); LET $offset = rand::int(0, array::len(${pool}) - 1); (<array> 0..$count).map(|$pick| ${pool}[($offset + $pick) % array::len(${pool})]) } ELSE { [] }`,
    );
  });

  statements.push(
    `FOR $row IN $rows { CREATE ${table} CONTENT object::extend($row, { ${fields.join(", ")} }) RETURN NONE; };`,
  );
  statements.push("COMMIT TRANSACTION;");
  statements.push(
    `RETURN { dataset: ${JSON.stringify(dataset)}, inserted: array::len($rows) };`,
  );
  return { sql: statements.join("\n"), variables: { rows } };
}

function dependencyOrder(config) {
  const names = Object.keys(config.datasets || {});
  const position = new Map(names.map((name, index) => [name, index]));
  const edges = new Map(names.map((name) => [name, new Set()]));
  const indegree = new Map(names.map((name) => [name, 0]));
  for (const to of names) {
    for (const group of relationGroups(config, to)) {
      const settings = cardinality(
        group.relations[0].cardinality,
        group.target.array,
      );
      if (settings.min === 0) continue;
      const anchored = new Set(anchorValues(group, config.anchors || {})).size;
      if (anchored >= settings.min) continue;
      for (const relation of group.relations) {
        const from = relation.from.dataset;
        if (!edges.has(from))
          throw new Error(`Unknown source dataset: ${from}`);
        if (from === to) continue;
        if (!edges.get(from).has(to)) {
          edges.get(from).add(to);
          indegree.set(to, indegree.get(to) + 1);
        }
      }
    }
  }
  const ready = names.filter((name) => indegree.get(name) === 0);
  const order = [];
  while (ready.length) {
    const name = ready.shift();
    order.push(name);
    for (const target of edges.get(name)) {
      indegree.set(target, indegree.get(target) - 1);
      if (indegree.get(target) === 0) ready.push(target);
    }
    ready.sort((left, right) => position.get(left) - position.get(right));
  }
  if (order.length !== names.length)
    throw new Error(
      "Cross-dataset relation cycle requires an explicit existing anchor or a redesigned dependency direction",
    );
  return order;
}

async function materializeData({
  db,
  data,
  config,
  tables = {},
  anchors = config.anchors || {},
  batchSize = 5000,
}) {
  if (!db?.query)
    throw new Error("materializeData requires a SurrealDB client");
  if (!Number.isInteger(batchSize) || batchSize < 1)
    throw new Error("batchSize must be a positive integer");
  const summary = [];
  for (const dataset of dependencyOrder(config)) {
    const rows = data[dataset];
    if (!Array.isArray(rows))
      throw new Error(`Missing payload dataset: ${dataset}`);
    const size = config.datasets[dataset].batchSize || batchSize;
    for (let offset = 0; offset < rows.length; offset += size) {
      const batch = buildBatch({
        config,
        dataset,
        rows: rows.slice(offset, offset + size),
        tables,
        anchors,
      });
      await db.query(batch.sql, batch.variables);
    }
    summary.push({
      dataset,
      table: tableFor(dataset, tables),
      inserted: rows.length,
    });
  }
  return summary;
}

module.exports = { buildBatch, dependencyOrder, materializeData };
