function use(namespace, database) {
  if (!namespace || !database) return "";
  return `USE NS ${namespace} DB ${database};\n\n`;
}

function quote(value) {
  return `'${String(value).replaceAll("'", "\\'")}'`;
}

function identifier(value) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value || "")) {
    throw new Error(`Invalid effect table identifier: ${value}`);
  }
  return value;
}

function outputExpression(field) {
  const value = `$response.patch.${field.name}`;
  const definition = field.definition || "";
  const optional = /\bTYPE\s+(?:option<|none\s*\|)/i.test(definition);
  let converted = value;
  if (/\bTYPE\s+(?:option<)?datetime\b/i.test(definition)) converted = `type::datetime(${value})`;
  else if (/\bTYPE\s+(?:option<)?uuid\b/i.test(definition)) converted = `type::uuid(${value})`;
  else if (/\bTYPE\s+(?:option<)?duration\b/i.test(definition)) converted = `type::duration(${value})`;
  else if (/\bTYPE\s+(?:option<)?record(?:<|\b)/i.test(definition)) converted = `type::record(${value})`;
  else if (/\bTYPE\s+(?:option<)?decimal\b/i.test(definition)) converted = `<decimal>${value}`;
  return optional && converted !== value ? `IF ${value} = NONE THEN NONE ELSE ${converted} END` : converted;
}

function changedExpression(fields) {
  return fields
    .map((field) => `($before.${field} != $after.${field} OR ($before.${field} = NONE AND $after.${field} != NONE) OR ($before.${field} != NONE AND $after.${field} = NONE))`)
    .join(" OR ");
}

function snapshotExpression(source, fields) {
  return `{ id: ${source}.id, owned_by: ${source}.owned_by${fields.length ? ", " : ""}${fields
    .map((field) => `${field}: ${source}.${field}`)
    .join(", ")} }`;
}

function eventPredicate(events, inputFields) {
  const predicates = events.map((event) => {
    if (event !== "UPDATE") return `$event = '${event}'`;
    const changed = changedExpression(inputFields);
    return changed ? `($event = 'UPDATE' AND (${changed}))` : "$event = 'UPDATE'";
  });
  return predicates.length === 1 ? predicates[0] : `(${predicates.join(" OR ")})`;
}

function lifecycleFields(table) {
  const name = identifier(table.name);
  const output = [];
  output.push(`DEFINE FIELD OVERWRITE execute_at ON TABLE ${name} TYPE datetime DEFAULT time::now()
    PERMISSIONS FOR select WHERE true FOR create WHERE true FOR update WHERE rebase_attempt = 0 AND rebase_lease_token = NONE AND rebase_outcome = NONE;`);
  output.push(`DEFINE FIELD OVERWRITE priority ON TABLE ${name} TYPE int DEFAULT 50
    ASSERT $value >= 10 AND $value <= 100
    PERMISSIONS FOR select WHERE true FOR create WHERE true FOR update WHERE rebase_attempt = 0 AND rebase_lease_token = NONE AND rebase_outcome = NONE;`);
  output.push(`DEFINE FIELD OVERWRITE execution_id ON TABLE ${name} TYPE uuid
    VALUE IF $before = NONE THEN rand::uuid::v7() ELSE $before END
    PERMISSIONS FOR select, create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE revision ON TABLE ${name} TYPE uuid
    VALUE IF $before = NONE THEN rand::uuid::v7() ELSE IF $value != NONE AND $value != $before THEN $value ELSE $before END
    PERMISSIONS FOR select, create, update NONE;`);
  output.push(`DEFINE INDEX OVERWRITE idx_${name}_execution_id ON TABLE ${name} FIELDS execution_id UNIQUE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_cancel_requested ON TABLE ${name} TYPE bool
    VALUE IF $before = NONE THEN false ELSE $value END
    ASSERT ($value = false OR $value = true)
    PERMISSIONS FOR select WHERE true FOR create WHERE $value = false FOR update WHERE $value = true AND ($before = NONE OR $before = false);`);
  output.push(`DEFINE FIELD OVERWRITE rebase_cancelled_at ON TABLE ${name} TYPE option<datetime> DEFAULT NONE
    VALUE IF $this.rebase_cancel_requested = true AND ($before.rebase_cancel_requested = NONE OR $before.rebase_cancel_requested = false) THEN time::now() ELSE $before.rebase_cancelled_at END
    PERMISSIONS FOR select, create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_lease_token ON TABLE ${name} TYPE option<uuid> DEFAULT NONE
    PERMISSIONS FOR select, create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_lease_until ON TABLE ${name} TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_provider_started_at ON TABLE ${name} TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select, create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_outcome ON TABLE ${name} TYPE option<string> DEFAULT NONE
    ASSERT $value = NONE OR $value IN ['succeeded', 'failed', 'ambiguous', 'partial']
    PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_attempt ON TABLE ${name} TYPE int DEFAULT 0
    VALUE IF $before = NONE THEN ($value ?? 0) ELSE IF $value != NONE AND $value >= $before THEN $value ELSE $before END
    ASSERT $value >= 0
    PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_wake_at ON TABLE ${name} TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_finished_at ON TABLE ${name} TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_error ON TABLE ${name} TYPE option<object> FLEXIBLE DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_status ON TABLE ${name} TYPE string COMPUTED
    IF rebase_lease_until != NONE AND rebase_lease_until > time::now() THEN 'running'
    ELSE IF rebase_provider_started_at != NONE THEN 'ambiguous'
    ELSE IF rebase_cancel_requested = true AND rebase_outcome = NONE THEN 'cancelled'
    ELSE IF rebase_outcome != NONE THEN rebase_outcome
    ELSE IF execute_at > time::now() THEN 'waiting'
    ELSE IF rebase_wake_at != NONE AND rebase_wake_at > time::now() THEN 'waiting'
    ELSE 'pending' END
    PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
  output.push(`DEFINE INDEX OVERWRITE idx_${name}_rebase_outcome ON TABLE ${name} FIELDS rebase_outcome;`);
  output.push(`DEFINE INDEX OVERWRITE idx_${name}_rebase_finished_at ON TABLE ${name} FIELDS rebase_finished_at;`);
  output.push(`DEFINE INDEX OVERWRITE idx_${name}_rebase_cancelled_at ON TABLE ${name} FIELDS rebase_cancelled_at;`);
  output.push(`DEFINE INDEX OVERWRITE idx_${name}_rebase_wake_at ON TABLE ${name} FIELDS rebase_wake_at;`);
  output.push(`DEFINE INDEX OVERWRITE idx_${name}_execute_at ON TABLE ${name} FIELDS execute_at;`);
  output.push(`DEFINE INDEX OVERWRITE idx_${name}_priority ON TABLE ${name} FIELDS priority;`);
  output.push(`DEFINE INDEX OVERWRITE idx_${name}_rebase_lease_until ON TABLE ${name} FIELDS rebase_lease_until;`);
  output.push(`DEFINE INDEX OVERWRITE idx_${name}_rebase_provider_started_at ON TABLE ${name} FIELDS rebase_provider_started_at;`);
  output.push(`DEFINE INDEX OVERWRITE idx_${name}_rebase_cancel_requested ON TABLE ${name} FIELDS rebase_cancel_requested;`);
  return output.join("\n\n");
}

function lifecycleMigrationTables(schema) {
  return [...schema.tables.values()]
    .filter((table) => table.effectProcess === "async"
      || table.operation?.mode === "inline"
      || table.operation?.mode === "queued")
    .sort((left, right) => left.name.localeCompare(right.name));
}

function lifecycleMigrationPredicate(table, row = null) {
  const field = (name) => row ? `${row}.${name}` : name;
  const conditions = [
    `${field("execution_id")} = NONE`,
    `${field("revision")} = NONE`,
    `${field("execute_at")} = NONE`,
    `${field("priority")} = NONE`,
    `${field("rebase_cancel_requested")} = NONE`,
    `(${field("rebase_cancel_requested")} = true AND ${field("rebase_cancelled_at")} = NONE)`,
    `${field("rebase_attempt")} = NONE`,
  ];
  if (table.effectProcess === "async") {
    conditions.push(
      `${field("schedule")} != NONE`,
      `${field("rebase_schedule_next_at")} != NONE`,
      `${field("rebase_schedule_index")} != NONE`,
      `${field("rebase_schedule_finished_at")} != NONE`,
    );
  }
  return conditions.join(" OR ");
}

function generateLifecycleMigration(schema, options = {}) {
  const tables = lifecycleMigrationTables(schema);
  const backfill = [
    use(options.namespace, options.database),
    "-- UPGRADE ONLY: first apply the new schema with all old gateway workers stopped.",
    "-- Run this file repeatedly until every table reports processed: 0, then run the finalizer.",
    "-- Each invocation updates at most 1000 records per table and is safe to repeat.",
  ];
  const finalize = [
    use(options.namespace, options.database),
    "-- Run only after the backfill reports processed: 0 for every table.",
    "-- This removes the retired recurring-schedule fields from upgraded async tables.",
  ];
  const finalizeChecks = [];
  const finalizeConditions = [];
  const finalizeCleanup = [];

  for (const table of tables) {
    const name = identifier(table.name);
    const batch = `$rebase_migration_batch_${name}`;
    const row = `$rebase_migration_row_${name}`;
    const activeLease = `(${row}.rebase_outcome = NONE AND ${row}.rebase_lease_token != NONE)`;
    const selectFields = [
      "id", "execution_id", "revision", "execute_at", "priority", "rebase_attempt",
      "rebase_cancel_requested", "rebase_lease_token", "rebase_provider_started_at",
      "rebase_cancelled_at",
      "rebase_wake_at", "rebase_outcome",
      "rebase_finished_at", "rebase_error",
    ];
    if (table.effectProcess === "async") {
      selectFields.push("schedule", "rebase_schedule_next_at", "rebase_schedule_index", "rebase_schedule_finished_at");
    }
    const assignments = [
      `execution_id = IF ${row}.execution_id = NONE THEN rand::uuid::v7() ELSE ${row}.execution_id END`,
      `revision = IF ${row}.revision = NONE THEN rand::uuid::v7() ELSE ${row}.revision END`,
      `execute_at = IF ${row}.execute_at != NONE THEN ${row}.execute_at ELSE ${table.effectProcess === "async"
        ? `IF ${row}.rebase_schedule_next_at != NONE THEN ${row}.rebase_schedule_next_at ELSE time::now()`
        : "time::now()"} END`,
      `priority = IF ${row}.priority = NONE THEN 50 ELSE ${row}.priority END`,
      `rebase_attempt = IF ${row}.rebase_attempt != NONE THEN ${row}.rebase_attempt ELSE IF ${row}.rebase_lease_token != NONE OR ${row}.rebase_wake_at != NONE OR ${row}.rebase_outcome != NONE THEN 1 ELSE 0 END`,
      `rebase_cancel_requested = ${row}.rebase_cancel_requested ?? false`,
      `rebase_cancelled_at = IF ${row}.rebase_cancel_requested = true AND ${row}.rebase_cancelled_at = NONE THEN time::now() ELSE ${row}.rebase_cancelled_at END`,
      "rebase_lease_token = NONE",
      "rebase_lease_until = NONE",
      `rebase_provider_started_at = ${row}.rebase_provider_started_at`,
      `rebase_outcome = IF ${activeLease} THEN 'ambiguous' ELSE ${row}.rebase_outcome END`,
      `rebase_finished_at = IF ${activeLease} THEN NONE ELSE ${row}.rebase_finished_at END`,
      `rebase_wake_at = IF ${activeLease} THEN time::now() ELSE ${row}.rebase_wake_at END`,
      `rebase_error = IF ${activeLease} THEN { code: 'MIGRATED_ACTIVE_LEASE', message: 'Legacy worker lease was active during the one-shot migration; provider outcome requires reconciliation.' } ELSE ${row}.rebase_error END`,
    ];
    if (table.effectProcess === "async") {
      assignments.push(
        "schedule = NONE",
        "rebase_schedule_next_at = NONE",
        "rebase_schedule_index = NONE",
        "rebase_schedule_finished_at = NONE",
      );
    }
    backfill.push(`LET ${batch} = (SELECT ${selectFields.join(", ")} FROM ${name}
      WHERE (${lifecycleMigrationPredicate(table)}) ORDER BY id LIMIT 1000);`);
    backfill.push(`FOR ${row} IN ${batch} {
      UPDATE ${row}.id SET ${assignments.join(",\n        ")} RETURN NONE;
    };`);
    backfill.push(`RETURN { table: '${name}', processed: ${batch}.len() };`);

    const remaining = `$rebase_migration_remaining_${name}`;
    finalizeChecks.push(`LET ${remaining} = (SELECT VALUE id FROM ${name}
      WHERE (${lifecycleMigrationPredicate(table)}) LIMIT 1);`);
    finalizeConditions.push(`${remaining}.len() = 0`);
    if (table.effectProcess === "async") {
      finalizeCleanup.push(`REMOVE INDEX IF EXISTS idx_${name}_rebase_schedule_next_at ON TABLE ${name};`);
      finalizeCleanup.push(`REMOVE FIELD IF EXISTS schedule ON TABLE ${name};`);
      finalizeCleanup.push(`REMOVE FIELD IF EXISTS rebase_schedule_next_at ON TABLE ${name};`);
      finalizeCleanup.push(`REMOVE FIELD IF EXISTS rebase_schedule_index ON TABLE ${name};`);
      finalizeCleanup.push(`REMOVE FIELD IF EXISTS rebase_schedule_finished_at ON TABLE ${name};`);
    }
  }
  return {
    backfill: backfill.filter(Boolean).join("\n\n"),
    finalize: [
      ...finalize,
      ...finalizeChecks,
      `IF (${finalizeConditions.length ? finalizeConditions.join(" AND ") : "true"}) {
        ${finalizeCleanup.join("\n        ") || "RETURN NONE;"}
      } ELSE {
        THROW 'REBASE_ONE_SHOT_BACKFILL_INCOMPLETE';
      };`,
    ].filter(Boolean).join("\n\n"),
  };
}

function generateEffectEvents(schema, options = {}) {
  if (!options.runtimeUrl || !options.runtimeSecret) return "";
  const runtimeUrl = String(options.runtimeUrl).replace(/\/+$/, "");
  let output = use(options.namespace, options.database);
  for (const table of schema.tables.values()) {
    if (!table.effectProcess) continue;
    const tableName = identifier(table.name);
    const inputFields = [...table.fields.values()]
      .filter((field) => field.effectInput)
      .map((field) => field.name);
    const outputFields = [...table.fields.values()]
      .filter((field) => field.effectOutput && !/^rebase_/.test(field.name));
    const events = table.effectEvents?.length ? table.effectEvents : ["CREATE"];
    const taskFields = [...new Set([...inputFields, "execute_at", "priority"] )];
    const taskChanged = changedExpression(taskFields);
    const when = table.effectProcess === "async"
      ? `($event = 'CREATE' OR ($event = 'UPDATE' AND $before.rebase_attempt = 0 AND $before.rebase_lease_token = NONE AND (${taskChanged})))`
      : eventPredicate(events, inputFields);
    const snapshotFields = [...new Set([
      ...inputFields,
      ...outputFields.map((field) => field.name),
    ])];
    const patchFields = outputFields.map((field) => `${field.name}: ${outputExpression(field)}`);
    const auth = `{ authorization: ${quote(`Bearer ${options.runtimeSecret}`)} }`;
    let body;
    if (table.effectProcess === "sync") {
      body = `
        LET $response = http::post(${quote(`${runtimeUrl}/internal/sync`)}, {
            namespace: session::ns(),
            database: session::db(),
            id: <string>(IF $event = 'DELETE' THEN $before.id ELSE $after.id END),
            event: $event,
            before: IF $event = 'CREATE' THEN NONE ELSE ${snapshotExpression("$before", snapshotFields)} END,
            after: IF $event = 'DELETE' THEN NONE ELSE ${snapshotExpression("$after", snapshotFields)} END
        }, ${auth});
        IF $response.outcome = 'success' AND $event != 'DELETE' AND $response.patch {
            UPDATE $after.id MERGE { ${patchFields.join(", ")} };
        } ELSE IF $response.outcome != NONE AND $response.outcome != 'success' {
            THROW 'REBASE_SYNC_EFFECT_FAILED';
        };
      `;
    } else {
      body = `
        LET $response = http::post(${quote(`${runtimeUrl}/internal/wake/task`)}, {
            namespace: session::ns(), database: session::db(), id: <string>$after.id
        }, ${auth});
      `;
    }
    if (table.effectProcess === "async") {
      output += `DEFINE EVENT OVERWRITE rebase_effect_${tableName}_revise ON TABLE ${tableName}\n`;
      output += `    WHEN $event = 'UPDATE' AND $before.rebase_attempt = 0 AND $before.rebase_lease_token = NONE AND (${taskChanged}) THEN {\n`;
      output += `        UPDATE $after.id SET revision = rand::uuid::v7() WHERE rebase_attempt = 0 AND rebase_lease_token = NONE AND rebase_outcome = NONE;\n`;
      output += `    };\n\n`;
    }
    output += `DEFINE EVENT OVERWRITE rebase_effect_${tableName} ON TABLE ${tableName}\n`;
    output += `    WHEN ${when}${table.effectProcess === "async" ? " ASYNC RETRY 0 MAXDEPTH 0" : ""} THEN {${body}};\n\n`;
  }
  return output;
}

function generateLifecycleFields(schema) {
  return [...schema.tables.values()]
    .filter((table) => table.effectProcess === "async"
      || table.operation?.mode === "inline"
      || table.operation?.mode === "queued")
    .map(lifecycleFields)
    .join("\n\n");
}

function generateOperationEvents(schema, options = {}) {
  if (!options.runtimeUrl || !options.runtimeSecret) return "";
  const runtimeUrl = String(options.runtimeUrl).replace(/\/+$/, "");
  let output = use(options.namespace, options.database);
  for (const table of schema.tables.values()) {
    if (!table.operation) continue;
    const tableName = identifier(table.name);
    const auth = `{ authorization: ${quote(`Bearer ${options.runtimeSecret}`)} }`;
    const operationInputs = [...table.fields.values()].filter((field) => field.operationInput);
    if (table.operation.mode === "grant") {
      const inputFields = operationInputs.map((field) => field.name);
      const outputFields = [...table.fields.values()]
        .filter((field) => field.operationOutput);
      const snapshotFields = [...new Set([
        ...inputFields,
        ...outputFields.map((field) => field.name),
      ])];
      const patchFields = outputFields.map((field) => `${field.name}: ${outputExpression(field)}`);
      const body = `
        LET $response = http::post(${quote(`${runtimeUrl}/internal/grant`)}, {
            namespace: session::ns(),
            database: session::db(),
            id: <string>$after.id,
            event: $event,
            before: IF $event = 'CREATE' THEN NONE ELSE ${snapshotExpression("$before", snapshotFields)} END,
            after: ${snapshotExpression("$after", snapshotFields)}
        }, ${auth});
        IF $response.outcome = 'success' AND $response.patch {
            UPDATE $after.id MERGE { ${patchFields.join(", ")} };
        } ELSE IF $response.outcome != NONE AND $response.outcome != 'success' {
            THROW 'REBASE_GRANT_FAILED';
        };
      `;
      for (const event of table.operation.events) {
        const eventWhen = event === "UPDATE"
          ? `($event = 'UPDATE' AND (${changedExpression(inputFields)}))`
          : `$event = '${event}'`;
        output += `DEFINE EVENT OVERWRITE rebase_operation_${tableName}_${event.toLowerCase()} ON TABLE ${tableName}\n`;
        output += `    WHEN ${eventWhen} THEN {${body}};\n\n`;
      }
      continue;
    }
    const taskFields = [...new Set([...operationInputs.map((field) => field.name), "execute_at", "priority"] )];
    const taskChanged = changedExpression(taskFields);
    output += `DEFINE EVENT OVERWRITE rebase_operation_${tableName}_revise ON TABLE ${tableName}\n`;
    output += `    WHEN $event = 'UPDATE' AND $before.rebase_attempt = 0 AND $before.rebase_lease_token = NONE AND (${taskChanged}) THEN {\n`;
    output += `        UPDATE $after.id SET revision = rand::uuid::v7() WHERE rebase_attempt = 0 AND rebase_lease_token = NONE AND rebase_outcome = NONE;\n`;
    output += `    };\n\n`;
    output += `DEFINE EVENT OVERWRITE rebase_operation_${tableName} ON TABLE ${tableName}\n`;
    output += `    WHEN $event = 'CREATE' OR ($event = 'UPDATE' AND $before.rebase_attempt = 0 AND $before.rebase_lease_token = NONE AND (${taskChanged})) ASYNC RETRY 0 MAXDEPTH 0 THEN {\n`;
    if (table.operation.mode === "inline") {
      output += `        LET $path = IF $event = 'CREATE' THEN '/internal/inline' ELSE '/internal/wake/task' END;\n`;
      output += `        LET $response = http::post(${quote(runtimeUrl)} + $path, {\n`;
    } else {
      output += `        LET $response = http::post(${quote(`${runtimeUrl}/internal/wake/task`)}, {\n`;
    }
    output += `            namespace: session::ns(), database: session::db(), id: <string>$after.id\n`;
    output += `        }, ${auth});\n`;
    output += `    };\n\n`;
  }
  return output;
}

const MACHINE_FIELDS = Object.freeze([
  "execute_at",
  "priority",
  "execution_id",
  "revision",
  "rebase_cancel_requested",
  "rebase_cancelled_at",
  "rebase_lease_token",
  "rebase_lease_until",
  "rebase_outcome",
  "rebase_attempt",
  "rebase_wake_at",
  "rebase_finished_at",
  "rebase_error",
  "rebase_status",
]);

function runtimeContractFor(table, schema = { tables: new Map() }) {
  const fields = [...table.fields.values()];
  const inputDefinitions = fields.filter((field) => field.effectInput);
  const inputs = inputDefinitions.map((field) => field.name).sort();
  const optionalInputs = inputDefinitions
    .filter((field) => /\bTYPE\s+option</i.test(field.definition || "") || /\bDEFAULT\s+NONE\b/i.test(field.definition || ""))
    .map((field) => field.name)
    .sort();
  const patchFields = fields
    .filter((field) => field.effectOutput)
    .map((field) => field.name)
    .sort();
  const references = fields
    .filter((field) => field.recordType)
    .map((field) => ({
      field: field.name,
      array: field.recordType.isArray,
      optional: field.recordType.isOptional,
      targets: [...field.recordType.targets].sort(),
    }))
    .sort((left, right) => left.field.localeCompare(right.field));
  return {
    process: table.effectProcess,
    events: [...(table.effectEvents || ["CREATE"])],
    timeoutMs: table.effectTimeoutMs || (table.effectProcess === "sync" ? 10000 : 60000),
    ...(table.effectProcess === "async" ? { identityFields: ["execution_id", "revision"] } : {}),
    triggers: [table.effectProcess === "sync" ? "sync" : "task"],
    inputFields: inputs,
    optionalInputs,
    patchFields,
    machineFields: table.effectProcess === "async" ? [...MACHINE_FIELDS] : [],
    references,
    adapters: [...(table.effectAdapters || [])],
    mutableInputs: table.effectMutableInputs === true,
    executeAtField: table.effectProcess === "async" ? "execute_at" : null,
    priorityField: table.effectProcess === "async" ? "priority" : null,
  };
}

function operationContractFor(table) {
  if (!table.operation) throw new Error(`${table.name} has no @rebase-operation declaration`);
  const fields = [...table.fields.values()];
  const inputs = fields.filter((field) => field.operationInput);
  const outputs = fields.filter((field) => field.operationOutput);
  return {
    mode: table.operation.mode,
    events: [...table.operation.events],
    timeoutMs: table.effectTimeoutMs || (table.operation.mode === "grant" ? 10000 : 60000),
    ...(table.operation.mode !== "grant" ? { identityFields: ["execution_id", "revision"] } : {}),
    ...(table.operation.mode !== "grant" ? { executeAtField: "execute_at", priorityField: "priority" } : {}),
    inputFields: inputs.map((field) => field.name).sort(),
    optionalInputs: inputs
      .filter((field) => /\bTYPE\s+option</i.test(field.definition || "") || /\bDEFAULT\s+NONE\b/i.test(field.definition || ""))
      .map((field) => field.name)
      .sort(),
    patchFields: outputs.map((field) => field.name).sort(),
    references: inputs
      .filter((field) => field.recordType)
      .map((field) => ({
        field: field.name,
        array: field.recordType.isArray,
        optional: field.recordType.isOptional,
        targets: [...field.recordType.targets].sort(),
      }))
      .sort((left, right) => left.field.localeCompare(right.field)),
    adapters: [...(table.effectAdapters || [])],
  };
}

function generateRuntimeContracts(schema, principals) {
  const tables = {};
  for (const table of [...schema.tables.values()].sort((left, right) => left.name.localeCompare(right.name))) {
    if (table.operation) tables[table.name] = operationContractFor(table);
    else if (table.effectProcess) tables[table.name] = runtimeContractFor(table, schema);
  }
  return {
    principals: principals ? {
      user: principals.user,
      group: principals.group,
      root: `${principals.group}:root`,
    } : undefined,
    tables,
    webhooks: {},
  };
}

module.exports = {
  MACHINE_FIELDS,
  generateEffectEvents,
  generateLifecycleMigration,
  generateOperationEvents,
  generateLifecycleFields,
  generateRuntimeContracts,
  lifecycleFields,
  operationContractFor,
  runtimeContractFor,
};
