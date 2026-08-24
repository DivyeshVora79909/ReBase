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

function lifecycleFields(table) {
  const name = identifier(table.name);
  const output = [];
  output.push(`DEFINE FIELD OVERWRITE rebase_cancel_requested ON TABLE ${name} TYPE bool
    VALUE IF $before = NONE THEN false ELSE $value END
    ASSERT ($value = false OR $value = true)
    PERMISSIONS FOR select WHERE true FOR create WHERE $value = false FOR update WHERE $value = true AND ($before = NONE OR $before = false);`);
  output.push(`DEFINE FIELD OVERWRITE rebase_lease_token ON TABLE ${name} TYPE option<uuid> DEFAULT NONE
    PERMISSIONS FOR select, create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_lease_until ON TABLE ${name} TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_outcome ON TABLE ${name} TYPE option<string> DEFAULT NONE
    ASSERT $value = NONE OR $value IN ['succeeded', 'failed', 'ambiguous', 'partial']
    PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_wake_at ON TABLE ${name} TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_finished_at ON TABLE ${name} TYPE option<datetime> DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_error ON TABLE ${name} TYPE option<object> FLEXIBLE DEFAULT NONE
    PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
  output.push(`DEFINE FIELD OVERWRITE rebase_status ON TABLE ${name} TYPE string COMPUTED
    IF rebase_cancel_requested = true AND rebase_outcome = NONE THEN 'cancelled'
    ELSE IF rebase_outcome != NONE THEN rebase_outcome
    ELSE IF rebase_lease_until != NONE AND rebase_lease_until > time::now() THEN 'running'
    ELSE IF rebase_wake_at != NONE AND rebase_wake_at > time::now() THEN 'waiting'
    ELSE 'pending' END
    PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
  if (table.effectProcess === "async") {
    output.push(`DEFINE FIELD OVERWRITE schedule ON TABLE ${name}
      TYPE option<{ cron: string, repeat: option<int>, skip: option<array<int>>, misfire: option<string> }>
      DEFAULT NONE
      ASSERT $value = NONE OR (
        string::matches(string::trim($value.cron), /^[^\\s]+(?:\\s+[^\\s]+){4}$/)
        AND string::len($value.cron) <= 256
        AND ($value.repeat = NONE OR ($value.repeat > 0 AND $value.repeat <= 9007199254740991))
        AND ($value.skip ?? []).len() <= 1000
        AND array::all($value.skip ?? [], |$skip| $skip >= 0 AND $skip <= 1000)
        AND ($value.misfire = NONE OR $value.misfire IN ['coalesce', 'skip', 'all'])
      )
      PERMISSIONS FOR select WHERE true FOR create WHERE true FOR update NONE;`);
    output.push(`DEFINE FIELD OVERWRITE rebase_schedule_next_at ON TABLE ${name} TYPE option<datetime> DEFAULT NONE
      PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
    output.push(`DEFINE FIELD OVERWRITE rebase_schedule_index ON TABLE ${name} TYPE option<int> DEFAULT NONE
      PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
    output.push(`DEFINE FIELD OVERWRITE rebase_schedule_finished_at ON TABLE ${name} TYPE option<datetime> DEFAULT NONE
      PERMISSIONS FOR select WHERE true FOR create, update NONE;`);
    output.push(`DEFINE INDEX OVERWRITE idx_${name}_rebase_outcome ON TABLE ${name} FIELDS rebase_outcome;`);
    output.push(`DEFINE INDEX OVERWRITE idx_${name}_rebase_wake_at ON TABLE ${name} FIELDS rebase_wake_at;`);
    output.push(`DEFINE INDEX OVERWRITE idx_${name}_rebase_schedule_next_at ON TABLE ${name} FIELDS rebase_schedule_next_at;`);
    output.push(`DEFINE INDEX OVERWRITE idx_${name}_rebase_lease_until ON TABLE ${name} FIELDS rebase_lease_until;`);
    output.push(`DEFINE INDEX OVERWRITE idx_${name}_rebase_cancel_requested ON TABLE ${name} FIELDS rebase_cancel_requested;`);
  }
  return output.join("\n\n");
}

function generateEffectEvents(schema, options = {}) {
  if (!options.runtimeUrl || !options.runtimeSecret) return "";
  let output = use(options.namespace, options.database);
  for (const table of schema.tables.values()) {
    if (!table.effectProcess) continue;
    const tableName = identifier(table.name);
    const inputFields = [...table.fields.values()]
      .filter((field) => field.effectInput)
      .map((field) => field.name);
    const outputFields = [...table.fields.values()]
      .filter((field) => field.effectOutput && !/^rebase_/.test(field.name) && !field.webhookEvent && !field.webhookOrder);
    const changed = changedExpression(inputFields);
    const when = table.effectProcess === "sync" && changed
      ? `$event = 'CREATE' OR ($event = 'UPDATE' AND (${changed}))`
      : "$event = 'CREATE'";
    const snapshotFields = [
      "id: $after.id",
      "owned_by: $after.owned_by",
      ...inputFields.map((field) => `${field}: $after.${field}`),
    ];
    const patchFields = outputFields.map((field) => `${field.name}: ${outputExpression(field)}`);
    const auth = `{ authorization: ${quote(`Bearer ${options.runtimeSecret}`)} }`;
    let body;
    if (table.effectProcess === "sync") {
      body = `
        LET $response = http::post(${quote(`${options.runtimeUrl}/internal/sync`)}, {
            namespace: session::ns(),
            database: session::db(),
            id: <string>$after.id,
            event: $event,
            record: { ${snapshotFields.join(", ")} }
        }, ${auth});
        IF $response.outcome = 'success' AND $response.patch {
            UPDATE $after.id MERGE { ${patchFields.join(", ")} };
        } ELSE IF $response.outcome != NONE AND $response.outcome != 'success' {
            THROW 'REBASE_SYNC_EFFECT_FAILED';
        };
      `;
    } else {
      body = `
        IF $after.schedule != NONE {
            LET $response = http::post(${quote(`${options.runtimeUrl}/internal/wake/schedule`)}, {
                namespace: session::ns(), database: session::db(), id: <string>$after.id
            }, ${auth});
        } ELSE {
            LET $response = http::post(${quote(`${options.runtimeUrl}/internal/wake/task`)}, {
                namespace: session::ns(), database: session::db(), id: <string>$after.id
            }, ${auth});
        };
      `;
    }
    output += `DEFINE EVENT OVERWRITE rebase_effect_${tableName} ON TABLE ${tableName}\n`;
    output += `    WHEN ${when}${table.effectProcess === "async" ? " ASYNC RETRY 0 MAXDEPTH 0" : ""} THEN {${body}};\n\n`;
  }
  return output;
}

function generateLifecycleFields(schema) {
  return [...schema.tables.values()]
    .filter((table) => table.effectProcess === "async")
    .map(lifecycleFields)
    .join("\n\n");
}

const MACHINE_FIELDS = Object.freeze([
  "rebase_cancel_requested",
  "rebase_lease_token",
  "rebase_lease_until",
  "rebase_outcome",
  "rebase_wake_at",
  "rebase_finished_at",
  "rebase_error",
  "rebase_status",
  "rebase_schedule_next_at",
  "rebase_schedule_index",
  "rebase_schedule_finished_at",
]);

function webhookAccountPath(table, schema = { tables: new Map() }) {
  if (!table.webhook) return null;
  if (!table.webhookAccountPath) throw new Error(`${table.name} webhook requires @rebase-webhook-account`);
  const segments = table.webhookAccountPath.split(".");
  if (segments.length < 1 || segments.length > 2) {
    throw new Error(`${table.name} webhook account path must be a field or one reference plus a field`);
  }
  const root = table.fields.get(segments[0]);
  if (!root) throw new Error(`${table.name} webhook account path starts with an unknown field: ${segments[0]}`);
  if (segments.length === 2) {
    if (!root.recordType || root.recordType.isArray) {
      throw new Error(`${table.name}.${segments[0]} must be a scalar record reference for webhook account resolution`);
    }
    for (const target of root.recordType.targets) {
      if (!schema.tables.get(target)?.fields.has(segments[1])) {
        throw new Error(`${table.name} webhook account path field is missing: ${target}.${segments[1]}`);
      }
    }
  }
  return segments;
}

function runtimeContractFor(table, schema = { tables: new Map() }) {
  const fields = [...table.fields.values()];
  const inputDefinitions = fields.filter((field) => field.effectInput);
  const inputs = inputDefinitions.map((field) => field.name).sort();
  const optionalInputs = inputDefinitions
    .filter((field) => /\bTYPE\s+option</i.test(field.definition || "") || /\bDEFAULT\s+NONE\b/i.test(field.definition || ""))
    .map((field) => field.name)
    .sort();
  const patchFields = fields
    .filter((field) => field.effectOutput && !field.webhookEvent && !field.webhookOrder)
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
  const webhookEvents = fields.filter((field) => field.webhookEvent).map((field) => field.name);
  const webhookOrders = fields.filter((field) => field.webhookOrder).map((field) => field.name);
  if (table.webhook && webhookEvents.length !== 1) {
    throw new Error(`${table.name} webhook requires exactly one @rebase-webhook-event field`);
  }
  if (table.webhook && webhookOrders.length !== 1) {
    throw new Error(`${table.name} webhook requires exactly one @rebase-webhook-order field`);
  }
  return {
    process: table.effectProcess,
    timeoutMs: table.effectTimeoutMs || (table.effectProcess === "sync" ? 10000 : 60000),
    triggers: [
      table.effectProcess === "sync" ? "sync" : "task",
      ...(table.effectProcess === "async" ? ["schedule"] : []),
      ...(table.webhook ? ["webhook"] : []),
    ],
    inputFields: inputs,
    optionalInputs,
    patchFields,
    machineFields: table.effectProcess === "async" ? [...MACHINE_FIELDS] : [],
    references,
    providers: [...(table.effectProviders || [])],
    mutableInputs: table.effectMutableInputs === true,
    schedule: table.effectProcess === "async" ? {
      field: "schedule",
      nextAtField: "rebase_schedule_next_at",
      indexField: "rebase_schedule_index",
      finishedAtField: "rebase_schedule_finished_at",
      timezone: "UTC",
      granularity: "minute",
    } : null,
    webhook: table.webhook ? {
      ...table.webhook,
      eventField: webhookEvents[0],
      orderField: webhookOrders[0],
      accountPath: webhookAccountPath(table, schema),
    } : null,
  };
}

function generateRuntimeContracts(schema) {
  const tables = {};
  for (const table of [...schema.tables.values()].sort((left, right) => left.name.localeCompare(right.name))) {
    if (table.effectProcess) tables[table.name] = runtimeContractFor(table, schema);
  }
  return { tables };
}

module.exports = {
  MACHINE_FIELDS,
  generateEffectEvents,
  generateLifecycleFields,
  generateRuntimeContracts,
  lifecycleFields,
  runtimeContractFor,
};
