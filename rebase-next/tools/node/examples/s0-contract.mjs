// S0 evidence checks, separate from the public SDK. No process or IO on import.
import { createHash } from 'node:crypto';
import { createNativeAjv } from '../private/config-validation.mjs';
import { parseFrame } from '../private/json-codec.mjs';

const requireThat = (value, message) => { if (!value) throw new Error(`S0 contract: ${message}`); };

export function prepareS0TraceCheck(schema) {
  const validate = createNativeAjv().compile(schema);
  return (trace, { readOnly = trace.path === 'native-tree', work } = {}) => {
    requireThat(validate(trace), JSON.stringify(validate.errors));
    requireThat(Buffer.byteLength(JSON.stringify(trace)) <= 1_048_576, 'trace byte bound');
    const byId = new Map();
    const depths = new Map();
    const known = new Map();
    for (const key of trace.initialKeys) {
      requireThat(!known.has(key.token), 'duplicate initial key');
      requireThat(!['attempt-cache','previously-known'].includes(key.origin) || trace.phase === 'attempt-repeat', 'cache witness requires repeat phase');
      known.set(key.token, { origin: key.origin, event: null, at: 0 });
    }
    const numeric = value => {
      if (typeof value === 'number') requireThat(Number.isSafeInteger(value), 'unsafe integer');
      else if (value && typeof value === 'object') for (const child of Object.values(value)) numeric(child);
    };
    numeric(trace);
    let lastId = -1;
    for (const event of trace.events) {
      requireThat(!byId.has(event.id), 'duplicate event ID');
      requireThat(event.id > lastId, 'event IDs must increase');
      lastId = event.id;
      requireThat(event.startNs <= event.endNs && event.endNs <= trace.durationNs, 'event time bounds');
      requireThat(event.parentId !== event.id, 'self parent');
      byId.set(event.id, event);
    }
    for (const event of trace.events) {
      const allowed = { attempt:['load','cache-hit'],facade:['get','scan','put','remove'],binding:['get','get-range','set','clear','clear-range','approximate-size'],commit:['commit'] };
      requireThat(allowed[event.layer].includes(event.operation), 'invalid layer/operation pair');
      if (event.layer === 'attempt') {
        requireThat(event.keyToken !== null, 'Attempt key token required');
        requireThat(event.keyKnowledge !== 'not-applicable', 'Attempt key knowledge is applicable');
        const fact = known.get(event.keyToken);
        if (event.keyKnowledge !== 'unknown') {
          requireThat(fact && fact.at <= event.startNs, 'key first-known witness missing or late');
          requireThat(fact.event === event.keyDiscoveredBy, 'key discovery source differs from first-known witness');
          if (event.keyKnowledge === 'invocation') requireThat(fact.origin === 'invocation', 'key was not invocation-known');
          if (event.keyKnowledge === 'locally-generated') requireThat(fact.origin === 'locally-generated', 'key was not locally generated');
        }
      }
      const completed = id => {
        const source = byId.get(id);
        requireThat(source && source.id < event.id && source.endNs <= event.startNs, 'dependency must exist and finish earlier');
        return source;
      };
      if (event.parentId !== null) {
        const parent = byId.get(event.parentId);
        requireThat(parent && parent.id < event.id && parent.startNs <= event.startNs && event.endNs <= parent.endNs, 'parent scope containment');
      }
      if (event.executionPredecessorId !== null) completed(event.executionPredecessorId);
      for (const id of event.controlDependencies) completed(id);
      if (event.keyDiscoveredBy !== null) {
        const source = completed(event.keyDiscoveredBy);
        requireThat(['result-discovered','previously-known'].includes(event.keyKnowledge), 'discovery edge requires discovered key');
        requireThat(source.layer === 'attempt' && source.operation === 'load' && source.outcome === 'found', 'discovery source must load a found native value');
      } else requireThat(event.keyKnowledge !== 'result-discovered', 'discovered key missing source');
      if (event.layer === 'attempt' && event.operation === 'load') {
        const inherited = event.keyDiscoveredBy === null ? 0 : depths.get(event.keyDiscoveredBy);
        requireThat(inherited !== undefined, 'discovery IDs must follow load order');
        depths.set(event.id, inherited + 1);
      }
      if (event.discoveredKeyTokens.length) {
        requireThat(event.layer === 'attempt' && event.operation === 'load' && event.outcome === 'found', 'only found Attempt loads disclose keys');
        for (const token of event.discoveredKeyTokens) if (!known.has(token)) known.set(token,{origin:'result-discovered',event:event.id,at:event.endNs});
        requireThat(known.size <= 4096, 'key provenance fact bound');
      }
    }
    if (trace.dependency.complete) {
      requireThat(trace.complete, 'truncated event graph cannot prove depth');
      requireThat(trace.events.filter(e => e.layer === 'attempt').every(e => e.keyKnowledge !== 'unknown'), 'unknown key lineage');
      requireThat(trace.dependency.observedReadDepth === Math.max(0, ...depths.values()), 'incorrect key read depth');
    }
    const count = (layer, operation) => trace.events.filter(e => e.layer === layer && e.operation === operation).length;
    const counts = {
      attemptLoadAttempts: count('attempt', 'load'), attemptCacheHits: count('attempt', 'cache-hit'),
      logicalTouches: count('attempt', 'load') + count('attempt', 'cache-hit'),
      attemptLoadedValueBytes: trace.events.filter(e => e.layer === 'attempt' && e.operation === 'load').reduce((total, e) => total + e.valueBytes, 0),
      facadeGet: count('facade', 'get'), facadeScan: count('facade', 'scan'),
      facadePut: count('facade', 'put'), facadeRemove: count('facade', 'remove'),
      bindingGet: count('binding', 'get'), bindingGetRange: count('binding', 'get-range'),
      bindingSet: count('binding', 'set'), bindingClear: count('binding', 'clear'), bindingClearRange: count('binding', 'clear-range'),
      bindingApproximateSize: count('binding', 'approximate-size'),
    };
    const primitive = trace.backend === 'foundationdb' ? 'binding' : 'facade';
    const reads = trace.events.filter(e => e.layer === primitive && ['get', 'get-range', 'scan'].includes(e.operation));
    const writes = trace.events.filter(e => e.layer === primitive && ['set', 'put', 'remove', 'clear', 'clear-range'].includes(e.operation));
    const sum = (events, key) => events.reduce((total, event) => total + event[key], 0);
    Object.assign(counts, { returnedRows: sum(reads, 'rows'), readKeyBytes: sum(reads, 'keyBytes'), readValueBytes: sum(reads, 'valueBytes'), writeKeyBytes: sum(writes, 'keyBytes'), writeValueBytes: sum(writes, 'valueBytes') });
    for (const [key, actual] of Object.entries(counts)) {
      const reported = trace.counters[key];
      if (reported === null) continue;
      requireThat(trace.complete ? reported === actual : reported >= actual, `${key} does not match retained events`);
    }
    if (trace.backend !== 'foundationdb') {
      requireThat(trace.counters.sdk === null, 'SDK metrics unsupported for embedded adapters');
      requireThat(!trace.events.some(event=>event.layer==='binding'), 'embedded adapters have no FDB binding events');
      for (const key of Object.keys(counts).filter(key => key.startsWith('binding'))) requireThat(trace.counters[key] === null, 'embedded binding counter must be absent');
    } else if (trace.complete) {
      requireThat(trace.counters.sdk !== null && Object.keys(counts).filter(key=>key.startsWith('binding')).every(key=>trace.counters[key] !== null), 'complete FDB trace requires supported metrics');
      const sdk=trace.counters.sdk;
      const successfulGets=trace.events.filter(e=>e.layer==='binding'&&e.operation==='get'&&['found','missing'].includes(e.outcome)).length;
      requireThat(sdk.callGet===successfulGets, 'SDK GET completed-success count differs from binding events');
      for(const [field,operation] of Object.entries({callSet:'set',callClear:'clear',callClearRange:'clear-range'})) requireThat(sdk[field]===count('binding',operation), `SDK ${field} differs from binding invocations`);
      requireThat(sdk.rowsFetched===sum(reads,'rows'), 'SDK fetched rows differ from successful binding reads');
      // Official bytesRead additionally includes a requested GET key on a miss.
      requireThat(sdk.bytesRead>=sum(reads,'keyBytes')+sum(reads,'valueBytes'), 'SDK read bytes below returned binding bytes');
    }
    const commits = trace.events.filter(e => e.layer === 'commit');
    requireThat(commits.length <= 1, 'automatic commit retry is forbidden');
    if (commits.length) {
      const commit = commits[0];
      requireThat(['success','definite-abort','conflict','unknown'].includes(commit.outcome), 'invalid commit outcome');
      requireThat(commit.outcome === trace.outcome, 'commit outcome differs from action');
      requireThat(trace.commitNs === commit.endNs - commit.startNs, 'commit duration differs from event');
      requireThat(commit.parentId === null && commit.keyToken === null && commit.keyKnowledge === 'not-applicable', 'commit event must be an unkeyed scope');
    } else {
      requireThat(trace.commitNs === null, 'commit duration without retained commit event');
      requireThat(readOnly || trace.outcome !== 'success' || !trace.complete, 'mutation success requires successful commit');
    }
    if (readOnly) requireThat(!trace.counters.facadePut && !trace.counters.facadeRemove && writes.length===0 && commits.length === 0, 'read-only action wrote or committed');
    if (trace.phase === 'attempt-repeat') {
      requireThat(readOnly, 'mutation cannot repeat an Attempt');
      requireThat(trace.counters.attemptLoadAttempts === 0 && trace.counters.attemptLoadedValueBytes === 0 && trace.counters.facadeGet === 0 && trace.counters.facadeScan === 0, 'repeat traversal must use the same populated Attempt');
      for (const key of Object.keys(counts).filter(key => key.startsWith('binding'))) requireThat(trace.counters[key] === null || trace.counters[key] === 0, 'repeat made binding calls');
    }
    if (work !== undefined) checkS0Work(trace, work);
    return { status: 'checked', dependencyComplete: trace.dependency.complete, events: trace.events.length };
  };
}

const I128_MIN = -(1n << 127n), I128_MAX = (1n << 127n) - 1n;
const I64_MIN = -(1n << 63n), I64_MAX = (1n << 63n) - 1n;
const uuid = value => { requireThat(typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value), 'canonical UUID required'); return value; };
function exact(value, min = I128_MIN, max = I128_MAX) {
  requireThat(typeof value === 'string' && /^(0|-?[1-9][0-9]*)$/.test(value), 'canonical exact decimal required');
  const number = BigInt(value); requireThat(number >= min && number <= max, 'exact integer outside native bounds'); return number;
}
const amount = value => { requireThat(value >= I128_MIN && value <= I128_MAX, 'exact amount overflow'); return value; };
const order = (a, b) => exact(a.key, I64_MIN, I64_MAX) < exact(b.key, I64_MIN, I64_MAX) ? -1
  : exact(a.key) > exact(b.key) ? 1 : (uuid(a.id) < uuid(b.id) ? -1 : a.id > b.id ? 1 : a.slot - b.slot);
const canonical = rows => JSON.stringify([...rows].sort((a,b) => a.id < b.id ? -1 : a.id > b.id ? 1 : a.slot-b.slot));

/** Independent full occurrence fold, including empty prefixes and complete-time boundaries. */
export function foldS0Financial(members, { from = null, until = null } = {}) {
  const lower = from === null ? null : exact(from, I64_MIN, I64_MAX);
  const upper = until === null ? null : exact(until, I64_MIN, I64_MAX);
  const identities = new Set();
  for (const member of members) {
    uuid(member.id); requireThat(Number.isSafeInteger(member.slot) && member.slot > 0 && member.slot <= 65535, 'native member slot');
    exact(member.key, I64_MIN, I64_MAX); exact(member.amount);
    const identity = `${member.id}/${member.slot}`; requireThat(!identities.has(identity), 'duplicate member occurrence'); identities.add(identity);
  }
  const rows = [...members].filter(m => (lower === null || BigInt(m.key) >= lower) && (upper === null || BigInt(m.key) < upper)).sort(order);
  let sum = 0n, min = 0n, max = 0n, boundaryMin = null, boundaryMax = null;
  for (let i = 0; i < rows.length; i++) {
    if (i > 0 && rows[i - 1].key !== rows[i].key) {
      boundaryMin = boundaryMin === null || sum < boundaryMin ? sum : boundaryMin;
      boundaryMax = boundaryMax === null || sum > boundaryMax ? sum : boundaryMax;
    }
    sum = amount(sum + exact(rows[i].amount)); min = sum < min ? sum : min; max = sum > max ? sum : max;
  }
  return { count: rows.length, first: rows[0]?.key ?? null, last: rows.at(-1)?.key ?? null,
    sum: String(sum), min_prefix: String(min), max_prefix: String(max),
    boundary_min: boundaryMin === null ? null : String(boundaryMin), boundary_max: boundaryMax === null ? null : String(boundaryMax) };
}

// This is deliberately limited to the frozen S0 Calculation corpus, not a model evaluator.
function sourceFacts(commands) {
  const facts = new Map();
  for (const command of commands) {
    requireThat(command.op === 'create' && [1,2,3,4,5,6,8].includes(command.contract), 'unsupported S0 setup command');
    uuid(command.id); requireThat(!facts.has(command.id), 'duplicate source ID');
    facts.set(command.id, structuredClone(command));
  }
  return facts;
}
function sourceMembers(facts) {
  const members = [];
  const reference = (id, contract) => { uuid(id); const fact = facts.get(id); requireThat(fact?.contract === contract, 'source reference contract unresolved'); return fact; };
  for (const fact of facts.values()) {
    const f = fact.fields;
    if (fact.contract === 8) {
      reference(f.account, 4); exact(f.at, I64_MIN, I64_MAX); exact(f.amount);
      members.push({ id: fact.id, slot: 1, owner: f.account, rootSlot: 2, key: f.at, amount: f.amount });
    }
    if (fact.contract === 6) {
      const rule = reference(f.rule, 1); reference(f.curve, 2); reference(f.account, 4); reference(f.subsidiary, 5);
      const at = exact(f.at, I64_MIN, I64_MAX);
      const quotes = [...facts.values()].filter(q => q.contract === 3 && q.fields.curve === f.curve)
        .map(q => ({ at: exact(q.fields.at, I64_MIN, I64_MAX), rate: exact(q.fields.rate, 1n, 1000n) }));
      requireThat(new Set(quotes.map(q => String(q.at))).size === quotes.length, 'ambiguous quote time');
      const selected = quotes.filter(q => q.at <= at).sort((a,b) => a.at < b.at ? -1 : a.at > b.at ? 1 : 0).at(-1);
      requireThat(selected, 'S0 quote selection unresolved');
      const native = amount(exact(f.units) * exact(rule.fields.c, 1n, 1000n));
      members.push({ id: fact.id, slot: 1, owner: f.account, rootSlot: 2, key: f.at, amount: String(native) },
        { id: fact.id, slot: 2, owner: f.subsidiary, rootSlot: 3, key: f.at, amount: String(amount(native * selected.rate)) });
    }
  }
  return members.sort(order);
}
function rootsFor(corpus, members) {
  return corpus.nByRoot.map(root => ({ owner: root.owner, slot: root.slot,
    summary: foldS0Financial(members.filter(m => m.owner === root.owner && m.rootSlot === root.slot)) }));
}
export function deriveS0Action(corpus, actionId) {
  const matches = corpus.actions.filter(action => action.id === actionId);
  requireThat(matches.length === 1, 'action ID must identify one action'); const action = matches[0];
  const facts = sourceFacts(corpus.setupCommands), beforeMembers = sourceMembers(facts);
  let result = null;
  if (action.kind === 'tree-prefix') result = foldS0Financial(beforeMembers, { until: action.before }).sum;
  else if (action.kind === 'tree-range') result = foldS0Financial(beforeMembers, { from: action.from, until: action.until });
  else if (action.kind === 'native-create') {
    for (const command of action.commands) { requireThat(!facts.has(command.id), 'create target exists'); const created = sourceFacts([command]); facts.set(command.id, created.get(command.id)); }
  } else if (action.kind === 'native-delete') requireThat(facts.delete(action.record), 'delete target absent');
  else if (action.kind === 'native-update') {
    requireThat(facts.has(action.record), 'update target absent'); Object.assign(facts.get(action.record).fields, action.set);
  } else requireThat(false, 'unsupported S0 action');
  const afterMembers = sourceMembers(facts);
  const recalculatedRecords = action.kind === 'native-update' ? [...facts.values()].filter(f => f.contract === 6 && (f.id === action.record || f.fields.rule === action.record)).map(f => f.id).sort() : [];
  return { beforeMembers, afterMembers, beforeRoots: rootsFor(corpus,beforeMembers), afterRoots: rootsFor(corpus,afterMembers), result, recalculatedRecords,
    beforeRecords: [...sourceFacts(corpus.setupCommands).values()], afterRecords: [...facts.values()] };
}

export function checkS0Work(trace, work) {
  const fields = ['work_units','command_visits','route_entries','selector_visits','node_visits','key_loads','loaded_bytes','staged_patches','candidates','evaluations','rotations','causal_candidates','causal_evaluations','dependency_edges','dependency_checks','graph_nodes','scheduler_visits','reader_checks','inventory_visits','allocations','detached_outputs','final_dirty_keys','encoded_bytes'];
  requireThat(work && Object.keys(work).length === fields.length && fields.every(field => Number.isSafeInteger(work[field]) && work[field] >= 0), 'Work requires exact bounded counters');
  const charged = ['command_visits','route_entries','selector_visits','node_visits','key_loads','staged_patches','dependency_edges','dependency_checks','graph_nodes','scheduler_visits','reader_checks','inventory_visits','allocations'];
  const total = charged.reduce((sum, field) => sum + BigInt(work[field]), 0n);
  requireThat(total === BigInt(work.work_units), 'Work charged total mismatch');
  for (const [field, counter] of Object.entries({key_loads:'attemptLoadAttempts',loaded_bytes:'attemptLoadedValueBytes',node_visits:'nodeVisits',selector_visits:'selectorVisits'})) requireThat(work[field] === trace.counters[counter], `Work ${field} differs from trace`);
  return { status: 'checked' };
}

export function checkS0Inputs(manifest, inputBytes) {
  requireThat(manifest.inputs.sha256 === createHash('sha256').update(inputBytes).digest('hex'), 'input hash mismatch');
  const inputs = parseFrame(Buffer.from(inputBytes));
  requireThat(inputs.corpora.length === manifest.inputs.corpusCount, 'corpus count');
  const declared = new Map(inputs.corpora.map(c => [c.id,c]));
  requireThat(declared.size === inputs.corpora.length, 'duplicate corpus');
  for (const selection of manifest.cases) for (const id of selection.corpusIds) {
    const corpus = declared.get(id);
    requireThat(corpus && corpus.m === selection.m, 'manifest corpus/m mismatch');
    requireThat(selection.selectedActionIds.every(id => corpus.actions.some(action => action.id === id)), 'manifest selected action missing');
    if (Array.isArray(selection.n)) requireThat(corpus.nByRoot.every(root => selection.n.includes(root.n)), 'manifest n mismatch');
    if (typeof selection.r === 'number') requireThat(corpus.r === selection.r, 'manifest r mismatch');
    else requireThat(selection.k.includes(corpus.r) && corpus.nByRoot.every(root=>root.n===corpus.r), 'manifest closure dimensions');
  }
  for (const corpus of inputs.corpora) {
    const members = sourceMembers(sourceFacts(corpus.setupCommands));
    requireThat(canonical(members) === canonical(corpus.expectedMembers), 'source-derived members differ');
    requireThat(new Set(members.map(m => m.slot)).size === corpus.m, 'actual member slots');
    const identities = new Set(corpus.nByRoot.map(r => `${uuid(r.owner)}/${r.slot}`));
    requireThat(identities.size === corpus.nByRoot.length && members.every(m => identities.has(`${m.owner}/${m.rootSlot}`)), 'source root inventory differs');
    for (const [i,root] of rootsFor(corpus,members).entries()) {
      requireThat(root.summary.count === corpus.nByRoot[i].n, 'actual per-root n');
      requireThat(root.summary.sum === (corpus.expectedSum ?? corpus.expectedSums[i]), 'source-derived root sum');
    }
    requireThat(new Set(corpus.actions.map(a => a.id)).size === corpus.actions.length, 'duplicate action ID');
    for (const action of corpus.actions) {
      const derived = deriveS0Action(corpus, action.id);
      if (action.kind === 'tree-prefix') requireThat(derived.result === action.expected, 'prefix expectation');
      else if (action.kind === 'tree-range') requireThat(derived.result.sum === action.expectedSum, 'range expectation');
      else {
        const sums = derived.afterRoots.map(root => root.summary.sum);
        requireThat(JSON.stringify(sums) === JSON.stringify(action.expectedSums ?? [action.expectedSum]), 'mutation root expectation');
      }
      if (action.expectedRecalculatedRecords) {
        requireThat(JSON.stringify(derived.recalculatedRecords) === JSON.stringify([...action.expectedRecalculatedRecords].sort()), 'source-derived recalculation closure');
        const target = corpus.setupCommands.find(f => f.id === action.record);
        requireThat(corpus.r === (target.contract === 1 ? derived.recalculatedRecords.length : 0), 'actual dependent r excludes command target');
      } else requireThat(corpus.r === 0, 'unexpected dependent r');
    }
  }
  return { status: 'checked', corpora: declared.size };
}
