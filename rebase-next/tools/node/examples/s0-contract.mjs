// S0 evidence checks, separate from the public SDK. No process or IO on import.
import { createHash } from 'node:crypto';
import { createNativeAjv } from '../private/config-validation.mjs';

const requireThat = (value, message) => { if (!value) throw new Error(`S0 contract: ${message}`); };

export function prepareS0TraceCheck(schema) {
  const validate = createNativeAjv().compile(schema);
  return trace => {
    requireThat(validate(trace), JSON.stringify(validate.errors));
    requireThat(Buffer.byteLength(JSON.stringify(trace)) <= 1_048_576, 'trace byte bound');
    const byId = new Map();
    const depths = new Map();
    const known = new Map();
    for (const key of trace.initialKeys) {
      requireThat(!known.has(key.token), 'duplicate initial key');
      requireThat(key.origin !== 'attempt-cache' || trace.phase === 'attempt-repeat', 'cache witness requires repeat phase');
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
      const allowed = { attempt:['load','cache-hit'],facade:['get','scan','put','remove'],binding:['get','get-range','set','clear','clear-range'],commit:['commit'] };
      requireThat(allowed[event.layer].includes(event.operation), 'invalid layer/operation pair');
      if (event.layer === 'attempt') {
        requireThat(event.keyToken !== null, 'Attempt key token required');
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
      requireThat(trace.events.every(e => e.keyKnowledge !== 'unknown'), 'unknown key lineage');
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
      for (const key of Object.keys(counts).filter(key => key.startsWith('binding'))) requireThat(trace.counters[key] === null, 'embedded binding counter must be absent');
    } else if (trace.complete) {
      requireThat(trace.counters.sdk !== null && Object.keys(counts).filter(key=>key.startsWith('binding')).every(key=>trace.counters[key] !== null), 'complete FDB trace requires supported metrics');
    }
    return { status: 'checked', dependencyComplete: trace.dependency.complete, events: trace.events.length };
  };
}

// Independent source expectations for the small declared Calculation corpus.
// This reads plain source facts and uses literal products; no native engine call.
export function checkS0Inputs(manifest, inputBytes) {
  requireThat(manifest.inputs.sha256 === createHash('sha256').update(inputBytes).digest('hex'), 'input hash mismatch');
  const inputs = JSON.parse(inputBytes);
  requireThat(inputs.corpora.length === manifest.inputs.corpusCount, 'corpus count');
  const declared = new Map(inputs.corpora.map(c => [c.id,c]));
  for (const selection of manifest.cases) for (const id of selection.corpusIds) {
    const corpus = declared.get(id);
    requireThat(corpus && corpus.m === selection.m, 'manifest corpus/m mismatch');
    requireThat(selection.selectedActionIds.every(id => corpus.actions.some(action => action.id === id)), 'manifest selected action missing');
    if (Array.isArray(selection.n)) requireThat(corpus.nByRoot.every(root => selection.n.includes(root.n)), 'manifest n mismatch');
    if (typeof selection.r === 'number') requireThat(corpus.r === selection.r, 'manifest r mismatch');
    else requireThat(selection.k.includes(corpus.r) && corpus.nByRoot.every(root=>root.n===corpus.r), 'manifest closure dimensions');
  }
  const cases = new Set();
  for (const corpus of inputs.corpora) {
    requireThat(!cases.has(corpus.id), 'duplicate corpus'); cases.add(corpus.id);
    const facts = new Map(corpus.setupCommands.map(command => [command.id, command]));
    requireThat(facts.size === corpus.setupCommands.length, 'duplicate source ID');
    const members = [];
    for (const fact of facts.values()) {
      const f = fact.fields;
      if (fact.contract === 8) members.push({ id: fact.id, slot: 1, owner: f.account, rootSlot: 2, key: f.at, amount: f.amount });
      if (fact.contract === 6) {
        const rule = facts.get(f.rule), curve = facts.get(f.curve);
        requireThat(rule?.contract === 1 && curve?.contract === 2, 'Posting reference contract');
        const quotes = [...facts.values()].filter(q => q.contract === 3 && q.fields.curve === curve.id && BigInt(q.fields.at) <= BigInt(f.at)).sort((a, b) => BigInt(a.fields.at) < BigInt(b.fields.at) ? -1 : 1);
        const rate = BigInt(quotes.at(-1)?.fields.rate ?? '1');
        const native = BigInt(f.units) * BigInt(rule.fields.c);
        members.push({ id: fact.id, slot: 1, owner: f.account, rootSlot: 2, key: f.at, amount: String(native) }, { id: fact.id, slot: 2, owner: f.subsidiary, rootSlot: 3, key: f.at, amount: String(native * rate) });
      }
    }
    const canonical = rows => JSON.stringify([...rows].sort((a,b) => a.id.localeCompare(b.id) || a.slot-b.slot));
    requireThat(canonical(members) === canonical(corpus.expectedMembers), 'source-derived members differ');
    requireThat(new Set(members.map(m => m.slot)).size === corpus.m, 'actual member slots');
    for (const root of corpus.nByRoot) {
      const selected = members.filter(m => m.owner === root.owner && m.rootSlot === root.slot);
      requireThat(selected.length === root.n, 'actual per-root n');
      const sum = selected.reduce((s,m) => s + BigInt(m.amount), 0n);
      const expected = corpus.expectedSum ?? corpus.expectedSums[corpus.nByRoot.indexOf(root)];
      requireThat(String(sum) === expected, 'source-derived root sum');
    }
    const actionIds = new Set();
    for (const action of corpus.actions) {
      requireThat(!actionIds.has(action.id), 'duplicate action ID'); actionIds.add(action.id);
      if (action.record) requireThat(facts.has(action.record), 'action target absent');
      const sum = rows => String(rows.reduce((total, member) => total + BigInt(member.amount), 0n));
      if (action.kind === 'tree-prefix') requireThat(sum(members.filter(m => BigInt(m.key) < BigInt(action.before))) === action.expected, 'prefix expectation');
      if (action.kind === 'tree-range') requireThat(sum(members.filter(m => BigInt(m.key) >= BigInt(action.from) && BigInt(m.key) < BigInt(action.until))) === action.expectedSum, 'range expectation');
      if (action.kind.startsWith('native-')) {
        const after = structuredClone(members);
        if (action.kind === 'native-create') for (const command of action.commands) after.push({ amount: command.fields.amount });
        else if (action.kind === 'native-delete') after.splice(after.findIndex(m => m.id === action.record), 1);
        else for (const member of after) {
          const fact = facts.get(member.id);
          if (fact.contract === 8 && member.id === action.record) member.amount = action.set.amount;
          if (fact.contract === 6) {
            const units = BigInt(member.id === action.record ? action.set.units : fact.fields.units);
            const c = BigInt(fact.fields.rule === action.record ? action.set.c : facts.get(fact.fields.rule).fields.c);
            member.amount = String(units * c * (member.slot === 1 ? 1n : 3n));
          }
        }
        if (action.expectedSum !== undefined) requireThat(sum(after) === action.expectedSum, 'mutation sum expectation');
        else for (const [i, root] of corpus.nByRoot.entries()) requireThat(sum(after.filter(m => m.owner === root.owner && m.rootSlot === root.slot)) === action.expectedSums[i], 'mutation root expectation');
      }
      if (action.expectedRecalculatedRecords) {
        const target = facts.get(action.record);
        const affected = [...facts.values()].filter(f => f.contract === 6 && (f.id === action.record || f.fields.rule === action.record)).map(f => f.id).sort();
        requireThat(JSON.stringify(affected) === JSON.stringify([...action.expectedRecalculatedRecords].sort()), 'source-derived recalculation closure');
        requireThat(corpus.r === (target.contract === 1 ? affected.length : 0), 'actual dependent r excludes command target');
      } else requireThat(corpus.r === 0, 'unexpected dependent r');
    }
  }
  return { status: 'checked', corpora: cases.size };
}
