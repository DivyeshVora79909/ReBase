//! Caller-owned, bounded S0 diagnostics. Never used for admission or persistence.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, MutexGuard},
    thread::{self, ThreadId},
    time::Instant,
};

const MAX_EVENTS: usize = 4096;
const MAX_FACTS: usize = 4096;
// Reserve enough for fixed counters/metadata and conservatively charge each event.
const MAX_TRACE_BYTES: usize = 1_048_576;
#[derive(Clone)]
pub struct Recorder(Arc<Mutex<State>>);
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counters {
    pub logical_touches: u64,
    pub attempt_cache_hits: u64,
    pub attempt_load_attempts: u64,
    pub attempt_loaded_value_bytes: u64,
    pub node_visits: u64,
    pub selector_visits: u64,
    pub facade_get: u64,
    pub facade_scan: u64,
    pub facade_put: u64,
    pub facade_remove: u64,
    pub binding_get: Option<u64>,
    pub binding_get_range: Option<u64>,
    pub binding_set: Option<u64>,
    pub binding_clear: Option<u64>,
    pub binding_clear_range: Option<u64>,
    pub binding_approximate_size: Option<u64>,
    pub returned_rows: u64,
    pub read_key_bytes: u64,
    pub read_value_bytes: u64,
    pub write_key_bytes: u64,
    pub write_value_bytes: u64,
    pub sdk: Option<SdkCounters>,
    pub retry_count: u64,
}
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SdkCounters {
    pub call_get: u64,
    pub call_set: u64,
    pub call_clear: u64,
    pub call_clear_range: u64,
    pub rows_fetched: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub retries: u64,
    pub conflicts: u64,
    pub commit_ms: u64,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub id: u64,
    pub parent_id: Option<u64>,
    pub execution_predecessor_id: Option<u64>,
    pub layer: String,
    pub operation: String,
    pub role: String,
    pub start_ns: u64,
    pub end_ns: u64,
    pub key_token: Option<String>,
    pub key_knowledge: String,
    pub key_discovered_by: Option<u64>,
    pub control_dependencies: Vec<u64>,
    pub outcome: String,
    pub rows: u64,
    pub key_bytes: u64,
    pub value_bytes: u64,
    pub discovered_key_tokens: Vec<String>,
}
#[derive(Clone, Serialize)]
pub struct InitialKey {
    pub token: String,
    pub origin: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    pub complete: bool,
    pub incomplete_reason: Option<String>,
    pub observed_read_depth: Option<u64>,
    pub remote_read_rounds: Option<u64>,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Trace {
    pub format: String,
    pub action_id: String,
    pub attempt_id: String,
    pub backend: String,
    pub path: String,
    pub phase: String,
    pub complete: bool,
    pub incomplete_reasons: Vec<String>,
    pub outcome: String,
    pub duration_ns: u64,
    pub commit_ns: Option<u64>,
    pub counters: Counters,
    pub dependency: Dependency,
    pub events: Vec<Event>,
    pub operation_id: Option<String>,
    pub initial_keys: Vec<InitialKey>,
}
#[derive(Clone)]
struct Fact {
    origin: String,
    source: Option<u64>,
    depth: u64,
}
struct State {
    action: String,
    attempt: String,
    backend: String,
    path: String,
    phase: String,
    started: Instant,
    counters: Counters,
    events: Vec<Event>,
    stack: Vec<u64>,
    last: Option<u64>,
    facts: BTreeMap<String, Fact>,
    initial: Vec<InitialKey>,
    loaded: BTreeSet<String>,
    reasons: Vec<String>,
    header_reasons: Vec<String>,
    dependency_reason: Option<String>,
    depth: u64,
    reserved: usize,
    #[cfg(feature = "foundationdb")]
    sdk: Option<foundationdb::metrics::TransactionMetrics>,
    sdk_baseline: SdkCounters,
    owner: ThreadId,
    active_scopes: u64,
}
impl State {
    fn reason(&mut self, reason: &str) {
        let reason = bounded(reason, 256);
        if self.reasons.len() < 16 && !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }
    fn checked_label(&mut self, value: &str, limit: usize) -> String {
        let result = if value.bytes().any(|b| b < 0x20 || b == b'"' || b == b'\\') {
            "invalid-label".into()
        } else {
            bounded(value, limit)
        };
        if result != value {
            self.reason("metadata-overflow");
        }
        result
    }
    fn same_thread(&mut self) -> bool {
        let same = self.owner == thread::current().id();
        if !same {
            self.reason("cross-thread-activity");
            self.dependency_reason = Some("cross-thread-activity".into());
        }
        same
    }
    fn now(&self) -> u64 {
        self.started.elapsed().as_nanos().min(u64::MAX as u128) as u64
    }
    fn add(&mut self, n: u64, field: fn(&mut Counters) -> &mut u64) {
        let v = field(&mut self.counters);
        if let Some(next) = v.checked_add(n) {
            *v = next
        } else {
            *v = u64::MAX;
            self.reason("counter-overflow");
        }
    }
}
impl Recorder {
    pub fn new(action_id: &str, attempt_id: &str, backend: &str, path: &str, phase: &str) -> Self {
        let mut counters = Counters::default();
        if backend == "foundationdb" {
            counters.binding_get = Some(0);
            counters.binding_get_range = Some(0);
            counters.binding_set = Some(0);
            counters.binding_clear = Some(0);
            counters.binding_clear_range = Some(0);
            counters.binding_approximate_size = Some(0);
        }
        let mut state = State {
            action: identity(action_id),
            attempt: identity(attempt_id),
            backend: bounded(backend, 64),
            path: bounded(path, 64),
            phase: bounded(phase, 64),
            started: Instant::now(),
            counters,
            events: Vec::new(),
            stack: Vec::new(),
            last: None,
            facts: BTreeMap::new(),
            initial: Vec::new(),
            loaded: BTreeSet::new(),
            reasons: Vec::new(),
            header_reasons: Vec::new(),
            dependency_reason: None,
            depth: 0,
            reserved: 65536,
            #[cfg(feature = "foundationdb")]
            sdk: None,
            sdk_baseline: SdkCounters::default(),
            owner: thread::current().id(),
            active_scopes: 0,
        };
        if action_id.len() > 256 || attempt_id.len() > 256 {
            state.reason("identity-overflow");
        }
        if backend.len() > 64 || path.len() > 64 || phase.len() > 64 {
            state.reason("metadata-overflow");
        }
        state.header_reasons = state.reasons.clone();
        Self(Arc::new(Mutex::new(state)))
    }
    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn is_foundationdb(&self) -> bool {
        self.lock().backend == "foundationdb"
    }
    pub fn token(&self, key: &[u8]) -> String {
        let s = self.lock();
        let mut h = Sha256::new();
        h.update(s.action.len().to_be_bytes());
        h.update(s.action.as_bytes());
        h.update(key);
        format!("{:x}", h.finalize())
    }
    pub fn seed_invocation(&self, key: &[u8]) {
        self.seed(key, "invocation");
    }
    pub fn seed_generated(&self, key: &[u8]) {
        self.seed(key, "locally-generated");
    }
    fn seed(&self, key: &[u8], origin: &str) {
        let token = self.token(key);
        let mut s = self.lock();
        if s.facts.contains_key(&token) {
            return;
        }
        if s.facts.len() >= MAX_FACTS || s.reserved + 160 > MAX_TRACE_BYTES {
            s.reason("key-fact-overflow");
            return;
        }
        s.reserved += 160;
        s.initial.push(InitialKey {
            token: token.clone(),
            origin: origin.into(),
        });
        s.facts.insert(
            token,
            Fact {
                origin: origin.into(),
                source: None,
                depth: 0,
            },
        );
    }
    pub fn mark_incomplete(&self, reason: &str) {
        self.lock().reason(reason);
    }
    pub fn mark_dependency_incomplete(&self, reason: &str) {
        let mut s = self.lock();
        s.dependency_reason = Some(s.checked_label(reason, 256));
    }
    pub fn work(&self, kind: &str, count: u64) {
        let mut s = self.lock();
        s.same_thread();
        match kind {
            "node" => s.add(count, |c| &mut c.node_visits),
            "select" => s.add(count, |c| &mut c.selector_visits),
            _ => {}
        }
    }
    pub fn scope(&self, layer: &str, operation: &str, role: &str, key: Option<&[u8]>) -> Scope {
        let token = key.map(|k| self.token(k));
        let mut s = self.lock();
        let tracked = s.same_thread();
        s.active_scopes = s.active_scopes.saturating_add(1);
        let layer = s.checked_label(layer, 64);
        let operation = s.checked_label(operation, 64);
        let role = s.checked_label(role, 64);
        match (layer.as_str(), operation.as_str()) {
            ("attempt", "load") => {
                s.add(1, |c| &mut c.logical_touches);
                s.add(1, |c| &mut c.attempt_load_attempts)
            }
            ("attempt", "cache-hit") => {
                s.add(1, |c| &mut c.logical_touches);
                s.add(1, |c| &mut c.attempt_cache_hits)
            }
            ("facade", "get") => s.add(1, |c| &mut c.facade_get),
            ("facade", "scan") => s.add(1, |c| &mut c.facade_scan),
            ("facade", "put") => s.add(1, |c| &mut c.facade_put),
            ("facade", "remove") => s.add(1, |c| &mut c.facade_remove),
            ("binding", op) => {
                let field = match op {
                    "get" => Some(&mut s.counters.binding_get),
                    "get-range" => Some(&mut s.counters.binding_get_range),
                    "set" => Some(&mut s.counters.binding_set),
                    "clear" => Some(&mut s.counters.binding_clear),
                    "clear-range" => Some(&mut s.counters.binding_clear_range),
                    "approximate-size" => Some(&mut s.counters.binding_approximate_size),
                    _ => None,
                };
                if let Some(v) = field {
                    let next = v.unwrap_or(0).checked_add(1);
                    *v = Some(next.unwrap_or(u64::MAX));
                    if next.is_none() {
                        s.reason("counter-overflow");
                    }
                }
            }
            _ => {}
        }
        let fact = token.as_ref().and_then(|k| s.facts.get(k)).cloned();
        let (knowledge, source, depth) = match fact {
            Some(f) => (f.origin, f.source, f.depth),
            None if token.is_some() => ("unknown".into(), None, 0),
            None => ("not-applicable".into(), None, 0),
        };
        if layer == "attempt" {
            if operation == "load" {
                s.depth = s.depth.max(depth.saturating_add(1));
            }
            if knowledge == "unknown" {
                s.dependency_reason = Some("unknown-key-provenance".into());
            }
        }
        let id = if s.events.len() >= MAX_EVENTS || s.reserved + 1280 > MAX_TRACE_BYTES {
            s.reason("event-overflow");
            None
        } else {
            s.reserved += 1280;
            let id = s.events.len() as u64;
            let now = s.now();
            let parent = tracked.then(|| s.stack.last().copied()).flatten();
            let predecessor = tracked.then_some(s.last).flatten();
            s.events.push(Event {
                id,
                parent_id: parent,
                execution_predecessor_id: predecessor,
                layer: layer.clone(),
                operation: operation.clone(),
                role: role.clone(),
                start_ns: now,
                end_ns: now,
                key_token: token,
                key_knowledge: knowledge,
                key_discovered_by: source,
                control_dependencies: Vec::new(),
                outcome: "definite-abort".into(),
                rows: 0,
                key_bytes: 0,
                value_bytes: 0,
                discovered_key_tokens: Vec::new(),
            });
            if tracked {
                s.stack.push(id);
            }
            Some(id)
        };
        Scope {
            recorder: self.clone(),
            id,
            layer,
            operation,
            finished: false,
            depth: depth.saturating_add(1),
            tracked,
        }
    }
    pub fn reset_phase(&self, phase: &str) {
        let sdk = self.sdk_counters();
        let mut s = self.lock();
        if s.active_scopes != 0 {
            s.reason("reset-active-scope");
            return;
        }
        let binding = s.backend == "foundationdb";
        s.counters = Counters::default();
        if binding {
            s.counters.binding_get = Some(0);
            s.counters.binding_get_range = Some(0);
            s.counters.binding_set = Some(0);
            s.counters.binding_clear = Some(0);
            s.counters.binding_clear_range = Some(0);
            s.counters.binding_approximate_size = Some(0);
        }
        s.sdk_baseline = sdk.unwrap_or_default();
        s.events.clear();
        s.last = None;
        s.reasons = s.header_reasons.clone();
        s.dependency_reason = None;
        s.depth = 0;
        s.phase = s.checked_label(phase, 64);
        s.started = Instant::now();
        s.same_thread();
        let loaded = s.loaded.clone();
        for key in &loaded {
            if !s.facts.contains_key(key) {
                if s.facts.len() < MAX_FACTS {
                    s.facts.insert(
                        key.clone(),
                        Fact {
                            origin: "previously-known".into(),
                            source: None,
                            depth: 0,
                        },
                    );
                } else {
                    s.reason("key-fact-overflow");
                }
            }
        }
        s.initial = s
            .facts
            .iter()
            .map(|(token, fact)| InitialKey {
                token: token.clone(),
                origin: if loaded.contains(token) {
                    "attempt-cache"
                } else if matches!(fact.origin.as_str(), "invocation" | "locally-generated") {
                    &fact.origin
                } else {
                    "previously-known"
                }
                .into(),
            })
            .collect();
        for (key, fact) in &mut s.facts {
            if loaded.contains(key) || fact.source.is_some() {
                fact.origin = "previously-known".into();
            }
            fact.source = None;
            fact.depth = 0;
        }
        s.reserved = 65536 + s.initial.len() * 160;
    }
    pub fn snapshot(&self, outcome: &str, duration_ns: u64, operation_id: Option<String>) -> Trace {
        let sdk = self.sdk_counters();
        let mut s = self.lock();
        s.same_thread();
        if s.active_scopes != 0 {
            s.reason("active-scope");
        }
        let mut counters = s.counters.clone();
        counters.sdk = sdk.map(|a| a.subtract(&s.sdk_baseline));
        if s.backend == "foundationdb" && counters.sdk.is_none() {
            s.reason("sdk-metrics-uncollected");
        }
        let operation_id = operation_id.map(|value| {
            if value.len() > 256 {
                s.reason("identity-overflow");
            }
            identity(&value)
        });
        let outcome = s.checked_label(outcome, 64);
        let reasons = s.reasons.clone();
        let reason = s
            .dependency_reason
            .clone()
            .or_else(|| (!reasons.is_empty()).then(|| "trace-incomplete".into()));
        Trace {
            format: "rebase-s0-trace-1".into(),
            action_id: s.action.clone(),
            attempt_id: s.attempt.clone(),
            backend: s.backend.clone(),
            path: s.path.clone(),
            phase: s.phase.clone(),
            complete: reasons.is_empty(),
            incomplete_reasons: reasons,
            outcome,
            duration_ns: duration_ns.max(s.now()),
            commit_ns: s
                .events
                .iter()
                .find(|e| e.layer == "commit")
                .map(|e| e.end_ns.saturating_sub(e.start_ns)),
            counters,
            dependency: Dependency {
                complete: reason.is_none(),
                incomplete_reason: reason.clone(),
                observed_read_depth: reason.is_none().then_some(s.depth),
                remote_read_rounds: None,
            },
            events: s.events.clone(),
            operation_id,
            initial_keys: s.initial.clone(),
        }
    }
    #[cfg(feature = "foundationdb")]
    pub fn attach_sdk(&self, metrics: foundationdb::metrics::TransactionMetrics) {
        let mut state = self.lock();
        if state.sdk.is_some() {
            state.reason("multiple-instrumented-transactions");
        } else {
            state.sdk = Some(metrics);
        }
    }
    fn sdk_counters(&self) -> Option<SdkCounters> {
        #[cfg(feature = "foundationdb")]
        {
            let metrics = self.lock().sdk.clone()?;
            let r = metrics.get_metrics_data();
            Some(SdkCounters {
                call_get: r.total.call_get,
                call_set: r.total.call_set,
                call_clear: r.total.call_clear,
                call_clear_range: r.total.call_clear_range,
                rows_fetched: r.total.keys_values_fetched,
                bytes_read: r.total.bytes_read,
                bytes_written: r.total.bytes_written,
                retries: r.transaction.retries,
                conflicts: r.transaction.conflict_count,
                commit_ms: r.time.commit_execution_ms,
            })
        }
        #[cfg(not(feature = "foundationdb"))]
        {
            None
        }
    }
}
impl SdkCounters {
    fn subtract(&self, b: &Self) -> Self {
        Self {
            call_get: self.call_get.saturating_sub(b.call_get),
            call_set: self.call_set.saturating_sub(b.call_set),
            call_clear: self.call_clear.saturating_sub(b.call_clear),
            call_clear_range: self.call_clear_range.saturating_sub(b.call_clear_range),
            rows_fetched: self.rows_fetched.saturating_sub(b.rows_fetched),
            bytes_read: self.bytes_read.saturating_sub(b.bytes_read),
            bytes_written: self.bytes_written.saturating_sub(b.bytes_written),
            retries: self.retries.saturating_sub(b.retries),
            conflicts: self.conflicts.saturating_sub(b.conflicts),
            commit_ms: self.commit_ms.saturating_sub(b.commit_ms),
        }
    }
}
pub struct Scope {
    recorder: Recorder,
    id: Option<u64>,
    layer: String,
    operation: String,
    finished: bool,
    depth: u64,
    tracked: bool,
}
impl Scope {
    pub fn id(&self) -> Option<u64> {
        self.id
    }
    /// Disclose actual decoded native addresses only, retaining earliest provenance.
    pub fn disclose(&self, keys: impl IntoIterator<Item = Vec<u8>>) {
        for key in keys {
            let token = self.recorder.token(&key);
            let mut s = self.recorder.lock();
            if s.facts.contains_key(&token) {
                continue;
            }
            let Some(id) = self.id else {
                s.reason("key-fact-overflow");
                continue;
            };
            if s.facts.len() >= MAX_FACTS || s.reserved + 240 > MAX_TRACE_BYTES {
                s.reason("key-fact-overflow");
                continue;
            }
            s.reserved += 240;
            s.facts.insert(
                token.clone(),
                Fact {
                    origin: "result-discovered".into(),
                    source: Some(id),
                    depth: self.depth,
                },
            );
            s.events[id as usize].discovered_key_tokens.push(token);
        }
    }
    pub fn control(&self, source: Option<u64>) {
        if let (Some(id), Some(source)) = (self.id, source) {
            let mut s = self.recorder.lock();
            let deps = &mut s.events[id as usize].control_dependencies;
            if !deps.contains(&source) {
                if deps.len() < 16 {
                    deps.push(source)
                } else {
                    s.reason("control-edge-overflow");
                }
            }
        }
    }
    pub fn finish(mut self, outcome: &str, rows: u64, key_bytes: u64, value_bytes: u64) {
        self.end(outcome, rows, key_bytes, value_bytes);
    }
    fn end(&mut self, outcome: &str, rows: u64, key_bytes: u64, value_bytes: u64) {
        if self.finished {
            return;
        }
        self.finished = true;
        let mut s = self.recorder.lock();
        s.active_scopes = s.active_scopes.saturating_sub(1);
        s.same_thread();
        let outcome = s.checked_label(outcome, 64);
        if self.layer == "attempt" && self.operation == "load" {
            s.add(value_bytes, |c| &mut c.attempt_loaded_value_bytes)
        }
        let primitive = if s.backend == "foundationdb" {
            "binding"
        } else {
            "facade"
        };
        if self.layer == primitive {
            if matches!(self.operation.as_str(), "get" | "get-range" | "scan") {
                s.add(rows, |c| &mut c.returned_rows);
                s.add(key_bytes, |c| &mut c.read_key_bytes);
                s.add(value_bytes, |c| &mut c.read_value_bytes)
            } else if matches!(
                self.operation.as_str(),
                "set" | "put" | "remove" | "clear" | "clear-range"
            ) {
                s.add(key_bytes, |c| &mut c.write_key_bytes);
                s.add(value_bytes, |c| &mut c.write_value_bytes)
            }
        }
        if let Some(id) = self.id {
            let now = s.now();
            if self.layer == "attempt"
                && self.operation == "load"
                && matches!(outcome.as_str(), "found" | "missing")
                && let Some(token) = s.events[id as usize].key_token.clone()
            {
                if s.loaded.len() < MAX_FACTS {
                    s.loaded.insert(token);
                } else {
                    s.reason("key-fact-overflow");
                }
            }
            let event = &mut s.events[id as usize];
            event.end_ns = now;
            event.outcome = outcome;
            event.rows = rows;
            event.key_bytes = key_bytes;
            event.value_bytes = value_bytes;
            if self.tracked {
                if s.stack.last() == Some(&id) {
                    s.stack.pop();
                } else {
                    s.reason("scope-order-incomplete");
                }
                s.last = Some(id);
            }
        }
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        self.end("definite-abort", 0, 0, 0)
    }
}
pub fn error_outcome(error: &crate::native_slice::Error) -> &'static str {
    match error.code {
        "outcome_unknown" => "unknown",
        "transaction_conflict" => "conflict",
        _ => "definite-abort",
    }
}

// Payload bounds apply even when a caller supplies arbitrary diagnostic labels.
fn bounded(value: &str, limit: usize) -> String {
    let mut end = value.len().min(limit);
    while !value.is_char_boundary(end) {
        end -= 1
    }
    value[..end].to_owned()
}
fn identity(value: &str) -> String {
    if value.len() <= 256 {
        value.into()
    } else {
        format!("sha256:{:x}", Sha256::digest(value.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recorder() -> Recorder {
        Recorder::new("action", "attempt", "redb", "native-tree", "attempt-first")
    }

    #[test]
    fn diagnostic_bounds_keep_counts_and_explicit_incompleteness() {
        let trace = recorder();
        for key in 0u64..5000 {
            trace.seed_invocation(&key.to_be_bytes());
            trace
                .scope("facade", "get", "native", None)
                .finish("missing", 0, 0, 0);
        }
        trace
            .scope("commit", "commit", "other", None)
            .finish("success", 0, 0, 0);
        let report = trace.snapshot("success", 0, None);
        assert_eq!(
            report.commit_ns, None,
            "truncated actual commit has no retained duration witness"
        );
        assert!(!report.complete);
        assert!(report.incomplete_reasons.contains(&"event-overflow".into()));
        assert!(
            report
                .incomplete_reasons
                .contains(&"key-fact-overflow".into())
        );
        assert_eq!(report.counters.facade_get, 5000);
        assert!(report.events.len() <= MAX_EVENTS);
        assert!(report.initial_keys.len() <= MAX_FACTS);
        assert!(serde_json::to_vec(&report).unwrap().len() <= MAX_TRACE_BYTES);

        let oversized = "\u{0}".repeat(10000);
        let labels = Recorder::new(&oversized, &oversized, "redb", "native-tree", "control");
        for _ in 0..1500 {
            labels
                .scope(&oversized, &oversized, &oversized, None)
                .finish(&oversized, u64::MAX, u64::MAX, u64::MAX);
        }
        let report = labels.snapshot("success", 0, Some(oversized));
        assert!(report.action_id.starts_with("sha256:"));
        assert!(
            report
                .incomplete_reasons
                .contains(&"identity-overflow".into())
        );
        assert!(
            report
                .incomplete_reasons
                .contains(&"metadata-overflow".into())
        );
        assert!(serde_json::to_vec(&report).unwrap().len() <= MAX_TRACE_BYTES);
    }

    #[test]
    fn diagnostic_unknown_provenance_and_counter_overflow_are_explicit() {
        let trace = recorder();
        trace
            .scope("attempt", "load", "native", Some(b"unknown"))
            .finish("missing", 0, 0, 0);
        let report = trace.snapshot("success", 0, None);
        assert!(!report.dependency.complete);
        assert_eq!(
            report.dependency.incomplete_reason.as_deref(),
            Some("unknown-key-provenance")
        );
        assert_eq!(report.dependency.observed_read_depth, None);
        trace.lock().counters.binding_get = Some(u64::MAX);
        trace
            .scope("binding", "get", "data", None)
            .finish("missing", 0, 0, 0);
        let report = trace.snapshot("success", 0, None);
        assert_eq!(report.counters.binding_get, Some(u64::MAX));
        assert!(
            report
                .incomplete_reasons
                .contains(&"counter-overflow".into())
        );
    }

    #[test]
    fn diagnostic_cross_thread_activity_has_no_fabricated_scope_parent() {
        let trace = recorder();
        let outer = trace.scope("attempt", "load", "native", None);
        let other = trace.clone();
        std::thread::spawn(move || {
            other
                .scope("facade", "get", "native", None)
                .finish("missing", 0, 0, 0);
        })
        .join()
        .unwrap();
        outer.finish("missing", 0, 0, 0);
        let report = trace.snapshot("success", 0, None);
        assert!(
            report
                .incomplete_reasons
                .contains(&"cross-thread-activity".into())
        );
        assert_eq!(report.events[1].parent_id, None);
        assert_eq!(report.events[1].execution_predecessor_id, None);
        assert!(!report.dependency.complete);
    }

    #[test]
    fn diagnostic_error_outcomes_preserve_unknown_and_conflict() {
        for (code, outcome) in [
            ("outcome_unknown", "unknown"),
            ("transaction_conflict", "conflict"),
            ("transaction_limit", "definite-abort"),
            ("invariant", "definite-abort"),
        ] {
            assert_eq!(
                error_outcome(&crate::native_slice::Error::new(code, "control")),
                outcome
            );
        }
    }
    #[test]
    fn diagnostic_reset_retains_header_limits_and_unknown_cache_lineage() {
        let trace = Recorder::new(
            &"a".repeat(300),
            "attempt",
            "redb",
            "native-tree",
            "attempt-first",
        );
        trace.reset_phase("attempt-repeat");
        let report = trace.snapshot("success", 0, None);
        assert!(!report.complete);
        assert!(
            report
                .incomplete_reasons
                .contains(&"identity-overflow".into())
        );
        let trace = recorder();
        trace
            .scope(
                "attempt",
                "cache-hit",
                "native",
                Some(b"unrecorded-before-overflow"),
            )
            .finish("success", 0, 0, 0);
        let report = trace.snapshot("success", 0, None);
        assert!(!report.dependency.complete);
        assert_eq!(
            report.dependency.incomplete_reason.as_deref(),
            Some("unknown-key-provenance")
        );
        assert_eq!(trace.lock().depth, 0);
    }
}
