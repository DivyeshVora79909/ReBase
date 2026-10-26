# N6 — private operator effect retry

Accepted within this bounded scope on 2026-10-26. All 139 Node tests pass, with
no failures or skips; native effect, host, service and reset controls pass.
[Evidence](evidence/2026-10-26-n6-private-effect-retry.json) records the fresh
working-tree build, exact native inputs, checks and independent review. This is
a development artifact, not a newly packaged committed-source release.

This checkpoint preserves the offline operator retry capability before the
legacy parser can be retired. It adds no public HTTP operation or provider
submission path. Bootstrap and Python/CLI retirement remain later N6 work.

The private `effects.retry` method uses `rebase-native-host-1` and requires an
explicit `effects.retry` operator grant. Its exact parameters are:

```json
{
  "scope": {"model": "<native model hash>", "store": "<store UUID>"},
  "execution_id": "<execution UUID>",
  "if_revision": "<canonical unsigned decimal u64>"
}
```

Native typed binding rejects missing/extra fields, noncanonical UUIDs, numeric
revision substitutes, signs, leading zeros and overflow. The advertised native
configuration schema is the authority for permitted grants. The Node native
handle exposes `retryEffect(params, options)`; a narrowed operator exposes
`retryEffect({ executionId, ifRevision }, options)` and supplies its existing
immutable store/model scope. Revisions remain strings, including zero and the
u64 maximum; they are never converted through JavaScript `Number`.

The host checks its configured model/store scope and rejects its running owned
service. The native retry checks the persisted worker is stopped. A model with
no effect action returns the known private `unsupported_effect` error. The
public HTTP operation API continues to return `method_not_found` for retry.

`Store::retry_effect_scoped` reads and validates the expected runtime store UUID
inside the same write transaction that reads current authority, checks the
execution revision and publishes the existing retry transition. A separate
pre-dispatch read is not the transaction fence. The current caller must retain
target Update authority and be the original requester or an administrator.
Denied authority, stale execution revision, invalid phase and wrong store UUID
publish no partial changes. There is no automatic CAS refresh or retry.

The underlying `Store::retry_effect` semantics are reused: a nonconflicting
blocked application becomes pending; waiting/uncertain or quarantined/conflicting
reconciliation cases reset their observation budget. Retry advances the execution
revision, clears the diagnostic and schedules existing work. It does not change
the immutable request, manufacture a provider outcome or authorize a second
submission after uncertain acceptance. Existing phase, authority, worker,
quarantine and budget controls remain native obligations.

Node admits this as a side-effecting request. An uncertain transport outcome
retains the admitted protocol, request ID, method and exact scope/execution/CAS
parameters. No new operation identity, revision refresh or resubmission is
performed by the wrapper. A lost response is not proof of rollback or success;
the caller retains the original request and observes execution state explicitly.

The bounded controls cover a real blocked effect retried through an owned
private host, granted/nongranted access, running-service rejection, current
requester authority revocation, stale revision, wrong store scope, unchanged
complete images on rejection and unchanged submission-attempt count. A test-only
real-adapter seam commits an actual competing reset at retry write admission:
the outer scope saw the old UUID, the retry transaction sees the new UUID and
returns `wrong_target` without changing the complete post-reset image. This is
local deterministic boundary evidence. FDB protection after the header read
uses the existing transactional read-set contract; this checkpoint adds no
multi-host or failover claim.

Actual-native Node controls use the newly copied default executable recorded in
`target/n6-retry-native-default/runtime-inputs.json`, rather than an older release
without the method. Unit fixtures separately exercise a lost response and exact
request retention. Native model behavior/store/codec identities are unchanged;
the native input fingerprint and executable identity change with this source.
