# JavaScript developer functions

`tools/node/index.mjs` is the explicit public ESM barrel for the current
developer functions. It requires Node 24 or newer and has no network, process,
filesystem or service effects on import. Functions perform work only when the
caller invokes them. Complete examples under `tools/node/examples/` show
specific compositions and remain examples, not exports promoted into the SDK.
N6 bootstrap and extracted-release acceptance are pending; see the
[G10 program](../research/56-node-and-index-redesign-program.md) for status.

The barrel exports these groups:

- `parseEnvironment` and `resolveConfig` compose an explicit Node runner and
  native launch configuration.
- `openNative` starts an owned `rebase-next host` process when called and
  returns a caller-owned handle. Close it in a `finally` block. `prepareModel`
  composes the native public catalog with the prepared model functions.
- `connect` creates a stateless authenticated HTTP client. It does not send a
  request until a method is called. `prepare` binds a draft to the current
  model, store, actor, credential epoch and operation context; `execute` and
  `status` recheck the captured target before sending. `savePlan` persists a
  detached plan with write-once semantics.
- `preparePopulation`, `propose`, `accept` and `reject` manage caller-owned
  population state. The proposal is local input generation; the server still
  enforces authority, references, limits and invariants.
- `openOperator` narrows grants on an already-owned native handle and exact
  model/store scope. It does not open another store or process.
- `runWorkload`, `walk`, `explore`, `logicalReplay`, `shrinkFailure`, the
  scenario helpers, resource observers and source oracles compose bounded
  caller-selected workflows and checks.
- `checkBackupStructure` checks a backup's declared structure; it does not
  replace native integrity verification. `openFdbEnvironment` starts a local
  disposable test environment when called.
- `prepareReleaseSource`, `describeReleaseBuild`, `packageRelease` and
  `verifyRelease` implement the bounded N5 packaging workflow. Its recorded
  evidence does not complete N6 acceptance.

From the `rebase-next/` directory, start the standard Node 24 REPL and use
dynamic import (the REPL accepts top-level `await`):

```js
const { connect, preparePopulation, openNative } = await import('./tools/node/index.mjs');
```

The [N2 Equipment](../tools/node/examples/n2-equipment-workflow.mjs) and
[N3 population](../tools/node/examples/n3-population.mjs) examples show full
caller-owned compositions. The [N5 lifecycle](../tools/node/examples/n5-lifecycle.mjs)
and [release](../tools/node/examples/n5-release.mjs) examples show additional
scoped workflows. N6's [signed ingress](../tools/node/examples/n6-signed-ingress.mjs)
and [IssueShare](../tools/node/examples/n6-issue-share.mjs) modules remain
examples and are not general HTTP middleware or SDK methods.

## Client plans and retry context

Prepare a plan once and retain it with its operation ID and original
`operation_context`. Reusing the same plan lets the server return the original
receipt after a lost response. A timeout is an unknown outcome; do not refresh
the context or change the operation ID to make an uncertain write appear new.
`status` reads the operation receipt after verifying the same target. A
committed receipt may omit a projection if the caller no longer has permission
to read that record version. Receipt absence alone does not prove that an earlier
request failed.

The client validates JSON size and shape, rejects unsafe JSON numbers and
noncanonical identifiers, and requires explicit token material or a token
provider. Remote cleartext HTTP is disabled unless the caller opts in. Credentials,
private plans and retained result directories should remain private. See the
[server guide](server.md) for bearer authentication, request limits and
unknown-outcome behavior.

## Model and query behavior

Native catalogs are authoritative for model schemas, public contracts and
capabilities. The JavaScript helpers do not author or replace server schemas,
calculation rules, references or authorization. Public catalogs exclude private
roles and fixture recipes. Developer catalogs can describe these details for
local tooling, but submitted mutations still pass native validation and current
authority checks.

Public reads use fresh graph scopes from the same snapshot as their data. Query
cursors are tied to their reader/contract epochs and authority revision. A
changed public derivation or relevant authority graph invalidates affected
cursors; scalar residual predicates still consume visit budget. See
[local model semantics](local-prototype.md) and [storage](storage.md) for the
technical contracts; command examples from earlier Python campaigns are dated
research evidence, not current operating instructions.
