# N1 — Node configuration and native host result

Status: **N1 accepted on 2026-10-25 within the bounded host contract.** This
checkpoint implements shared Node configuration and a private structured host
for model catalogs and redb check/inspection. It does not replace the existing
Python developer workflows or accept later Node, service, or storage work.

`tools/node/config.mjs` exports `parseEnvironment` and `resolveConfig`.
`tools/node/native.mjs` exports `openNative`; the returned owned handle exposes
`describe`, `catalog`, granted `check`/`inspect`, bounded `diagnostics` and
idempotent `close`. The native model catalog and configuration schema remain the
authority. JavaScript validates local shape and obtains compiled selectors,
configuration schema and hard limits from `host.describe` before configuration
can open a store. No model selector registry is duplicated in JavaScript.

For example, a caller composes ordinary imports around an explicit host config:

```js
import { parseEnvironment, resolveConfig } from './tools/node/config.mjs';
import { openNative } from './tools/node/native.mjs';

const config = resolveConfig({
  defaults: {
    native: { binary: '/absolute/path/to/rebase-next', environment: {} },
  },
  environment: parseEnvironment(process.env),
  overrides: {
    native: {
      configuration: {
        model: 'equipment',
        backend: { kind: 'redb', cluster_file: null },
        target: null,
        operator_methods: [],
      },
    },
  },
});

const host = await openNative(config);
try {
  const catalog = await host.catalog({ scope: 'public' });
  console.log(catalog);
} finally {
  await host.close();
}
```

The same complete example is in [the N1 model-catalog module](../tools/node/examples/n1-model-catalog.mjs).
The executable path is explicit and must identify a built `rebase-next` binary.
The owner starts it with the fixed `host` argument, private stdin/stdout pipes,
and only the caller-provided child environment. N1 host store ownership is
redb-only. Other backends may be reported as compiled features, but N1 does not
claim to own them.

The native owner ran focused offline Rust verification using the shared
`CARGO_HOME=/workspace/.rebase-tools/rust-review/cargo` cache and
`CARGO_TARGET_DIR=target/verification-build`:

- The native host integration target passed 11 tests. The focused library host
  test passed 1 test; 93 unrelated library tests were filtered out.
- The all-features `rebase-next` binary check passed, as did `cargo fmt --check`
  and scoped Clippy with warnings denied.
- Node 24.22.1 / npm 11.19.1 `npm test` passed 36 tests with no skips. The scoped
  npm audit reported zero vulnerabilities. The real-host cases exercised all
  six catalogs and secured redb create/check/inspect, plus ownership and
  wrong-target controls.
- Independent review passed after fixes for abort draining, close admission and
  timeout escalation, diagnostic redaction before truncation, and UTF-8 byte
  bounds at small tails.

Negative controls cover malformed, duplicate, oversized and invalid-Unicode
frames; invalid or unknown configuration and grants; response loss after
configure; wrong model/store with unchanged bytes; exclusive create; same- and
cross-process ownership; clean EOF and close; forced termination recovery; and
denial of private methods through public RPC. Native tests used stable local
paths. They do not claim adversarial filesystem isolation.

The Node runner's detailed [execution record](../tools/node/test/n1-execution.json)
captures the exact test output, runtime, audit result and implementation hashes.
The reviewed native binary is
`target/verification-build/debug/rebase-next`, SHA-256
`ef3c26e9abc77853e59b85be32cf81ba153ddec67f81f988b66b172869c72633`. Rust
source, test, Node source, lockfile and binary hashes are recorded in the
[N1 evidence record](evidence/2026-10-25-n1-native-host.json). Cargo reused the
offline registry cache and shared target; no FDB process was started. The
all-features check proves compilation only.

N2 remains responsible for service ownership, credentials, backup/restore,
archive/reset, and FoundationDB or SurrealKV host ownership and recovery. N3–N6
still own population, workloads, packaging and the Python/legacy CLI retirement.
S0–S3 ordered-storage work remains pending; N1 makes no storage-layout or
capacity claim.
