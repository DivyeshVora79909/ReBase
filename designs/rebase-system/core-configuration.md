# Core configuration and verification reference

Source snapshot: 2026-09-28, HEAD `a6626c0` plus the audited working tree and
the K1–K3 core stabilization continuation. This describes the **current
implementation**. K4 in the
[handoff](./core-handoff.md) deliberately change some of these contracts;
update this file when they do. Defaults below are not blanket recommendations.

## 1. Configuration resolution

`config/environment.js` is authoritative. Entrypoints resolve one process
environment into a validated, deeply frozen object. Node loads optional files:

```bash
node --env-file=.env.local gateway/server.js
node --env-file=.env.local dev-tools/compiler/cli.js
```

The file option belongs to **Node before the script**. The application does
not parse `.env` automatically. Inherited process values take precedence over
the file. Compiler callers inject a complete validated `configuration`;
`startServer` uses the option name `config`. A second resolver override bag or
connection-related CLI flags is rejected.

Missing/null values select defaults. Empty numeric and boolean strings are
invalid. String settings generally trim whitespace; secrets preserve their
nonempty original text. Boolean strings accept `true/1/yes/on` and
`false/0/no/off`. Integer inputs must be safe integers within their setting's
range. Unknown structured-configuration fields fail; unrelated process env
keys are not all rejected.

## 2. Connection, context, and event binding

| Environment variable | Default | Contract |
|---|---|---|
| `NODE_ENV` | `development` | Only `development`, `test`, or `production`; production activates additional startup guards. |
| `SURREAL_ENDPOINT` | Absent | `ws`, `wss`, `http`, or `https`; provide with username/password. |
| `SURREAL_USERNAME` | Absent | System connection identity. This app does not read `SURREAL_USER`. |
| `SURREAL_PASSWORD` | Absent | Secret; this app does not read `SURREAL_PASS`. |
| `SURREAL_NAMESPACE` | Absent | Must accompany database; simple SurrealDB identifier. |
| `SURREAL_DATABASE` | Absent | Must accompany namespace. |
| `SURREAL_CONNECT_TIMEOUT_MS` | `10000` | Positive integer. |
| `REBASE_ALLOWED_CONTEXTS` | `[]` | JSON array of unique `{namespace,database}` objects; no extra keys or wildcard. |
| `REBASE_RUNTIME_URL` | Absent | `http`/`https`; must accompany runtime secret. |
| `REBASE_RUNTIME_SECRET` | Absent | Internal service/event capability; protect generated bound artifacts too. |

The default namespace/database is added to the allowed contexts if missing.
Compiling without any connection details is valid. Starting connected tools
requires the connection triple; runtime startup needs configured contexts.
URL validation rejects embedded username/password and fragments, including
in Redis URLs. Authenticated Redis URL support is therefore **not implemented
by the current profile parser**; do not invent a password option to work around
it in deployment instructions.

There are two independent compiler facts:

- No namespace/database means a context-neutral artifact.
- No runtime URL/secret means external-effect HTTP events are omitted.

A neutral build that parses successfully does not prove bound event dispatch.
Compile and check with the same profile. Never dump a bound schema or
`--print-raw` output into a public log without checking for embedded secrets.

## 3. HTTP and reconciliation

| Environment variable | Default | Valid values / meaning |
|---|---|---|
| `REBASE_HTTP_HOST` | `127.0.0.1` | Listener address. |
| `REBASE_HTTP_PORT` | `8788` | `0..65535`; zero is useful for disposable tests. |
| `REBASE_HTTP_BODY_LIMIT_BYTES` | `262144` | Positive integer; raw request limit. |
| `REBASE_HTTP_REQUEST_TIMEOUT_MS` | `30000` | Positive integer. |
| `REBASE_HTTP_DEBUG` | `false` | Boolean; `.env.example` currently explicitly sets `true`. |
| `REBASE_RECONCILE_INTERVAL_MS` | `60000` | At least `1000` and strictly less than the fixed `300000ms` queue horizon. |
| `REBASE_TERMINAL_TASK_RETENTION_DAYS` | `30` | Integer `1..3650`; durable terminal task cleanup. |

There is no `REBASE_QUEUE_HORIZON_MS` environment setting. The fixed five-minute
horizon lives in `config/runtime-timing.js`; the runtime derives the database
query duration from the same milliseconds value it uses for queue admission.
Each scan schedules its next scan one interval after the completed run. An
entirely admitted page with a durable cursor schedules a prompt continuation;
queue-capacity or publishing deferral waits for the regular interval. The scan
interval is a best-effort cadence, not a strict end-to-end lateness bound under
long scans, many contexts, or sustained capacity exhaustion.

## 4. Queue and storage

| Environment variable | Default | Contract |
|---|---|---|
| `REBASE_QUEUE_PREFIX` | `rebase` | Starts alphanumeric; remaining characters `[A-Za-z0-9_.:-]`. Use isolated prefixes in probes. |
| `REBASE_QUEUE_REDIS_URL` | Absent | `redis`/`rediss`, currently without embedded credentials. Required by the normal BullMQ startup path. |
| `REBASE_QUEUE_REDIS_CONNECT_TIMEOUT_MS` | `5000` | Positive integer. |
| `REBASE_QUEUE_STARTUP_TIMEOUT_MS` | `10000` | Positive integer. |
| `REBASE_QUEUE_HEALTH_TIMEOUT_MS` | `2000` | Positive integer. |
| `REBASE_QUEUE_DRIVER` | Absent | If supplied, only `bullmq` is accepted; no SQS path. |
| `REBASE_STORAGE_BUCKET` | Absent | Shared bucket; generated object keys include context isolation. |

Provider API credentials are typed database data. Do not add Brevo/Twilio/S3
tenant secrets to the shared process config. The shared bucket name is an
infrastructure setting; per-tenant bucket selection is not the current contract.

## 5. Authentication

| Environment variable | Default | Contract |
|---|---|---|
| `REBASE_AUTHENTICATION_PAYLOAD_SECRET` | Absent | Stable encryption key for queued challenge payloads; production requires at least 32 bytes when principal auth is enabled. |
| `REBASE_AUTHENTICATION_CHALLENGE_TTL_MS` | `600000` | Integer `60000..86400000`. |
| `REBASE_AUTHENTICATION_RATE_LIMIT_WINDOW_MS` | `900000` | Integer at least `1000`. |
| `REBASE_AUTHENTICATION_RATE_LIMIT_IP` | `10` | Integer at least one per window. |
| `REBASE_AUTHENTICATION_RATE_LIMIT_IDENTIFIER` | `3` | Integer at least one per window. |

Use a separate value for payload encryption and runtime event authentication.
The code requires a production payload key and its minimum length, but does
not currently reject equality with the runtime secret. Development can fall
back to the runtime secret; that fallback is not key-rotation support.
Preserve the key while pending encrypted tasks still need it.

Current typed provider fields:

| Table | Fields | Current boundary |
|---|---|---|
| `rebase_email_delivery_config` | `api_key`, `from_email`, `from_name`, optional `reply_to` | Table and fields are native private; no generated owner metadata. |
| `rebase_sms_delivery_config` | `account_sid`, optional `auth_token`, optional `api_key_sid`/`api_key_secret`, `from_number` | Native private; Twilio adapter consumes the supported credential form. |
| `rebase_authentication_delivery_policy:default` | Optional references `email_configuration`, `phone_configuration` | Private, developer-populated auth selector. |

The two credential tables exist, but shared root-group ownership and ordinary
authenticated reuse are **K4 work**, not implemented by the current private
schema. Identity tables (`authentication_email`/`authentication_phone`) identify
recipients; they are not provider credential stores. Auth service routing uses
an allowlisted context and existing identity, not arbitrary guest record input.

`REBASE_TEST_RECORD__*` entries in `.env.example` are documentation-only fixture
placeholders. The shared resolver does not load them into database rows.
Development provisioning is an explicit developer operation. Do not print the
personal `.env` or use real service keys in disposable verification.

## 6. Internal options and constants, not environment switches

| Source | Setting | Current value / caveat |
|---|---|---|
| `gateway/runtime.js` options | `maxPatchBytes` | `65536`; bounds an allowed handler patch. |
| Same | `leaseMs` | `120000`; task execution lease. |
| Same | `maxTaskAttempts` | `5`. |
| Same | `queueHorizonMs` | Shared `QUEUE_HORIZON_MS`, currently `300000`; its query duration is formatted from this same value. |
| Same | `reconcilePageSize` | `100`. |
| Same | `terminalTaskRetentionMs` | 30 days; explicitly validates a positive safe integer. Server derives it from days. |
| `gateway/queues/bullmq.js` policy | attempts / base backoff / concurrency | `5` / `1000ms` / `8`. |
| Same, admission | `maxLiveHints` / `receiptReserve` | `1000` / `100`; max at least 2, reserve from 0 to max minus 1. |
| Same, admission | Redis boundary | Capacity count and BullMQ job insertion share one Lua script execution; no distributed admission lease is used. The custom insertion adapter is tied to BullMQ `6.2.0`. |
| Same, worker | `lockDurationMs` | `30000`; distinct from the task execution lease. |
| Same, priority | operation / receipt | Operation `10..100`, default 50; receipt exactly 1. Smaller runs first. |
| Same, completed jobs | `removeOnComplete` | Age 3600 seconds, count 1000. |
| Same, failed jobs | `removeOnFail` | Age 7 days, count 5000. |
| Same, dead-letter diagnostics | `deadLetterRetentionMs` / prune interval / batch | `30 days` / `60 seconds` / up to `1000` waiting diagnostics per pass. Startup and periodic cleanup remove expired entries; this is an age policy, not a hard count or memory bound. |

Several other constructor options still use `||` defaults. They are not uniformly
validated configuration APIs. Verify allowed zero/absence behavior at the
specific call site before exposing a knob. A live-hint count is not a Redis
memory limit: completed, failed, dead-letter jobs and metadata also occupy space.

## 7. Compiler switches and artifact discipline

```bash
node dev-tools/compiler/cli.js --project designs/test --output build/test
node dev-tools/compiler/cli.js --project designs/test --output build/test --check
surreal validate build/test/schema.surql
```

Existing switches: `--project` (alias `--source`), `--framework`, `--output`,
`--check`, `--print-raw`, `--no-root-permissions`, `--help`. Default project is
`designs/test`, framework `framework`, output `build/<project basename>`.
Root permission bootstrap is included unless explicitly disabled.

The `gateway/server.js` executable currently accepts **no application flags**
and loads `build/test`. For a different compiled artifact directory, the
existing JavaScript API accepts `startServer({ config, projectDir })` (or its
`project` basename option). Do not invent `--project` support on the server or
assume the compiler's project switch configures the runtime.

`--check` does not refresh artifacts. A stale-output failure may indicate
changed inputs or a different profile; compare those before rebuilding.
Generated artifacts are not the source of truth. Never repair only a generated
schema. `runtime-contracts.json` and generated handlers are private deployment
artifacts. Migration SQL is a separate output, not automatically a safe
production migration just because it parses.

For programmatic compiler work use the existing public API in
`dev-tools/compiler/index.js`: resolve/validate, emit, then write artifacts when
requested. Read its actual exported signatures; do not create a second compiler
pipeline or assume the CLI is the only entrypoint.

## 8. Small source contracts worth remembering

- Roots declare `@rebase-tree-root @rebase-tree-key datetime|int`; node fields
  declare `@rebase-tree-node`, the key type, and finite
  `@rebase-tree-owner table.root_field` targets. Use current fixtures for exact
  field storage types. Membership identity is `(record, slot)`, independent
  of mutable order. Optional absence omits membership; zero/net-zero is not
  automatically absence.
- `@rebase-members`, `@rebase-derived`, explicit opaque dependencies, and
  required-output contracts are compiled; do not infer arbitrary SurrealQL
  dependencies or manually mutate private AVL fields.
- Calculation dependencies form a DAG. Reference edges, reader edges, and AVL
  links are different relations. Direct-reader permission never implies
  recursive ancestor access.
- Field audit is explicit (`@rebase-audit`, `@rebase-change-log`); private
  provider secrets must not enter value projections. Generated helpers and
  internal bookkeeping are not business audit data.
- Ordered integer tests cover safe transported values, not every possible
  numeric encoding. SurrealDB 3.2.0 has a known fractional-decimal-to-int abort;
  preserve guarded numeric input. Use disposable servers for crash cases.
- Grants, inline committed operations, and queued tasks have different effect
  boundaries. Native operation/effect annotations currently coexist; copy a
  matching accepted fixture and check compiler diagnostics instead of inventing
  annotation names. A provider timeout can mean an ambiguous external result;
  it does not prove that retrying a send is safe.

## 9. Verification selection and bootstrap

Audited tools: Node `v22.23.2`, SurrealDB `3.2.0`, Redis `7.0.15`, BullMQ `6.2.0`.
`package.json` permits Node `>=20.6.0`; exact audited behavior is tied to the
versions above. Use the existing lockfile; do not upgrade dependencies while
fixing an unrelated packet. Install with `npm ci` only if dependencies need it.

| Change | First checks | Broader gate when ready |
|---|---|---|
| Docs only | Links, scoped diff, `git diff --check` | No database suite. |
| Config | `npm run probe:environment` | `probe:runtime` if startup/binding changes. |
| Queue/runtime | Relevant smallest case, `npm run probe:queues` | `npm run probe:runtime`. |
| Authentication/credentials | `npm run probe:authentication`; `node dev-tools/probe.js security` | Runtime + affected compiler fixture. |
| Compiler or readers/audit | `npm run probe:compiler`; `npm run probe:architecture` | Security and affected generated/tree checks. |
| AVL/ordering | Affected typed/position/temporal fixture | Full tree and dependent fixtures at integration. |
| Required/causal outputs | Corresponding `probe:required-outputs` / `probe:causal-outputs` | Affected foundation and source-oracle integration. |
| Final core integration | Rebuild/check matching profiles and native validation | `npm run verify` once, plus changed coverage omitted from it. |

The main probes start their own loopback servers. `dev-tools/probe.js` is
disposable by default; **do not set `REBASE_PROBE_ENDPOINT`** for this audit
workflow because that selects an external server. Test fixtures have their own
credentials and mocked service transports. Build/check first only when their
inputs/profile changed. A source read or documentation edit does not justify
repeating expensive tree probes.

2026-09-26 local samples: compiler 1.22s, config 0.89s, security 3.46s,
runtime 55.79s, quick temporal 42.31s, typed tree 87.08s, positions 204.41s.
Some overlapped; these are scheduling aids, not benchmarks or promised runtimes.
The slowest audit check was the exhaustive positions fixture, not compilation.

For large generated SQL, reuse the existing fixture schema-application helper,
which splits parsed statements to respect request limits. Do not send a whole
large schema in a default 256 KB `/sql` request, split arbitrary semicolons,
or use a personal database to save fixture setup time.
