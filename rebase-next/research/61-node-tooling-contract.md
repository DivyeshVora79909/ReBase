# N0 — Node tooling feasibility and contract freeze

Status: **N0 proposal and bounded feasibility witness; no developer API is implemented.**
This checkpoint selects the Node runtime, dependency set, configuration authority,
and the eight-module N1+ surface. It does not mark N1–N6 accepted and does not
claim full model generation, a completed native host, or production capacity.

## Runtime baseline

Select Node 24 as the minimum supported major and record `24` in `.nvmrc`.
The upstream release schedule says Node 24 entered LTS on 2025-10-28 and remains
supported through 2028-04-30. As of this checkpoint date, 2026-10-25, Node 26's
LTS date (2026-10-28) has not arrived; choosing the numerically newest supported
release would be the wrong rule for a stable tooling baseline. The final
feasibility witness ran on Node 24.22.1 with npm 11.19.1, obtained from the
official Node distribution and checked against its published `SHASUMS256.txt`.
The package declares `node >=24`.
The manifest is scoped to `tools/node/`; it does not change the unrelated
repository-root compiler package or the retained `tools/schema-values` bridge.
It has no install or postinstall hook.

Source: [Node.js Release schedule](https://github.com/nodejs/Release/blob/main/schedule.json),
entries `v24` and `v26`, consulted 2026-10-25. The selected baseline is a
supported LTS line, not a promise to freeze dependency updates for that line.

## Dependency and schema trial

The trial installed the exact lockfile set in an isolated temporary directory
outside the checkout (`npm ci --ignore-scripts --no-audit --no-fund`):

| Package | Version | Use |
| --- | --- | --- |
| `ajv` | 8.20.0 | Draft 2020-12 compiled validation |
| `ajv-formats` | 3.0.1 | Standard JSON Schema formats, including UUID |
| `json-schema-faker` | 0.6.3 | Bounded schema-shaped generation with per-instance seeded generators |
| `json-bigint` | 1.0.0 | Duplicate-key rejecting parser and lossless inspection of integer tokens |

The selected dialect is `https://json-schema.org/draft/2020-12/schema`, the
value of `SCHEMA_DIALECT` in `src/model.rs`. The compiled schema source uses
`uuid`, `i64`, `i128` and `u16` formats (for example
`src/indexes/standard.rs` and `src/indexes/measurement.rs`) and native extension
keywords `x-rebase-range` and `x-rebase-binding`. The trial registered the three
integer string formats with strict Ajv, enabled `ajv-formats`, and declared the
native extension keywords as metadata. The custom format validators checked
canonical decimal spelling and exact i64/i128/u16 bounds. The faker witness
used a constrained u16 enum to model a caller-supplied field strategy; it
generated UUID and canonical integer-string examples from a 2020-12 witness
schema. A second generator with the same seed reproduced both values,
successive calls advanced to a distinct value, and each generated value passed
Ajv validation. This validates a concrete supported subset, not every exported
schema keyword or a complete JS interpretation of native range extensions.

The chosen seed mechanism is json-schema-faker's `createGeneratorSync({ seed })`
(Mulberry32, with a per-generator cursor that increments the seed for each call).
Each prepared population owns its generator object; the witness produced values
that were both reproducible and fresh without mutating process-global faker
state. The seed is a bounded 32-bit nonnegative integer; a seed does not promise
equal data after a dependency upgrade. Generation is an input-shaping aid, not a
constraint solver or proof that a proposal satisfies native invariants. Keep
custom generation strategies explicit where authored schemas need them.

For untrusted JSON, `json-bigint` with `{ strict: true }` rejects duplicate keys
(including nested duplicates). It represents integer tokens losslessly as
BigNumber values; a deliberate exact-value boundary can safely convert values
within Number's safe range and reject larger numeric tokens, requiring canonical
decimal strings for exact integers outside that range. Native wire exact values
remain governed by the native JSON contract. Invalid `NaN` syntax is rejected.
The parser accepts escaped lone UTF-16 surrogates, so the strict private codec
must separately reject unpaired surrogate code units and decode IPC bytes with
a fatal UTF-8 decoder; the witness covers both cases and a valid surrogate pair.
Do not use the `useNativeBigInt` parser option at a generic transport boundary:
it converts every integer token to BigInt, including ordinary small JSON counters.
Convert only fields whose declared model semantics require BigInt.

Installed APIs/docs used for the trial: [Ajv](https://ajv.js.org/),
[ajv-formats](https://github.com/ajv-validator/ajv-formats),
[json-schema-faker](https://github.com/json-schema-faker/json-schema-faker), and
[json-bigint](https://github.com/sidorares/json-bigint). Exact package versions
and integrity hashes are in [the Node lockfile](../tools/node/package-lock.json).

## Configuration authority and provenance

[The registry fixture](fixtures/n0-config-registry.json) records each seeded
setting's owner, default, unit, allowed range, override policy, source and secret
status. It also maps the later target/backend, server, client, child-process,
population, workload and release configuration families to their owning layer
and source. It separates three sources:

- Hard application and protocol limits are native-owned. The private host's
  `host.describe` and selected model catalog must report them with identity and
  provenance. JavaScript cannot override them and does not place them into
  mutable defaults. Current Rust source references include `MAX_REQUEST_BYTES`
  in `src/json.rs` (65,536 request bytes), the public/output/reservation bounds
  in `src/binding.rs` (4,096, 8,192, 16,384), and `MUTATION_WORK_LIMIT` in
  `src/local.rs` (200,000 work units). Model-specific limits can be smaller.
  The private `rebase-native-host-1` frame limits are protocol identities
  frozen in [the native host contract](60-native-host-contract.md) and must be
  returned by `host.describe`.
- JavaScript runner budgets have explicit defaults and provenance in the
  registry. They bound only Node-owned startup waiting and retained diagnostic
  text; they do not redefine native request, model, storage, or mutation limits.
- Caller values resolve with precedence **explicit overrides > explicitly
  parsed environment > defaults**. Environment parsing is opt-in and allowlisted.
  Unknown setting names, null where not declared nullable, non-finite numbers,
  unsafe exact integer numbers, contradictory backend settings and any attempt
  to raise a native hard limit are rejected. Secrets are explicit protected
  values/providers and are redacted recursively from diagnostics and reports.

This registry is a planning fixture, not an implemented environment parser.
N1 has two validation phases. Node rejects locally knowable shape, range,
unknown-key and contradiction errors before spawning anything. It then obtains
the authoritative schema and hard limits through the inert, bounded native
bootstrap; configuration rejected by that schema is sent to the native host,
which must reject it before opening a store, listener or worker. Node closes the
owned bootstrap on every rejection path. Native-owned facts cannot be validated
before contacting the native authority that supplies them.

## Frozen proposed module and export surface

Freeze the eight capability groups and public verbs from paper 57, with the
native lead's private-host name matching the frozen wire fixture. These are
proposed APIs, not implemented exports:

| Module | Proposed exports |
| --- | --- |
| `config.mjs` | `resolveConfig`, `parseEnvironment` |
| `native.mjs` | `openNative` |
| `model.mjs` | `prepareModel` |
| `client.mjs` | `connect`, `savePlan` |
| `population.mjs` | `preparePopulation`, `propose`, `accept`, `reject` |
| `operator.mjs` | `openOperator` |
| `workload.mjs` | `runWorkload`, `checkRun` |
| `package.mjs` | `buildPackage`, `verifyPackage` |

Handles may expose `close`; operations may accept `AbortSignal`. Keep protocol
codecs, hashes, framing, redaction and schema traversal private. Do not add
aliases for old Python/CLI names or a ninth public capability group. Preserve
caller ownership and the native operator capability scope. The frozen protocol
wire and its counterexamples are owned by `research/60-native-host-contract.md`
and `research/fixtures/n0-native-protocol.json`.

## Bounded verification

`tools/node/test/n0-feasibility.test.mjs` covers three focused obligations:
2020-12/Ajv format validation, per-instance seeded/fresh generation, and strict
lossless JSON, exact-number and Unicode handling. It was executed from a copied
package in `/tmp/rebase-n0-node24-final-2` after isolated `npm ci`, with no
dependencies installed in the checkout: **3 passed, 0 failed** on Node 24.22.1.
This is a dependency and contract witness, not an acceptance test for native IPC,
full exported catalogs, or all generation keywords. N1/N3 own those remaining
checks.
