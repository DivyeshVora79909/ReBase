# N6 — Native bootstrap contract

Status: **native implementation verified; extracted-release acceptance
pending.** The [local evidence](evidence/2026-10-26-n6-bootstrap.json) records
200 default native tests, seven focused scope controls, an explicitly executed
local FoundationDB reset control, and 141 Node tests with no skips. The initial
example assertion failure and its targeted repair remain recorded. This does
not yet claim N6 release acceptance.

The subsequent [catalog correction](evidence/2026-10-26-n6-model-catalogs.json)
shares the strict native schema registry across configuration and model tools.
All six models, both catalog scopes and every native fixture now pass; the full
Node suite has 143 passes and no skips. Native inputs are unchanged. Refreshed
committed-source packages still require extracted acceptance.

## Entry points and configuration

The production binary exposes exactly `rebase-next host` and
`rebase-next serve /absolute/service.json`. Rust performs model preparation,
store access, authentication, service work and shutdown; neither command
requires Node, Python, a shell command parser, or developer tooling at runtime.
The host uses the bounded `rebase-native-host-1` line protocol. The service file
is strict, size-bounded JSON with `format: "rebase-service-1"`, one compiled
`model`, explicit `backend`, typed `target`, and explicit `service` settings.
Unknown fields and unsupported argument shapes fail before store or listener
side effects.

Standalone serving accepts only `target.mode: "open"` for an existing secured
store. Embedded backends use an absolute `path`; FoundationDB uses a nonempty
`namespace` and explicit absolute cluster file. Every target supplies the canonical
`expect_store` UUID. Model and native store/codec identities are checked against
the opened store. Startup never creates, recovers, or resets a store. Backend
and model preparation go through the same typed native preparation and
validation used by the private host; service configuration is not a second
domain dispatcher.

## Store and request fences

The expected runtime store UUID is checked on scoped reads, writes, session
description, authenticated ingress, and effect-worker operations. Read checks
use the same read snapshot as the header. A write reads and validates the
header inside its writable transaction before mutation, so reset or store
replacement cannot race the fence. Reset changes the store UUID and invalidates
old scopes and operation contexts; ingress and worker work must also honor the
new identity. Store UUIDs and revisions are intentionally visible where the
documented APIs expose them. Private signing keys and runtime secrets are not
exposed.

A model or store-format mismatch is `model_mismatch`; a wrong expected store
UUID or stale scope is `wrong_target`. RPC maps `wrong_target` to a fixed safe
message, without returning private backend details. Initial integrity checking
occurs before listener readiness or worker activation. Corrupt or incompatible
store state must prevent startup.
The HTTP service requires a real valid EdDSA JWT and fresh native
`session.describe` operation context for a mutation. A retry retains the same
operation ID, request and context to obtain its original receipt. SIGTERM drains
admitted requests and joins owned worker/service tasks before releasing store
ownership.

## Acceptance evidence still required

Native controls in `tests/native_bootstrap.rs`, `tests/native_host.rs`, and
`tests/native_service.rs` cover parts of this boundary. The final acceptance
record must report fresh execution results rather than infer them from source or
older N1–N5 evidence. It must cover:

- A standalone real-binary `serve` run with an empty `PATH`, a fresh signed JWT,
  `session.describe` context, one mutation, and same-ID/context replay with the
  original receipt for all six compiled models.
- Absolute config-path and strict bounded-JSON behavior; malformed, wrong-model,
  wrong-store and corrupt-integrity startup failures leave the store unchanged,
  create no destination, bind no listener and activate no worker.
  Corrupt-integrity startup remains an explicit acceptance case; source review
  alone does not establish this behavior.
- Runtime UUID checks across read, write, session, signed ingress, worker and
  post-reset paths; `wrong_target` is safely mapped, and protected header reads
  are covered at the transaction boundary.
- SIGTERM drain and cleanup of owned native/service/worker resources, followed
  by a successful clean reopen and integrity check.
- Fresh extracted-package checks for each claimed backend. FoundationDB host and
  service acceptance is explicitly unverified until a feature-enabled run with
  an owned real cluster, namespace isolation and complete cleanup is recorded;
  compilation or configuration rejection alone is not backend acceptance.

These are required acceptance controls, not claims that every item has passed.
Root records exact source and artifact identities, executed cases, failures,
cleanup and backend-specific limits in new evidence before deciding acceptance.
The bounded model and workload results do not imply unrestricted capacity,
multi-host FoundationDB behavior, or failover guarantees.

See the [frozen private host protocol](60-native-host-contract.md),
[server guide](../docs/server.md), [deployment guide](../docs/deployment.md),
and [N6 retirement handoff](77-node-tooling-retirement.md).
