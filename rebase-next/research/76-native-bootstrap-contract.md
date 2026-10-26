# N6 — Native bootstrap contract

Status: **accepted within the bounded N6 release scope.** The final
[N6 result](78-node-retirement-result.md) and
[release evidence](evidence/2026-10-26-n6-release.json) record committed-source
packages, extracted controls, native bootstrap checks, and their limits. The
earlier [bootstrap evidence](evidence/2026-10-26-n6-bootstrap.json) and
[catalog correction](evidence/2026-10-26-n6-model-catalogs.json) remain separate
dated executions; they are not relabeled as final release runs.

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

## Accepted controls and boundaries

The real-binary service check runs all six compiled models with an empty `PATH`,
fresh JWT, native session context, mutation, SIGTERM shutdown, restart, and
original-ID receipt replay. Seven invalid configurations fail without changing
stores. The native campaign records 200 default tests, seven focused scope
controls, and a real local FoundationDB reset control. The final extracted
release adds 143 passing Node tests with no skips and redb, SurrealKV, and local
FoundationDB lifecycle runs; see the [N6 result](78-node-retirement-result.md)
for the complete restore/archive/reset boundaries.

The checks exercise expected-store UUID guards across scoped operations and
post-reset paths. Read fences use the same snapshot as the header; writes read
the header in their writable transaction. `wrong_target` maps to a fixed safe
RPC message, while model or store-format mismatch is `model_mismatch`. The
service opens existing stores only, checks integrity before readiness, and
drains owned work on SIGTERM. Local FoundationDB evidence does not establish
multi-host behavior. No result here implies unrestricted production capacity.

See the [frozen private host protocol](60-native-host-contract.md),
[server guide](../docs/server.md), [deployment guide](../docs/deployment.md),
and [N6 retirement handoff](77-node-tooling-retirement.md).
