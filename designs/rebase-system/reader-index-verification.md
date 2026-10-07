# Reader and custom-index verification — 2026-10-07

Status: **local implementation and required verification complete**. Baseline
accounting commit: `88c5ae7794abc11f7ecad0e0b39d2e55ed56d2e9`.
The [developer blueprint](developer-blueprint.md) and
[executable analytics example](../index-analytics/README.md) describe the API.

The [dated evidence record](evidence/2026-10-07-reader-index-acceptance.json)
contains command coverage, source/generated hashes, versions and transcript
hashes. Runtime: Node v22.23.2, npm 12.0.2, SurrealDB 3.3.0 on Linux x86_64.

## Completed checks

| Check | Result |
| --- | --- |
| New reader/index probe | 53 source checkpoints, 6 complete rollback snapshots; populated reapplication and cleanup |
| Accounting regression | 63 mutation checkpoints, 35 complete rollback snapshots; populated reapplication and cleanup |
| Typed trees | 113 mutation checkpoints, 1,101 ordered reads, 105 rejection snapshots |
| Ordered trees | 22 mutations, 683 typed reads/pages, 10 rollback cases |
| Developer tools | 27 tests passed, zero failures |
| Build checks | Default, all-in-one, accounting and analytics artifacts current; schema validation passed |
| Static checks | 21 changed/new JavaScript files parse; 34 accounting public schemas match exports; documentation links and diff whitespace pass |

All **40 gates** in `npm run verify` passed across the initial and resumed runs.
The [initial transcript](evidence/2026-10-07-reader-index-backend-before-resume.txt)
records 30 successful gates followed by an obsolete test that expected a
nine-component key declaration to be rejected. The test now accepts nine and
sixteen components and still checks invalid declarations. The
[resumed transcript](evidence/2026-10-07-reader-index-backend-remaining.txt)
records all ten remaining gates passing. The original aggregate invocation
exited 1; this is complete gate coverage, not a claim that it exited 0.

Those gates include authentication, tenant isolation, record permissions and
views, passkeys, credentials, compiler/architecture checks, queues, admission,
retention, runtime, live queries, scheduling, webhooks, adapters, temporal/typed/
ordered/boundary trees, dependency ordering, required/causal outputs, account
calculations, CRM/HRM, general permissions and the developer-tool tests.

The final [focused transcript](evidence/2026-10-07-reader-index-focused.txt)
adds user-deletion identity cleanup to the earlier 51-checkpoint run. The
[accounting transcript](evidence/2026-10-07-reader-index-accounting.txt)
verifies the existing accounting domain against the new framework.

## What the evidence exercises

The new probe reconstructs identity and analytics memberships from source facts
and uses the independent AVL/link/summary oracle. Rejection snapshots include
all compiled tables, including source rows, authorization state and audit rows.
Checks cover private identity lookup, cross-table collisions, normalization,
rekey/reuse, concurrent writers, source deletion and principal cascade deletion.

Reader cases cover declared branch order, descendant selection, authorization
graph changes, old-token revocation, source-owner changes, explicit shared groups,
fallback ownership and record-client creates with forged reader inputs. Analytics
cases cover creation/effective-time separation, omitted and disabled memberships,
owner moves, composite ranges, paging, summary privacy and 16-component keys.

An early runtime regression exposed duplicate insertion when internal principal
depth updates ran during username creation. Internal authorization/authentication
metadata is now marked as system state so it cannot trigger a second business
membership update. Nested principal creation, authentication, the full runtime
probe and the final focused probe passed after that fix.

## Evidence boundary

Checks use disposable local services. Passkey verification uses software P-256;
no browser authenticator, live provider or production database was used. Counts
are functional checkpoints, not row counts or throughput measurements. Shared
identity roots and graph repairs still have contention and maintenance costs.

Identical populated schema reapplication is covered. Converting an older
populated database needs an explicit backfill/migration rehearsal; this change
does not perform it. The accounting domain sources and public inputs remain
unchanged from `88c5ae7`. The separate MetaSol worktree was not modified. New
framework changes are uncommitted; no push or deployment was performed.
