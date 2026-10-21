# Whole-system review and change impact

**Reviewed 2026-10-22, starting at ReBase `e5d13b3` and MetaSol `28c6e7f`.**
This is a research review. The next work is contract and scenario design;
the previous instruction to start implementing a runtime slice is superseded.

## 1. Assessment

The direction is coherent: preserve typed facts, independent participation,
declared calculations, ordered summaries and atomic integrity, while moving
execution into one native transaction workspace. Rust and reusable infrastructure
are plausible choices. Neither the dominant current bottleneck nor a Rust speedup
has been established. Replacing the database transfers responsibilities to this
project even when fewer statements and dependencies appear in the final design.

The main optimization target is the cost of making a correct change: how many
independent declarations, adapters and assumptions a developer must update.
One resolved model, ordinary functions and explicit boundaries help that goal.
A universal database adapter, generic policy language or automatic dependency
discovery would introduce additional semantics to maintain.

The mathematics and transaction papers are useful foundations. The main gaps
were contracts between components: model activation, exact wire values, mutation
outcomes, query initialization, public versus developer metadata, and replacing
database-provided tooling. Papers [7](07-contract-wireframes.md) and
[8](08-research-workflow.md) now make those gaps reviewable. These are proposed
contracts, not implemented capabilities or proof that the whole design is ready.

## 2. Context recovered without repeating the whole investigation

- The first supplied attachment is byte-identical to the discussion indexed in
  [sources.md](sources.md): 5,669 lines, SHA-256 beginning `50568320`.
  Its original prompts and appended corrections were checked against the compact
  context. The later restoration of scalar `read_by` governs the design.
- The second attachment contains the inspector work, the request to research in
  an independent directory, and the creation of `e5d13b3`. Repeated prompts and
  tool transcripts are historical records, not new implementation instructions.
- All 26 repository inputs in the previous source manifest still match. Git has
  no changes outside `rebase-next/` between `a963b25` and the starting revision.
  The relevant current source and additional tooling/frontend seams were inspected.
- All 11 inputs fingerprinted by the existing Rust evidence still match. Its
  eight semantic tests, redb example, formatting and Clippy results remain
  **October 21 evidence**. They were not rerun or promoted to runtime acceptance.
- Older memory supplied failure patterns and preferences. Its October 13
  authored-impact implementation is superseded by October 16 named queries.
  No global memory was changed.

The [audit manifest](evidence/2026-10-22-context-audit.json) records inspected
sections, source hashes and the documentation inventory. Inventory coverage is
distinct from a behavioral audit: a listed document or passing historical test
does not establish that every code path was reviewed this turn.

## 3. Documentation map

Read the owning contract before a dated handoff. The repository contains several
generations of architecture; a document's word “current” belongs to its revision.

| Route in the existing project | What it tells us; how to use it |
| --- | --- |
| [Root README](../../README.md) | Entry points, pinned tools, current accounting and build/runtime layout. A routing index, not the entire semantic contract. |
| [Engineering profile](../../HOW_I_THINK.md) | Work from primitives, challenge assumptions, expose worst cases, then bootstrap a small implementation. Guidance, not performance evidence. |
| [Developer blueprint](../../designs/rebase-system/developer-blueprint.md) | Record obligations, scalar reader selection, explicit memberships, supported reads and domain extension recipe. |
| [Declared queries](../../designs/rebase-system/function-reactivity.md) and [October 16 design](../../designs/rebase-system/declarative-engine-plan.md) | Fixed slots, pure helpers, causal settlement, source fences and calculation/validation phases. These supersede dynamic capture. |
| [Ordered tree contract](../../designs/rebase-system/ordered-tree-contract.md) | Key types, tie order, uniqueness/coalescing, intervals, publication and native traversal limitations. |
| [Tenant/authentication](../../designs/rebase-system/tenant-authentication.md) | DAG, direct role inheritance, readers, private identity lookup, challenges, passkeys and explicit credential use. Source/package versions still outrank old prose. |
| [One design](../../designs/rebase-system/single-design-runtime.md) and [configuration](../../designs/rebase-system/core-configuration.md) | Fixed deployment identity, explicit tenants, worker recovery and settings ownership. The one-design paper's frontend paragraph is stale. |
| [Operations](../../designs/rebase-system/operations.md) | Durable intents, leases, provider-start markers, receipts, scheduling and cleanup. Some credential/context paragraphs retain the pre-tenant model; see the conflicts below. |
| [Developer tools](../../dev-tools/README.md) | `build`, `explain`, REPL connection ownership, inspector catalogs, explicit preparation, fixture planning/population and current defaults. |
| [Fixture design](../../designs/rebase-system/fixture-generation.md) and [accounting recipe](../../designs/all-in-accounting/fixtures/README.md) | Seeded source generation, saved-reference normalization, explicit transaction ownership and design-owned defaults. |
| [Accounting source map](../../designs/all-in-accounting/context-map.md) and [guide](../../designs/all-in-accounting/developer-guide.md) | Sparse native dimensions, directed event-time valuation, real/receivable/payable, invoice constraints, adjustments, taxes, claims, production and fees. These are domain compositions. |
| [Frontend architecture](../../designs/frontend/architecture.md), [screens](../../designs/frontend/screen-contracts.md) and [extension guide](../../designs/frontend/developer-guide.md) | Generated inputs, native exact values, index readers, retained drafts, version checks, session fences and explicit workflows. |
| [Frontend deferred work](../../designs/frontend/deferred-work.md) | Collaboration, durable activity, bulk operations, authentication UI and acceptance limits. A missing future feature is not a current backend guarantee. |
| [Research index](../../research/README.md) | Separates observed SurrealDB behavior from adopted ReBase policy. Database-specific findings do not automatically transfer to a KV runtime. |
| [Authorization stress](../../research/rebase/authorization-stress-results.md) | Access-path costs under stated fixtures; owner partitions alone are incomplete when owner and reader differ. No Rust or distributed benchmark follows. |
| [October 16 evidence](../../designs/rebase-system/declarative-engine-verification.md), [accounting evidence](../../designs/all-in-accounting/verification.md), [frontend evidence](../../designs/frontend/verification.md) | Revision-specific checks and limits. Their counts are historical observations, not acceptance of this redesign. |
| Other `plan`, `handoff`, `review`, integrity-packet and dated redesign files; [readiness report](../../PRODUCTION-READINESS-REPORT.md) | Design chronology, rejected candidates and reproducible failures. Consult for the affected question; do not restart their old task lists. |
| [Isolated context](../CONTEXT.md), papers 1–5 | Current redesign meaning, proposed stack and bounded executable proof. Papers 6–8 add the system review and research gates. |

### Conflicts found in routing material

| Historical claim still visible | Current interpretation |
| --- | --- |
| `operations.md` §8 describes `rebase_group:root` and a global `:default` delivery policy | The tenant/authentication contract, single-design reference and current gateway use explicit same-tenant configuration/policy. Do not copy the older defaults. |
| `single-design-runtime.md` says the frontend migration is deferred; the system index describes the October 8 frontend | MetaSol's October 18 architecture, source and verification supersede those frontend statements. |
| October 16 verification says changes are uncommitted against its starting revision | That is a historical execution snapshot; present Git owns present commit status. |
| Earlier memory describes authored impact functions and unfinished October 13 accounting acceptance | Named query declarations and the later accounting evidence supersede that state. |
| Reuse of unchanged JSON Schemas could be read as old wire compatibility | Current `account_entry`, `invoice_settlement` and `exchange_rate` reference patterns require table-prefixed IDs. UUID-only transport requires new authored patterns/bindings; preserve domain and target-type obligations, not the old spelling. |
| The isolated context and feasibility conclusion say “next: implement” | The October 22 request explicitly returns work to wireframes, scenarios and design review. |

These conflicts are documented here. Editing the original project is outside
this isolated work. Keeping this route explicit is cheaper than copying every
historical document into another supposedly authoritative summary.

## 4. What a stack change affects

“Preserve” below means preserve a semantic obligation, not reuse the existing
JavaScript or SurrealQL unchanged. The named scenario families live in paper 8.

| Surface and concrete current seam | New ownership / breakage to account for | Scenarios |
| --- | --- | --- |
| `dev-tools/compiler/{schema,fields,read-only,derived-order}.js` | Loaded contracts must resolve exact types, input/protected fields, actual dependencies and trusted behavior. A schema validator alone supplies none of the cross-record rules. | M1, D1 |
| `designs/all-in-accounting/schemas/*.schema.json` | Retain applicable validation, but change reference wire patterns/bindings for UUID-only IDs. A standard schema format does not make a vendor-specific payload portable. | D1, W2 |
| `framework/auth.surql`, `compiler/generators/security.js` | Engine owns same-tenant checks, owner assignment, operation/field permissions, DAG integrity and atomic reader/index repair. | A1, A2 |
| `framework/{access,authentication,passkeys}.surql`, `gateway/{authentication,passkeys}.js` | Native signin/session verification disappears. An identity library verifies credentials; ReBase still owns tenant binding, session policy, challenges and revocation. | F3 |
| `compiler/generators/references.js` and native `REFERENCE` | Engine must track target existence, allowed types, inverse routes and delete actions, including concurrent link/delete. | M5, T2 |
| `compiler/{temporal,queries,dependencies}.surql` | Shared typed workspace replaces incremental SQL, but still owns links, summaries, reverse slots, publication and conflict obligations. | M2–M6, T1–T3 |
| Required-output recipes and domain write functions | Stable managed-output identity, activation/update/removal, private writes and causal order remain explicit. A source cannot count its published output twice. | M5 |
| `views.surql` and computed publications | Every used grouped view needs a declared projection/publication or a deliberate omission. There is no general SQL/group-by engine in the proposal. | A1, D1 |
| `framework/audit.surql` | Decide field-selected business audit separately from temporary calculation explanation, operation receipts and provider receipts. “No event replay” does not erase those obligations. | D3, F1 |
| `gateway/{app,server,store,runtime}.js` | RPC replaces direct DB client operations; transport still needs bounded input, cancellation, readiness, shutdown and stable error outcomes. | W1, W2, F1 |
| `gateway/{live,reconciler}.js`, queues, webhooks | KV watches are not automatically SurrealDB LIVE queries or a durable inbox. Recovery needs authoritative discovery even when a wakeup is lost. | F1, F2 |
| `compiler/catalog.js`, `MetaSol/client-contract.js` | One resolved model produces separate developer and public projections. Full authored source/private metadata must not become a generic client schema. | D1 |
| `dev-tools/prepare.js` | SQL installation and import-mode clearing cannot be carried over. Define model/store compatibility and isolated reset/rebuild lifecycles before a replacement command. | D2, D3 |
| `dev-tools/fixtures/{model,values,generate}.js` | Rebind exact values and references; use supported mutations and settled rereads. Preserve seeds, staged recipes and design-owned defaults without importing the old compiler. | D3 |
| `dev-tools/inspector/{access,graph,layouts}.js` | Graph/layout concepts can stay ordinary UI code. Live access/record inspection needs a new authorized data adapter; static possible edges differ from active slots. | D1, D3 |
| `MetaSol/src/data/{auth,records,references,traversal,values,writes}.js` | Native `RecordId`, `Decimal`, NONE, SQL bindings, `$auth`, backlinks and `.responses()` all change. UUID-only IDs need an explicit contract in record envelopes. | Q1–Q3, W1, W2 |
| `MetaSol/src/app/{WorkspaceProvider,SessionProvider}.jsx` and forms | Preserve endpoint/design/tenant/session identity, stale-callback suppression, stable create IDs, draft lifetime and unknown-write inspection. Query caches are not fresh authority. | A2, W1 |
| `config/environment.js`, build outputs, launch/test scripts | One explicit design/store/profile; no accidental fallback to the original database, build directory or credentials. Bootstrap and shutdown are part of the experiment. | D2, D3 |

New standard-facing APIs do not remove these responsibilities. Libraries can
own HTTP, cryptographic verification, schema validation and ACID storage. ReBase
owns the meaning at their boundaries. Future CRM/HRM, inventory, offline sync,
compliance and arbitrary query planning are recorded exclusions, not missing
modules to scaffold now.

## 5. Past failures turned into research constraints

| Observed failure or misleading evidence | Constraint for this redesign |
| --- | --- |
| Whole-row helper aliases hid dependencies; `a_total` remained 4 when it should be 6 ([compiler review](../../designs/rebase-system/integrity-2026-10-15/compiler.md)) | Formulas receive resolved declared inputs. Use names whose lexical order disagrees with dependency order. |
| Captured reads mutated shared structures during formula evaluation; later arithmetic could look right while links were stale ([runtime review](../../designs/rebase-system/integrity-2026-10-15/runtime.md)) | Pure evaluation and structural reconciliation are distinct stages. One workspace owns latest state; do not restore cached whole nodes over newer patches. |
| A checker could miss an entire removed dependency inventory ([checker review](../../designs/rebase-system/integrity-2026-10-15/verification.md)) | Derive expected roles/reads from source facts and declarations, then compare with maintained state. Prove the checker detects a missing whole inventory. |
| Coincident interval slots were coalesced; whole-result/endpoint changes escaped invalidation ([October 16 defects](../../designs/rebase-system/declarative-engine-verification.md#reproduced-defects)) | Preserve role identity and consumed semantic fields, even when bounds or numerical outputs coincide. |
| Current intrusive cleanup requires old neighbours and child-first deletion | A future staged deletion must retain old slot images and apply declared reference/output policies. Do not assume that a bulk KV delete runs the engine. |
| Build output overlapped source; generated symlinks could overwrite inputs ([tool review](../../designs/rebase-system/developer-experience-handoff.md#lead-review-and-corrections)) | Preflight all output paths before pruning/writing. Build, connect, activate and populate have separate effects. |
| Saved fixture references differed from supplied strings ([fixture correction](../../designs/rebase-system/fixture-generation.md#saved-reference-correction--october-18-2026)) | Identity binding has one canonical typed representation; fixtures consume confirmed identities and current settled values. |
| Browser callbacks crossed session boundaries; parent forms lost state | Keep request identity with the request, and let one editor own its draft/version/create ID. A backend rewrite must preserve those UI contracts. |
| A binary-float demo comparison failed while the exact accounting oracle passed | Keep exact domain comparisons. Local tolerance for an approximate demo cannot weaken the shared exact checker. |
| Large suites and stale summaries suggested broader acceptance than their actual scope | Evidence identifies inputs, version, oracle and exclusions. Check affected boundaries once; preserve old evidence instead of relabeling it. |

## 6. Decision boundary

Continue with [contract wireframes](07-contract-wireframes.md), then the
[scenario and gate register](08-research-workflow.md). The next useful experiment
is a small source-based settlement model after its unresolved causal contract is
closed. It is not yet a full Rust runtime, an API server, a new frontend or a
distributed adapter. Whole-system awareness informs that small experiment;
freezing every future product feature is not a prerequisite to learning from it.
