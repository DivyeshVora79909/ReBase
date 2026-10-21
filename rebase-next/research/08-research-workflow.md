# Research scenarios, decisions and gates

**Active phase: bounded native-slice acceptance complete, 2026-10-22.**
The user requested whole-system understanding before implementation planning.
The impact review and concrete M1/M2/M4 contracts preceded implementation.
The [first implementation plan](11-native-slice-plan.md) is now complete through
S1–S5; [paper 12](12-native-slice.md) records native execution and independent
acceptance. The complete proposed application runtime remains unimplemented.
This paper owns continuation and testing scope.

## 1. What “ready” means

Whole-system awareness requires an inventory of affected responsibilities. It
does not require guessing every future product feature. Readiness applies to a
named experiment with explicit inputs, observable outcomes, boundaries and an
independent way to find errors. Unresolved questions that can change that
experiment's meaning must be closed first. Other questions remain visible at
the gate for the capability that needs them.

Use four evidence labels consistently:

| Label | Meaning |
| --- | --- |
| Proposed | A reasoned choice or wireframe; no implementation implied |
| Established | Mathematics or a cited platform contract, with its assumptions |
| Executed | A particular program/check ran against fingerprinted inputs |
| Deferred | Deliberately outside the selected experiment; no acceptance claim |

An established AVL bound does not prove a new AVL implementation. A small redb
example does not prove distributed conflict coverage. A scenario described in
this paper is not an executed test.

## 2. The bounded reference scenario

This is a complete source-level fixture specification for reasoning about the
first native calculation slice. It is not a new accounting model or an API
implementation. Labels below stand for fixed distinct UUIDs in one tenant.

| Fact/role | Declaration |
| --- | --- |
| Rule `D` | Authored dimensionless positive integer coefficient `c` |
| Curve `C` | A unique-time quote root; quotes have authored time and positive rate in reporting minor units per native minor unit |
| Account `A` | Native history root; duplicate times allowed; all its contributions have the same native unit |
| Subsidiary `S` | Reporting history root in one reporting unit |
| Posting `P` | Authored `units`, `at`, references to D/C/A/S; `native_minor = units * D.c`; `reporting_minor = native_minor * latest(C, at).rate` |
| Memberships | Required `(P,native)` into A and `(P,reporting)` into S; key `(at, UUID, slot)`; no double counting through an account publication |
| Query | Quote time `<= at`; unique quote time makes selection unambiguous. Existing empty curve uses a declared toy fallback rate of 1. A missing curve is an invalid reference, not an empty curve. |
| Invariant | Every account's native balance after each complete timestamp is nonnegative, including the empty prefix |

All keys/activation/root choices in this fixture depend on authored facts, not
on a query result. The calculation graph is acyclic by construction. There are
no managed outputs, prefix-consuming postings or arbitrary mutable helper reads
in this first fixture. Those harder features retain named cases below.

For a bounded arithmetic domain, allow at most 16 postings with `abs(units) <=
1000`, and coefficients/rates in `1..1000`. A reporting contribution is bounded
by `10^9`, and the sum of absolute contributions by `16 * 10^9`. All regroupings
fit the proof's checked `i128`; this establishes no general decimal range policy.
Time remains an exact integer nanosecond key. Use a few explicit times first.
The [native plan](11-native-slice-plan.md#2-fixed-model-and-exact-values) fixes
the `i64` range, exact bindings, command/state caps and reproducible identities
for this experiment without promoting them to a production decimal policy.

### Hand-worked expectations

Each row starts from the same baseline unless stated otherwise:
`D.c=2`, quotes `(10,3)` and `(20,5)`, P at 15 with units 4, Q at 25 with units 1.

| Change | P native/reporting | Q native/reporting | A total / S total |
| --- | --- | --- | --- |
| Baseline | 8 / 24 | 2 / 10 | 10 / 34 |
| Change quote at 10 from 3 to 4 | 8 / 32 | 2 / 10 | 10 / 42 |
| Change coefficient from 2 to 3 | 12 / 36 | 3 / 15 | 15 / 51 |
| Move P from time 15 to 25 | 8 / 40 | 2 / 10 | 10 / 50 |
| Delete quote at 10 | 8 / 8 (fallback) | 2 / 10 | 10 / 18 |
| Move quote at 10 to 30 | 8 / 8 (fallback) | 2 / 10 | 10 / 18 |
| Delete P | absent | 2 / 10 | 2 / 10 |
| Move P to another native account B, same S/unit | 8 / 24 in B | 2 / 10 in A | A=2, B=8 / S=34 |

Deleting C while postings reference it rejects under this fixture's REJECT
policy. Before any preceding quote, fallback is 1; at time 20, the rate is 5.
Changing a quote's date changes selection intervals even when its rate is equal
to another quote's. Identical resulting amounts do not remove source protection.

An additional guard counterexample uses native deltas `+10 @0`, `-15 @10`,
`+10 @20`: final total 5, complete-time minimum -5, so reject. Conversely,
`-10` and `+10` at the same time in one atomic operation have complete-time
minimum 0. A separately declared record-prefix rule would reject that order;
complete-time grouping does not permit causal feedback in a formula.

### Reference execution boundary

1. Start with source facts and verified toy actor/tenant context. Apply the
   allowed authored commands to a copy, checking shape, protected fields,
   prior versions and declared reference/owner permissions. Earlier staged
   creations may supply references; a missing target is not deferred silently.
2. Derive every expected active slot/query from those facts and declarations.
   Scan quote facts for the selected rate; calculate native before reporting.
   This independent oracle never consults runtime descriptors or summaries.
3. Sort projected occurrences and scan equal-time groups to recompute roots and
   invariant results. This defines the final state without prescribing an
   incremental tree or scheduler implementation.
4. If valid, the native implementation must match facts, values, complete
   membership/query inventory and summaries. On rejection, all its attempted
   source/slot/root/receipt/guard changes must be absent. Old images remain
   available for deletion/move repair until the attempt ends.
5. Storage conflict schedules separately test which overlapping operations may
   commit. An oracle's final arithmetic does not establish atomicity or discovery
   completeness under concurrency.

This closes the semantics of the small authored-key fixture. It does not prove
that a general dynamic causal scheduler terminates or that arbitrary designs
with prefix/required-output cycles are admissible.

## 3. Scenario register

The entries specify acceptance conditions; only explicitly reported scope is
executed. Rust coverage is identified in [paper 5](05-feasibility.md) and the
[native result](12-native-slice.md). The separate bounded
[M3/M5 model](09-causal-settlement.md) and
[M6 checker](10-independent-checker.md) have executed their stated controls.
Those earlier models verify synthetic structures and causal examples. The
native fixture now connects M1/M2/M4 and the corresponding M6 observation
obligations to real transactions. Run the smallest entry
that can falsify a changed claim, expanding when another capability is connected.
Rows group related assertions to avoid a test per phrase.

| ID | Small scenario and independent acceptance condition |
| --- | --- |
| M1 | Executed in the fixed native model: local field names oppose dependency order, and changing D gives 12/36 and 3/15. The existing local-plan tests reject unknown inputs/cycles; a general declaration loader remains deferred. |
| M2 | Executed native quote/posting insert/edit/move/delete/reparent, old/new reverse routes, exact quote boundaries and empty-curve fallback. Independent source inventories and values match; missing C rejects. Curve discovery is conservative, not minimal interval invalidation. |
| M3 | Two strictly prior prefix consumers exchange effective positions. Paper 9 defines final-shape causality and checks every valid order of a bounded private-output/diamond model. Old/new graph union and incomplete detachment are explicit counterexamples. Incremental discovery and ordered-result-dependent shape remain unproved. |
| M4 | Executed native multi-command settlement rejects final-positive/intermediate-negative history, accepts same-time cancellation and honors separate checkpoints. Independent grouped scans match; all rejected application KV state is preserved, including aborts after actual writes. |
| M5 | Paper 9 defines coincident financial roles, two positions, identical query/interval bounds, private required-output activation/removal and rejected parent deletion. Its model checks logical inventories and rejection predicates. UUID allocation, real private-write enforcement and atomic lifecycle repair still need implementation evidence. |
| M6 | Paper 10's synthetic contract retains five valid, 28 invalid and two incomplete controls. The simpler native fixture now adds complete real snapshots, independent role inventories, actual AVL links and exact subtree/publication checks, plus four valid, 20 invalid and two incomplete native-format controls. This does not supply a native M3/M5 writer or interval reverse index. |
| T1 | Change a rate concurrently with registration/quantity update of a zero-valued consumer. A no-op output does not drop the source/discovery protection. Each adapter's controlled schedule must prevent a stale committed consumer. |
| T2 | Race unique creation against unique creation, and target deletion against a new reference. Protect absence/predicates and reverse registrations; a correct final index cannot omit a newly committed dependent. |
| T3 | Two withdrawals each appear valid in the same old snapshot but violate the shared historical bound together. Their guards must prevent the invalid pair of commits. Retry reloads all authority and facts; limits reject without partial publication. |
| A1 | A DAG diamond loses one edge while its alternate path remains. Incomparable reader candidates keep declaration order. A row whose reader differs from owner appears in the reader list; a visibility-neutral analytics slot changes no access. |
| A2 | Revoke before a fresh request, revoke during an overlapping snapshot read/write, and revoke before receipt replay. Test the chosen time boundary and result disclosure separately. Session change suppresses a late callback without claiming to cancel server work. |
| Q1 | Several authorized partitions, including empty ones, exceed initialization limits. Never emit an incorrectly ordered first page or `no` from partial scope. After initialization, a sparse predicate yields an empty resumable page, then `yes` or exhausted `no`. |
| Q2 | Equal timestamps, complete occurrence ties, extreme timestamp bounds and composite prefixes. Raw sorting/filtering defines forward/reverse membership; no precision loss, skipped ties or overflow sentinel. Unsupported order/field access rejects. |
| Q3 | Fetch page 1; change only a residual-filter field, add to an empty partition, move a reader, or revoke scope before page 2. Relevant revisions force restart. One page's tree traversal and hydration share a snapshot. |
| W1 | Commit succeeds but response is lost; repeat the same operation concurrently and with different content. Same content applies once, changed content conflicts, absent receipt stays “not observed,” and replay rechecks visibility. |
| W2 | Create/update with zero, false, missing, null, unset, immutable/protected fields and exact values beyond JS safe integers. Complete post-patch validation and exact round-trip agree; stale editor versions are never silently overwritten. |
| D1 | Add one input, one derived field and one private root to a design. Explain, prepared plan, public contract and full catalog agree on their different projections. Replace old table-prefixed reference patterns for UUID transport while retaining target-type checks. Unknown codes, stale artifacts and mismatched types reject; no second SQL parser or hand-maintained field list is added. |
| D2 | Open the same store/model twice; then try a changed codebook/behavior/comparator and an old writer after permitted activation. Reopen is safe, incompatible populated activation rejects, and no old-format write commits. |
| D3 | Preview fixtures offline; populate a named disposable store; observe saved references and settled values. Attempt source/output overlap and a generated symlink before writing. Connections/workers shut down on success/failure; original source hashes remain unchanged. |
| F1 | Commit intent but lose the wake; lose the worker after provider start; delete/recreate the source. Recovery finds durable work, uncertain execution is not blindly resubmitted, and old attempts cannot affect the replacement. Mock provider only. |
| F2 | Signed webhook repeats, reuses an event ID with different content, arrives out of order or names another tenant/config. Commit a deduplicated receipt before acknowledgment; allowed transitions cannot regress terminal state. |
| F3 | Before exposing authentication: bad issuer/audience/expiry, wrong tenant, identity revision change, challenge replay/attempt limits, passkey counter/exchange race and revoked credential use. Library verification and transactional state each need their own evidence. |

M1/M2/M4 define the bounded calculation slice; [paper 11](11-native-slice-plan.md)
specifies its commands and [paper 12](12-native-slice.md) records acceptance.
M3/M5 establish the restricted
causal contract in paper 9; M6 establishes the bounded checker contract and its
failure controls in paper 10.
T cases require controlled schedules against the intended adapter before any
distributed concurrency claim. Q/W/D are contract tests when their
boundaries exist, not reasons to build an HTTP server or browser today. F cases
are gates before adding those capabilities, not current implementation work.

## 4. Decisions and explicit exclusions

| Decision | Research position and next evidence needed |
| --- | --- |
| D-CORE: first calculation scope | Fixed M1/M2/M4 native commands, linked trees, bounded point-owned reverse lists and independent real snapshots are accepted in paper 12. Curve edits conservatively discover all old/new subscribers. Native M3/M5 discovery/detachment needs its own contract; general query-driven shape remains deferred. |
| D-SETTLE: validation boundary | Final settled validation and separate operation checkpoints passed M4 for the toy context. General action permissions and public `mutate` remain gated; this deliberately differs from the current engine's statement boundary. |
| D-VALUES: general exact values | Toy integers are bounded. Choose full decimal range/rounding, timestamp/string comparator and scalar binding before claiming production or generic type support; Q2/W2 provide counterexamples. |
| D-MODEL: persisted identity | The native slice passed same-model reopen and requested model/codec mismatch rejection with a compiled source fingerprint. Semantic artifact identity, activation and stale-writer protection beyond the fixed model still require D1/D2. No legacy migration framework. |
| D-QUERY: scope and cursors | Complete bounded setup, scoped content revisions, typed prefix boundaries and explicit restart are proposed. Validate Q1–Q3 before implementing a general reader API; no unbounded residual-scan fallback. |
| D-STORE: distributed choice | redb remains the embedded proof. FoundationDB is conditional; conformance includes range overlays, absences, reverse phantoms, no-op guards and authority. A coarse guard's contention belongs in the cost model. |
| D-API: replay and authority | Structured operations, exact values, explicit preconditions and same-operation reconciliation are proposed. Receipt retention and externally exposed identity/session policy must be fixed before W1/F3 acceptance. |
| D-TOOLS: author/client views | Separate artifacts from one resolved model; source-preserving build and explicit fixture lifecycle. No custom REPL, generic form language or duplicate schema compiler is justified now. |
| D-LATER: external and operational scope | Effects, webhooks, authentication providers, business-audit retention, live subscriptions, backup/restore, populated migration and large exports remain separate capabilities with recorded gates. They are not supplied by the current proof. |

No throughput target, hardware workload or representative multi-tenant fanout
has been established. Do not manufacture a numeric performance acceptance goal.
When measurement becomes relevant, fix input distribution and correctness first;
count scope work, node loads, actual evaluations, dirty keys/bytes, retries,
memory and I/O. Separate model-load/setup, warm/cold requests and commit latency.
Increasing memberships or DAG reachability has unavoidable cost in any language.

## 5. Research loop and minimum verification

For each small packet:

1. Read `CONTEXT.md`, its owning paper and the named scenario. Check Git and
   relevant fingerprints. Reopen original conversation only for an ambiguity,
   not because another agent/session started.
2. State the question, candidate contract, invariant, counterexample and what
   result would change the decision. Trace affected surfaces through paper 6.
3. Prefer a mathematical derivation or source-based expected state first. If a
   fact remains implementation-dependent, use a disposable bounded experiment.
4. Preserve independent arithmetic and inventory expectations. A structural
   checker may walk actual nodes; its expected membership population must come
   from facts/declarations. Add a corruption control when extending the checker.
5. Record result, exact inputs/revision, oracle, relevant work counts and limits.
   Keep a failed minimized case. Avoid whole-tree repair, tolerance changes or
   deduplication merely to make a failing result look acceptable.
6. Patch the owning contract and compact continuation together. Make the next
   uncertainty explicit. Stop testing when the selected question is answered.

| Change in this directory | Minimum useful check |
| --- | --- |
| Research/docs only | Local links, consistency of statuses/scenario references, scoped diff; fingerprint unchanged proof inputs. No database or Cargo suite needed. |
| Existing proof's arithmetic/order/overlay | The affected semantic test, then the small locked suite if integrated; formatting/Clippy for Rust changes. Preserve old dated evidence. |
| New cross-record settlement | Tiny independent source oracle plus complete inventory/structural comparison and one rejection snapshot; M1/M2/M4, then only the newly connected cases. |
| Adapter/concurrency | Controlled interleaving with barriers, exact read/protection/write obligations and atomic snapshots. A conflict-set toy or serialized redb writer is insufficient distributed evidence. |
| API/tool/client boundary | An example of valid input, the named counterexample and observable outcome; mock transport/provider until external behavior is specifically under study. |

No unrequested dependency upgrades, broad original-ReBase suites, production
provider calls or million-row campaigns belong to a documentation packet.
All generated outputs and experiments stay under `rebase-next/`; references to
the original repository remain read-only. A future isolated checkout must still
build the proof without loading that repository or MetaSol.

## 6. Current closure and continuation

Completed here: attachment reconciliation, current-source impact review,
historical-conflict routing, API/tooling/lifecycle wireframes, bounded fixture
semantics and the scenario/gate register. Proof inputs were unchanged at that stage;
the [audit evidence](evidence/2026-10-22-context-audit.json) records documentation
checks and distinguishes reused evidence from new execution.

The [M3/M5 packet](09-causal-settlement.md) now defines before/after graphs,
permitted shape changes, exact prefix/output states, a diamond, private role
lifecycle and rejection predicates. Its [evidence](evidence/2026-10-22-m3-m5.json)
records nine accepted source states, all 36 valid fixed-step orders, failed
alternative-order countermodels and missing-inventory controls. These are new
research-model checks; the original Rust/database suites were not rerun.

The [M6 packet](10-independent-checker.md) now separates expected source/role
inventories, complete raw observation and structural verification. Its
[evidence](evidence/2026-10-22-m6.json) records five valid images, 28 invalid-state
controls and two incomplete-scope/budget controls. The prior M3/M5 source oracle
is reused without rerunning its order campaign. Neither historical evidence
file was rewritten; that packet did not change the Rust proof.

The [M1/M2/M4 implementation plan](11-native-slice-plan.md) now defines supported
records/commands, exact values/codes, versions and final-state lifecycle rules,
point-addressed storage, conservative reverse discovery, independent expected
inventories and complete rejection snapshots. Its [evidence](evidence/2026-10-22-native-slice-plan.json)
records planning/documentation checks and unchanged executable inputs at that
stage; it remains separate from subsequent execution evidence.

The user's later autonomous-completion request authorized S1–S5 as one bounded
goal. All five stages are now complete. [Paper 12](12-native-slice.md) and its
[evidence](evidence/2026-10-22-native-slice.json) record 68 native cases / 93
operations, 40 complete-state rejections, real precommit aborts and 68 reopens.
The independent checker verified complete source/role inventories and actual
links/caches. Thirteen integrated Rust tests, formatting and Clippy passed.
The original proof's Cargo files and module exports changed, so its original
eleven-input fingerprint claim is historical; old evidence and Python programs
remain unchanged.

There is no pending work in that goal. The next native causal expansion must
first close M3/M5 incremental discovery, detachment, identity reservation and
final ordering against its source oracle. Required outputs/prefix scheduling,
general ordered-result-dependent shape, minimal interval invalidation, full
API/dev tools and distributed schedules retain their gates. Do not restart S1,
repeat a whole-system audit or infer production acceptance from this experiment.
