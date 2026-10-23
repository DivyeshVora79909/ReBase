# G4b: exact reactive time windows

**Prepared, 2026-10-23.** Follows [G4a](31-terminal-validation.md) in the
[capability program](30-capability-program.md). Implement one shared window
contract through tree reads, reverse selection, causal readiness, checking and
ordinary developer interfaces. No arbitrary query language is introduced.

## Values, identity and semantics

`TimeBound` is unbounded, included(time) or excluded(time). The JSON form is
`null`, `{"included":"0"}` or `{"excluded":"0"}` using canonical exact i64
strings. `TimeRange { lower, upper }` requires both fields and rejects arrays,
unknown fields, duplicates and noncanonical scalars. Included equal endpoints
select a complete timestamp group; other equal or reversed intervals are empty.
All extreme endpoints work without timestamp increments or UUID sentinels.

Replace the shared reactive `Read.before` with `Read.range`. Stored `Query`
uses the same typed range instead of an untyped lower string and upper enum.
Latest selection remains its separate operation, with its upper inclusive time
represented faithfully. Empty and zero-valued active queries keep their slot,
registration and invalidation identity. Validation ranges run after all outputs;
they never create calculation edges.

Expose a financial root range read through the ordinary authorized RPC boundary
and model catalog. Reuse complete timestamp aggregation; no client may supply
an arbitrary comparator, function or non-indexed predicate.

## Ordered tree read

Fold ordered canonical covered subtrees and boundary leaves, preserving source
order. This can return the existing complete financial summary for a window;
it does not require subtracting minima or other non-invertible summaries.
Full-root reads use the cached summary. Every path is work-charged and retains
link/depth checks. Reject genuine arithmetic overflow rather than wrap it.

## Reverse discovery

Reuse the existing upper-ordered reverse AVL. A subscription stores its exact
range and the minimum nonempty lower cut in its subtree. An all-empty subtree
has no lower cut; this must serialize distinctly from an unbounded lower cut.
Inclusive and exclusive upper cuts interleave at each timestamp; sorting all
included values after all excluded values would be incorrect.

Maintain a header count of bounded-lower subscriptions. Roots containing only
prefix readers retain the accepted earliest-impact suffix fast path. Roots with
bounded readers stab every distinct changed time against both original and
staged registrations, pruning by upper order and subtree lower augmentation.
Retain all old/new changed timestamps from authored and private membership
changes. A value edit, rekey, deletion or root move can affect disjoint windows.
Deduplicate work/candidates, preserve hard budgets and test mixed populations.

## Final-graph readiness

Keep the accepted prefix-gate path for unbounded-lower calculation reads. For
bounded reads, build attempt-local segment gates over sorted final emissions.
A time leaf depends on all producers at that time, parents on children, and a
reader only on the canonical cover of emission positions inside its range.
Zero contributions still create dependencies. Excluded producers create none.
Using two prefix gates would introduce false predecessors and false cycles.

Only the final active graph determines order and feedback rejection. Old/new
routes serve discovery. A move whose union graph is cyclic can still be valid.
No unresolved contribution may be interpreted as a settled zero.

## Persisted and model contracts

Typed stored ranges and route augmentation change native format: bump store and
codec 4 to 5, plus every affected production binding's behavior. Preserve a
matching 0.6 binary/store before switching. Old stores reject explicitly; no
silent migration is promised. Update exact query builders and complete-route
checking, catalogs, tools and live source oracles together. Historical evidence
remains dated and unchanged.

## Independent acceptance

The [literal source oracle](experiments/reactive_windows.py) uses ordinary
bound conjunction, full source sums and pairwise final producer/read edges.
It imports no runtime code and implements neither AVL selection nor compressed
readiness gates. Its self-tests are preparation evidence, not native acceptance.

1. Match bound truth tables, discrete empty intervals, equal-time groups,
   canonical wire controls, extremes and large exact values.
2. Compare randomized point stabbing, original/staged moves and multiple same-root
   impacts to literal membership. Independently check all interval augmentations,
   disconnected registrations, counts and balance; reject corrupted caches.
3. Compare exact producer reachability/cycles against pairwise enumeration,
   including self-feedback, zero outputs, valid edge reversal and a false-cycle
   counterexample. Preserve dense-prefix graph/work controls.
4. Native mutations exercise bound/root edits, insertion/revalue/deletion,
   disjoint windows, direct inherited bounds, output lifecycle and terminal-only
   validators. Check complete source-derived inventories, atomic rollback,
   receipt absence, replay and reopen.
5. Measure a many-disjoint-window selection workload and representative existing
   selective/cascade paths. Report measured costs and hard rejection boundaries,
   not universal logarithmic mutation capacity.

Run formatting/Clippy before debug/optimized suites and affected independent
corpora. Add representative authenticated range reads, authority failures and
recovery. Update the active handoff, commit/push acceptance, then continue G4c/G5
using the program's next concrete observable boundary.
