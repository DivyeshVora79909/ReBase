# G1: compiled model reuse

**Active implementation goal, 2026-10-22.** The user requested continuation after
the reviewed bounded 0.2 release. Deliver a second materially different compiled
model through shared mutation/lifecycle/authority/tooling, preserving the existing
calculation model and independent checks. Do not extend its fixed input enum to
pretend another fixture is a reusable runtime.

Use native associated input/publication types and ordinary trusted Rust functions.
One prepared model supplies schemas, resolved declarations and identity. Generic
typed staging/codec/store implementations keep database and protocol concerns
outside model behavior. Binary composition selects a compiled model explicitly;
there is no plugin registry, executable JSON language or arbitrary code loader.
Default calculation type aliases may keep tests/examples concise; they must not
select a second mutation implementation or create a compatibility protocol.

## Checkpoints

1. **G1a — typed model boundary.** Remove fixed record/derived/count/slot/private
   assumptions from the shared codec, workspace and outer store. One compiled
   binding owns declarations, canonical native binding, settlement behavior and
   independent semantic checking. Shared command staging owns authorization,
   existence/CAS, schemas/mutability, tenant/reference checks and final publication.
   Sparse model codes and arbitrary declared nonzero slots must work. Explicitly
   version incompatible storage/model changes; no silent reinterpretation.
2. **G1b — shared reactive mechanism.** Extract final-shape dependency ordering,
   role allocation, old-output detachment and member reconciliation around resolved
   shapes and ordinary evaluation functions. Both models must use it. Keep fixed
   declared role/query sets and authored/direct-input shape; ordered results may
   change amounts, not discover new topology.
3. **G1c — independent second model acceptance.** Timed equipment pools, deliveries
   and clipped reservations use sparse codes and different root/member/role slots.
   A reservation emits a nonzero consume and release contribution. Delivery=10,
   A requests 8 over [10,30), B requests 7 over [20,40): allocations 8/2. Delivery
   changes to 12: 8/4. A ends at 15: 8/7. Test deactivation/reactivation, retargeting,
   zero contributions, rejection/rollback, authority, pages/root reads, receipts,
   reopening, integrity, backup/restore and cross-model rejection through the same
   public operations and developer tools. Source-only expected arithmetic must
   remain separate from mutation/tree traversal.

Commit coherent tested checkpoints on existing `main`. Continue through this
goal; do not stop after the document. Broader capacity, arbitrary monoids,
unbounded dynamic topology, full accounting, effects and distributed adapters
remain later capability gates. Preserve dated D1–D6 evidence and record new
source/behavior/format identity and exact execution separately.
