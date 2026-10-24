# Exact time windows

The 0.7.0 source adds exact financial time windows to causal reads and the
authorized `roots.read` operation. The source tree is ahead of the last verified
deployment bundle: that bundle is 0.6.0 and uses store/native codec format 4.
Current source 0.16.0 uses store 10 /native codec 7 /effect codec 4 /API 4;
see [storage upgrades](storage.md#data-identity-and-upgrades) before opening a store.

## Wire form

`TimeRange` has required `lower` and `upper` fields. Each bound is `null`, an
included time, or an excluded time. Times are canonical `i64` decimal strings:

```json
{"lower":null,"upper":{"excluded":"12"}}
```

That example includes every event strictly before time 12. Use
`{"included":"12"}` for an inclusive endpoint. Both ends are inclusive in
this example, so all events at time 12 form one selected timestamp group:

```json
{"lower":{"included":"12"},"upper":{"included":"12"}}
```

Reversed bounds and intervals with no representable timestamp are empty. For
example, `(12, 13)` is empty on the discrete `i64` timeline. Empty windows keep
their declared query slot and registration identity; an active query whose sum
is zero also remains a query. Neither case invents dependencies on excluded
events. Bounds work at `i64::MIN` and `i64::MAX` without timestamp arithmetic
or UUID sentinels.

`TimeRange::schema()` supplies the closed shape used by the model catalog.
Native binding also enforces exact `i64` bounds and canonical scalars; ingress
rejects duplicate keys. JSON Schema alone does not enforce those native rules.

## Reactive model reads

Trusted Rust bindings describe every reactive read with
`causal::Read { slot, root, range, validate }`. A calculation read depends on
every final emission whose root and timestamp fall inside its range, including
zero-valued emissions. The evaluator receives the resulting sum. A
validation-only read uses the same range but creates no calculation edge; its
check runs after all outputs settle. Only the final active dependency graph
determines evaluation order and feedback rejection.

All financial roots in the calculation, equipment and invoicing catalogs
declare the `range` root read. A caller sends the ordinary authorized
`roots.read` request with `read.kind` set to `range`. Replace `model` below
with the resolved model identity returned by `model public`:

```json
{
  "model":"<resolved-model-identity>",
  "owner":"00000000-0000-4000-8000-000000000020",
  "slot":2,
  "read":{"kind":"range","range":{"lower":{"included":"10"},"upper":{"excluded":"20"}}}
}
```

The response includes `owner`, `slot` and an opaque UUID root `revision`.
Compare revision tokens only for equality; no global store revision is returned.
Its `value` contains `count`, `sum`, `complete_min`, `first` and `last`; amounts
and timestamps are decimal strings, while `first` and `last` are null
for an empty result. The server applies the same current root-owner and reader
authority checks as other root reads. The client cannot provide a comparator,
function or undeclared predicate. Count is a bounded JSON integer. The minimum
is relative to a zero starting balance for the selected window. Quote roots do
not expose financial ranges.

The ordered tree folds fully covered cached subtrees and boundary leaves in
source order. It reuses the complete-time financial summary, including its
minimum prefix, rather than subtracting two prefixes. A whole-root range uses
the cached root summary. The existing strictly-before scalar prefix read still
uses the optimized `tree::prefix` path.

## Discovery and scheduling

Reverse registrations retain each subscriber's exact range in an upper-ordered
AVL tree. Each subtree caches its minimum lower cut, and the route header counts
subscribers with bounded lower ends. Inclusive and exclusive endpoints at the
same time have distinct adjacent positions in the order. For roots with only
prefix readers, invalidation keeps the earliest-impact suffix path. When a root
has bounded readers, settlement stabs every distinct changed time against both
the original and staged registrations, using the upper order and lower-cut
cache to prune. This covers revalues, rekeys, deletions and root moves that
affect disjoint windows.

For a root with `E` distinct emission times, bounded calculation reads depend on
the canonical segment-tree cover of the selected time positions. Prefix reads
retain their shared prefix gates. With `P` producers and `R` reads, the bounded
graph has `O(P + E)` nodes and `O(P + E + R log E)` edges; the prefix-only graph
retains its previous linear-edge construction. These are graph-size bounds,
not a mutation-throughput promise. All discovery, graph construction and
scheduling remain charged to the mutation work budget and can reject atomically.

The implementation provides exact financial sum windows. It does not add
arbitrary monoids, composite time/UUID query keys, general query predicates or
typed query-result variants. Ordered query results remain exact `i128` sums.

## Store compatibility

G4b introduced these semantics in source 0.7.0 /format 5; G4c's source 0.8.0
native-index extraction advanced to format 6. Current source 0.16.0 uses
store 10 /native codec 7 /effect codec 4 /API 4, with UUID revisions and scoped
cursor epochs. Its behavior contracts include `rebase-calculation-contract-7`,
`equipment-reservations-6` and `invoice-assessments-6`. The earlier financial
range semantics and reverse-route caches remain in use.
There is no implicit migration from older stores. Preserve matching binaries
and backups; the verified 0.6.0 bundle remains the last deployment artifact.
