# Packet C: local dependency analysis

Status: the bounded repair described here is implemented and verified. Further
language expansion is deferred. Starting review revision: `d267dc2`.

## Failure and correction

The previous analyser followed directly bound helper parameters, but did not
follow `LET $copy = $row`. Its attempted unsupported-argument check also inserted
`$row` into a regular expression without escaping `$`. A wrapped whole-row
argument bypassed that check. Both shapes compiled with `a_total` before
`z_rate`. On a disposable native database, input `2` initially produced rate `2`
and total `4`; updating input to `3` committed rate `3` and total **4**, although
the required total was **6**. Fresh SELECTs confirmed stored stale values.

There was another scheduling defect: masking strings before splitting call
arguments erased a literal argument. In `fn::parts('total', $row)`, the row could
be bound to the wrong formal parameter. The native fixture now contains this
case through nested helpers.

Changes in `dev-tools/compiler/derived-order.js`:

- Retain original argument text and positions while using masked code to locate
  calls. Literal arguments no longer disappear.
- Permit a whole local row only as a static field projection or a direct argument
  to a declared helper. Validate each use of the row, including forwarded helper
  parameters. An unsupported escape fails compilation before generating an order.
- Remove the ineffective parameter-regex guard. Keep dependency-based topological
  ordering and existing cycle detection.

Examples:

```surql
-- Supported: fields are visible to the analyser through both helpers.
DEFINE FUNCTION fn::outer($row: object) {
    RETURN fn::parts('total', $row);
};
DEFINE FUNCTION fn::parts($label: string, $row: object) {
    RETURN $row.z_rate * 2dec;
};
-- VALUE fn::outer($this) COMMENT '@rebase-derived'

-- Also supported: the local dependency is explicit at the call site.
DEFINE FUNCTION fn::twice($value: decimal) {
    LET $copy = $value;
    RETURN $copy * 2dec;
};
-- VALUE fn::twice($this.z_rate ?? 0dec) COMMENT '@rebase-derived'
```

Whole-row `LET` aliases, IF/object/function wrappers around a row, returning a
whole row, dynamic root-field access, and unknown whole-row helpers are rejected.
This is an intentional supported-language boundary, not an implementation of
general SurrealQL data-flow analysis. Direct field syntax uses ordinary unquoted
identifiers (`$this.field`). Broadening the grammar must update native CREATE
shadow substitution and runtime substitution together with dependency analysis.

## Evidence

Fresh on October 15, SurrealDB 3.3.0 / Node 22.23.2:

- `node --test dev-tools/tests/derived-order.test.js`: direct and nested helper
  ordering, literal argument positions, comments, scalar aliases, hidden cycle,
  and nine unsupported flow controls pass.
- `npm run probe:derived-order`: native CREATE, local and parent UPDATE, ASSERT
  rollback, declaration reordering, populated reapplication, restricted record
  user and audit tests pass. This includes literal-before-row helper forwarding.
- `npm run test:dev-tools`: 38 tests pass, including the separate oracle repair.
- Both accounting and all-in-one profiles compile. Compiler and architecture
  probes pass. No domain equations were changed.

The historical review's rejected helper forms now fail compilation. Do not claim
that aliases or arbitrary wrappers are automatically inferred; they are rejected.

## Instructions for a future compiler-language packet

Only expand row support when needed by an authored use case. Do not add a chain
of independent regex exceptions. Either retain the documented restriction or
introduce a bounded, scope-aware expression representation which can prove local
row provenance and which all expression rewrites share.

If implementing aliases, support a clearly stated subset first: immutable local
bindings, lexical scope, static projections, and declared helper calls. Handle
shadowing, branches, nested calls, literal positions, and return-value provenance;
reject everything outside that subset. Preserve explicit scalar composition.
Run native CREATE and UPDATE with names deliberately opposed to dependency
order. Add both a hidden cycle and an acyclic control. A textual check of generated
SQL alone is insufficient.

This repair does not certify arbitrary SELECTs, dynamic function calls, external
I/O, mutating helper functions, or feedback through publication. Those are
separate compiler/coordinator boundaries. Do not describe the accepted language
as having automatic dependency discovery for unrestricted SurrealQL.

Keep a future implementation and its native tests in one reviewable commit.
Record accepted grammar and rejected grammar in the same commit. No compatibility
layer or new application-authored impact rule is required.
