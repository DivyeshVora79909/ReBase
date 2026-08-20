# Parent Field Findings

Status: implemented and probe-gated on SurrealDB `3.2.0`.

## Field context

Inside a field `VALUE` clause, `$value` is the incoming value for that field
and `$before` is the previously stored value for that field. `$before` is not
the previous whole record, so a field rule must not read `$before.parents`.

Validating the complete resulting array is incorrect for graph administration.
A dominating actor may be allowed to update a child while one of the child's
existing parents is intentionally outside that actor's select scope. Rechecking
the unchanged hidden edge makes every otherwise valid update fail.

## Implemented rule

```surql
VALUE array::distinct($value ?? [])
ASSERT $value.len() > 0
    AND array::all(
        array::difference($value ?? [], $before ?? []),
        |$parent| record::exists($parent)
    )
```

Groups add the bootstrap exception:

```surql
ASSERT id = groups:root
    OR ($value.len() > 0
        AND array::all(
            array::difference($value ?? [], $before ?? []),
            |$parent| record::exists($parent)
        ))
```

The default remains the authenticated actor (`[$auth]`) when the client omits
the field. An explicitly supplied empty array is not omission and is rejected
for ordinary users and groups. `groups:root` is the only parentless record.

## Why `array::difference`

SurrealDB `3.2.0` defines `array::difference(left, right)` as the symmetric
difference. The measured result is:

```text
array::difference([a, b], [b, c]) -> [a, c]
```

That is exactly the changed edge set for these deduplicated parent arrays:

- additions are checked, preventing assignment to hidden or missing parents;
- removals are checked, preventing an actor from rewriting an edge they cannot
  select;
- unchanged hidden parents are ignored, so unrelated authorized changes remain
  possible.

`array::complement` is one-sided and would need two calls plus a union.
`array::intersect` plus complements expresses the same operation with more
allocations and more surface area. The native symmetric operation is clearer.

On creation `$before` is `NONE`, normalized to `[]`, so every supplied parent is
validated. On update `$before` is the previous value of the `parents` field, not
the previous record object.

## Measured permission matrix

The permanent reference probe measured, from a record-user session:

- accessible target: `record::exists(target)` is `true`;
- existing but row-hidden target: `false`;
- missing target: `false`.

The permanent security probe constructs a child visible to Alice with parents
`[user:alice, groups:other]`, where `groups:other` is hidden from Alice. It then
proves:

| Mutation | Result |
| --- | --- |
| Retain hidden parent; add visible `groups:team` | accepted |
| Retain hidden parent; add hidden `groups:other_child` | rejected |
| Remove hidden `groups:other` | rejected |
| Remove visible `groups:team` | accepted |

The architecture probe repeats the same rule on a small isolated table, so the
field behavior does not depend on the larger principal graph implementation.

This behavior is version-sensitive because the official documentation does not
promise permission-aware `record::exists()` in every evaluation context. The
probe is therefore the compatibility gate for SurrealDB upgrades.

## Privilege escalation remains separate

Reference existence only proves that the parent is visible and real. It does
not prove that the actor may grant the parent group new roles. The
`prevent_role_escalation` event remains necessary because it protects the role
set itself, not the validity of the `parents` reference.

## Alternatives rejected

- `$before.parents`: wrong field context.
- full-result existence validation: rejects unchanged hidden edges and blocks
  legitimate updates.
- two `array::complement` calls plus `array::union`: correct but needlessly
  replaces the native symmetric `array::difference`.
- truthiness-only `ASSERT $value`: ambiguous and less explicit than a length
  invariant.
- field/table permission predicates as validation: permissions can filter or
  silently omit writes and do not provide the same assertion semantics.
- existence as complete authorization: existence does not prove ownership,
  delegation, or permission to grant inherited roles.
