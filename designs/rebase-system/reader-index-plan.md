# Reader and index implementation — 2026-10-07

This historical packet is committed as `a8ecfca`. The October 8 accounting
extension now sets an explicit 16-component key limit; see the current
[ordered-tree contract](ordered-tree-contract.md).

Baseline: clean accounting commit `88c5ae7`. The supplied October 7 conversation
and confirmed continuation govern this change.

1. Replace persisted reader arrays with one VALUE-derived `read_by`: direct
   declared reference owners, then membership-root owners; a descendant replaces
   the chosen ancestor, and incomparable candidates retain the first. `owned_by`
   is the fallback. SELECT uses `read_by`; writes retain ownership. Refresh after
   source-owner and DAG edits.
2. Index normalized email, phone, username and passkey identifiers in one private
   tenant `z_auth_identifiers` unique tree. Authentication lookups use that tree;
   owner listings use native reference backlinks. Keep private runtime indexes
   whose queries still need them, and stop generating generic lookup indexes.
3. Allow trees on framework principals and explicit membership without reader
   inheritance. Build an executable analytics design with tenant creation/effective
   time, owner creation/effective time and composite owner/creation keys. Enrollment
   is explicit, optional effective dates omit membership, and summaries have an
   explicit privacy boundary. Remove the arbitrary eight-component key limit.
4. Verify identity collisions, rollback, rekey/delete, concurrent writers, record
   clients, single-reader branch selection, graph edits, analytics arithmetic and
   tree structure, backdating, owner changes, reapplication and cleanup. Run the
   affected backend and accounting regression gates.
5. Write the developer blueprint, worked source references and current evidence.
   Update active continuation routes. MetaSol remains a separate migration.

Status: implemented and locally verified. The [verification record](reader-index-verification.md)
records all 40 backend gates, 53 focused checkpoints with six rollback snapshots,
the 63-checkpoint accounting regression with 35 rollback snapshots, and all 27
developer-tool tests. The [developer blueprint](developer-blueprint.md) is the
authoring entry point. The original accounting work is committed as `88c5ae7`;
this framework change is uncommitted. No push or deployment.
