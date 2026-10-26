# N6 Node IssueShare composition

Accepted within this bounded scope on 2026-10-26. All 135 Node tests pass with
zero failures or skips; focused real-native tests pass 2/2. Root also executed
the imported workflow, obtaining 15002/5001 then 20002/6667.
[Evidence](evidence/2026-10-26-n6-issue-share.json) records exact source, artifact,
commands and review. No Rust changes, build or dependency changes were needed.

The Node example opens the compiled invoicing model, reads its developer
catalog, asks the native fixture API for the deterministic `issue-share` draft,
then uses the existing `client.prepare`, `client.execute`, and `records.get`
calls. It adds no model-specific SDK or JavaScript accounting implementation.

The real-native test uses independent literal values: quantity `3/2` times
unit price `10001` is `15002` minor units under half-even rounding, and one
third of `15002` is `5001`; changing quantity to `2` yields issue basis `20002`
and share `6667`. It checks floor/ceiling/zero ratio behavior, exact rounding
rejection, complete backup-table preservation and absent receipt on rejection,
stale-version rejection, and parent/consumer edits in both command orders.
It also distinguishes schema shape checks from native semantic validation:
`2/6` and `4/3` pass the JSON schema layer but native validation rejects them;
canonical `1/3` passes both.

The existing native coverage remains the authority for broader invoicing
behavior. `tests/issue_share.rs` covers current-parent publication, retargeting,
both command orders, invalid rollback, authority, restore, and corrupted
publication/route rejection. `src/values.rs` and `tests/exact_values.rs` cover
canonical rational values and all rounding modes. `tests/invoicing.rs` and
`src/models/invoicing_check.rs` cover independently reconstructed dated
invoice, assessment, credit, payment, refund, claim, and output histories.
The Python `Fraction` oracle and broad real-process workload remain in
`tools/test_invoicing.py`, `tools/issue_shares.py`, and `tools/invoicing.py`;
their stress, chronology, settlement, and authority campaigns are not duplicated
in this focused Node workflow. Existing G3c/G4d evidence and model artifacts
remain unchanged.
