# Instructions for future changes

This frontend was implemented directly. These prompts are for later maintenance
and extension, not a replacement for the delivered application.

## Start from the actual checkout

```text
Work in /home/divyeshvora/javascript/node/projects/ReBase and its separate
MetaSol repository. Read designs/frontend/README.md, architecture.md,
screen-contracts.md and verification.md. Inspect Git status in both roots.
Do not restore the removed generic console, resource registry, query engine,
compatibility routes or old scripts. Preserve unrelated work.

Implement the requested change yourself. Use ordinary Solid/JavaScript and
the installed TanStack and SurrealDB libraries directly. Read the relevant
route, native data function and backend source contract before editing.
Write down the successful behavior, rejected behavior and smallest check.
Keep native record keys, decimal amounts, epoch fencing and exact-row writes.

Change the smallest complete user-visible workflow. Run the focused native
and browser checks that establish its behavior. Update the corresponding
contract and evidence, distinguishing verified behavior from future work.
Routine fixes and removal of superseded frontend code are authorized.
Do not deploy, call real providers or send messages as part of local testing.
```

## Implement a new screen/action

```text
Implement packet [ID] from designs/frontend/deferred-work.md.
Read its named source contract and the current similar route/data module.
Confirm prerequisites from the checkout; historical evidence alone is not
acceptance. List the public fields, permissions, dimensions and time meaning.

Create an ordinary route component and explicit native SDK functions. Use
the existing Records, RecordPicker, feedback and session helpers where they
fit. Add a shared component only for actual repeated behavior. Do not build
a registry, form generator, query DSL, universal context or generic editor.

Keep a stable create ID across retries, snapshot Solid stores, bind values,
and check every transactional result. Use updated_at on changes/deletes.
Write one native success/rollback case and the actual browser interaction.
Inspect mobile layout when controls/forms change. Explain any genuine
remaining policy decision without inventing a browser-side accounting rule.
```

## Review a change

```text
Review the requested diff against the working baseline, not against the
obsolete committed generic console. Identify concrete defects with paths
for reproducing them. Check permission affordances versus server authorization,
record-key types, exact decimals, timestamp preservation, stable ordering,
pagination bounds and the population represented by every total.

For asynchronous code, hold an actual response and change the term, account
or workspace. Verify the late response cannot replace current data, lose
form focus, reopen a dialog or report a different account's save as success.
For writes, test a useful rejected case and inspect the source/aggregate
after rollback. A build alone is not financial behavior verification.

Keep findings scoped. Do not require unrelated provider/capacity suites or
propose a framework rewrite to fix a normal route/component problem.
```

## Verification and completion record

Record the changed behavior and exact source revision/fingerprint, the commands
actually run, their outcomes, and any material limitations. Keep screenshots
from disposable fixtures. Link current documentation to actual files. A plan,
mock screen or passed build is not a native workflow test. A native fixture is
not a production migration, live-provider test or physical-capacity claim.

The completion response should lead with the result, give the relevant test
counts and link the implementation/docs. Do not claim deferred tax, filing,
valuation, CRM or HRM work is implemented because a scaffold or plan exists.
