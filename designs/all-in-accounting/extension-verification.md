# Accounting extension verification — October 8

Acceptance passed locally for the completed accounting extension. The exact
source snapshot, command record, phase coverage and transcript hashes are in the
[acceptance record](../rebase-system/evidence/2026-10-08-accounting-extension-acceptance.json).
Its six linked transcripts contain the command output. The [implementation
contract](extension-contract.md) defines the tested behavior. The October 7
[verification](verification.md) remains evidence for the earlier `88c5ae7`
accounting snapshot only; it does not certify this extension.

The packet builds 43 domain tables and 43 public create schemas from 15 native
domain files into 60 compiled tables, with 23 materials and no views. Core
accounting passed 63 mutation checkpoints and 35 full rollback snapshots; the
extension passed 50 checkpoints and 24 full rollback snapshots. Both suites
reapplied populated schemas and explicitly cleaned up records child-first.
Developer tools passed all 27 tests, including 15 client-schema tests. The
public schema exports were byte-identical, and a manual `parseSchema` audit
confirmed that all 43 schemas expose authored inputs only.

Focused shared-engine checks passed: compiler validation; ordered trees with 22
mutations, 683 reads/pages and 10 rollback cases; reader/index with 53
checkpoints, 6 rollback snapshots, 16-component acceptance and 17-component
rejection. Fifteen native domain files compiled to the 60-table result. The
compiler/runtime change is limited to the business-key component ceiling of
16; framework, gateway, configuration and other runtime files are unchanged
from baseline `a8ecfca`. The accounting baseline is `88c5ae7`; this working-tree
snapshot is being prepared for a separate local commit, whose hash is not yet
available.

The core financial oracle independently replays authored inputs with rational
`BigInt` arithmetic and compares derived monetary values exactly, including
ties-to-even quantization. Structural checks derive memberships and rebuild
ordered roots, chronology and summaries using the existing numerical-tolerance
oracle; rate comparisons there use JavaScript numbers. Checkpoints are oracle
boundaries, not row counts or throughput measurements.

Recorded commands include `npm run build`, the four project build/check gates,
Surreal validation of generated schemas and migration files,
`npm run probe:accounting-core`, `npm run probe:accounting-extensions`,
`npm run test:dev-tools`, `npm run probe:compiler`,
`npm run probe:ordered-tree`, `npm run probe:reader-index`, the temporal-tree
contract probe, source syntax checks, the SDK fixture example, and the
schema-to-authored-field audit. See the acceptance record for the exact command
list and linked [core](../rebase-system/evidence/2026-10-08-accounting-extension-accounting-output.txt),
[extension](../rebase-system/evidence/2026-10-08-accounting-extension-extensions-output.txt),
[developer-tool](../rebase-system/evidence/2026-10-08-accounting-extension-developerTools-output.txt),
[compiler](../rebase-system/evidence/2026-10-08-accounting-extension-compiler-output.txt),
[ordered-tree](../rebase-system/evidence/2026-10-08-accounting-extension-orderedTree-output.txt)
and [reader/index](../rebase-system/evidence/2026-10-08-accounting-extension-readerIndex-output.txt)
transcripts.

The recorded wall-clock duration for the extension probe is 7,597.18 seconds;
these timings include schema application, reapplication, snapshots, concurrent
work and execution scheduling. They are not production performance evidence.
The full gateway/provider/backend verify suite was not rerun; only affected
focused gates were repeated. Fixtures use disposable SurrealKV databases and
do not represent deployed data or migration from the prior populated API. No
MetaSol code changed, and no push or deployment occurred.
