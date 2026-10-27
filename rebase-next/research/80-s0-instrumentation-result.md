# S0.1 instrumentation result — accepted within bounds

**S0.1 is accepted within the recorded scope and limits.** The final focused working-tree matrix completed on redb, standalone SurrealKV, and local FoundationDB. Each backend reported 32 samples and 32 per-sample ACKs; the independent checker inspected every sample before allowing the next. All accepted matrix runs, resource observations and owned-target cleanup completed. The checker status remains explicitly `incomplete` for the unsupported settlement key lineage, with an additional redb protected-read limitation. The full Node suite and both negative-ACK controls passed. Root accepted this bounded checkpoint.

## Scope and claim limits

S0.1 adds optional caller-owned diagnostics around the existing native `Attempt`, storage facade, FoundationDB binding calls, and bounded probe. Normal storage begin methods and the ordinary application binding remain separate. The probe measures direct adapter/Attempt/tree/native-settlement work; it excludes authenticated HTTP and Store receipt/authority overhead. Process warmup does not establish a cold OS or storage cache.

Tree reads have a full-key independent source fold, and the checker compares decoded Root/Node key disclosures with raw native rows. Settlement record, route, and causal key discovery remains incomplete by design; dependent read depth for native settlement stays null/incomplete. Local FoundationDB evidence is one-host only. Redb’s serialized writer cannot execute the overlapping protected-read conflict control; the checker retains this as an explicit unavailable scope item.

These are focused S0.1 correctness and instrumentation checks: one sample per selected action/phase. They do not establish the S0.2 committed-source campaign, 30-sample latency distributions, 30-pair overhead, broad capacity, a layout choice, production capacity, or multi-host behavior.

## Source and build identity

The final focused probe is a working-tree build based on `0c14b41cf684a13fcf0af7e143a9564783b8fcc6`, not a committed-source S0.2 pilot. Its 96-entry compile-time source map digest is `a88c0782685cafe374a62cec8f31055b814a80db66b7221f80383fdeceb19f34`; its pinned binary SHA-256 is `50094d1a7b404c3e02501a441c204be8e36fb1e52e4078fdebc67e5d8f8c8213`. The default application binary SHA-256 is `688616f7572faad5ed19e97613c11a18425ac13c6ba9638fbc349b7575f72663`, with a 91-entry source-map digest `be20039f3f563320bf4095a3a85d6b4da57aa2875ba858c64e6a6acc4c077281`. Both inventories cover Cargo metadata, every Rust source, and all model files; the probe also covers its example sources and three frozen S0 fixtures.

An independent Node check matched all 96 and 91 source-map entries to current filesystem bytes, recomputed both sorted digests, and verified the probe and application binaries. Seven mathematical/model/codec files are byte-identical to base `0c14b41`; `BEHAVIOR_CONTRACT` remains `rebase-calculation-contract-7` and `CODEC` remains `native-slice-kv-7`. The frozen Node execution inventory has 66 maintained runtime/test inputs and four transient execution inputs, with original sorted digest `ed8fb60d8f0c1283de4154253fbaf5f5b2c9c8fe4279ca92fe5a0b49302d22d9`; the four transient scripts are retained byte-for-byte as non-runnable `.source` evidence files. the final S0 baseline checker source hash is `ad1a6901ede409e4a191236eb3e6682e0bbae1e5932ab4afc819d79bfff222d1`, and the source-oracle hash is `ade110bc7be2d5a970dffde70b566a864837b400ddccae3a91abb1ed4b98f284`. The full Node input map and execution inventory are separate evidence files. Full maps, proof, and build metadata are retained separately.

## Verification

The retained logs report:

- Default native suite: 114 passed, 0 failed.
- Focused diagnostics/native/storage tests: 12 passed, 0 failed.
- Focused FoundationDB tests: 3 passed, 0 failed.
- Probe example control: 1 passed, including the literal guard/checkpoint ACK and actual eight-corpus setup.
- Clippy completed successfully.
- Node 24.22.1 focused barrier suite: 22 passed, 0 failed.
- Full Node 24 suite: 166 passed, 0 failed.

The native example verifies assembled read and mutation sample fields for trace-off/on cases and final-report equality with per-sample checkpoints. The Node barrier validates each checkpoint independently, observes resources while native execution is paused, and acknowledges its exact action/phase identity before the next sample.

## Focused adapter matrix

The final matrix selected 23 frozen actions per adapter. It recorded 32 native samples and 32 checked ACKs on each adapter; first and repeat traversals are separate samples. All three run reports and resource observations are complete, with no run or resource incomplete reasons. The independent checker inspected every sample and returned these scoped incomplete reasons:

- SurrealKV: 14 `dependency-incomplete` reasons, one for each mutation sample whose record/route/causal lineage is not fully instrumented.
- Local FoundationDB: the same 14 lineage reasons. Its owned single-server loopback cluster was stopped and its data/log directories were removed.
- Redb: the same 14 lineage reasons plus `adapter-protected-read-control-unavailable` because the embedded serialized writer cannot overlap two conflicting writes.

The SurrealKV and FoundationDB protected-read conflict controls executed and preserved complete bytes. Redb’s protected-read conflict cases were explicitly marked unavailable. All native targets were cleared, all processes stopped, and each owned target was confirmed absent after cleanup. Local FoundationDB infrastructure, cleanup and topology are retained; this is not multi-host evidence.

A standalone Entry 8 prefix run on the final probe produced two ACKed samples and a source-checked result; its checker status remains incomplete only for redb’s unavailable protected-read control.

## Failure and recovery evidence retained

The v1 Entry 8 prefix trial stopped before any sample because the real rollback control returned `invalid_input` with `tiny application rollback control failed`. Investigation identified the status spelling mismatch `not-observed` versus `not_observed`; the raw run records only the generic control failure. Its process stopped and cleanup completed. It is preserved as a failed trial and excluded from the accepted matrix.

The v2 Entry 8 prefix trial produced a sample, but the Node ACK barrier rejected it with `outer commit boundary duration`: read-only sample serialization emitted `commitNs: null` while omitting required `commitBoundaryNs: null`. It stopped before acknowledging a sample; process and owned-target cleanup completed. It is preserved as a rejected trial.

An intermediate v3 redb matrix trial stopped after 27 ACKs when the independent checker found a native tree member absent from the source inventory. This was a Node oracle slot assumption: it treated a model-declared member as slot 1 where the authored model declares slot 3. The source oracle was corrected without a native change; the final 32-sample redb matrix then passed per-sample correctness checks. The earlier raw trial remains preserved and is excluded from accepted counts.

Both actual negative-ACK controls passed. A caller rejection stopped after one checked sample with `checkpoint-rejected`; a wrong-action ACK stopped after one checked sample with `checkpoint-acknowledgement-invalid`. Neither produced a repeat sample; both processes and native targets were cleaned up, and the targets were confirmed absent.

Large raw run JSON files are gzip-compressed losslessly in the evidence directory. The evidence manifest records compressed and uncompressed byte counts and SHA-256 hashes. The runs contain bounded public S0 fixture state; no complete private store is included. Four obsolete generated ELF files totaling 1,192,055,280 bytes were removed; their paths, hashes and reasons are retained separately.

## Next checkpoint

S0.2 is the next checkpoint and has not started. It will use committed-source inputs and the declared baseline and overhead campaigns. No S0.2 result, latency claim or layout/capacity conclusion is made here. The bounded S0.1 acceptance retains the incomplete settlement lineage, redb overlap-control limitation, and single-host FoundationDB scope as explicit limits.

The user requested a stop after this S0.1 commit/push. On a later continuation,
build an optimized probe from committed source and run the declared pilot first.
The focused wire reports are 19,064,357 bytes on redb, 19,068,530 on SurrealKV,
and 19,834,625 on FoundationDB for 32 samples. Projections for 30 repetitions of each action are
about 571–595 MB, beyond the 64 MiB bound; even one Posting 64 action projects
beyond the wire bound at 30 samples. These are size projections, not campaign
results or release-build duration estimates.

Use the pilot to freeze a bounded campaign revision before admission. A small
explicit `sampleStart`/count extension with global indices 0–29, one action per
fragment, and an independent checker for exact nonoverlapping campaign coverage
is a proposed solution. It is not implemented or accepted here. Preserve all
30 samples and the original outcome identities; never silently raise the bound
or discard oversized samples. The shared release cache is available, but its
build reuse and peak disk use still require observation.

## Evidence files

[2026-10-27 S0.1 evidence](evidence/2026-10-27-s0-instrumentation.json) indexes the source maps and independent proof, build/test logs, focused matrix and cleanup record, positive and negative ACK trials, and retained failed runs. Prior dated JSON evidence was not modified.
