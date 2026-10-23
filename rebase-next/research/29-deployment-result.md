# ReBase Next 0.6 deployment acceptance

**G3d/G3e complete, 2026-10-23.** The requested destination was a verified
deployment bundle in this environment. The bundle builds and runs all three
compiled models outside Git, with authenticated workflows and verified recovery.
[Release evidence](evidence/2026-10-23-g3e-deployment.json) records the exact
artifact, source fingerprints, commands, results and remaining scope.

## Artifact and provenance

The retained archive is
`target/g3e-release/rebase-next-0.6.0-linux-x86_64.tar.gz`, **7,726,619 bytes**.
Its sibling `.tar.gz.sha256` file verifies the archive. It contains the executable,
source, schemas, tools, tests, deployment templates, `BUNDLE.json` and `SHA256SUMS`.
The archive is a local deliverable; source and acceptance evidence are published
on `origin/main`.

```text
source commit: 305a7b8bf6065d3f22dbd5bdc9d4ab8bea7c6fec
source tree:   3e4abf35e65a839d849cfa7321f5f4fc819b9f34
archive SHA256:
e328c9da75eefaa4678f760e86707422a1b36a5bec5dc5e34231f23209c560f9
binary SHA256:
3d91ebffb31e2c59e3e885a6a0dde23316a1278334bd8fdc7db7971ff4b08eba
```

Settlement was published as `54b1249`; packaging/tool instructions were published
as `305a7b8`. This acceptance report follows testing of that immutable bundle.
Rebuilding a later documentation commit produces a different source archive.
To reproduce this exact input, use a separate checkout of `305a7b8` and run
`python3 -B tools/package.py --out target/reproduced-bundle` from `rebase-next/`.

Two builds from separate exported source directories produced **identical archive,
manifest and executable bytes** in this environment. Both built the copied source
outside Git with Rust 1.95.0, the lockfile and incremental compilation disabled;
the dependency compilation cache was reused. The executable also equals G3d's
accepted binary. This is observed reproducibility on this build host.

The final extracted inventory matches all **157 committed source blobs** and
their executable modes. All **159 payload checksums** pass before and after the
workflows. Changed-file and missing-binary controls fail verification. Runtime
keys, tokens, plans, stores and backups are generated under the private acceptance
directories and are absent from the source archive. The committed public test
keys remain test fixtures only.

## Executed acceptance

| Check | Result |
| --- | --- |
| Packaged calculation developer workflow | Two composed fixtures, three commits, six rejections, restart/replay and receipt archive fencing |
| Packaged calculation and equipment workflows | 64 public sources each; independent source arithmetic, selective edits, fanout, retargeting, complete rollback, replay, graceful restart, acknowledged process crash and restored HTTP service |
| Packaged invoicing workflow | 111 mutations /340 commands: 75 commits and 36 rejections; 40 pricing/rule and 24 settlement stress batches, source-limit rejection, stable roles, replay, crash recovery and restore |
| Packaged Python controls | All 18 tests pass: six client, three population-oracle and nine invoicing-oracle controls |
| Shipped configuration template | Fresh issuer for each model, authenticated client CLI readiness, ordinary fixture mutation and literal value checks |
| Failed restore isolation | Three damaged-checksum rejections, three wrong-model rejections and three existing-destination rejections; no published invalid destination or leaked temporary file; existing destination bytes unchanged |
| Restored template instances | All three models return the original values and replay the original receipt |
| Final artifact/process checks | Archive and payload checksums pass; all owned servers are stopped |

The standalone tools import only the extracted copies of `client`, `harness`,
`capacity` and `invoicing`. The temporary build sources had already been removed
before runtime acceptance. The final reports and logs are retained under
`target/g3e-release/`; `extracted.json` locates the private disposable stores and
saved requests used for the checks.

The [template/recovery probe](experiments/deployment_bundle.py) preserves the exact
executed probe source. To repeat it against a fresh extracted bundle, first create
that bundle's `target/` directory, then run from this source checkout:

```sh
python3 -B research/experiments/deployment_bundle.py /absolute/path/to/extracted-bundle
```

The invoicing fixture ends with gross/paid/cash/refund capacity **9244**, balance
**0**, and gross receivable = payable = **13866**. Its missing-refund and delayed
refund histories reject atomically. All 36 rejected HTTP mutations preserve
complete logical application-table bytes and leave no success receipt.

G3d's **76 debug and optimized Rust tests**, **116 independent native/local cases**
and clean formatting/Clippy remain the native acceptance for this byte-identical
executable; see [settlement evidence](evidence/2026-10-23-g3d-settlement.json).
G3e adds packaging, deployment and recovery evidence. The 64-source checks do
not repeat G2's 4,096-source/16,384-role trials or establish new capacity numbers.

## Platform, identities and operation

The supplied binary targets **Linux x86_64**, requiring **glibc 2.38+**,
`libgcc_s.so.1`, `libm.so.6` and the GNU dynamic loader. The manifest records the
build host and exact dependencies. Packaged workflows require Python 3.11+ and
OpenSSL. Building a bundle requires Python 3.12+, Git, pinned Rust 1.95.0,
a C/C++ toolchain, CMake and GNU `readelf`; Cargo can download the locked source
dependencies. Other target hosts require their own compatible build and checks.

| Model | Identity | Public / active outputs / retained roles |
| --- | --- | --- |
| calculation | `4d5eb880ac2420897d4affd0211fb4b6ea6bfea5edbf9ad598bc4589b8be59ff` | 4096 /8192 /16384 |
| equipment | `4ec3816f297bbf66bde48bf0643cd0b91f447fb93990e038c991e77746e152fd` | 4096 /8192 /16384 |
| invoicing | `7230c26cc5c85bd56db3ba67da1748e727aebee59d5aaaae1ce188d7da8d33be` | 64 /256 /512 |

All use `rebase-store-4` and `native-slice-kv-4`. Calculation/equipment identities
remain compatible with 0.4/0.5; invoicing behavior is `invoice-assessments-2` and
requires a new store compared with 0.5. The retained matching 0.5 binary verifies
its old invoicing store; G3d proves a clean incompatible open preserves physical
bytes. Recover crashed old files with their matching binary before upgrading.

Follow the [deployment guide](../docs/deployment.md) for extraction, checksums,
the three workflow commands, issuer provisioning and service installation. For
the invoice/refund workflow after extracting and checking the archive:

```sh
mkdir -p target
python3 -B tools/invoicing.py --binary bin/rebase-next --out target/my-invoicing-run
```

Select the same model on every command against a store. Stop its server before
operator checks/backups/restores. Use a new restore destination and retain the
matching binary, backup and original operation plans. The configuration template
and actual loopback services were exercised; systemd installation and a public
TLS endpoint remain operator deployment steps outside the selected bundle goal.

## Completion and remaining capability boundary

There are no unresolved release blockers for this bundle. It supports one
embedded process, one tenant and one selected compiled model per store. The
200,000-work-unit mutation budget, 64 commands, 32 returned IDs, 1,024 receipts
and 64 MiB backup ceiling remain separate limits. Larger causal closures may
reject atomically. The historical G2 measurements retain their authored workload
scope; no sustained throughput, power-loss or distributed guarantee is added.

Payments/refunds are authored facts, not external transfers. Full accounting
parity, quantity-return pricing, dated rational FX, arbitrary model loading,
broader aggregate/topology contracts, external effects, distributed adapters,
larger invoicing populations and frontend remain separate capability gates.
**The selected deployment goal is complete. No follow-on implementation gate is
active.** Start a named bounded gate when further capability work is requested;
preserve the accepted source snapshots and independent evidence.
