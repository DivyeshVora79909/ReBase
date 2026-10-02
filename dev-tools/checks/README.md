# Developer checks

This directory holds maintained top-level regression entrypoints. Their
`package.json` script names are unchanged; `npm run verify` remains the
default compiler, schema-validation, and regression gate. It includes the
environment, authentication, credentials, compiler, architecture, queue,
admission, dead-letter, runtime, scheduling, webhook-inbox, adapter, account,
suite, and general security/data checks. `runtime-probe-worker.js` is an
internal child-process helper for the runtime check.

`razorpay-refund-probe.js` remains a separately invoked regression through
`npm run probe:razorpay-refunds`. The temporal-tree and accounting checks stay
in their existing subdirectories with their fixtures and oracles.

## Experiments

Performance and measurement tools live in `../experiments/`:

- `authorization-performance.js`
- `reference-permission-performance.js`
- `write-amplification-probe.js`
- `synthetic-write-amplification-probe.js` and its fixture directory

These commands remain available under their existing package script names,
but they are measurement runs rather than members of `npm run verify`.
`../research/redesign-probe.js` and dated evidence remain in place as historical
research material. The old admission-lease reproducer is preserved in
`../../designs/rebase-system/evidence/admission-lock-expiry.cjs`; the maintained
admission regression is `admission-capacity-probe.js`.
