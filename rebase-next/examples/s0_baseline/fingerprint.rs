//! Compile-time fingerprints of the exact observer, model, fixture and native inputs.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
pub fn digest() -> Value {
    let inputs: &[(&str, &[u8])] = &[
        ("Cargo.lock", include_bytes!("../../Cargo.lock")),
        ("Cargo.toml", include_bytes!("../../Cargo.toml")),
        (
            "examples/s0_baseline.rs",
            include_bytes!("../../examples/s0_baseline.rs"),
        ),
        (
            "examples/s0_baseline/fingerprint.rs",
            include_bytes!("../../examples/s0_baseline/fingerprint.rs"),
        ),
        (
            "model/fixtures/causal-demo.json",
            include_bytes!("../../model/fixtures/causal-demo.json"),
        ),
        (
            "model/schemas/account.json",
            include_bytes!("../../model/schemas/account.json"),
        ),
        (
            "model/schemas/adjustment.json",
            include_bytes!("../../model/schemas/adjustment.json"),
        ),
        (
            "model/schemas/basis.json",
            include_bytes!("../../model/schemas/basis.json"),
        ),
        (
            "model/schemas/curve.json",
            include_bytes!("../../model/schemas/curve.json"),
        ),
        (
            "model/schemas/entry.json",
            include_bytes!("../../model/schemas/entry.json"),
        ),
        (
            "model/schemas/moment.json",
            include_bytes!("../../model/schemas/moment.json"),
        ),
        (
            "model/schemas/output.json",
            include_bytes!("../../model/schemas/output.json"),
        ),
        (
            "model/schemas/pin.json",
            include_bytes!("../../model/schemas/pin.json"),
        ),
        (
            "model/schemas/posting.json",
            include_bytes!("../../model/schemas/posting.json"),
        ),
        (
            "model/schemas/quote.json",
            include_bytes!("../../model/schemas/quote.json"),
        ),
        (
            "model/schemas/rule.json",
            include_bytes!("../../model/schemas/rule.json"),
        ),
        (
            "model/schemas/subsidiary.json",
            include_bytes!("../../model/schemas/subsidiary.json"),
        ),
        (
            "research/fixtures/s0-inputs.json",
            include_bytes!("../../research/fixtures/s0-inputs.json"),
        ),
        (
            "research/fixtures/s0-trace.schema.json",
            include_bytes!("../../research/fixtures/s0-trace.schema.json"),
        ),
        (
            "research/fixtures/s0-workload-manifest.json",
            include_bytes!("../../research/fixtures/s0-workload-manifest.json"),
        ),
        ("src/access.rs", include_bytes!("../../src/access.rs")),
        ("src/algebra.rs", include_bytes!("../../src/algebra.rs")),
        (
            "src/bin/rebase-next.rs",
            include_bytes!("../../src/bin/rebase-next.rs"),
        ),
        ("src/binding.rs", include_bytes!("../../src/binding.rs")),
        ("src/causal.rs", include_bytes!("../../src/causal.rs")),
        ("src/demo.rs", include_bytes!("../../src/demo.rs")),
        (
            "src/dependency.rs",
            include_bytes!("../../src/dependency.rs"),
        ),
        (
            "src/diagnostics.rs",
            include_bytes!("../../src/diagnostics.rs"),
        ),
        (
            "src/effect_tests.rs",
            include_bytes!("../../src/effect_tests.rs"),
        ),
        ("src/effects.rs", include_bytes!("../../src/effects.rs")),
        (
            "src/effects/application.rs",
            include_bytes!("../../src/effects/application.rs"),
        ),
        (
            "src/effects/conformance.rs",
            include_bytes!("../../src/effects/conformance.rs"),
        ),
        (
            "src/effects/fake.rs",
            include_bytes!("../../src/effects/fake.rs"),
        ),
        (
            "src/effects/inbox.rs",
            include_bytes!("../../src/effects/inbox.rs"),
        ),
        (
            "src/effects/inbox_tests.rs",
            include_bytes!("../../src/effects/inbox_tests.rs"),
        ),
        (
            "src/effects/state.rs",
            include_bytes!("../../src/effects/state.rs"),
        ),
        (
            "src/effects/worker.rs",
            include_bytes!("../../src/effects/worker.rs"),
        ),
        (
            "src/effects/worker_tests.rs",
            include_bytes!("../../src/effects/worker_tests.rs"),
        ),
        ("src/fixtures.rs", include_bytes!("../../src/fixtures.rs")),
        ("src/host.rs", include_bytes!("../../src/host.rs")),
        (
            "src/host/backend.rs",
            include_bytes!("../../src/host/backend.rs"),
        ),
        (
            "src/host/bootstrap.rs",
            include_bytes!("../../src/host/bootstrap.rs"),
        ),
        (
            "src/host/operations.rs",
            include_bytes!("../../src/host/operations.rs"),
        ),
        ("src/identity.rs", include_bytes!("../../src/identity.rs")),
        ("src/index.rs", include_bytes!("../../src/index.rs")),
        (
            "src/index_tests.rs",
            include_bytes!("../../src/index_tests.rs"),
        ),
        (
            "src/indexes/measurement.rs",
            include_bytes!("../../src/indexes/measurement.rs"),
        ),
        (
            "src/indexes/mod.rs",
            include_bytes!("../../src/indexes/mod.rs"),
        ),
        (
            "src/indexes/standard.rs",
            include_bytes!("../../src/indexes/standard.rs"),
        ),
        ("src/inspector.rs", include_bytes!("../../src/inspector.rs")),
        ("src/integrity.rs", include_bytes!("../../src/integrity.rs")),
        ("src/json.rs", include_bytes!("../../src/json.rs")),
        ("src/lib.rs", include_bytes!("../../src/lib.rs")),
        ("src/lifecycle.rs", include_bytes!("../../src/lifecycle.rs")),
        ("src/local.rs", include_bytes!("../../src/local.rs")),
        ("src/merge.rs", include_bytes!("../../src/merge.rs")),
        ("src/model.rs", include_bytes!("../../src/model.rs")),
        (
            "src/models/calculation.rs",
            include_bytes!("../../src/models/calculation.rs"),
        ),
        (
            "src/models/calculation_reactivity.rs",
            include_bytes!("../../src/models/calculation_reactivity.rs"),
        ),
        (
            "src/models/effect_demo.rs",
            include_bytes!("../../src/models/effect_demo.rs"),
        ),
        (
            "src/models/equipment.rs",
            include_bytes!("../../src/models/equipment.rs"),
        ),
        (
            "src/models/invoicing.rs",
            include_bytes!("../../src/models/invoicing.rs"),
        ),
        (
            "src/models/invoicing_check.rs",
            include_bytes!("../../src/models/invoicing_check.rs"),
        ),
        (
            "src/models/invoicing_fixtures.rs",
            include_bytes!("../../src/models/invoicing_fixtures.rs"),
        ),
        (
            "src/models/measurement.rs",
            include_bytes!("../../src/models/measurement.rs"),
        ),
        (
            "src/models/mod.rs",
            include_bytes!("../../src/models/mod.rs"),
        ),
        (
            "src/models/quantity.rs",
            include_bytes!("../../src/models/quantity.rs"),
        ),
        ("src/mutation.rs", include_bytes!("../../src/mutation.rs")),
        (
            "src/native_codec.rs",
            include_bytes!("../../src/native_codec.rs"),
        ),
        (
            "src/native_slice.rs",
            include_bytes!("../../src/native_slice.rs"),
        ),
        (
            "src/parameter_tests.rs",
            include_bytes!("../../src/parameter_tests.rs"),
        ),
        ("src/plan.rs", include_bytes!("../../src/plan.rs")),
        (
            "src/publication_tests.rs",
            include_bytes!("../../src/publication_tests.rs"),
        ),
        ("src/query.rs", include_bytes!("../../src/query.rs")),
        ("src/receipts.rs", include_bytes!("../../src/receipts.rs")),
        (
            "src/route_tests.rs",
            include_bytes!("../../src/route_tests.rs"),
        ),
        ("src/routes.rs", include_bytes!("../../src/routes.rs")),
        ("src/rpc.rs", include_bytes!("../../src/rpc.rs")),
        ("src/security.rs", include_bytes!("../../src/security.rs")),
        ("src/server.rs", include_bytes!("../../src/server.rs")),
        ("src/staging.rs", include_bytes!("../../src/staging.rs")),
        ("src/storage.rs", include_bytes!("../../src/storage.rs")),
        (
            "src/storage/application_checks.rs",
            include_bytes!("../../src/storage/application_checks.rs"),
        ),
        (
            "src/storage/concurrency_checks.rs",
            include_bytes!("../../src/storage/concurrency_checks.rs"),
        ),
        (
            "src/storage/conformance.rs",
            include_bytes!("../../src/storage/conformance.rs"),
        ),
        (
            "src/storage/coordination_checks.rs",
            include_bytes!("../../src/storage/coordination_checks.rs"),
        ),
        (
            "src/storage/diagnostic_checks.rs",
            include_bytes!("../../src/storage/diagnostic_checks.rs"),
        ),
        (
            "src/storage/foundationdb.rs",
            include_bytes!("../../src/storage/foundationdb.rs"),
        ),
        (
            "src/storage/lifecycle_checks.rs",
            include_bytes!("../../src/storage/lifecycle_checks.rs"),
        ),
        (
            "src/storage/redb.rs",
            include_bytes!("../../src/storage/redb.rs"),
        ),
        (
            "src/storage/surrealkv.rs",
            include_bytes!("../../src/storage/surrealkv.rs"),
        ),
        (
            "src/storage/target.rs",
            include_bytes!("../../src/storage/target.rs"),
        ),
        (
            "src/time_range.rs",
            include_bytes!("../../src/time_range.rs"),
        ),
        ("src/tree.rs", include_bytes!("../../src/tree.rs")),
        ("src/values.rs", include_bytes!("../../src/values.rs")),
        (
            "src/window_tests.rs",
            include_bytes!("../../src/window_tests.rs"),
        ),
    ];
    let mut hash = Sha256::new();
    let mut files = Vec::new();
    for (path, bytes) in inputs {
        let digest = format!("{:x}", Sha256::digest(bytes));
        hash.update(path.as_bytes());
        hash.update([0]);
        hash.update(digest.as_bytes());
        hash.update([10]);
        files.push(json!({"path":path,"sha256":digest}));
    }
    json!({"algorithm":"sha256(path + NUL + sha256(file) + LF), sorted paths","sha256":format!("{:x}",hash.finalize()),"files":files})
}
