# N6 Node signed ingress

Accepted within the scope below on 2026-10-26. The full Node suite passes 133
tests without failures or skips; focused real-native and startup-failure tests
pass 2/2. Root also executed the complete imported example successfully.
[Evidence](evidence/2026-10-26-n6-signed-ingress.json) records source hashes,
the unchanged native artifact, the exact run and the independent review.

The Node workflow sends provider outcome events to the native `/effects/fake`
route. It uses the existing native service configuration
`effects.ingress_secret_file`; the secret is an explicit 32–128 byte file with
private permissions. Ed25519 remains part of bearer-token setup only. Webhook
authentication is HMAC-SHA256.

The caller serializes the exact JSON body bytes, then signs
`account + LF + event UUID + LF + timestamp milliseconds + LF + body bytes`.
The accepted payload is `{ "execution_id": UUID, "outcome": { ... } }`; for
effect-demo the outcome has the native catalog's exact six fields:
`execution_id`, `account`, `action`, `units`, `phase`, and `receipt`. Signing
does not canonicalize or reserialize JSON. The request must send the same bytes
that were signed.

`tools/node/examples/n6-signed-ingress.mjs` owns two ordinary example helpers:
one constructs the HMAC headers and one sends a single bounded request. The
`runN6SignedIngress({ binary, directory, tenant?, actor? })` composes those
helpers with the existing native, client, service and provider APIs. Import it
in the standard Node REPL or an ordinary script; the example has no argument
parser or automatic command-line entry point. Its directory must be new and is
removed with its owned processes on completion or failure.

The request helper accepts at most 16 KiB so it can exercise the native 8 KiB
rejection boundary; it caps responses at 8 KiB, has a 5-second default total
deadline, follows no redirects, and never retries an unknown result. It accepts
an origin or native `/rpc` endpoint and rejects query strings, fragments and
other paths. It is not a general provider SDK or production delivery guarantee.

`tools/node/test/n6-signed-ingress.test.mjs` uses a real native service and an
owned ACK-dropping proxy. It covers invalid signature, stale timestamp, wrong
account, unknown execution, request-bound outcome mismatch, duplicate JSON
keys, oversized input, lost ACK followed by caller-controlled retry, durable
same-body duplicate, changed-body conflict, process restart, inbox consumption,
and one domain application with no provider submission. A controlled crypto
setup failure proves startup cleanup closes owned resources; a pre-existing
caller directory with a sentinel is preserved. The first service is
disabled so intake is isolated from automatic delivery; after restart,
reconcile mode consumes the durable event and applies it.

Rust retains the lower-level controls mapped to
`src/effects/inbox_tests.rs`: `authentication_covers_exact_bytes_identity_skew_and_bounded_typed_json`
covers signature framing, canonical identity/time and typed body validation;
`durable_ack_dedup_and_consumed_fact_rollback_cover_actual_writes` covers
transactional ACK, event deduplication and changed bytes; capacity, body
deadline, injected storage abort, restore, archive and reset controls remain in
the existing ingress acceptance suite. Application authorization continues
through the original requester and current authority in
`src/effects/application.rs`; this Node transport test does not replace those
native authority checks.

The Node change is limited to the example and its real-native test. It adds no
public SDK wrapper, modifies no Rust surface, and changes no compiled model.
