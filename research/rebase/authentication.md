# ReBase Authentication

Status: adopted design; engine-sensitive claims are probe-gated

ReBase treats authentication as a set of credentials and verified identities,
not as a boolean derived from a password field. Authorization remains on the
principal graph (`user`/`groups` or the compiler-bound equivalents).

## Data model

| Table | Purpose | Secret material |
| --- | --- | --- |
| principal | Name, optional username, optional Argon2 password, login switch | password is write-only |
| `authentication_email` | One normalized email identity per row | no plaintext challenge |
| `authentication_phone` | One E.164 phone identity per row | no plaintext challenge |
| `authentication_challenge` | One active code per identity | Argon2 code hash only |

Identity addresses are unique within a database. A principal may own any number
of typed identity rows allowed by its normal table permissions; authentication
does not add a presence or count guard. Identity rows carry a revision and a
private `verified_revision`. Verification is valid only when the two values
match. Address/number changes, identity deletion, and password changes fence
the principal revision and invalidate pending challenges. Identity rows may be
removed independently; a principal with no remaining delivery identity simply
cannot use local password or code authentication until one is added and
verified.

## Access methods

`account_password` accepts one normalized `identifier` (email, phone, or
username) and a password. Email/phone sign in requires a currently verified
identity. Username sign in requires that the principal has at least one
verified identity. `AUTHENTICATE` checks only that the resulting principal is
login-enabled; it does not inspect password presence.

`account_code` accepts `identifier`, `code`, and an optional
`password_action` (`keep`, `set`, or `clear`). The method validates the
principal and revision fence, atomically claims an unconsumed challenge,
increments failed-attempt state, verifies the Argon2 hash, and then marks the
identity verified. A supplied password is hashed in the same access method.
The database access method caps attempts at five and the challenge is
single-use.

OAuth is a separate signin-only access method. It sends `{ provider, token }`
to the internal runtime verifier, receives `{ verified, email }`, and matches
the email against an existing local email identity. The provider's verified
email is the proof for this path, so a separate local OTP is not required.
Provider subjects and OAuth sessions are never persisted. A static allowlist in the runtime maps
provider names to verifier functions; an absent or invalid entry fails closed.

## Anonymous challenge endpoint

`POST /anonymous/authentication/challenges` takes `namespace`, `database`, an
`identifier`, and an optional `channel` (`email`, `phone`, or `username`).
Username requests choose the highest-priority configured identity for which a
delivery adapter exists. The endpoint returns the same `202 {"ok":true}` for
missing, invisible, and disallowed identities. A configured rate limiter keys
both the client address and a hash of context/channel/identifier. Delivery is
injected as a platform Resend or Twilio function; tenant provider credentials
remain strict SurrealDB record fields.

The endpoint never returns a challenge code. The service writes the hash and
the revision fence first, then sends the code. Missing or disallowed identities
still receive the privacy-preserving `202`; database, limiter, timeout, and
provider failures return a generic `503` and are reported only through the
server error hook.

## Lifecycle and recovery

Administrators create principals and unverified identities. The recipient asks
for a challenge and redeems it through `account_code`; no database `SIGNUP`
operation or invite field is needed. A code can establish a password or replace
an existing one. A principal is not eligible for local authentication without a
currently verified delivery identity; an identity must be verified through
email or SMS before password sign-in or username-based code sign-in can
succeed. OAuth remains a separate provider-verified signin path.

## Security boundaries

- SurrealDB owns normalization, uniqueness, references, field permissions,
  password hashing, challenge comparison, attempt limits, and token issuance.
- The gateway owns delivery, rate limiting, context allowlisting, and generic
  anonymous responses.
- Existing record tokens remain valid until their normal expiry; changing an
  identity fences new challenges and password/identity state, but does not
  pretend to revoke already-issued JWTs. Short token duration and re-login are
  the current expiry policy.
- Identity history is visible only to the principal or a dominating admin;
  challenge hashes and password fields are never selectable by record users.

Engine behavior that affects this design is covered by the disposable runtime
probe and should be re-run after a SurrealDB upgrade, especially access-method
write ordering and conditional update atomicity.
