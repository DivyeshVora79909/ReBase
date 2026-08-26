# SurrealDB Session Lifecycle

Measured with SurrealDB `3.2.0` and `surrealdb` JavaScript SDK `2.0.8`.

## Runtime Admin Connections

The gateway keeps one SurrealDB WebSocket and system-user session per active
namespace/database context. `gateway/directory.js` deduplicates concurrent
creation and evicts idle contexts; it does not share one authentication token
across contexts.

System-user sign-in returns a JWT even when the user has `DURATION FOR SESSION
NONE`. The default root user observed in SurrealDB 3.2.0 has `FOR TOKEN 1h, FOR
SESSION NONE`. Token expiry therefore remains relevant to a long-running
gateway.

The connection helper supplies the username/password through the SDK's
`authentication` connection option. The SDK then:

1. signs in while establishing the connection;
2. schedules renewal from the JWT `exp` claim;
3. signs in again before a system-user token expires;
4. restores namespace, database, variables, and authentication after a
   WebSocket reconnect.

This was tested with a system user whose token lasted one second. Queries still
succeeded after expiry. A disposable TCP proxy was then used to destroy the
WebSocket while SurrealDB stayed available; the same cached connection
reconnected, re-authenticated, and continued querying.

Calling `signin()` only after `connect()` is insufficient for this lifecycle.
In that mode, the SDK has no credential provider. Its token eventually becomes
invalid, or a reconnect restores the context without authentication, leaving a
connected socket whose queries fail as anonymous. The gateway previously used
that pattern and has been changed to the connection authentication provider.

## Record Access Sessions

The generated `account` access method currently uses:

```surql
DURATION FOR SESSION 8h, FOR TOKEN 1h
```

It does not declare `WITH REFRESH`. A record-access sign-in therefore returns an
access JWT without a refresh token. In a one-second-token test, the WebSocket
remained connected after expiry, but subsequent queries failed as anonymous.
This is expected for browser/client actor sessions: the client must sign in
again, or the access method and client flow must deliberately adopt refresh
tokens later.

The gateway's job workers never use record-access sessions. They use system-user
credentials, so record token expiry does not interrupt queue processing.

## Remaining Boundary

The SDK's default WebSocket reconnect policy is bounded. A brief socket loss is
restored, but a database outage that outlasts all reconnect attempts can leave a
cached context unavailable until it is recreated or the gateway restarts. This
is separate from token renewal. Before production, choose either a bounded
context-eviction/recreation policy or a deliberately configured long-lived
reconnect policy together with operation deadlines; infinite reconnect without
query deadlines would allow worker operations to hang.
