# Access Definition Execution Order

Status: measured compatibility reference
Tested: SurrealDB `3.2.0`, x86_64 Linux, isolated in-memory database.

During `DEFINE ACCESS ... SIGNIN` or `SIGNUP`, the `UPDATE` block and `AUTHENTICATE` block execute sequentially, not transactionally. The `UPDATE` commits before `AUTHENTICATE` evaluates. If `AUTHENTICATE` returns `NONE`, no session token is issued, but the committed `UPDATE` is not rolled back.

Mutation-blocking conditions must therefore be expressed inside the `UPDATE` `WHERE` clause. `AUTHENTICATE` controls token issuance only; it cannot prevent or revert the preceding write.

Re-probe on SurrealDB version change for shared transactional semantics.
