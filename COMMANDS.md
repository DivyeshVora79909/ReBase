# ReBase Commands

ReBase requires Node.js 20+, the SurrealDB CLI, and a POSIX-compatible shell. Commands are run from the repository root.

## Environment

Create the ignored local environment file once:

```bash
cp .env.example .env
```

Node commands load it with `--env-file=.env`. Before running SurrealDB CLI commands directly, export it into the current shell:

```bash
set -a
. ./.env
set +a
```

## Compile and check

The default output is `build/<design-name>/schema.surql`:

```bash
npm run build -- --project designs/test
npm run build -- --project designs/crm
npm run build -- --project designs/accounts
```

Use an exact output directory only when needed:

```bash
npm run build -- --project designs/test --output /tmp/rebase-test
```

Check that an existing build is current:

```bash
npm run check -- --project designs/test
```

## Validate and deploy

Always validate before deployment:

```bash
surreal validate "$REBASE_BUILD_DIR/schema.surql"
```

Deploy with normal SQL execution so events, assertions, field processing, and seed statements run:

```bash
surreal sql \
  --endpoint "$SURREAL_ENDPOINT" \
  --user "$SURREAL_USER" \
  --pass "$SURREAL_PASS" \
  --ns "$SURREAL_NAMESPACE" \
  --db "$SURREAL_DATABASE" \
  --hide-welcome \
  < "$REBASE_BUILD_DIR/schema.surql"
```

Do not use `surreal import` for schema deployment. Import mode disables events and field processing.

## Bootstrap the first record administrator

Open an interactive system-authenticated session:

```bash
surreal sql \
  --endpoint "$SURREAL_ENDPOINT" \
  --user "$SURREAL_USER" \
  --pass "$SURREAL_PASS" \
  --ns "$SURREAL_NAMESPACE" \
  --db "$SURREAL_DATABASE" \
  --pretty
```

Then enter a one-time command with values that are not committed to source control:

```surrealql
UPSERT user:root SET
  name = 'System Administrator',
  email = 'admin@example.com',
  parents = [groups:root],
  login_access = true,
  password = crypto::argon2::generate('replace-with-a-strong-password');
```

## Tests and diagnostics

```bash
npm test
npm run verify
npm run benchmark
```

The runtime verifier creates deterministic `rebase_verify_*` records. The benchmark creates and replaces `rebase_bench_resource`; never point it at a production database.

## Isolated runtime testing

Start a disposable in-memory server:

```bash
surreal start memory \
  --user root \
  --pass root \
  --bind 127.0.0.1:8001 \
  --no-banner
```

Use a separate `.env` or exported variables targeting port `8001` and an isolated namespace/database. Stop the server with `Ctrl-C`.

Development databases created before polymorphic ownership must be recreated before deployment. ReBase intentionally does not generate destructive migrations.
