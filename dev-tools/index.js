import repl from "node:repl";
import readline from "node:readline/promises";
import { Surreal } from "surrealdb";

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

async function ask(question, fallback) {
  const answer = await rl.question(
    `\x1b[90m${question} [${fallback}]:\x1b[0m `,
  );
  return answer.trim() || fallback;
}

async function main() {
  console.log("\n🚀 ReBase | CLI Tester\n");

  const url = await ask("RPC URL", "http://localhost:8000/rpc");
  const ns = await ask("Namespace", "main");
  const db = await ask("Database", "main");
  const access = await ask("Access Method", "account");
  const action = await ask("Action (signin/signup)", "signin");
  const email = await ask("Email", "divy.r.vora14@gmail.com");
  const password = await ask("Password", "password");
  const new_password = await ask("New Password", "password");
  const invite = await ask("Invite Token (UUID)", "");

  rl.close();

  const client = new Surreal();

  try {
    console.log(`\n[~] Connecting to ${url}...`);
    await client.connect(url);

    console.log(`[~] Executing ${action.toUpperCase()}...`);

    const authConfig = {
      namespace: ns,
      database: db,
      access: access,
      variables: { email, password, new_password, invite },
    };

    const access_token = await client[action](authConfig);
    console.log(
      "\x1b[32m[✓] Authentication Successful!\x1b[0m\n",
      access_token,
    );
  } catch (err) {
    console.error(
      "\x1b[31m[x] Authentication Failed:\x1b[0m",
      JSON.stringify(err, null, 2),
    );
    process.exit(1);
  }

  repl.start({
    prompt: "\x1b[36mdb-test>\x1b[0m ",
    eval: async (cmd, context, filename, callback) => {
      try {
        cmd = cmd.trim();
        if (!cmd) return callback(null);

        const res = await client.query(cmd);
        callback(null, res);
      } catch (err) {
        callback(err);
      }
    },
  });
}

main();
