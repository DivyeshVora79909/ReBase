import repl from "node:repl";
import { Surreal } from "surrealdb";

const admin = new Surreal();

await admin.connect("http://localhost:8000/rpc");

await admin.signin({
  namespace: "main",
  database: "main",
  access: "account",
  variables: { email: "admin@example.com", password: "admin123" },
});

const r = repl.start({
  prompt: "db-test> ",
  eval: async (cmd, context, filename, callback) => {
    try {
      cmd = cmd.trim();

      if (!cmd) return callback(null);

      const res = await admin.query(cmd);
      callback(null, res);
    } catch (err) {
      callback(err);
    }
  },
});
