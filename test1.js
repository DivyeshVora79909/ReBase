import { Surreal } from "surrealdb";

const db = new Surreal();

async function run() {
  try {
    await db.connect("http://localhost:8000/rpc");

    await db.signin({
      namespace: "main",
      database: "main",
      access: "account",
      variables: {
        email: "admin@example.com",
        password: "admin123",
      },
    });

    console.log(await db.query("SELECT id, name FROM $auth;"));
    console.log(await db.query(`SELECT * FROM user;`));
    console.log(await db.query(`SELECT * FROM groups;`));
  } catch (error) {
    console.error("❌", error.message);
  } finally {
    db.close();
  }
}

run();
