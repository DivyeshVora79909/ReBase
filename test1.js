import { Surreal } from "surrealdb";

const db = new Surreal();

async function run() {
  await db.connect("http://localhost:8000/rpc");

  await db.signin({
    namespace: "main",
    database: "main",
    access: "user",
    variables: {
      email: "admin@example.com",
      password: "admin123",
    },
  });

  const beforeRefresh = await db.query(`RETURN $auth;`);
  console.log("before refresh", beforeRefresh);

  const refresh = await db.query(`RETURN fn::refresh_access($auth);`);
  console.log("refresh", refresh);

  const afterRefresh = await db.query(`RETURN (SELECT * FROM $auth);`);
  console.log("after refresh", afterRefresh);

  try {
    const users = await db.query(`SELECT id, email FROM user;`);
    console.log("\n✅ PERMISSION TEST SUCCESS! Fetched users:");
    console.log(users[0]);
  } catch (error) {
    console.log("\n❌ PERMISSION TEST FAILED:", error.message);
  }
}

run();
