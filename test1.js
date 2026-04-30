import { Surreal } from "surrealdb";

async function main() {
  const db = new Surreal();

  try {
    await db.connect("http://localhost:8000/rpc");

    const variables = {
      email: "a1@g.c",
      new_password: "password",
      password: "password",
      invite: "019d7d9f-8b6f-7933-8e20-efb46ff28c10",
    };

    console.log("[~] Executing Final SIGNUP...");

    const result = await db.signup({
      namespace: "main",
      database: "main",
      access: "update_password", // account
      variables: variables,
    });

    console.log("SUCCESSFUL");
    console.log("JWT Received:", result.access);
  } catch (err) {
    console.error("XXX FAILED", err.message);
  } finally {
    await db.close();
  }
}

main();
