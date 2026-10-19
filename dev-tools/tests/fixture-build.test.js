"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { RecordId } = require("surrealdb");
const { loadModel } = require("../fixtures");
const { build } = require("..");
const { resolveConfiguration } = require("../../config/environment");

function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rebase-fixture-build-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}
function write(directory, relative, value) {
  const file = path.join(directory, relative);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === "string" ? value : JSON.stringify(value, null, 2) + "\n");
}

test("shipped fixture models combine public and private inputs, resolve references and reject collisions", t => {
  const directory = temporary(t);
  write(directory, "schema.surql", [
    "DEFINE TABLE note SCHEMAFULL; DEFINE FIELD name ON note TYPE string;",
    "DEFINE TABLE reply SCHEMAFULL; DEFINE FIELD name ON reply TYPE string; DEFINE FIELD parent ON reply TYPE record<note>;",
  ].join("\n"));
  const note = { $id: "urn:fixture:note", type: "object", additionalProperties: false,
    definitions: { label: { type: "string", minLength: 1 } }, required: ["name"],
    properties: { name: { $ref: "#/definitions/label" } } };
  write(directory, "client/schemas/note.schema.json", note);
  write(directory, "fixtures/schemas/reply.schema.json", { type: "object", additionalProperties: false,
    required: ["name", "parent"], properties: { name: { $ref: "urn:fixture:note#/definitions/label" }, parent: { type: "string" } } });
  const model = loadModel(directory);
  assert.deepEqual([...model.tables.keys()], ["note", "reply"]);
  assert.deepEqual(model.bind("reply", { name: "Reply", parent: "note:one" }).parent, new RecordId("note", "one"));
  assert.throws(() => model.bind("reply", { name: "", parent: "note:one" }), /Invalid reply input/);
  write(directory, "fixtures/schemas/note.schema.json", note);
  assert.throws(() => loadModel(directory), /Duplicate fixture input schema: note/);
  fs.rmSync(path.join(directory, "fixtures"), { recursive: true });
  assert.equal(loadModel(directory).tables.size, 1);
  fs.rmSync(path.join(directory, "client"), { recursive: true });
  assert.throws(() => loadModel(directory), /No fixture input schemas/);
});

test("build copies recipes verbatim without execution and detects changed or removed fixture trees", t => {
  const directory = temporary(t), projectDir = path.join(directory, "design"), outputDir = path.join(directory, "build");
  write(projectDir, "schema.surql", "DEFINE TABLE note SCHEMAFULL; DEFINE FIELD name ON note TYPE string;\n");
  const recipe = "throw new Error('A build must never execute fixture scripts');\n";
  write(projectDir, "fixtures/recipe.js", recipe);
  write(projectDir, "fixtures/defaults.json", { seed: "first" });
  const options = { projectDir, outputDir, configuration: resolveConfiguration({ NODE_ENV: "test" }) };
  build(options);
  assert.equal(fs.readFileSync(path.join(outputDir, "fixtures/recipe.js"), "utf8"), recipe);
  build({ ...options, check: true });
  write(projectDir, "fixtures/defaults.json", { seed: "second" });
  assert.throws(() => build({ ...options, check: true }), /stale/);
  build(options);
  fs.rmSync(path.join(projectDir, "fixtures"), { recursive: true });
  assert.throws(() => build({ ...options, check: true }), /stale/);
  build(options);
  assert(!fs.existsSync(path.join(outputDir, "fixtures")), "removed source cannot leave a runnable stale recipe");
});
