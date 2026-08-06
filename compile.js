#!/usr/bin/env node

const path = require("path");
const { compileProject } = require("./src/compiler");
const { parseCliArgs, printUsage } = require("./src/project");

function main() {
  const args = parseCliArgs(process.argv.slice(2));

  if (args.help) {
    printUsage();
    return;
  }

  const result = compileProject(args);
  const relativeOutput = path.relative(process.cwd(), result.outputDir) || ".";

  console.log(`ReBase compiled ${result.tableCount} tables and ${result.viewCount} views.`);
  console.log(`Output: ${relativeOutput}`);
  console.log(`Schema: ${path.join(relativeOutput, "schema.surql")}`);
  console.log(`Optimizer findings: ${path.join(relativeOutput, "optimizer.json")}`);
}

try {
  main();
} catch (error) {
  console.error(`ReBase compilation failed: ${error.message}`);
  process.exitCode = 1;
}
