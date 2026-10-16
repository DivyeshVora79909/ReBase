"use strict";

const path = require("node:path");
const { buildProject } = require("./compiler");
const { connectDatabase } = require("../gateway/connection");
const {
  assertConfiguredContext,
  assertConnectionConfiguration,
  resolveConfiguration,
  validateConfiguration,
} = require("../config/environment");
const fixtures = require("./fixtures");

const ROOT = path.resolve(__dirname, "..");
const DEFAULT_PROJECT = "all-in-accounting";

function configurationFor(configuration) {
  return configuration
    ? validateConfiguration(configuration)
    : resolveConfiguration(process.env);
}

function projectOptions(options = {}) {
  const rootValue = options.root ?? ROOT;
  if (typeof rootValue !== "string" || !rootValue.trim()) {
    throw new Error("root must be a non-empty path");
  }
  const root = path.resolve(rootValue);
  if (Object.hasOwn(options, "sourceDir") || Object.hasOwn(options, "buildDir")) {
    throw new Error("Use projectDir and outputDir for project paths");
  }
  const hasProjectDir = options.projectDir !== undefined && options.projectDir !== null;
  const reference = hasProjectDir ? options.projectDir : options.project ?? DEFAULT_PROJECT;
  if (typeof reference !== "string" || !reference.trim()) {
    throw new Error("project must be a project name or directory");
  }
  const projectDir = hasProjectDir || path.isAbsolute(reference) || reference.includes(path.sep) || reference.startsWith(".")
    ? reference
    : path.join("designs", reference);
  const name = path.basename(projectDir);
  const frameworkDir = options.frameworkDir ?? "framework";
  const outputDir = options.outputDir ?? options.buildDir ?? path.join("build", name);
  if (typeof frameworkDir !== "string" || !frameworkDir.trim()) {
    throw new Error("frameworkDir must be a non-empty path");
  }
  if (typeof outputDir !== "string" || !outputDir.trim()) {
    throw new Error("outputDir must be a non-empty path");
  }
  return {
    root,
    name,
    projectDir,
    frameworkDir,
    outputDir,
  };
}

const PROCESS_PROFILE_FIELDS = [
  "endpoint",
  "username",
  "password",
  "namespace",
  "database",
  "connectTimeoutMs",
  "runtimeUrl",
  "runtimeSecret",
  "environment",
];

function assertNoProcessProfileOverrides(options) {
  for (const key of PROCESS_PROFILE_FIELDS) {
    if (Object.hasOwn(options, key)) {
      throw new Error(`${key} is process-profile configuration and cannot be overridden`);
    }
  }
}

function build(options = {}) {
  assertNoProcessProfileOverrides(options);
  const project = projectOptions(options);
  const configuration = configurationFor(options.configuration);
  const { root: _root, ...args } = options;
  return buildProject({
    ...args,
    projectDir: project.projectDir,
    frameworkDir: project.frameworkDir,
    outputDir: project.outputDir,
    configuration,
  }, project.root);
}

function explain(subject = '*', options = {}) {
  return build({ ...options, explain: subject }).explanation;
}

function selectContext(configuration, requested) {
  const candidate = requested
    ?? configuration.surreal.defaultContext
    ?? (configuration.surreal.contexts.length === 1 ? configuration.surreal.contexts[0] : undefined);
  if (!candidate) {
    throw new Error("Select a configured { namespace, database } context before connecting");
  }
  return assertConfiguredContext(configuration, candidate);
}

async function connect(context, options = {}) {
  assertNoProcessProfileOverrides(options);
  const configuration = configurationFor(options.configuration);
  assertConnectionConfiguration(configuration);
  const selected = selectContext(configuration, context);
  const { endpoint, username, password, connectTimeoutMs } = configuration.surreal;
  const openConnection = options.openConnection || connectDatabase;
  if (typeof openConnection !== "function") throw new Error("openConnection must be a function");
  return openConnection({ endpoint, username, password, connectTimeoutMs, ...selected });
}

module.exports = {
  DEFAULT_PROJECT,
  ROOT,
  build,
  explain,
  connect,
  fixtures,
  projectOptions,
};
