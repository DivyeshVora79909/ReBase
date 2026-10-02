#!/usr/bin/env node

"use strict";

const path = require("node:path");
const repl = require("node:repl");
const { inspect } = require("node:util");
const { stdin, stdout } = require("node:process");
const { resolveConfiguration } = require("../config/environment");
const tools = require("./index");
const { projectOptions: resolveProjectOptions } = tools;

const ROOT = path.resolve(__dirname, "..");

function parseArgs(argv) {
  const options = { project: tools.DEFAULT_PROJECT };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === "--project") {
      index += 1;
      if (argv[index] === undefined) throw new Error("Missing value for --project");
      options.project = argv[index];
    } else if (option === "--help" || option === "-h") options.help = true;
    else throw new Error(`Unknown option: ${option}`);
  }
  return options;
}

function usage() {
  return "Usage: node [--env-file PATH] dev-tools/workbench.js [--project NAME|DIR]";
}

const projectOptions = (reference, root = ROOT) => resolveProjectOptions({ project: reference, root });

function startNativeRepl({ context, input, output, onExit }) {
  const server = repl.start({
    prompt: "rebase> ",
    input,
    output,
    terminal: Boolean(input.isTTY && output.isTTY),
    useGlobal: false,
  });
  const restoreContext = (target) => Object.assign(target, {
    ...context,
    ...(context.project && typeof context.project === "object"
      ? { project: { ...context.project } }
      : {}),
  });
  restoreContext(server.context);
  server.on("reset", restoreContext);
  server.once("exit", () => {
    void Promise.resolve()
      .then(() => onExit?.())
      .catch(() => {
        try {
          output.write("ReBase workbench connection cleanup failed.\n");
        } catch {}
      });
  });
  return server;
}

function inspectableBuildResult(result, operation) {
  const withSummary = (value) => {
    if (value === null || typeof value !== "object") return value;
    const summary = { operation };
    for (const key of ["projectDir", "outputDir"]) {
      if (typeof value[key] === "string") summary[key] = value[key];
    }
    for (const key of ["tableHandlerCount", "webhookHandlerCount", "materialFileCount"]) {
      if (Number.isSafeInteger(value[key])) summary[key] = value[key];
    }
    const displayValue = Object.create(
      Object.getPrototypeOf(value),
      Object.getOwnPropertyDescriptors(value),
    );
    Object.defineProperty(displayValue, inspect.custom, {
      value: () => summary,
      configurable: true,
    });
    return displayValue;
  };

  if (result && typeof result.then === "function") return result.then(withSummary);
  return withSummary(result);
}

function startWorkbench({
  project = tools.DEFAULT_PROJECT,
  environment = process.env,
  input = stdin,
  output = stdout,
  api = tools,
} = {}) {
  const configuration = resolveConfiguration(environment);
  const selectedProject = resolveProjectOptions({ project });
  const connections = new Set();
  const openingConnections = new Set();
  const closeErrors = [];
  let closing;
  let server;

  const closeConnection = async (connection) => {
    try {
      if (typeof connection.close === "function") await connection.close();
      else await connection.db?.close?.();
    } catch (error) {
      closeErrors.push(error);
      throw error;
    }
  };

  const track = (connection) => {
    let closePromise;
    const managed = {
      ...connection,
      close() {
        if (!closePromise) {
          closePromise = Promise.resolve()
            .then(() => closeConnection(connection))
            .finally(() => connections.delete(managed));
        }
        return closePromise;
      },
    };
    connections.add(managed);
    return managed;
  };

  const closeConnections = () => {
    if (!closing) {
      closing = (async () => {
        await Promise.allSettled([...openingConnections]);
        await Promise.allSettled(
          [...connections].map((connection) => connection.close()),
        );
        if (closeErrors.length) {
          throw new AggregateError(closeErrors, "Workbench connection cleanup failed");
        }
      })();
    }
    return closing;
  };

  const context = { project: { project } };
  const optionsFor = (overrides = {}) => {
    const activeProject = (server?.context ?? context).project;
    if (!activeProject || typeof activeProject !== "object" || Array.isArray(activeProject)) {
      throw new Error("Workbench project must be an options object");
    }
    const base = { ...activeProject };
    if (Object.hasOwn(overrides, "project") && !Object.hasOwn(overrides, "projectDir")) {
      delete base.projectDir;
    }
    return {
      ...base,
      ...overrides,
      root: ROOT,
      configuration,
    };
  };
  const connect = (selectedContext) => {
    if (closing) return Promise.reject(new Error("Workbench connections are closing"));
    let opening;
    opening = Promise.resolve()
      .then(() => api.connect(selectedContext, { configuration }))
      .then(async (connection) => {
        if (closing) {
          await closeConnection(connection);
          throw new Error("Workbench connections are closing");
        }
        return track(connection);
      })
      .finally(() => openingConnections.delete(opening));
    openingConnections.add(opening);
    return opening;
  };

  Object.assign(context, {
    build: (overrides = {}) => inspectableBuildResult(api.build(optionsFor(overrides)), "build"),
    check: (overrides = {}) => inspectableBuildResult(api.check(optionsFor(overrides)), "check"),
    connect,
    deploy: (connection, overrides = {}) => api.deploy(connection, optionsFor(overrides)),
    populate: (overrides = {}) => api.populate(optionsFor(overrides)),
    closeConnections,
  });

  output.write(`ReBase JavaScript workbench: ${selectedProject.projectDir}\n`);
  output.write("Use JavaScript, top-level await, and the SDK directly. Type .help for Node REPL commands.\n");
  server = startNativeRepl({ context, input, output, onExit: closeConnections });
  return {
    server,
    get context() { return server.context; },
    closeConnections,
  };
}

async function main(argv = process.argv.slice(2), environment = process.env) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(usage());
    return null;
  }
  return startWorkbench({ project: args.project, environment });
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`ReBase workbench failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { main, parseArgs, projectOptions, startWorkbench, usage };
