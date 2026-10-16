"use strict";

/**
 * Run native Z3 constraints in an isolated, optional solver session.
 * Extract ordinary JavaScript values from models inside the callback: native
 * contexts, expressions and models belong to this session only. timeoutMs is
 * the native timeout for each solver check, not a timeout for callback code.
 */
async function withSolver(callback, { timeoutMs = 5000 } = {}) {
  if (typeof callback !== "function") throw new Error("withSolver requires a callback");
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 0xffffffff) {
    throw new Error("timeoutMs must be an integer between 1 and 4294967295");
  }
  const { init, killThreads } = require("z3-solver");
  const api = await init();
  try {
    const context = new api.Context("fixture");
    const solver = new context.Solver();
    solver.set("timeout", timeoutMs);
    async function solve() {
      const status = await solver.check();
      if (status === "sat") return solver.model();
      const error = new Error(status === "unsat"
        ? "Fixture constraints are unsatisfiable (unsat)"
        : `Fixture solver returned ${status}: ${solver.reasonUnknown()}`);
      error.code = status === "unsat" ? "FIXTURE_SOLVER_UNSAT" : "FIXTURE_SOLVER_UNKNOWN";
      throw error;
    }
    return await callback({ ...context, solver, solve });
  } finally {
    await killThreads(api.em);
  }
}

module.exports = { withSolver };
