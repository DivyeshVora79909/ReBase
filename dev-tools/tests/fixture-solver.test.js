"use strict";

const assert = require("node:assert/strict");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const test = require("node:test");
const { withSolver } = require("../fixtures/solver");

test("native solver finds coupled constraints with exact integers and rationals", async () => {
  const result = await withSolver(async ({ Int, Real, solver, solve }) => {
    const x = Int.const("x"), y = Int.const("y"), rate = Real.const("rate");
    solver.add(x.add(y).eq(9007199254741003n), x.sub(y).eq(3), rate.mul(3).eq(1));
    const model = await solve();
    return { x: model.eval(x).value(), y: model.eval(y).value(), rate: model.eval(rate).value() };
  });
  assert.deepEqual(result, {
    x: 4503599627370503n,
    y: 4503599627370500n,
    rate: { numerator: 1n, denominator: 3n },
  });
});

test("unsatisfiable constraints produce a distinct actionable error", async () => {
  await assert.rejects(withSolver(async ({ Int, solver, solve }) => {
    const x = Int.const("x");
    solver.add(x.gt(2), x.lt(1));
    await solve();
  }), { code: "FIXTURE_SOLVER_UNSAT", message: /unsatisfiable \(unsat\)/ });
});

test("unknown retains the native reason instead of returning a model", async () => {
  await assert.rejects(withSolver(async ({ Int, solver, solve }) => {
    const x = Int.const("x");
    solver.add(x.gt(2));
    solver.set("rlimit", 1);
    await solve();
  }), { code: "FIXTURE_SOLVER_UNKNOWN", message: /unknown: .+/ });
});

test("a bounded solver check reports its native timeout", async () => {
  await assert.rejects(withSolver(async ({ Int, Distinct, solver, solve }) => {
    const slots = Array.from({ length: 100 }, (_, index) => Int.const(`slot_${index}`));
    solver.add(Distinct(...slots), ...slots.flatMap(slot => [slot.ge(0), slot.lt(99)]));
    await solve();
  }, { timeoutMs: 1 }), {
    code: "FIXTURE_SOLVER_UNKNOWN",
    message: /unknown: timeout/,
  });
});

test("concurrent sessions are isolated and worker cleanup allows process exit", async () => {
  const script = `
    const assert = require('node:assert/strict');
    const { withSolver } = require(${JSON.stringify(require.resolve("../fixtures/solver"))});
    const run = value => withSolver(async ({ Int, solver, solve }) => {
      const x = Int.const('same_name');
      solver.add(x.eq(value));
      return (await solve()).eval(x).value();
    });
    (async () => {
      assert.deepEqual(await Promise.all([run(17), run(29)]), [17n, 29n]);
      await assert.rejects(withSolver(async ({ Int, solver, solve }) => {
        solver.add(Int.const('x').eq(1));
        await solve();
        throw new Error('caller failed');
      }), /caller failed/);
      assert.equal(await run(41), 41n);
    })().catch(error => { console.error(error); process.exitCode = 1; });
  `;
  await promisify(execFile)(process.execPath, ["-e", script], { timeout: 30000 });
});

test("invalid arguments fail before initializing the optional dependency", async () => {
  await assert.rejects(withSolver(null), /requires a callback/);
  for (const timeoutMs of [0, -1, 1.5, Infinity, 0x100000000]) {
    await assert.rejects(withSolver(() => {}, { timeoutMs }), /timeoutMs must be/);
  }
});
