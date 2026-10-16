'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { generateBundle } = require('../compiler/pipeline');
const { classifyMaterials, readMaterialFiles } = require('../compiler/materials');
const { resolveReadOnly } = require('../compiler/read-only');

const framework = readMaterialFiles([{ name: 'framework', roots: [path.resolve(__dirname, '../../framework')] }]);
const base = `DEFINE TABLE source SCHEMAFULL;
DEFINE FIELD points ON source TYPE object COMMENT '@rebase-tree-root @rebase-tree-key int';
DEFINE TABLE point SCHEMAFULL COMMENT '@rebase-members fn::point';
DEFINE FIELD z_point ON point TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner source.points';
DEFINE FUNCTION fn::point($row: object) { RETURN []; };
DEFINE TABLE reader SCHEMAFULL;
DEFINE FIELD source ON reader TYPE record<source> REFERENCE ON DELETE REJECT;
DEFINE FIELD q ON reader TYPE option<object> FLEXIBLE VALUE {source:$this.source,arguments:[NONE,[10]],path:'count',fallback:0}
COMMENT '@rebase-dependency range @rebase-dependency-source source.points';`;
const compile = source => generateBundle(classifyMaterials([...framework,
  { group: 'project', path: '/dependencies/fixture.surql', relative: 'fixture.surql', source }]));

test('dependency declarations produce one named private slot and source-root inventory', () => {
  const built = compile(base + `DEFINE FIELD answer ON reader TYPE int VALUE fn::dependency::value($this.q) COMMENT '@rebase-derived';`);
  const [query] = built.temporalModel.dependencyModel.declarations;
  assert.equal(query.node, '__rebase_dependency_q');
  assert.equal(query.sources[0].index, '__rebase_dependents_points_range');
  assert.equal(query.phase, 'refresh');
  assert(built.temporalModel.derivedOrder.get('reader').findIndex(field => field.name === 'q')
    < built.temporalModel.derivedOrder.get('reader').findIndex(field => field.name === 'answer'));
  assert.match(built.bundle, /rebase_dependency_revision ON source/);
  assert.doesNotMatch(built.bundle, /fn::reads::|DEFINE TABLE OVERWRITE rebase_read/);
});

test('compiler rejects ambiguous, untyped, audited and misplaced query declarations', () => {
  for (const [source, pattern] of [
    [base.replace('range @rebase', 'before @rebase'), /declare one @rebase-dependency/],
    [base.replace('@rebase-dependency-source source.points', '@rebase-dependency-source source.missing'), /unknown dependency source root/],
    [base.replace('option<object> FLEXIBLE', 'object FLEXIBLE'), /TYPE option<object>/],
    [base.replace(' FLEXIBLE', ''), /require FLEXIBLE/],
    [base.replace(' FLEXIBLE', '').replace("path:'count'", "path:'FLEXIBLE'"), /require FLEXIBLE/],
    [base.replace('source.points\';', 'source.points @rebase-audit\';'), /cannot be audited/],
    [base.replace('source.points\';', 'source.points @rebase-change-log\';'), /cannot be audited/],
    [base + `DEFINE FIELD rebase_dependency_revision ON source TYPE int;`, /reserved for source fences/],
    [base + `DEFINE FIELD __rebase_dependency_fake ON reader TYPE int;`, /reserved for generated dependency/],
    [`DEFINE TABLE example COMMENT '@rebase-depends source.value';`, /field-only/],
    [`DEFINE TABLE example COMMENT '@rebase-dependency range';`, /field-only/],
  ]) assert.throws(() => compile(source), pattern);
});

test('calculations cannot consume validation-phase queries directly or through helpers', () => {
  const validation = base.replace('@rebase-dependency range', '@rebase-dependency range @rebase-dependency-validate');
  for (const expression of ['$this.q.result.value', 'fn::consume($this)']) {
    assert.throws(() => compile(validation + `
      DEFINE FUNCTION fn::consume($row: object) { RETURN fn::dependency::value($row.q); };
      DEFINE FIELD result ON reader TYPE int VALUE ${expression} COMMENT '@rebase-derived';`), /cannot consume validation-phase/);
  }
  assert.throws(() => compile(validation.replace('DEFINE TABLE reader SCHEMAFULL;',
    "DEFINE TABLE reader SCHEMAFULL COMMENT '@rebase-members fn::unsafe_members';") + `
      DEFINE FIELD z_node ON reader TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner source.points';
      DEFINE FUNCTION fn::unsafe_members($row: object) {
        RETURN [fn::tree::ordered_member($row.id,'z_node',$row.source,'points',[1],{amount:fn::dependency::value($row.q)},{})];
      };`), /cannot consume validation-phase/);
});

test('validators may read their own root through a helper but must declare external reads', () => {
  const pure = resolveReadOnly(`DEFINE FUNCTION fn::query($owner: record) {
    RETURN fn::tree::read_value($owner,'points','range',[NONE,NONE],'count',0);
  }; DEFINE FUNCTION fn::local($row: object) { RETURN fn::query($row.id); };
  DEFINE FUNCTION fn::external($row: object) { RETURN fn::query($row.source); };`);
  pure.validate('fn::local($this)', 'validator', { allowLocalTreeReads: true });
  assert.throws(() => pure.validate('fn::external($this)', 'validator', { allowLocalTreeReads: true }), /undeclared ordered read/);
  assert.throws(() => pure.validate('fn::local($this)', 'calculation'), /undeclared ordered read/);
});
