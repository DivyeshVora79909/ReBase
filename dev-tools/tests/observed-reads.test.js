'use strict';
const assert=require('node:assert/strict');
const test=require('node:test');
const {resolveObservedReads}=require('../compiler/observed-reads');
const {parseSchema}=require('../compiler/schema');
const {resolveTreeContract}=require('../compiler/tree-contract');

test('capture follows helper call graphs and leaves quoted text and comments untouched',()=>{
  const source=`DEFINE FUNCTION fn::outer($row: object) {
    RETURN IF $row.enabled THEN fn::inner(fn::empty(), $row.at) ELSE 0dec END;
  };
  DEFINE FUNCTION fn::inner($owner: record, $at: datetime) {
    -- fn::tree::read_value(fake, 'fake', 'before', [], '', 0dec)
    LET $example='fn::tree::read_value(fake)';
    RETURN fn::tree::read_value($owner,'z_points','latest',[[$at]],'measures.rate.sum',NONE);
  };
  DEFINE FUNCTION fn::empty() { RETURN curve:a; };`;
  const model=resolveObservedReads(source);
  assert.deepEqual([...model.tracked].sort(),['fn::inner','fn::outer']);
  assert.match(model.generated,/fn::reads::captured::inner\(\$__rebase_observer, fn::empty\(\), \$row.at\)/);
  assert.match(model.generated,/fn::reads::tree\(\$__rebase_observer, \$owner/);
  assert.match(model.generated,/-- fn::tree::read_value\(fake/);
  assert.match(model.generated,/'fn::tree::read_value\(fake\)'/);
  assert.equal(model.rewrite('fn::outer($this)', '$scope'),'fn::reads::captured::outer($scope, $this)');
  assert.equal(model.rewrite("'fn::outer($this)'",'$scope'),"'fn::outer($this)'");
  model.validate('fn::outer($this)','invoice.rate');
});

test('an ordered calculation cannot hide an untracked lookup in a helper',()=>{
  const model=resolveObservedReads(`DEFINE FUNCTION fn::hidden($owner: record) {
    RETURN fn::tree::read($owner,'z_points','seek',[[1],true,false]);
  }; DEFINE FUNCTION fn::outer() { RETURN fn::hidden(curve:a); };`);
  assert.throws(()=>model.validate('fn::outer()','invoice.rate'),/invoice.rate.*read_value.*fn::tree::read/);
  assert.throws(()=>parseSchema("DEFINE TABLE quote COMMENT '@rebase-impact fn::inverse';",''),/retired annotation.*read_value/);
});

test('interval tuple keys are private metadata, rather than untyped application ordering',()=>{
  const schema=parseSchema(`DEFINE TABLE example;
    DEFINE FIELD z_root ON example TYPE object COMMENT '@rebase-tree-root @rebase-tree-key tuple';`, '');
  assert.throws(()=>resolveTreeContract(schema),/unsupported tree key 'tuple'/);
});
