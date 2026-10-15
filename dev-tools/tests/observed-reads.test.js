'use strict';
const assert=require('node:assert/strict');
const test=require('node:test');
const {resolveObservedReads}=require('../compiler/observed-reads');
const {parseSchema}=require('../compiler/schema');
const {resolveTreeContract}=require('../compiler/tree-contract');
const path=require('node:path');
const {classifyMaterials,readMaterialFiles}=require('../compiler/materials');
const {generateBundle}=require('../compiler/pipeline');

const frameworkFiles=readMaterialFiles([{name:'framework',roots:[path.resolve(__dirname,'../../framework')]}]);
function compile(source) {
  return generateBundle(classifyMaterials([...frameworkFiles,{
    group:'project',path:'/reactive-read-only/fixture.surql',relative:'fixture.surql',source,
  }]));
}

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

test('reactive expressions reject direct and nested writes with their helper identified',()=>{
  const mutations=[
    'CREATE source:one SET value=1',
    'INSERT INTO source {value:1}',
    'UPDATE $source SET value=1',
    'UPSERT source:one SET value=1',
    'DELETE source:one',
    'RELATE source:one->edge->source:two',
    'DELETE `source`',
    'CREATE `source`',
    "DELETE r'source:one'",
    'DELETE /* target */ ⟨source⟩',
  ];
  for (const mutation of mutations) {
    const model=resolveObservedReads(`
      DEFINE FUNCTION fn::inner($source: record) { IF true { ${mutation}; }; RETURN 0; };
      DEFINE FUNCTION fn::outer($source: record) { RETURN fn::inner($source); };`);
    const keyword=mutation.split(' ')[0];
    assert.throws(()=>model.validate(`(${mutation})`,'reader.value'),new RegExp(`reader.value.*read-only.*${keyword}`));
    assert.throws(()=>model.validate('fn::outer(source:one)','reader.value'),new RegExp(`reader.value.*read-only.*${keyword}.*fn::inner`));
  }
  for (const expression of [
    'LET $write = (UPDATE source:one SET value=1); RETURN $write;',
    'RETURN IF true THEN (DELETE source:one) ELSE NONE END;',
    'RETURN [1].map(|$n| { CREATE source SET value=$n; RETURN $n; });',
    'FOR $n IN [1] { UPDATE source:one SET value=$n; }; RETURN 0;',
  ]) assert.throws(()=>resolveObservedReads('').validate(expression,'reader.value'),/read-only/);
});

test('reactive helpers reject schema, transaction, runtime and opaque effects',()=>{
  for (const expression of [
    'DEFINE TABLE surprise;', 'REMOVE TABLE source;', 'ALTER TABLE source DROP;',
    'REBUILD INDEX unique_value ON source;', 'ACCESS api GRANT FOR USER root;',
    'BEGIN TRANSACTION;', 'COMMIT TRANSACTION;', 'CANCEL TRANSACTION;',
    'USE DB other;', 'OPTION IMPORT;', 'LIVE SELECT * FROM source;', 'KILL $query;', 'SLEEP 1s;',
    "RETURN http::post('https://example.invalid', {});",
    "RETURN http::get('https://example.invalid');",
    "RETURN api::invoke('/write');",
    'RETURN function() { return 1; };', 'RETURN $call();',
    'RETURN fn::missing();', 'RETURN fn::rebase::refresh(source:one,NONE,true);',
    'RETURN fn::reads::flush({});', 'RETURN fn::`hidden`();', 'RETURN fn::⟨hidden⟩();',
  ]) assert.throws(()=>resolveObservedReads('').validate(expression,'reader.value'),/reader.value.*read-only/,expression);
});

test('read-only controls preserve keywords in fields, records, strings and comments',()=>{
  const source=`DEFINE FUNCTION fn::pure($row: object) {
    -- UPDATE source:one SET value=2; fn::missing()
    /* DELETE source:one; http::post('ignored') */
    LET $label = 'CREATE INSERT UPDATE UPSERT DELETE RELATE DEFINE REMOVE SLEEP fn::missing()';
    LET $quoted = "UPDATE source:one";
    LET $ids = [source:UPDATE, DELETE:one, source:⟨DELETE⟩, source:\`CREATE\`];
    LET $fields = {update:$row.update, delete:$row.DELETE, create:$row.\`CREATE\`};
    LET $projection = (SELECT update, delete, create AS inserted, option, begin, commit AS committed, cancel, sleep + 1 FROM source);
    IF $row.update < 0 { THROW 'UPDATE rejected'; };
    RETURN IF $row.delete THEN math::abs($row.update) ELSE 0 END;
  };`;
  const model=resolveObservedReads(source);
  model.validate('fn::pure($this)','reader.value');
  model.validate('fn::tree::member(source:one,"node",NONE,"root",NONE,{},{},{},false)','member');
  model.validate('fn::tree::ordered_member(source:one,"node",NONE,"root",[],{},{})','member');
  model.validate('fn::tree::combine(fn::tree::empty(), fn::tree::empty())','reader.value');
  // Unreachable ordinary write helpers remain valid application entry points.
  resolveObservedReads(source+' DEFINE FUNCTION fn::write() { UPDATE source:one SET value=2; };')
    .validate('fn::pure($this)','reader.value');
});

test('bundle compilation rejects the stale-value reproduction before generating capture code',()=>{
  assert.throws(()=>compile(`
    DEFINE TABLE mutable_source SCHEMAFULL;
    DEFINE FIELD value ON mutable_source TYPE int;
    DEFINE FUNCTION fn::mutating_lookup($source: record) {
      LET $value = fn::record::read_value($source, 'value', 0);
      IF $value < 2 { UPDATE $source SET value=$value+1 RETURN NONE; };
      RETURN $value;
    } PERMISSIONS NONE;
    DEFINE TABLE mutable_reader SCHEMAFULL;
    DEFINE FIELD source ON mutable_reader TYPE record<mutable_source>;
    DEFINE FIELD value ON mutable_reader TYPE int VALUE fn::mutating_lookup($this.source) COMMENT '@rebase-derived';
  `),/mutable_reader.value.*read-only.*UPDATE.*fn::mutating_lookup/);
});

test('bundle compilation enforces read-only helpers in every reactive phase',()=>{
  assert.throws(()=>compile(`
    DEFINE TABLE reader SCHEMAFULL;
    DEFINE FIELD value ON reader TYPE int VALUE (UPDATE source:one SET value=1) COMMENT '@rebase-derived';
  `),/reader.value.*read-only.*UPDATE/);
  for (const marker of ['derived','members','required-outputs','validate']) {
    const declaration=marker==='derived'
      ? "DEFINE TABLE reader SCHEMAFULL; DEFINE FIELD value ON reader TYPE int VALUE fn::outer($this.id) COMMENT '@rebase-derived';"
      : `DEFINE TABLE reader SCHEMAFULL COMMENT '@rebase-${marker} fn::outer';`;
    for (const body of ['UPDATE $source SET value=1; RETURN 0;', 'RETURN fn::inner($source);']) {
      assert.throws(()=>compile(`${declaration}
        DEFINE FUNCTION fn::outer($source: any) { ${body} };
        DEFINE FUNCTION fn::inner($source: any) { DELETE $source; RETURN 0; };
      `),new RegExp(`reader.*read-only.*(?:UPDATE.*fn::outer|DELETE.*fn::inner)`),marker);
    }
  }
});

test('bundle compilation accepts pure reactive phases and retains coordinator writes',()=>{
  const result=compile(`
    DEFINE FUNCTION fn::pure($source: record) {
      LET $value=fn::record::read_value($source,'value',0);
      IF $value < 0 { THROW 'NEGATIVE'; };
      RETURN $value;
    };
    DEFINE FUNCTION fn::members($row: object) { RETURN []; };
    DEFINE FUNCTION fn::outputs($row: object) { RETURN []; };
    DEFINE FUNCTION fn::validate($row: object) { fn::pure($row.id); RETURN true; };
    DEFINE TABLE reader SCHEMAFULL COMMENT '@rebase-members fn::members @rebase-required-outputs fn::outputs @rebase-validate fn::validate';
    DEFINE FIELD z_root ON reader TYPE object COMMENT '@rebase-tree-root @rebase-tree-key int';
    DEFINE FIELD z_node ON reader TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner reader.z_root';
    DEFINE FIELD value ON reader TYPE int VALUE fn::pure($this.id) COMMENT '@rebase-derived';
    DEFINE TABLE managed SCHEMAFULL PERMISSIONS NONE COMMENT '@rebase-managed-output';
    DEFINE FIELD rebase_managed_source ON managed TYPE string COMMENT '@rebase-system';
    DEFINE FIELD rebase_managed_role ON managed TYPE string COMMENT '@rebase-system';
    DEFINE FUNCTION fn::application_write() { UPDATE reader:one SET value=3; };
  `);
  assert.match(result.bundle,/fn::reads::captured::pure/);
  assert.match(result.bundle,/DEFINE FUNCTION OVERWRITE fn::reads::flush/);
  assert.match(result.bundle,/UPDATE \$link.rid PATCH/);
  assert.match(result.bundle,/UPDATE reader:one SET value=3/);
});
