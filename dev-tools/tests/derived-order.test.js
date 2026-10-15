'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveDerivedOrder } = require('../compiler/derived-order');

function order(expression, helpers = '', rate = '$this.input') {
  const fields = [['a_total', expression], ['z_rate', rate]].map(([name, value]) => [name, {
    name, reactive: true,
    definition: `DEFINE FIELD ${name} ON example TYPE decimal VALUE ${value} COMMENT '@rebase-derived';`,
  }]);
  return resolveDerivedOrder({ name: 'example', fields: new Map(fields) }, helpers).map(field => field.name);
}

const direct = 'DEFINE FUNCTION fn::total($row: object) { RETURN ($row.z_rate ?? 0dec) * 2dec; };';

test('helper dependency order preserves literal argument positions and nested forwarding', () => {
  assert.deepEqual(order('fn::total($this)', direct), ['z_rate', 'a_total']);
  const helpers = `
    DEFINE FUNCTION fn::outer($row: object) { RETURN fn::parts('ignored', $row); };
    DEFINE FUNCTION fn::parts($label: string, $row: object) { RETURN $row.z_rate * 2dec; };
  `;
  assert.deepEqual(order('fn::outer($this)', helpers), ['z_rate', 'a_total']);
  assert.deepEqual(order("fn::parts('ignored', /* keep parameter position */ $this)", helpers), ['z_rate', 'a_total']);
  assert.throws(() => order('fn::outer($this)', helpers, '$this.a_total'), /derived field cycle/);
});

test('unproved whole-row flows fail compilation instead of silently using an old derived value', () => {
  const cases = [
    ['fn::alias($this)', 'DEFINE FUNCTION fn::alias($row: object) { LET $copy = $row; RETURN ($copy.z_rate ?? 0dec) * 2dec; };'],
    ['fn::total((IF true THEN $this ELSE $this END))', direct],
    ['fn::total(object::extend($this, {}))', direct],
    ['fn::total({ row: $this })', direct],
    ['fn::identity($this).z_rate', 'DEFINE FUNCTION fn::identity($row: object) { RETURN $row; };'],
    ['fn::total($this)', 'DEFINE FUNCTION fn::total($row: object) { RETURN $row["z_rate"] * 2dec; };'],
    ['$this["z_rate"] * 2dec', ''],
    ['fn::missing($this)', ''],
    ['fn::total($this)', 'DEFINE FUNCTION fn::total($row: object) { LET $row = {}; RETURN $row.z_rate; };'],
  ];
  for (const [expression, helpers] of cases) {
    assert.throws(() => order(expression, helpers), /cannot infer derived-field dependencies/, expression);
  }
});

test('explicit scalar dependencies can use aliases, expressions and quoted text', () => {
  const helpers = `DEFINE FUNCTION fn::twice($value: decimal) {
    LET $copy = $value;
    -- $this and $row are inert here, as in '$this.z_rate'
    RETURN $copy * 2dec;
  };`;
  assert.deepEqual(order('fn::twice($this.z_rate ?? 0dec)', helpers), ['z_rate', 'a_total']);
  assert.deepEqual(order('fn::twice($this.z_rate)', helpers), ['z_rate', 'a_total']);
});
