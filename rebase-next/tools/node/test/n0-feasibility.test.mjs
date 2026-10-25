import assert from 'node:assert/strict';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import JSONbigFactory from 'json-bigint';
import { createGeneratorSync } from 'json-schema-faker';

const ajv = new Ajv2020({ strict: true, allErrors: true });
addFormats(ajv);
ajv.addKeyword({ keyword: 'x-rebase-range', schemaType: 'array', valid: true });
ajv.addKeyword({ keyword: 'x-rebase-binding', schemaType: 'string', valid: true });
for (const [name, expression, minimum, maximum] of [
  ['i64', /^(0|-?[1-9][0-9]*)$/, -9223372036854775808n, 9223372036854775807n],
  ['i128', /^(0|-?[1-9][0-9]*)$/, -170141183460469231731687303715884105728n, 170141183460469231731687303715884105727n],
  ['u16', /^[1-9][0-9]*$/, 1n, 65535n],
]) ajv.addFormat(name, {
  type: 'string',
  validate: value => expression.test(value) && BigInt(value) >= minimum && BigInt(value) <= maximum,
});

const catalogSchema = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  type: 'object',
  additionalProperties: false,
  properties: {
    id: { type: 'string', format: 'uuid' },
    at: { type: 'string', format: 'i64', pattern: '^(0|-?[1-9][0-9]*)$', 'x-rebase-range': ['-9223372036854775808', '9223372036854775807'] },
    amount: { type: 'string', format: 'i128', pattern: '^(0|-?[1-9][0-9]*)$', 'x-rebase-range': ['-170141183460469231731687303715884105728', '170141183460469231731687303715884105727'] },
    code: { type: 'string', format: 'u16', pattern: '^[1-9][0-9]*$', enum: ['1', '24', '65535'], 'x-rebase-binding': 'u16' },
  },
  required: ['id', 'at', 'amount', 'code'],
};

test('Ajv validates the native 2020-12 dialect and catalog formats', () => {
  const validate = ajv.compile(catalogSchema);
  assert.equal(validate({ id: 'b42b6d6c-51c8-4afd-9d85-35553dd3f857', at: '-12', amount: '123456789012345678901', code: '65535' }), true);
  assert.equal(validate({ id: 'not-a-uuid', at: '01', amount: '2', code: '0' }), false);
  assert.equal(validate({ id: 'b42b6d6c-51c8-4afd-9d85-35553dd3f857', at: '9223372036854775808', amount: '2', code: '24' }), false);
});

test('json-schema-faker uses isolated reproducible seeds and advances to fresh output', () => {
  const first = createGeneratorSync({ seed: 913, failOnInvalidTypes: true });
  const second = createGeneratorSync({ seed: 913, failOnInvalidTypes: true });
  const values = [first.generate(catalogSchema), first.generate(catalogSchema)];
  assert.deepEqual(values, [second.generate(catalogSchema), second.generate(catalogSchema)]);
  assert.notDeepEqual(values[0], values[1]);
  for (const value of values) assert.equal(ajv.validate(catalogSchema, value), true);
});

test('strict lossless JSON rejects duplicate keys and preserves exact integer inspection', () => {
  const json = JSONbigFactory({ strict: true });
  const exactBoundary = value => {
    if (value?.constructor?.name === 'BigNumber') {
      const integer = BigInt(value.toString());
      if (integer < BigInt(Number.MIN_SAFE_INTEGER) || integer > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new RangeError('unsafe JSON integer; encode exact values as decimal strings');
      }
      return Number(integer);
    }
    if (Array.isArray(value)) return value.map(exactBoundary);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, exactBoundary(item)]));
    return value;
  };
  const unicodeBoundary = value => {
    const check = text => {
      for (let index = 0; index < text.length; index += 1) {
        const unit = text.charCodeAt(index);
        if (unit >= 0xd800 && unit <= 0xdbff) {
          const low = text.charCodeAt(index + 1);
          if (!(low >= 0xdc00 && low <= 0xdfff)) throw new SyntaxError('unpaired UTF-16 surrogate');
          index += 1;
        } else if (unit >= 0xdc00 && unit <= 0xdfff) throw new SyntaxError('unpaired UTF-16 surrogate');
      }
    };
    if (typeof value === 'string') check(value);
    else if (Array.isArray(value)) value.forEach(unicodeBoundary);
    else if (value && typeof value === 'object') for (const [key, item] of Object.entries(value)) { check(key); unicodeBoundary(item); }
    return value;
  };
  assert.throws(() => json.parse('{"outer":{"x":1,"x":2}}'), error => error?.message?.includes('Duplicate key'));
  const parsed = json.parse('{"safe":9007199254740991,"tooLarge":9007199254740992,"canonical":"9007199254740992"}');
  const safe = { ...parsed, tooLarge: undefined };
  assert.equal(exactBoundary(safe).safe, Number.MAX_SAFE_INTEGER);
  assert.throws(() => exactBoundary(parsed), /unsafe JSON integer/);
  assert.equal(exactBoundary({ canonical: parsed.canonical }).canonical, '9007199254740992');
  assert.throws(() => unicodeBoundary(json.parse('{"x":"\\ud800"}')), /surrogate/);
  assert.equal(unicodeBoundary(json.parse('{"x":"\\ud83d\\ude00"}')).x, '😀');
  assert.throws(() => new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.of(0xc3, 0x28)), /encoded data/);
  assert.throws(() => json.parse('{"x":NaN}'));
});
