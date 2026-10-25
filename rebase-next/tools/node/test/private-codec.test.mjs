import assert from 'node:assert/strict';
import test from 'node:test';
import { encodeFrame, parseFrame } from '../private/json-codec.mjs';
import { LineFrameDecoder, REQUEST_MAX_BYTES, RESPONSE_MAX_BYTES } from '../private/framing.mjs';

test('frozen request and response bounds exclude the terminating LF', () => {
  const exactRequest = encodeFrame({ x: 'a'.repeat(REQUEST_MAX_BYTES - 8) }, REQUEST_MAX_BYTES);
  assert.equal(exactRequest.byteLength, REQUEST_MAX_BYTES + 1);
  assert.equal(exactRequest.at(-1), 0x0a);
  assert.throws(() => encodeFrame({ x: 'a'.repeat(REQUEST_MAX_BYTES - 7) }, REQUEST_MAX_BYTES), /byte limit/);
  const decoder = new LineFrameDecoder(5);
  assert.deepEqual(decoder.push(Buffer.from('abcde\n')), [Buffer.from('abcde')]);
  assert.throws(() => decoder.push(Buffer.from('abcdef')), /byte limit/);
  assert.equal(RESPONSE_MAX_BYTES, 8_388_608);
});

test('strict codec rejects unsafe exact numeric literals and malformed scalar values', () => {
  assert.deepEqual(parseFrame(Buffer.from('{"count":9007199254740991}')), { count: Number.MAX_SAFE_INTEGER });
  assert.throws(() => parseFrame(Buffer.from('{"count":9007199254740992}')), /Unsafe JSON integer/);
  assert.throws(() => parseFrame(Buffer.from('{"x":1,"x":2}')), /Invalid JSON frame/);
  assert.throws(() => parseFrame(Buffer.from('{"x":"\\ud800"}')), /Unpaired UTF-16 surrogate/);
  assert.throws(() => parseFrame(Buffer.from([0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d])), /Invalid UTF-8/);
});
