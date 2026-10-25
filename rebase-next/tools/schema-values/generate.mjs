import { createGeneratorSync } from 'json-schema-faker';

const MAX_INPUT_BYTES = 256 * 1024;
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_COUNT = 128;
const MAX_SEED = 0xffffffff;

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exitCode = 2;
}

let input = '';
let inputBytes = 0;
process.stdin.setEncoding('utf8');
for await (const chunk of process.stdin) {
  inputBytes += Buffer.byteLength(chunk, 'utf8');
  if (inputBytes > MAX_INPUT_BYTES) {
    fail(`input exceeds ${MAX_INPUT_BYTES} bytes`);
    break;
  }
  input += chunk;
}
if (process.exitCode) process.exit();

try {
  const request = JSON.parse(input);
  if (!Number.isInteger(request.count) || request.count < 1 || request.count > MAX_COUNT) {
    throw new Error(`count must be an integer in 1..${MAX_COUNT}`);
  }
  if (!Number.isInteger(request.seed) || request.seed < 0 || request.seed > MAX_SEED) {
    throw new Error(`seed must be an integer in 0..${MAX_SEED}`);
  }
  if (!request.schema || typeof request.schema !== 'object' || Array.isArray(request.schema)) {
    throw new Error('schema must be an object');
  }
  const generator = createGeneratorSync({ seed: request.seed });
  const serialized = [];
  let outputBytes = 2; // opening and closing brackets
  for (let index = 0; index < request.count; index += 1) {
    const value = JSON.stringify(generator.generate(request.schema));
    if (typeof value !== 'string') throw new Error('schema generated a value that cannot be serialized as JSON');
    const valueBytes = Buffer.byteLength(value, 'utf8') + (index === 0 ? 0 : 1);
    if (outputBytes + valueBytes > MAX_OUTPUT_BYTES) {
      throw new Error(`output exceeds ${MAX_OUTPUT_BYTES} bytes`);
    }
    outputBytes += valueBytes;
    serialized.push(value);
  }
  const output = `[${serialized.join(',')}]`;
  process.stdout.write(output);
} catch (error) {
  fail(error instanceof Error ? error.stack ?? error.message : String(error));
}
