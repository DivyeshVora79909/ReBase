export const PROTOCOL = 'rebase-native-host-1';
export const REQUEST_MAX_BYTES = 65_536;
export const RESPONSE_MAX_BYTES = 8_388_608;
export const MAX_OUTSTANDING = 1;

export class LineFrameDecoder {
  #maximum;
  #partial = Buffer.alloc(0);

  constructor(maximumBytes) {
    this.#maximum = maximumBytes;
  }

  get hasPartialFrame() { return this.#partial.byteLength !== 0; }

  push(chunk) {
    if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk);
    const frames = [];
    let start = 0;
    for (let index = 0; index < chunk.byteLength; index += 1) {
      if (chunk[index] !== 0x0a) continue;
      const segmentLength = index - start;
      const frameLength = this.#partial.byteLength + segmentLength;
      if (frameLength > this.#maximum) throw frameError('Response byte limit');
      const frame = Buffer.concat([this.#partial, chunk.subarray(start, index)], frameLength);
      this.#partial = Buffer.alloc(0);
      frames.push(frame);
      start = index + 1;
    }
    const tail = chunk.subarray(start);
    if (tail.byteLength) {
      const length = this.#partial.byteLength + tail.byteLength;
      if (length > this.#maximum) throw frameError('Response byte limit');
      this.#partial = Buffer.concat([this.#partial, tail], length);
    }
    return frames;
  }

  finish() {
    if (this.#partial.byteLength) throw frameError('Truncated response frame');
  }
}

function frameError(message) {
  const error = new Error(message);
  error.name = 'NativeFrameError';
  error.code = 'frame_error';
  return error;
}
