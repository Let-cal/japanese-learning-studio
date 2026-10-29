import test from 'node:test';
import assert from 'node:assert/strict';
import { writeAll } from './write-all.mjs';

test('advances by actual bytesWritten until every byte is persisted', async () => {
  const seen = [];
  const handle = { async write(bytes) {
    const bytesWritten = Math.min(2, bytes.length);
    seen.push(...bytes.subarray(0, bytesWritten));
    return { bytesWritten };
  } };
  await writeAll(handle, Uint8Array.of(1, 2, 3, 4, 5));
  assert.deepEqual(seen, [1, 2, 3, 4, 5]);
});

test('rejects zero progress instead of silently truncating or looping', async () => {
  let calls = 0;
  const handle = { async write() { calls++; return { bytesWritten: 0 }; } };
  await assert.rejects(writeAll(handle, Uint8Array.of(1)), /no progress/);
  assert.equal(calls, 1);
});
