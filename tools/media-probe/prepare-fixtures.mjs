// Capability fixtures only: four pinned public charts and small synthetic cases.
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import sharp from 'sharp';
const root = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.join(root, 'artifacts', 'fixtures');
const manifest = JSON.parse(await fs.readFile(path.join(root, 'fixture-manifest.json'), 'utf8'));
const MAX_BYTES = 12 * 1024 * 1024;
const hash = data => createHash('sha256').update(data).digest('hex');
await fs.mkdir(fixtures, { recursive: true });
async function fetchPinned(item, maxBytes = MAX_BYTES) {
  assert.equal(new URL(item.url).origin, 'https://heic.fyi');
  const response = await fetch(item.url, { signal: AbortSignal.timeout(30_000), redirect: 'error' });
  assert.equal(response.status, 200, `fetch status ${item.url}`);
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maxBytes)) {
    await response.body?.cancel();
    throw new Error('FETCH_BYTE_BOUND_CONTENT_LENGTH');
  }
  const chunks = [];
  let total = 0;
  const reader = response.body.getReader();
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new Error('FETCH_BYTE_BOUND_STREAM');
      chunks.push(value);
    }
  } finally { await reader.cancel(); }
  const data = Buffer.concat(chunks, total);
  assert.equal(hash(data), item.sha256, `pinned SHA256 ${item.url}`);
  return data;
}
// Verification precedes the write; no remote code is evaluated.
await fs.writeFile(path.join(fixtures, 'LICENSE-heic-fyi.txt'), await fetchPinned(manifest.license, 64 * 1024));
for (const fixture of manifest.fixtures) {
  await fs.writeFile(path.join(fixtures, fixture.name), await fetchPinned(fixture));
}
const colors = [[230,30,40],[20,190,50],[30,60,230],[230,200,20]];
const width = 120, height = 80, raw = Buffer.alloc(width * height * 3);
for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) {
  raw.set(colors[(y >= height / 2 ? 2 : 0) + (x >= width / 2 ? 1 : 0)], (y * width + x) * 3);
}
for (let orientation = 1; orientation <= 8; orientation++) {
  const data = await sharp(raw, {raw: {width, height, channels: 3}})
    .withMetadata({orientation})
    .withExifMerge({IFD0: {Make: 'Task0 Synthetic', ImageDescription: 'Asymmetric RGB quadrants'},
      IFD3: {GPSLatitudeRef: 'N', GPSLatitude: '10/1 0/1 0/1', GPSLongitudeRef: 'E', GPSLongitude: '106/1 0/1 0/1'}})
    .jpeg({quality: 100, chromaSubsampling: '4:4:4'}).toBuffer();
  const meta = await sharp(data).metadata();
  assert.equal(meta.orientation, orientation);
  assert.ok(meta.exif?.length > 0);
  await fs.writeFile(path.join(fixtures, `orientation-${orientation}.jpg`), data);
}
const heic = await fs.readFile(path.join(fixtures, manifest.fixtures[0].name));
await fs.writeFile(path.join(fixtures, 'truncated.heic'), heic.subarray(0, 100));
await fs.writeFile(path.join(fixtures, 'truncated-body.heic'), heic.subarray(0, Math.floor(heic.length * .8)));
const corrupt = Buffer.from(heic.subarray(0, 64)); corrupt.fill(0, 16);
await fs.writeFile(path.join(fixtures, 'corrupt.heic'), corrupt);
// Fixture construction only, not a production container parser or fuzzing.
const overPixels = Buffer.from(heic), ispe = overPixels.indexOf(Buffer.from('ispe'));
assert.ok(ispe >= 0 && ispe + 16 <= overPixels.length, 'known chart ispe fixture field');
overPixels.writeUInt32BE(6001, ispe + 8); overPixels.writeUInt32BE(5000, ispe + 12);
await fs.writeFile(path.join(fixtures, 'header-over-30mp.heic'), overPixels);
const overBytes = await fs.open(path.join(fixtures, 'over-12mib.bin'), 'w');
try { await overBytes.truncate(MAX_BYTES + 1); } finally { await overBytes.close(); }
await fs.writeFile(path.join(fixtures, 'provenance.json'), JSON.stringify({
  preparedAt: new Date().toISOString(), license: manifest.license,
  fixtures: manifest.fixtures, synthetic: '8 asymmetric JPEG orientation/GPS charts and 5 bounded HEIC/byte negative cases'
}, null, 2));
console.log(JSON.stringify({prepared: true, publicCharts: manifest.fixtures.length, syntheticCases: 13, directory: 'artifacts/fixtures'}));
