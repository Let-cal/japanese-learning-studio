// Throwaway probe only. Never a production upload handler.
import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import sharp from 'sharp';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
const root = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const [command, argument, destination, planJson] = process.argv.slice(2);
const start = performance.now();
const result = { command, argument, started: new Date().toISOString(), inputRead: false };
const MAX_BYTES = 12 * 1024 * 1024;
try {
  let input;
  if (['info', 'decode'].includes(command)) {
    const stat = await fs.stat(argument);
    result.inputBytes = stat.size;
    if (stat.size > MAX_BYTES) throw new Error('BYTE_BOUND_PRE_READ');
    input = await fs.readFile(argument);
    result.inputRead = true;
  }
  let plan;
  if (command === 'decode') {
    plan = JSON.parse(planJson);
    if (createHash('sha256').update(input).digest('hex') !== plan.sha256) throw new Error('PREFLIGHT_INPUT_HASH_CHANGED');
    if (plan.unrecognizedImageRows?.length) throw new Error('INFO_IMAGE_ROWS_UNRECOGNIZED');
    if (!plan.images?.length || plan.images.some(x => !(Number.isSafeInteger(x.width) && Number.isSafeInteger(x.height) && Number.isSafeInteger(x.width * x.height) && x.width > 0 && x.height > 0 && x.width * x.height <= 30_000_000))) throw new Error('PIXEL_BOUND_BEFORE_CLI_RASTER_AFTER_INFO_PARSE');
    if (plan.images.some(x => !Number.isSafeInteger(x.id) || x.id <= 0) || new Set(plan.images.map(x=>x.id)).size !== plan.images.length) throw new Error('TOP_LEVEL_IDS_INVALID_OR_DUPLICATE');
    if (plan.images.reduce((sum,x) => sum + x.width * x.height, 0) > 30_000_000) throw new Error('TOTAL_PIXEL_BOUND_BEFORE_CLI_RASTER_AFTER_INFO_PARSE');
    if (plan.images.filter(x => x.primary).length !== 1) throw new Error('PRIMARY_MISSING_OR_AMBIGUOUS');
    result.preflight = plan;
  }
  const entry = path.join(root, 'node_modules/@ai-ecoverse/wasm-libheif/bin', command === 'info' ? 'heif-info' : 'heif-dec');
  const mod = require(entry);
  if (!mod.calledRun) await new Promise((resolve, reject) => {
    mod.onRuntimeInitialized = resolve;
    mod.onAbort = reject;
  });
  result.moduleExports = Object.keys(mod);
  if (input) mod.FS.writeFile('/input.heic', input);
  const args = command === 'info' ? ['/input.heic'] : command === 'decode' ? ['/input.heic', '/decoded.png'] : [argument];
  result.argv = args;
  let status;
  try { status = mod.callMain([...args]); }
  catch (error) { if (error.name === 'ExitStatus') status = error.status; else throw error; }
  result.cliStatus = status ?? process.exitCode ?? 0;
  if (result.cliStatus !== 0) throw new Error(`CLI_EXIT_${result.cliStatus}`);
  if (command === 'decode') {
    result.virtualFiles = mod.FS.readdir('/');
    const primaryIndex = plan.images.findIndex(x => x.primary);
    const selectedPath = plan.images.length === 1 ? '/decoded.png' : `/decoded-${primaryIndex + 1}.png`;
    const actualPngs = result.virtualFiles.filter(x => /^decoded(?:-\d+)?\.png$/.test(x));
    if (actualPngs.length !== plan.images.length) throw new Error('CLI_IMAGE_COUNT_MISMATCH');
    result.selectedPrimary = { id: plan.images[primaryIndex].id, index: primaryIndex, path: selectedPath, naiveFirstIsPrimary: plan.images[0].primary };
    const png = Buffer.from(mod.FS.readFile(selectedPath));
    const source = sharp(png, { limitInputPixels: 30_000_000, failOn: 'warning' });
    const meta = await source.metadata();
    result.pngMetadata = { format: meta.format, width: meta.width, height: meta.height, orientation: meta.orientation, exifBytes: meta.exif?.length || 0, xmpBytes: meta.xmp?.length || 0, iccBytes: meta.icc?.length || 0 };
    if (!(meta.width > 0 && meta.height > 0 && meta.width * meta.height <= 30_000_000)) throw new Error('PIXEL_BOUND_AFTER_HEIC_RASTER');
    const jpeg = await source.autoOrient().jpeg({ quality: 95, chromaSubsampling: '4:4:4' }).toBuffer();
    await fs.writeFile(destination, jpeg);
    const output = await sharp(jpeg).metadata();
    result.outputBytes = jpeg.length;
    result.outputMetadata = { format: output.format, width: output.width, height: output.height, orientation: output.orientation, exifBytes: output.exif?.length || 0, xmpBytes: output.xmp?.length || 0, iccBytes: output.icc?.length || 0, iptcBytes: output.iptc?.length || 0 };
  }
  result.ok = true;
} catch (error) {
  result.ok = false;
  result.error = String(error.message || error);
  result.errorName = String(error.name || 'Error');
  result.errorCode = error.code == null ? undefined : String(error.code);
  result.errorStack = String(error.stack || '');
  if (error.cause != null) result.errorCause = String(error.cause.message || error.cause).slice(0, 4096);
  process.exitCode = 1;
}
result.elapsedMs = Math.round((performance.now() - start) * 100) / 100;
result.maxRSSKiB = process.resourceUsage().maxRSS;
result.endRSSBytes = process.memoryUsage().rss;
process.stdout.write('\nPROBE_JSON=' + JSON.stringify(result) + '\n');
