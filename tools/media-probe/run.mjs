import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const root = path.dirname(fileURLToPath(import.meta.url));
process.chdir(root);
const resourceBudgetKiB = 768 * 1024; // Observed corpus peak gate, not an OS limit.
const fixtureRoot = path.join(root, 'artifacts', 'fixtures');
const sha256 = data => createHash('sha256').update(data).digest('hex');
const runId = new Date().toISOString().replace(/[:.]/g,'-') + '-' + process.pid;
const outputDir = path.join(root, 'artifacts', 'runs', runId);
await fs.mkdir(path.dirname(outputDir), { recursive: true });
await fs.mkdir(outputDir); // Fail rather than reuse a previous run directory.
const result = { runId, timestamp: new Date().toISOString(), node: process.version, platform: process.platform, arch: process.arch, deadlineMs: 30000, outputDir, resourceBudgetKiB, productionAcceptance: false, sharpVersions: sharp.versions, jobs: [], checks: [], fixtures: [], outputs: [] };
const env = Object.fromEntries(['SystemRoot', 'WINDIR', 'TEMP', 'TMP'].filter(k => process.env[k]).map(k => [k, process.env[k]]));
function run(command, argument, destination='', plan) {
  const child = spawnSync(process.execPath, [path.join(root,'worker.mjs'), command, argument, destination, JSON.stringify(plan || {})], { cwd: root, encoding: 'utf8', timeout: 30000, killSignal: 'SIGKILL', maxBuffer: 1024*1024, windowsHide: true, env });
  const line = child.stdout?.split('\n').find(x=>x.startsWith('PROBE_JSON='));
  let value;
  try { value = line ? JSON.parse(line.slice(11)) : {}; } catch { value = {}; }
  value = { ...value, command, argument, childStatus: child.status, signal: child.signal, childError: child.error?.message, childErrorCode: child.error?.code, stdout: child.stdout?.split('\n').filter(x=>!x.startsWith('PROBE_JSON=')).join('\n'), stderr: child.stderr };
  value.ok = value.ok === true && child.status === 0 && !child.error;
  result.jobs.push(value);
  return value;
}
for (const arg of ['--version','--list-decoders','--help']) run('cli',arg);
for (const name of ['basic-8bit-srgb.heic','grid-12mp-512px-tiles.heic','orientation-6.heic','multi-image-burst.heic','truncated.heic','truncated-body.heic','corrupt.heic','header-over-30mp.heic','over-12mib.bin']) {
  const file = path.join(fixtureRoot,name);
  const bytes = await fs.readFile(file);
  const fixture = { name, bytes: bytes.length, sha256: sha256(bytes) };
  result.fixtures.push(fixture);
  const info = run('info',file);
  if (!info.ok) { result.checks.push({kind:'rejected-preflight',name,pass: ['truncated.heic','truncated-body.heic','corrupt.heic','header-over-30mp.heic','over-12mib.bin'].includes(name), error:info.error }); continue; }
  const images = [...info.stdout.matchAll(/^image: (\d+)x(\d+) \(id=(\d+)\)(, primary)?\s*$/gm)].map(x=>({ width:+x[1], height:+x[2], id:+x[3], primary:!!x[4] }));
  const destination = path.join(outputDir,name+'.jpg');
  const decode = run('decode',file,destination,{sha256:fixture.sha256,images,unrecognizedImageRows:info.stdout.split('\n').filter(x=>/^image:/.test(x)&&!/^image: \d+x\d+ \(id=\d+\)(, primary)?\s*$/.test(x))});
  const positive = ['basic-8bit-srgb.heic','grid-12mp-512px-tiles.heic','orientation-6.heic','multi-image-burst.heic'].includes(name);
  result.checks.push({ kind: positive ? 'heic-positive' : 'heic-negative', name, pass: positive ? decode.ok : !decode.ok, error:decode.error });
  if (decode.ok) {
    const jpeg = await fs.readFile(destination);
    result.outputs.push({name:path.basename(destination),bytes:jpeg.length,sha256:sha256(jpeg)});
    const meta = decode.outputMetadata;
    result.checks.push({kind:'metadata-stripped',name,pass:meta.exifBytes===0&&meta.xmpBytes===0&&meta.iccBytes===0&&meta.iptcBytes===0&&!meta.orientation});
    if (name==='orientation-6.heic') result.checks.push({kind:'heic-orientation-dimensions',name,pass:meta.width===1200&&meta.height===800,actual:[meta.width,meta.height],expected:[1200,800],note:'Dimensions only; visual inspection of current HEIC orientation chart remains required, particularly on Linux.'});
    if (name==='multi-image-burst.heic') result.checks.push({kind:'actual-primary',name,pass:decode.selectedPrimary.id===3&&decode.selectedPrimary.index===2&&decode.selectedPrimary.naiveFirstIsPrimary===false,actual:decode.selectedPrimary});
  }
}
// Cheap contract regressions against one public chart; these are not fuzz inputs.
const basicFile=path.join(fixtureRoot,'basic-8bit-srgb.heic');
const basicHash=sha256(await fs.readFile(basicFile));
const basePlan={sha256:basicHash,images:[{width:1600,height:1200,id:1,primary:true}]};
const planCases=[
 ['hash-change',{...basePlan,sha256:'0'.repeat(64)},'PREFLIGHT_INPUT_HASH_CHANGED'],
 ['unsafe-dimension',{...basePlan,images:[{width:Number.MAX_SAFE_INTEGER+1,height:1,id:1,primary:true}]},'PIXEL_BOUND_BEFORE_CLI_RASTER_AFTER_INFO_PARSE'],
 ['duplicate-id',{...basePlan,images:[{width:10,height:10,id:1,primary:true},{width:10,height:10,id:1,primary:false}]},'TOP_LEVEL_IDS_INVALID_OR_DUPLICATE'],
 ['missing-primary',{...basePlan,images:[{width:10,height:10,id:1,primary:false}]},'PRIMARY_MISSING_OR_AMBIGUOUS'],
 ['multiple-primary',{...basePlan,images:[{width:10,height:10,id:1,primary:true},{width:10,height:10,id:2,primary:true}]},'PRIMARY_MISSING_OR_AMBIGUOUS'],
 ['unknown-image-row',{...basePlan,unrecognizedImageRows:['image: unexpected pinned CLI contract']},'INFO_IMAGE_ROWS_UNRECOGNIZED'],
 ['aggregate-pixels',{...basePlan,images:[{width:5000,height:4000,id:1,primary:true},{width:5000,height:4000,id:2,primary:false}]},'TOTAL_PIXEL_BOUND_BEFORE_CLI_RASTER_AFTER_INFO_PARSE'],
 ['image-count-mismatch',{...basePlan,images:[{width:10,height:10,id:1,primary:true},{width:10,height:10,id:2,primary:false}]},'CLI_IMAGE_COUNT_MISMATCH']
];
for(const [label,plan,expectedError]of planCases) {
 const job=run('decode',basicFile,path.join(outputDir,`unexpected-${label}.jpg`),plan);
 job.contractCase=label;
 result.checks.push({kind:'preflight-contract',name:label,expectedError,pass:!job.ok&&job.error===expectedError&&job.childStatus===1});
}
// Independent generated JPEG orientation/privacy regression using only this package's synthetic fixtures.
// Minimal TIFF inspection exclusively for our generated JPEG GPS regression.
// No application parser or HEIC input handling uses this helper.
function syntheticGpsTagIds(exif) {
  if (!exif || exif.length < 14) return [];
  const little = exif.toString('ascii',6,8)==='II';
  const u16 = n => little ? exif.readUInt16LE(6+n) : exif.readUInt16BE(6+n);
  const u32 = n => little ? exif.readUInt32LE(6+n) : exif.readUInt32BE(6+n);
  const ifd = u32(4);
  for(let n=0;n<u16(ifd);n++) {
    const entry=ifd+2+n*12;
    if(u16(entry)===0x8825) {
      const gps=u32(entry+8);
      return Array.from({length:u16(gps)},(_,i)=>u16(gps+2+i*12));
    }
  }
  return [];
}
const colors = [[230,30,40],[20,190,50],[30,60,230],[230,200,20]];
const cornerMappings = [[0,1,2,3],[1,0,3,2],[3,2,1,0],[2,3,0,1],[0,2,1,3],[2,0,3,1],[3,1,2,0],[1,3,0,2]];
for(let orientation=1;orientation<=8;orientation++) {
  const file = path.join(fixtureRoot,`orientation-${orientation}.jpg`);
  const data = await fs.readFile(file);
  const inputMetadata = await sharp(data).metadata();
  const jpeg = await sharp(data,{limitInputPixels:30_000_000,failOn:'warning'}).autoOrient().jpeg({quality:95,chromaSubsampling:'4:4:4'}).toBuffer();
  const destination=path.join(outputDir,`jpeg-orientation-${orientation}.jpg`);
  await fs.writeFile(destination,jpeg);
  const decoded = await sharp(jpeg).raw().toBuffer({resolveWithObject:true});
  const meta = await sharp(jpeg).metadata();
  const samples=[[.25,.25],[.75,.25],[.25,.75],[.75,.75]].map(([x,y])=>{const i=(Math.floor(decoded.info.height*y)*decoded.info.width+Math.floor(decoded.info.width*x))*decoded.info.channels;return [...decoded.data.subarray(i,i+3)];});
  const delta=Math.max(...samples.flatMap((p,i)=>p.map((v,c)=>Math.abs(v-colors[cornerMappings[orientation-1][i]][c]))));
  result.checks.push({kind:'jpeg-orientation-privacy',orientation,pass:delta<=12&&meta.width===(orientation<=4?120:80)&&meta.height===(orientation<=4?80:120)&&!meta.exif&&!meta.xmp&&!meta.icc&&!meta.iptc&&!meta.orientation,maxChannelDelta:delta,inputOrientation:inputMetadata.orientation,inputExifBytes:inputMetadata.exif?.length||0,inputGpsTagIds:syntheticGpsTagIds(inputMetadata.exif)});
  result.outputs.push({name:path.basename(destination),bytes:jpeg.length,sha256:sha256(jpeg)});
}
for (const count of [10,11]) result.checks.push({kind:'batch-bound-simulation',inputCount:count,maxCount:10,action:count>10?'rejected before dispatch':'accepted by count gate',actualDecoderJobs:0,pass:(count<=10)===(count===10),note:'Array-length policy simulation only; not a real batch or concurrency test.'});
for (const job of result.jobs) result.checks.push({kind:'corpus-peak-observation',name:path.basename(job.argument),pass:Number.isFinite(job.maxRSSKiB)&&job.maxRSSKiB>0&&job.maxRSSKiB<=resourceBudgetKiB,maxRSSKiB:job.maxRSSKiB,budgetKiB:resourceBudgetKiB,note:'Per-process high-water RSS including imports; observational gate, not an enforced memory cap.'});
await fs.writeFile(path.join(outputDir,'results.json'),JSON.stringify(result,null,2));
await fs.writeFile(path.join(root,'artifacts','latest-run.json'),JSON.stringify({runId,outputDir},null,2));
console.log(JSON.stringify({runId,resultFile:path.relative(root,path.join(outputDir,'results.json')),jobs:result.jobs.length,checks:result.checks.length,failed:result.checks.filter(x=>!x.pass),outputs:result.outputs.length},null,2));
if(result.checks.some(x=>!x.pass)||result.jobs.slice(0,3).some(x=>!x.ok)) process.exitCode=1;
