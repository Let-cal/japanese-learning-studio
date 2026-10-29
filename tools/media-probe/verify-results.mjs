import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import sharp from 'sharp';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
const root = path.dirname(fileURLToPath(import.meta.url));
const latest=process.argv[2]?null:JSON.parse(await fs.readFile(path.join(root,'artifacts','latest-run.json'),'utf8'));
const file=process.argv[2]||path.join(latest.outputDir,'results.json');
const r=JSON.parse(await fs.readFile(file,'utf8'));
const failures=[]; let count=0;
const check=(v,message)=>{count++;try {assert.ok(v,message);} catch(error) {failures.push(error.message);}};
check(r.jobs.length===26,'26 expected jobs'); check(r.checks.length===59,'59 expected checks'); check(r.outputs.length===12,'12 current outputs');
const job=(command,name)=>r.jobs.filter(x=>!x.contractCase&&x.command===command&&(name.startsWith('--')?x.argument===name:path.basename(x.argument)===name));
for(const [arg,re] of [['--version',/libheif: 1\.23\.6/],['--list-decoders',/libde265 HEVC decoder, version 1\.1\.3/],['--help',/--disable-limits/]]) {
  const a=job('cli',arg);check(a.length===1&&a[0].ok&&a[0].childStatus===0&&re.test((a[0].stdout||'')+(a[0].stderr||'')),`runtime ${arg}`);
}
const known={
 'basic-8bit-srgb.heic':['3fe7d32e5568f8bfd6b5d3290e61ac9b964d08464d388fa064f69cddddfee82c',1600,1200],
 'grid-12mp-512px-tiles.heic':['ed14b6e639fc61ce19b933163579ea23f226aa2f0a78cb757753628bcee0e55e',4032,3024],
 'orientation-6.heic':['80b615ae433d7ec53e9aaaeee081ecd11c0d9931350da13d6ce4e2b363d12c12',1200,800],
 'multi-image-burst.heic':['a3f76e9b8552b1deca83b7196bfa637e2742894b7ff2a17deddcef24f010d813',1280,960],
};
for(const [name,[hash,w,h]]of Object.entries(known)) {
  check(r.fixtures.filter(x=>x.name===name&&x.sha256===hash).length===1,`fixture hash ${name}`);
  const a=job('info',name); check(a.length===1&&a[0].ok&&a[0].childStatus===0,`info ${name}`);
  const d=job('decode',name);check(d.length===1&&d[0].ok&&d[0].childStatus===0,`decode ${name}`);
  if(d.length===1) {const m=d[0].outputMetadata||{};check(m.width===w&&m.height===h,`dimensions ${name}`);check(m.exifBytes===0&&m.xmpBytes===0&&m.iccBytes===0&&m.iptcBytes===0&&!m.orientation,`privacy ${name}`);check(d[0].preflight.sha256===hash,`preflight bytes ${name}`);}
}
for(const [name,error]of [['truncated.heic','CLI_EXIT_1'],['corrupt.heic','CLI_EXIT_1'],['over-12mib.bin','BYTE_BOUND_PRE_READ']]) {
  const a=job('info',name);check(a.length===1&&a[0].ok===false&&a[0].childStatus===1&&a[0].error===error,`negative ${name}`);check(job('decode',name).length===0,`no decode ${name}`);
  if(name==='over-12mib.bin')check(a[0]?.inputRead===false,'over-byte rejected before worker read');
}
for(const [name,error]of [['truncated-body.heic','CLI_EXIT_1'],['header-over-30mp.heic','PIXEL_BOUND_BEFORE_CLI_RASTER_AFTER_INFO_PARSE']]) {
  const i=job('info',name),d=job('decode',name);check(i.length===1&&i[0].ok,`metadata parses ${name}`);check(d.length===1&&d[0].ok===false&&d[0].childStatus===1&&d[0].error===error,`decode rejects ${name}`);
  if(name==='header-over-30mp.heic')check(d[0]?.moduleExports===undefined,'over-pixel rejects before decoder module initialization');
}
const burst=job('decode','multi-image-burst.heic')[0];check(burst?.selectedPrimary?.id===3&&burst?.selectedPrimary?.index===2&&burst?.selectedPrimary?.path==='/decoded-3.png'&&burst?.selectedPrimary?.naiveFirstIsPrimary===false,'actual primary third output');
check(r.node==='v24.22.1'&&r.sharpVersions.sharp==='0.35.5','pinned actual Node and Sharp runtime');
check(r.jobs.filter(x=>x.contractCase).length===8,'8 explicit preflight contract jobs');
for(const c of r.checks.filter(x=>x.kind==='preflight-contract'))check(r.jobs.filter(x=>x.contractCase===c.name&&x.error===c.expectedError&&!x.ok&&x.childStatus===1).length===1,'actual contract rejection '+c.name);
for(const c of r.checks)check(c.pass===true,`check ${c.kind} ${c.name||c.orientation}`);
for(let o=1;o<=8;o++)check(r.checks.filter(x=>x.kind==='jpeg-orientation-privacy'&&x.orientation===o&&x.pass&&x.maxChannelDelta<=12).length===1,`JPEG orientation ${o}`);
check(r.resourceBudgetKiB===768*1024,'declared corpus peak budget');
check(r.jobs.every(x=>Number.isFinite(x.maxRSSKiB)&&x.maxRSSKiB>0&&x.maxRSSKiB<=r.resourceBudgetKiB),'all worker peak observations below corpus gate');
for(const n of [10,11])check(r.checks.filter(x=>x.kind==='batch-bound-simulation'&&x.inputCount===n&&x.actualDecoderJobs===0&&x.pass).length===1,'batch count simulation '+n);
for(const c of r.checks.filter(x=>x.kind==='jpeg-orientation-privacy'))check(c.inputOrientation===c.orientation&&c.inputExifBytes>0&&[1,2,3,4].every(id=>c.inputGpsTagIds.includes(id)), 'generated input orientation and GPS '+c.orientation);
const actualFiles=(await fs.readdir(r.outputDir)).filter(x=>x.endsWith('.jpg')).sort();check(JSON.stringify(actualFiles)===JSON.stringify(r.outputs.map(x=>x.name).sort()),'fresh exact output inventory');
for(const out of r.outputs) {
 const bytes=await fs.readFile(path.join(r.outputDir,out.name));check(bytes.length===out.bytes&&createHash('sha256').update(bytes).digest('hex')===out.sha256,`output hash ${out.name}`);
 const meta=await sharp(bytes).metadata();check(meta.format==='jpeg'&&!meta.exif&&!meta.xmp&&!meta.icc&&!meta.iptc&&!meta.orientation,`actual JPEG privacy ${out.name}`);
}
check(r.jobs.every(x=>x.signal===null&&!x.childError&&!x.childErrorCode),'all children completed without timeout');
console.log(JSON.stringify({file,assertions:count,failures,pass:failures.length===0,productionAcceptance:false},null,2));
if(failures.length)process.exitCode=1;
