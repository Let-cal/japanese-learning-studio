// Local synthetic compatibility spike. No product restore or cloud calls.
import { Encrypter, Decrypter } from 'age-encryption';
import { ZipWriter, ZipReader, Reader, configure } from '@zip.js/zip.js';
import { randomBytes, createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, open, stat, writeFile } from 'node:fs/promises';
import { Readable, Writable } from 'node:stream';
import { resolve } from 'node:path';
import assert from 'node:assert/strict';
import { writeAll } from './write-all.mjs';
configure({ useWebWorkers: false });
const MiB = 1024 ** 2, cap = 1024 ** 3;
const requested = Number(process.argv[2] ?? 25);
assert([25,249].includes(requested), 'Only bounded 25 or249 MiB runs allowed');
const out = resolve(import.meta.dirname, '../../artifacts/recovery-probe', `${requested}MiB-${Date.now()}`);
await mkdir(out, { recursive: true });
const started = performance.now(), before = process.memoryUsage().rss;
let peak = before;
function guard() { peak = Math.max(peak, process.memoryUsage().rss); if (peak > cap) throw Error('RSS exceeds1GiB'); }
const timer = setInterval(() => { try { guard(); } catch { process.exitCode = 1; process.stderr.write('RSS guard abort\n'); process.exit(1); } }, 20);
const passphrase = randomBytes(32).toString('base64url'); // Disposable, never saved.
const hash = () => createHash('sha256');
function source(size, digest) { let remaining = size; return new ReadableStream({ pull(c) { guard(); if (!remaining) return c.close(); const b = randomBytes(Math.min(64 * 1024, remaining)); remaining -= b.length; digest.update(b); c.enqueue(b); } }); }
function fileStream(path) { return Readable.toWeb(createReadStream(path, { highWaterMark: 64 * 1024 })); }
function fileSink(path) { return Writable.toWeb(createWriteStream(path, { flags: 'wx' })); }
async function digestStream(s) { const h = hash(); let bytes = 0; for await (const b of s) { guard(); h.update(b); bytes += b.length; } return { bytes, sha256: h.digest('hex') }; }
async function decrypt(s, p=passphrase) { const d = new Decrypter(); d.addPassphrase(p); return d.decrypt(s); }
const results = { scope: 'Node local synthetic only', node: process.version, dependencies: { 'age-encryption': '0.3.1', '@zip.js/zip.js': '2.24.0' }, scryptLogN:18, requestedMiB:requested, limits:{compressedBytes:250*MiB, expandedBytes:1024*MiB, entries:10000}, transportChunkBoundBytes:4*MiB };
try {
 const archive = resolve(out, 'synthetic.zip'), restored = resolve(out, 'decrypted.zip');
 const original = hash(), generatedBytes = requested * MiB;
 const z = new ZipWriter(fileSink(archive));
 await z.add('synthetic-random.bin', source(generatedBytes, original), { level: 0 });
 await z.close();
 const originalHash = original.digest('hex'), archiveBytes = (await stat(archive)).size;
 assert(archiveBytes < 250 * MiB);
 const archiveHash = await digestStream(fileStream(archive));
 const e = new Encrypter(); e.setPassphrase(passphrase);
 const encrypted = await e.encrypt(fileStream(archive));
 let handle, chunkBytes=0, encryptedBytes=0; const chunks=[];
 try { for await (const b of encrypted) { guard(); let offset=0; while(offset<b.length) { if(!handle) { const path=resolve(out,`chunk-${String(chunks.length).padStart(3,'0')}.age-part`); handle=await open(path,'wx'); chunks.push({path,bytes:0}); } const n=Math.min(4*MiB-chunkBytes,b.length-offset); await writeAll(handle,b.subarray(offset,offset+n)); offset+=n; chunkBytes+=n; encryptedBytes+=n; chunks.at(-1).bytes+=n; if(chunkBytes===4*MiB) {await handle.close();handle=null;chunkBytes=0;} } } } finally { await handle?.close(); }
 async function* parts() { for(const c of chunks) yield* createReadStream(c.path,{highWaterMark:64*1024}); }
 await (await decrypt(Readable.toWeb(Readable.from(parts())))).pipeTo(fileSink(restored));
 assert.deepEqual(await digestStream(fileStream(restored)),archiveHash);
 class DiskReader extends Reader { constructor(h,size) { super();this.h=h;this.size=size; } async readUint8Array(index,length) { guard(); const b=new Uint8Array(length); const r=await this.h.read(b,0,length,index); assert.equal(r.bytesRead,length);return b; } }
 const h=await open(restored,'r'); let entryResult;
 try { const zr=new ZipReader(new DiskReader(h,archiveBytes)); const entries=await zr.getEntries(); assert.equal(entries.length,1); let expanded=0; const eh=hash(); await entries[0].getData(new WritableStream({write(b){guard();expanded+=b.length;assert(expanded<=1024*MiB);eh.update(b);}})); entryResult={bytes:expanded,sha256:eh.digest('hex')};assert.equal(entryResult.sha256,originalHash);assert.equal(expanded,generatedBytes);await zr.close(); } finally {await h.close();}
 results.roundtrip={generatedBytes,archiveBytes,encryptedBytes,entries:1,originalSHA256:originalHash,archiveSHA256:archiveHash.sha256,entry:entryResult,hashesMatch:true,chunkCount:chunks.length,maxChunkBytes:Math.max(...chunks.map(c=>c.bytes)),eachUnder50MB:chunks.every(c=>c.bytes<50*1000*1000)};
 // Small ciphertext only: bounded adversarial cases reuse one default-work-factor envelope.
 const se=new Encrypter();se.setPassphrase(passphrase);const small=await se.encrypt(randomBytes(128*1024));
 async function rejects(label,bytes,p=passphrase) { let rejected=false;try{await digestStream(await decrypt(new Blob([bytes]).stream(),p));}catch{rejected=true;}assert(rejected,label);return true; }
 const tampered=small.slice();tampered[tampered.length-30]^=1;
 results.rejection={wrongPassphrase:await rejects('wrong passphrase',small,randomBytes(32).toString('hex')),bitTamper:await rejects('tamper',tampered),truncation:await rejects('truncation',small.subarray(0,small.length-1))};
 let cancelled=false,pulls=0;const cancelInput=new ReadableStream({pull(c){pulls++;c.enqueue(randomBytes(64*1024));},cancel(){cancelled=true;}});
 const ce=new Encrypter();ce.setPassphrase(passphrase);const cs=await ce.encrypt(cancelInput);const controller=new AbortController();let writes=0,aborted=false;
 await assert.rejects(cs.pipeTo(new WritableStream({write(){if(++writes===4)controller.abort(new Error('synthetic cancellation'));},abort(){aborted=true;}}),{signal:controller.signal}));
 await new Promise(r=>setImmediate(r));const pullsAtAbort=pulls;await new Promise(r=>setTimeout(r,50));assert(cancelled&&aborted);assert.equal(pulls,pullsAtAbort);
 results.cancellation={upstreamCancelled:cancelled,sinkAborted:aborted,sourcePullsStopped:true,writesBeforeAbort:writes,scope:'stream phase only; scrypt setup is not abortable'};
 results.status='passed';
} catch(error) {results.status='failed';results.error=String(error);process.exitCode=1;} finally {clearInterval(timer);guard();results.measurement={rssBeforeBytes:before,rssPeakBytes:peak,rssAfterBytes:process.memoryUsage().rss,elapsedMs:Math.round(performance.now()-started),condition:'single Node process;20ms RSS sampling plus stream guards; disk-backed archive and parts; includes default scrypt18 setup and negative cases'};await writeFile(resolve(out,'results.json'),JSON.stringify(results,null,2));console.log(JSON.stringify({out,...results},null,2));}
