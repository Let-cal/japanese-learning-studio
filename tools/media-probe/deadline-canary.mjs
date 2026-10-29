// Expected timeout test of one owned direct child. No decoder or descendant process.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
const timeoutMs = 1000; // Allows startup/ready evidence; this is not a benchmark.
const code = `process.on('SIGTERM',()=>{}); process.stdout.write('CANARY_READY\\n'); while(true){}`;
const child = spawnSync(process.execPath, ['--eval', code], {
  encoding: 'utf8', timeout: timeoutMs, killSignal: 'SIGKILL',
  maxBuffer: 1024 * 1024, windowsHide: true,
  env: Object.fromEntries(['SystemRoot','WINDIR','TEMP','TMP'].filter(k=>process.env[k]).map(k=>[k,process.env[k]]))
});
assert.match(child.stdout || '', /CANARY_READY/, 'child installed handler and entered owned loop before timeout');
assert.equal(child.error?.code, 'ETIMEDOUT', 'actual supervisor timeout');
assert.ok(child.pid > 0, 'owned child PID');
let gone = false;
try { process.kill(child.pid, 0); } catch(error) { if(error.code === 'ESRCH') gone = true; else throw error; }
assert.ok(gone, 'spawnSync returned after child termination and reaping');
if(process.platform !== 'win32') assert.equal(child.signal, 'SIGKILL');
console.log(JSON.stringify({pass:true,expectedTimeout:true,timeoutMs,pid:child.pid,childErrorCode:child.error.code,signal:child.signal,pidGone:gone,platform:process.platform,note:process.platform==='win32'?'Windows force termination; no POSIX signal-handler semantics established.':'POSIX SIGKILL terminates a direct child whose SIGTERM handler was installed.',descendantTreeGuarantee:false}));
