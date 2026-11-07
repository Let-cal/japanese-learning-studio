import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import type { Pool } from 'pg';
import { AUTH, initializeAuthFixture, cleanupAuthFixture, createAuthProofPool } from './authFixture';
import { assertServerIdentity } from './protocol';
import { adapt } from './fixture';
import { encryptPkceVerifier, decryptPkceVerifier } from '../../src/infrastructure/auth/authActionSecrets';
import { encryptOrphanTokens, decryptOrphanTokens } from '../../src/infrastructure/auth/orphanTokenEnvelope';
import { encryptUpstreamTokens, decryptUpstreamTokens } from '../../src/infrastructure/auth/tokenEnvelope';
export { createAuthProofPool };
export const OAUTH = {
  ...AUTH,
  issuance: '10000000-0000-4000-8000-000000000001', claim: '10000000-0000-4000-8000-000000000002',
  candidate: '10000000-0000-4000-8000-000000000003', commit: '10000000-0000-4000-8000-000000000004',
  close: '10000000-0000-4000-8000-000000000005', cleanupClaim: '10000000-0000-4000-8000-000000000006',
  flow: 'e'.repeat(64), fingerprint: 'f'.repeat(64),
  orphanEnvelope: `orphan-v1.fixture.${'A'.repeat(16)}.${'A'.repeat(64)}.${'A'.repeat(22)}`,
};
export const oauthMigration = new URL('../../supabase/migrations/20261107050258_auth_oauth_lifecycle.sql', import.meta.url);
export const oauthSignatures = [
  'jls_auth_issue_proof_v1(uuid,text,uuid,text,uuid,text,text,text,text,uuid,bigint,bigint,uuid)',
  'jls_auth_begin_login_v1(text,text,uuid,text,uuid,text,text,text)',
  'jls_auth_callback_claim_v1(text,text,uuid,uuid)',
  'jls_auth_callback_mark_sent_v1(text,text,uuid,uuid)',
  'jls_auth_callback_commit_v1(text,text,uuid,uuid,uuid,text,uuid,uuid,uuid,uuid,text,text,timestamptz)',
  'jls_auth_callback_resolve_v1(text,text,uuid,uuid,uuid,text)',
  'jls_auth_callback_close_v1(text,text,uuid,uuid,uuid,text,uuid,uuid,uuid,text,text)',
  'jls_auth_candidate_cleanup_claim_v1(uuid,uuid)',
  'jls_auth_candidate_cleanup_complete_v1(uuid,uuid,text)',
] as const;
export interface OAuthDatabase { query(sql: string, values?: unknown[]): Promise<{ rows: Record<string, any>[] }> }
export async function initializeOAuthFixture(pool: Pool) {
  await initializeAuthFixture(pool);
  try {
    const client=await pool.connect();
    try {
      await assertServerIdentity(adapt(client));
      const source=await readFile(oauthMigration,'utf8');
      if((source.match(/^BEGIN;$/gm)??[]).length!==1 || (source.match(/^COMMIT;$/gm)??[]).length!==1) throw new Error('Unexpected OAuth migration framing.');
      await client.query('BEGIN');
      try {await client.query(source.replace(/^BEGIN;$/m,'').replace(/^COMMIT;$/m,'')); await client.query('COMMIT');}
      catch(cause) {try{await client.query('ROLLBACK');}catch(rollback){throw new AggregateError([cause,rollback],'OAuth initialization rollback failed.');} throw cause;}
    } finally {client.release(true);}
  } catch (cause) {
    try {await cleanupAuthFixture(pool);} catch(cleanup){throw new AggregateError([cause,cleanup],'OAuth initialization and foundation cleanup failed.');}
    throw cause;
  }
}
export async function cleanupOAuthFixture(pool: Pool) {
  // Verify identity/sentinel before any extra wrapper DDL; inherited cleanup verifies again.
  const client = await pool.connect();
  try {
    await assertServerIdentity(adapt(client));
    const marker = (await client.query('SELECT marker FROM jls_auth_fixture.marker')).rows;
    if (marker.length !== 1 || marker[0]?.marker !== 'jls-auth-control-proof-v1') throw new Error('OAuth cleanup sentinel mismatch.');
    const roles=(await client.query("SELECT rolname,rolsuper,rolbypassrls,rolcanlogin FROM pg_roles WHERE rolname IN ('anon','authenticated','service_role')")).rows;
    if(roles.length!==3 || roles.some(row=>row.rolsuper || row.rolbypassrls || row.rolcanlogin)) throw new Error('OAuth cleanup role identity mismatch.');
    await client.query('BEGIN');
    try { for (const signature of oauthSignatures) await client.query(`DROP FUNCTION public.${signature}`); await client.query('COMMIT'); }
    catch (cause) {try{await client.query('ROLLBACK');}catch(rollback){throw new AggregateError([cause,rollback],'OAuth cleanup rollback failed.');} throw cause;}
  } finally { client.release(true); }
  await cleanupAuthFixture(pool);
}
export async function resetOAuthFixture(db: OAuthDatabase) {
  const client='connect' in db ? await (db as Pool).connect() : db;
  try {
    if('release' in client) {
      await assertServerIdentity(adapt(client));
      const marker=(await client.query('SELECT marker FROM jls_auth_fixture.marker')).rows;
      if(marker.length!==1 || marker[0]?.marker!=='jls-auth-control-proof-v1') throw new Error('OAuth reset sentinel mismatch.');
    }
    await client.query('BEGIN');
    try {
  await client.query(`TRUNCATE jls_auth.candidate_cleanup_work,jls_auth.proof_issuances,
    jls_auth.cleanup_work,jls_auth.action_receipts,jls_auth.csrf_proofs,jls_auth.oauth_attempts,
    jls_auth.session_credentials,jls_auth.app_sessions,jls_auth.browser_bindings,jls_auth.datasets,jls_auth.owner_control`);
  await client.query('INSERT INTO jls_auth.owner_control(owner_id,auth_subject) VALUES ($1,$2)', [OAUTH.owner,OAUTH.subject]);
  await client.query('INSERT INTO jls_auth.datasets(owner_id,dataset_epoch) VALUES ($1,$2)', [OAUTH.owner,OAUTH.epoch]);
  await client.query('UPDATE jls_auth.owner_control SET active=true,current_dataset_epoch=$2 WHERE owner_id=$1', [OAUTH.owner,OAUTH.epoch]);
      await client.query('COMMIT');
    } catch(cause) {try{await client.query('ROLLBACK');}catch(rollback){throw new AggregateError([cause,rollback],'OAuth reset rollback failed.');} throw cause;}
  } finally {if('release' in client) client.release(true);}
}
export async function oauthRpc(db: OAuthDatabase, index: number, values: unknown[], role = 'service_role') {
  const capabilities=[...oauthSignatures,'jls_auth_logout_v1(text,text,uuid,text)','jls_auth_delivery_retire_v1(text,uuid,uuid,bigint)','jls_auth_delivery_ack_v1(text,text,bigint)'];
  if (!['service_role','anon','authenticated'].includes(role) || !capabilities[index]) throw new Error('Unknown fixture capability.');
  // Pin a connection for SET LOCAL ROLE when supplied a native pool.
  const client = 'connect' in db ? await (db as Pool).connect() : db;
  try {
    await client.query('BEGIN'); await client.query(`SET LOCAL ROLE ${role}`);
    const name = capabilities[index].split('(')[0];
    const result = (await client.query(`SELECT public.${name}(${values.map((_,i)=>`$${i+1}`).join(',')}) AS result`,values)).rows[0]?.result;
    await client.query('COMMIT'); return result;
  } catch (cause) {try{await client.query('ROLLBACK');}catch(rollback){throw new AggregateError([cause,rollback],'OAuth RPC rollback failed.');} throw cause;}
  finally { if ('release' in client) client.release(true); }
}
export function oauthFlow(db: OAuthDatabase) {
  const a=OAUTH;
  return {
    issue: (overrides: Record<number,unknown> = {}) => oauthRpc(db,0,Object.assign([a.issuance,a.fingerprint,a.browser,a.browserSecret,a.proof,a.proofSecret,'login','absent',null,a.operation,null,null,null],overrides)),
    begin: (overrides: Record<number,unknown> = {}) => oauthRpc(db,1,Object.assign([a.browserSecret,a.proofSecret,a.operation,'absent',a.attempt,a.flow,a.pkceEnvelope,a.fingerprint],overrides)),
    claim: (claim = a.claim) => oauthRpc(db,2,[a.browserSecret,a.flow,a.attempt,claim]),
    sent: (claim = a.claim) => oauthRpc(db,3,[a.browserSecret,a.flow,a.attempt,claim]),
    commit: (overrides: Record<number,unknown> = {}) => oauthRpc(db,4,Object.assign([a.browserSecret,a.flow,a.attempt,a.claim,a.commit,a.fingerprint,a.candidate,a.subject,a.upstream,a.session,a.secret,a.envelope,new Date(Date.now()+3_600_000)],overrides)),
    resolve: (overrides: Record<number,unknown> = {}) => oauthRpc(db,5,Object.assign([a.browserSecret,a.flow,a.attempt,a.claim,a.commit,a.fingerprint],overrides)),
    close: (overrides: Record<number,unknown> = {}) => oauthRpc(db,6,Object.assign([a.browserSecret,a.flow,a.attempt,a.claim,a.close,a.fingerprint,a.candidate,a.subject,a.upstream,a.orphanEnvelope,'fixture'],overrides)),
  };
}
async function ready(db: OAuthDatabase) { const f=oauthFlow(db); assert.equal((await f.issue()).kind,'issued'); assert.equal((await f.begin()).kind,'begun'); assert.equal((await f.claim()).kind,'claimed'); assert.equal((await f.sent()).kind,'send_intent'); return f; }
async function scalar(db: OAuthDatabase, sql: string) { return (await db.query(sql)).rows[0]; }
// Shared behavior cases execute identical production SQL on native PG17 and the explicitly
// separate, ignored PGlite sequential adapter. No PG17 guard bypass exists here.
export const oauthCases: readonly [string,(db: OAuthDatabase)=>Promise<void>][] = [
  ['O01 persists proof issuance and rejects changed issuance arguments', async db => {
    const f=oauthFlow(db); const first=await f.issue(); assert.equal(first.kind,'issued');
    assert.deepEqual(await f.issue(),first); assert.equal((await f.issue({7:OAUTH.cookie})).kind,'denied');
    assert.equal((await scalar(db,'SELECT count(*)::int AS n FROM jls_auth.csrf_proofs')).n,1);
  }],
  ['O02 binds exact cookie and operation before consuming proof', async db => {
    const f=oauthFlow(db); await f.issue(); assert.equal((await f.begin({3:OAUTH.cookie})).kind,'denied');
    assert.equal((await f.begin({2:OAUTH.claim})).kind,'denied'); assert.equal((await f.begin()).kind,'begun');
    assert.equal((await f.begin({6:OAUTH.envelope})).kind,'denied'); assert.equal((await f.begin()).kind,'begun');
  }],
  ['O03 requires controlled owner enrollment before beginning OAuth', async db => {
    const f=oauthFlow(db); await f.issue(); await db.query('UPDATE jls_auth.owner_control SET active=false');
    assert.equal((await f.begin()).kind,'denied'); assert.equal((await scalar(db,'SELECT count(*)::int AS n FROM jls_auth.oauth_attempts')).n,0);
  }],
  ['O04 stores a distinct encrypted PKCE verifier and allows only the same pre-send claim', async db => {
    const f=oauthFlow(db); await f.issue(); assert.equal((await f.begin({6:OAUTH.envelope})).kind,'denied');
    await f.begin(); const claim=await f.claim(); assert.equal(claim.kind,'claimed'); assert.equal(claim.pkceEnvelope,OAUTH.pkceEnvelope);
    assert.equal(typeof claim.now,'number'); assert.ok(Math.abs(claim.now-Date.now())<5_000);
    assert.equal((await f.claim()).claimId,OAUTH.claim); assert.equal((await f.claim(OAUTH.close)).kind,'restart_required');
    assert.equal((await f.sent(OAUTH.close)).kind,'denied');
  }],
  ['O05 durably marks possible transmission and never grants a resend or claim takeover', async db => {
    const f=await ready(db); assert.equal((await f.sent()).kind,'restart_required');
    assert.equal((await f.claim()).kind,'restart_required'); assert.equal((await f.claim(OAUTH.close)).kind,'restart_required');
    const row=await scalar(db,'SELECT state,exchange_transmission_intent_at IS NOT NULL AS sent FROM jls_auth.oauth_attempts');
    assert.deepEqual(row,{state:'exchange_unknown',sent:true});
  }],
  ['O06 commits candidate once, creates unacknowledged session and resolves metadata without bearers', async db => {
    const f=await ready(db); const expiry=new Date(Date.now()+3_600_000); const result=await f.commit({12:expiry});
    assert.equal(result.kind,'committed'); assert.equal(result.sessionId,OAUTH.session); assert.equal(result.generation,1);
    assert.deepEqual(await f.commit({12:expiry}),result); assert.deepEqual(await f.resolve(),result);
    assert.equal(JSON.stringify(result).includes(OAUTH.envelope),false); assert.equal(JSON.stringify(result).includes(OAUTH.secret),false);
    assert.equal((await f.resolve({5:'0'.repeat(64)})).kind,'denied'); assert.equal((await f.commit({12:expiry,10:'0'.repeat(64)})).kind,'denied');
    assert.deepEqual(await scalar(db,'SELECT generation::int AS generation FROM jls_auth.browser_bindings'),{generation:1});
    assert.equal((await scalar(db,'SELECT delivery_state FROM jls_auth.app_sessions')).delivery_state,'unacknowledged');
  }],
  ['O07 refuses unapproved subject and supports independent candidate cleanup without app session', async db => {
    const f=await ready(db); assert.equal((await f.commit({7:OAUTH.owner})).kind,'denied');
    assert.equal((await f.close({7:OAUTH.owner})).kind,'closed'); assert.equal((await scalar(db,'SELECT count(*)::int AS n FROM jls_auth.app_sessions')).n,0);
    const work=await oauthRpc(db,7,[OAUTH.attempt,OAUTH.cleanupClaim]); assert.equal(work.kind,'cleanup'); assert.equal(work.tokenEnvelope,OAUTH.orphanEnvelope); assert.equal(work.authSubject,OAUTH.owner); assert.equal(work.scope,'local');
    assert.equal((await oauthRpc(db,8,[OAUTH.attempt,OAUTH.claim,'completed'])).kind,'denied');
    assert.equal((await oauthRpc(db,8,[OAUTH.attempt,OAUTH.cleanupClaim,'completed'])).kind,'completed');
  }],
  ['O08 fences owner changes and generation changes after transmission', async db => {
    const f=await ready(db); await db.query('UPDATE jls_auth.owner_control SET control_version=control_version+1');
    assert.equal((await f.commit()).kind,'denied'); await db.query('UPDATE jls_auth.owner_control SET control_version=0');
    await db.query('UPDATE jls_auth.browser_bindings SET generation=1'); assert.equal((await f.commit()).kind,'denied');
    assert.equal((await f.close()).kind,'closed');
  }],
  ['O09 closes crash-lost credentials explicitly and cannot invent a cleanup bearer', async db => {
    const f=await ready(db); const lost={6:null,7:null,8:null,9:null,10:null}; assert.equal((await f.close(lost)).kind,'closed');
    assert.equal((await f.close(lost)).kind,'closed'); assert.equal((await f.close()).kind,'denied');
    assert.equal((await oauthRpc(db,7,[OAUTH.attempt,OAUTH.cleanupClaim])).kind,'credential_unavailable');
    assert.equal((await scalar(db,'SELECT state FROM jls_auth.candidate_cleanup_work')).state,'credential_unavailable');
  }],
  ['O10 denies mutation proof without current owner session and version fences', async db => {
    const f=oauthFlow(db); assert.equal((await f.issue({6:'mutation',9:null,10:0,11:0,12:OAUTH.epoch})).kind,'denied');
    await ready(db); await f.commit();
    const args={0:OAUTH.close,4:OAUTH.claim,5:'0'.repeat(64),6:'mutation',7:OAUTH.cookie,8:OAUTH.secret,9:null,10:0,11:0,12:OAUTH.epoch};
    assert.equal((await f.issue({...args,10:1})).kind,'denied'); assert.equal((await f.issue({...args,11:1})).kind,'denied');
    assert.equal((await f.issue(args)).kind,'issued');
  }],
  ['O11 blocks stale proofs, expired attempts and expired access candidates', async db => {
    const f=oauthFlow(db); await f.issue(); await db.query('UPDATE jls_auth.browser_bindings SET generation=1');
    assert.equal((await f.begin()).kind,'denied'); await db.query('UPDATE jls_auth.browser_bindings SET generation=0');
    await f.begin(); await f.claim(); await f.sent(); assert.equal((await f.commit({12:new Date(0)})).kind,'denied');
    await db.query("UPDATE jls_auth.oauth_attempts SET issued_at=statement_timestamp()-interval '11 minutes',expires_at=statement_timestamp()-interval '1 minute'");
    assert.equal((await f.commit()).kind,'denied'); assert.equal((await f.claim()).kind,'restart_required');
  }],
  ['O12 keeps one live attempt and requires closing a possible transmission before a fresh login', async db => {
    const f=await ready(db); const second={0:OAUTH.close,4:OAUTH.claim,5:'0'.repeat(64),9:OAUTH.close};
    await f.issue(second); assert.equal((await f.begin({1:'0'.repeat(64),2:OAUTH.close,4:OAUTH.close,5:'1'.repeat(64)})).kind,'restart_required');
    await f.close(); assert.equal((await f.begin({1:'0'.repeat(64),2:OAUTH.close,4:OAUTH.close,5:'1'.repeat(64)})).kind,'begun');
  }],
  ['O13 never permits a completed candidate to be sent to orphan cleanup', async db => {
    const f=await ready(db); await f.commit(); assert.equal((await f.close()).kind,'denied');
    assert.equal((await scalar(db,'SELECT count(*)::int AS n FROM jls_auth.candidate_cleanup_work')).n,0);
  }],
  ['O14 rolls back session creation and generation if credential insertion fails', async db => {
    const f=await ready(db); await db.query('ALTER TABLE jls_auth.session_credentials ADD CONSTRAINT oauth_reject CHECK (false) NOT VALID');
    const errors:unknown[]=[];
    try { await assert.rejects(f.commit(),/violates check constraint/); }
    catch(error) {errors.push(error);}
    finally {
      try{await db.query('ALTER TABLE jls_auth.session_credentials DROP CONSTRAINT oauth_reject');}catch(error){errors.push(error);}
      if(errors.length===1) throw errors[0];
      if(errors.length) throw new AggregateError(errors,'Commit rollback assertion and constraint cleanup failed.');
    }
    assert.equal((await scalar(db,'SELECT count(*)::int AS n FROM jls_auth.app_sessions')).n,0);
    assert.equal((await scalar(db,'SELECT generation::int AS n FROM jls_auth.browser_bindings')).n,0);
    assert.equal((await f.resolve()).kind,'unresolved'); assert.equal((await f.commit()).kind,'committed');
  }],
  ['O15 denies anonymous and authenticated roles every new control wrapper and private cleanup', async db => {
    for (const role of ['anon','authenticated']) {
      const row=(await db.query(`SELECT has_schema_privilege($1,'jls_auth','USAGE') AS schema,
        has_table_privilege($1,'jls_auth.candidate_cleanup_work','SELECT') AS credentials,
        (SELECT bool_or(has_function_privilege($1,p.oid,'EXECUTE')) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'jls_auth_%') AS execute`,[role])).rows[0];
      assert.deepEqual(row,{schema:false,credentials:false,execute:false});
      await assert.rejects(oauthRpc(db,2,[OAUTH.browserSecret,OAUTH.flow,OAUTH.attempt,OAUTH.claim],role),/permission denied/);
    }
  }],
  ['O16 rotates the prior app session and preserves old-cookie recovery CAS', async db => {
    const f=await ready(db); await f.commit();
    const a=OAUTH;
    assert.equal((await f.issue({0:a.close,4:a.claim,5:'0'.repeat(64),7:a.cookie,8:a.secret,9:a.close})).kind,'issued');
    assert.equal((await f.begin({1:'0'.repeat(64),2:a.close,3:a.cookie,4:a.close,5:'1'.repeat(64)})).kind,'begun');
    await oauthRpc(db,2,[a.browserSecret,'1'.repeat(64),a.close,a.candidate]);
    await oauthRpc(db,3,[a.browserSecret,'1'.repeat(64),a.close,a.candidate]);
    const values=[a.browserSecret,'1'.repeat(64),a.close,a.candidate,a.issuance,a.fingerprint,a.proof,a.subject,a.proof,a.claim,'2'.repeat(64),a.envelope,new Date(Date.now()+3_600_000)];
    assert.equal((await oauthRpc(db,4,values)).kind,'committed');
    assert.equal((await scalar(db,'SELECT generation::int AS n FROM jls_auth.browser_bindings')).n,2);
    assert.equal((await scalar(db,'SELECT count(*)::int AS n FROM jls_auth.app_sessions WHERE revoked_at IS NULL')).n,1);
    assert.equal((await scalar(db,'SELECT count(*)::int AS n FROM jls_auth.cleanup_work')).n,1);
    assert.equal((await oauthRpc(db,10,[a.browserSecret,a.attempt,a.session,1])).kind,'denied');
    assert.equal((await oauthRpc(db,10,[a.browserSecret,a.close,a.claim,2])).kind,'retired');
    assert.equal((await f.resolve()).kind,'committed'); // receipt is history, never new authority
  }],
  ['O17 logout cancels an in-flight callback while preserving orphan cleanup after network', async db => {
    const f=await ready(db); const a=OAUTH;
    assert.equal((await f.issue({0:a.close,4:a.candidate,5:'0'.repeat(64),6:'logout',9:a.close})).kind,'issued');
    assert.equal((await oauthRpc(db,9,[a.browserSecret,'0'.repeat(64),a.close,'absent'])).kind,'logged_out');
    assert.equal((await f.commit()).kind,'denied'); assert.equal((await f.close()).kind,'closed');
    assert.equal((await oauthRpc(db,7,[a.attempt,a.cleanupClaim])).kind,'cleanup');
    assert.equal((await scalar(db,'SELECT count(*)::int AS n FROM jls_auth.app_sessions')).n,0);
  }],
  ['O18 never retires an acknowledged result after a lost callback response', async db => {
    const f=await ready(db); await f.commit();
    assert.equal((await oauthRpc(db,11,[OAUTH.secret,OAUTH.browserSecret,0])).kind,'acknowledged');
    assert.equal((await oauthRpc(db,10,[OAUTH.browserSecret,OAUTH.attempt,OAUTH.session,1])).kind,'denied');
    assert.equal((await scalar(db,'SELECT count(*)::int AS n FROM jls_auth.app_sessions WHERE revoked_at IS NULL')).n,1);
  }],
  ['O19 cancels an expired unsent attempt and never reuses its encrypted verifier', async db => {
    const f=oauthFlow(db); await f.issue(); await f.begin(); await f.claim();
    await db.query("UPDATE jls_auth.oauth_attempts SET issued_at=statement_timestamp()-interval '11 minutes',expires_at=statement_timestamp()-interval '1 minute'");
    assert.equal((await f.sent()).kind,'restart_required');
    await f.issue({0:OAUTH.close,4:OAUTH.claim,5:'0'.repeat(64),9:OAUTH.close});
    assert.equal((await f.begin({1:'0'.repeat(64),2:OAUTH.close,4:OAUTH.close,5:'1'.repeat(64)})).kind,'begun');
    assert.equal((await f.claim()).kind,'restart_required');
  }],
  ['O20 bounds independent cleanup attempts and rejects reused or stale claim identities', async db => {
    const f=await ready(db); await f.close(); const a=OAUTH;
    assert.equal((await oauthRpc(db,7,[a.attempt,a.cleanupClaim])).kind,'cleanup');
    assert.equal((await oauthRpc(db,8,[a.attempt,a.cleanupClaim,'transport'])).kind,'pending');
    assert.equal((await oauthRpc(db,7,[a.attempt,a.cleanupClaim])).kind,'denied');
    assert.equal((await oauthRpc(db,7,[a.attempt,a.issuance])).kind,'cleanup');
    assert.equal((await oauthRpc(db,8,[a.attempt,a.cleanupClaim,'completed'])).kind,'denied');
    assert.equal((await oauthRpc(db,8,[a.attempt,a.issuance,'timeout'])).kind,'pending');
    assert.equal((await oauthRpc(db,7,[a.attempt,a.close])).kind,'cleanup');
    assert.equal((await oauthRpc(db,8,[a.attempt,a.close,'transport'])).kind,'failed');
    assert.equal((await oauthRpc(db,7,[a.attempt,a.claim])).kind,'denied');
  }],
  ['O21 keeps cleanup credentials bound to orphan purpose and exact decrypt context', async db => {
    const f=await ready(db); assert.equal((await f.close({9:OAUTH.envelope})).kind,'denied');
    assert.equal((await f.close({10:null})).kind,'denied'); assert.equal((await f.close()).kind,'closed');
    const work=await oauthRpc(db,7,[OAUTH.attempt,OAUTH.cleanupClaim]);
    assert.equal(work.environment,'fixture'); assert.equal(work.attemptId,OAUTH.attempt);
    assert.equal(work.candidateId,OAUTH.candidate); assert.equal(work.authSubject,OAUTH.subject); assert.equal(work.upstreamSessionId,OAUTH.upstream);
  }],
  ['O22 rejects wrong browser, flow and claim and prevents commit before durable transmission intent', async db => {
    const f=oauthFlow(db); await f.issue(); await f.begin();
    assert.equal((await oauthRpc(db,2,['0'.repeat(64),OAUTH.flow,OAUTH.attempt,OAUTH.claim])).kind,'denied');
    assert.equal((await oauthRpc(db,2,[OAUTH.browserSecret,'0'.repeat(64),OAUTH.attempt,OAUTH.claim])).kind,'denied');
    assert.equal((await f.sent()).kind,'denied'); await f.claim(); assert.equal((await f.commit()).kind,'denied');
    await f.sent(); assert.equal((await f.commit({3:OAUTH.close})).kind,'denied');
    assert.equal((await f.commit({1:null})).kind,'denied'); assert.equal((await f.close({3:OAUTH.close})).kind,'denied');
    assert.equal((await f.commit()).kind,'committed');
  }],
  ['O23 cannot consume an expired proof or issue mutation authority for a revoked current session', async db => {
    const f=oauthFlow(db); await f.issue();
    await db.query("UPDATE jls_auth.csrf_proofs SET issued_at=statement_timestamp()-interval '16 minutes',expires_at=statement_timestamp()-interval '1 minute'");
    assert.equal((await f.begin()).kind,'denied');
    await db.query("UPDATE jls_auth.csrf_proofs SET issued_at=clock_timestamp(),expires_at=clock_timestamp()+interval '14 minutes'");
    await f.begin(); await f.claim(); await f.sent(); await f.commit();
    await db.query('UPDATE jls_auth.app_sessions SET revoked_at=clock_timestamp()');
    assert.equal((await f.issue({0:OAUTH.close,4:OAUTH.claim,5:'0'.repeat(64),6:'mutation',7:OAUTH.cookie,8:OAUTH.secret,9:null,10:0,11:0,12:OAUTH.epoch})).kind,'denied');
  }],
  ['O24 rechecks current owner, epoch and browser expiry before candidate commit', async db => {
    const f=await ready(db);
    await db.query('UPDATE jls_auth.owner_control SET active=false'); assert.equal((await f.commit()).kind,'denied');
    await db.query('UPDATE jls_auth.owner_control SET active=true');
    await db.query('INSERT INTO jls_auth.datasets(owner_id,dataset_epoch) VALUES ($1,$2)',[OAUTH.owner,OAUTH.close]);
    await db.query('UPDATE jls_auth.owner_control SET current_dataset_epoch=$1',[OAUTH.close]); assert.equal((await f.commit()).kind,'denied');
    await db.query('UPDATE jls_auth.owner_control SET current_dataset_epoch=$1',[OAUTH.epoch]);
    assert.equal((await f.commit({12:new Date(Date.now()+2*86_400_000)})).kind,'denied');
    await db.query("UPDATE jls_auth.browser_bindings SET created_at=clock_timestamp()-interval '2 days',expires_at=clock_timestamp()-interval '1 day'");
    assert.equal((await f.commit()).kind,'denied');
  }],
  ['O25 expires cleanup leases without granting stale completion and stops at deadline', async db => {
    const f=await ready(db); await f.close();
    await oauthRpc(db,7,[OAUTH.attempt,OAUTH.cleanupClaim]);
    await db.query("UPDATE jls_auth.candidate_cleanup_work SET lease_expires_at=clock_timestamp()-interval '1 second'");
    assert.equal((await oauthRpc(db,8,[OAUTH.attempt,OAUTH.cleanupClaim,'completed'])).kind,'denied');
    assert.equal((await oauthRpc(db,7,[OAUTH.attempt,OAUTH.close])).kind,'cleanup');
    await db.query("UPDATE jls_auth.candidate_cleanup_work SET created_at=statement_timestamp()-interval '2 hours',deadline_at=statement_timestamp()-interval '1 hour'");
    assert.equal((await oauthRpc(db,7,[OAUTH.attempt,OAUTH.claim])).kind,'failed');
    assert.equal((await scalar(db,'SELECT state FROM jls_auth.candidate_cleanup_work')).state,'failed');
  }],
  ['O26 terminalizes an exhausted final cleanup lease instead of stranding claimed work', async db => {
    const f=await ready(db); await f.close();
    await oauthRpc(db,7,[OAUTH.attempt,OAUTH.cleanupClaim]);
    await oauthRpc(db,8,[OAUTH.attempt,OAUTH.cleanupClaim,'transport']);
    await oauthRpc(db,7,[OAUTH.attempt,OAUTH.close]); await oauthRpc(db,8,[OAUTH.attempt,OAUTH.close,'transport']);
    await oauthRpc(db,7,[OAUTH.attempt,OAUTH.issuance]);
    await db.query("UPDATE jls_auth.candidate_cleanup_work SET lease_expires_at=clock_timestamp()-interval '1 second'");
    assert.equal((await oauthRpc(db,7,[OAUTH.attempt,OAUTH.claim])).kind,'failed');
    assert.deepEqual(await scalar(db,'SELECT state,error_category FROM jls_auth.candidate_cleanup_work'),{state:'failed',error_category:'attempts_exhausted'});
  }],
  ['O27 returns exact decrypt context for real encrypted PKCE and independent orphan credentials', async db => {
    const a=OAUTH; const f=oauthFlow(db); const key={keyId:'fixture',keyBytes:new Uint8Array(32).fill(7)};
    const pkceContext={environment:'fixture',bindingId:a.browser,attemptId:a.attempt};
    const pkce=encryptPkceVerifier(pkceContext,'A'.repeat(43),key);
    await f.issue(); await f.begin({6:pkce}); const claimed=await f.claim();
    assert.equal(decryptPkceVerifier(pkceContext,claimed.pkceEnvelope,key),'A'.repeat(43)); await f.sent();
    const context={environment:'fixture',attemptId:a.attempt,candidateId:a.candidate,authSubject:a.owner,upstreamSessionId:a.upstream};
    const tokens={accessToken:'fixture_access',refreshToken:'fixture_refresh'};
    const envelope=encryptOrphanTokens(context,tokens,key);
    assert.equal((await f.close({7:a.owner,9:envelope})).kind,'closed');
    const work=await oauthRpc(db,7,[a.attempt,a.cleanupClaim]);
    const storedContext={environment:work.environment,attemptId:work.attemptId,candidateId:work.candidateId,authSubject:work.authSubject,upstreamSessionId:work.upstreamSessionId};
    assert.deepEqual(decryptOrphanTokens(storedContext,work.tokenEnvelope,key),tokens);
    assert.throws(()=>decryptOrphanTokens({...storedContext,candidateId:a.close},work.tokenEnvelope,key),/decryption failed/);
    assert.equal((await scalar(db,'SELECT count(*)::int AS n FROM jls_auth.app_sessions')).n,0);
  }],
  ['O28 commits a real app-session token envelope and retains only encrypted credentials', async db => {
    const a=OAUTH; const f=await ready(db); const key={keyId:'fixture',keyBytes:new Uint8Array(32).fill(7)};
    const context={environment:'fixture',ownerId:a.owner,sessionId:a.session,authSubject:a.subject};
    const tokens={accessToken:'fixture_access',refreshToken:'fixture_refresh'};
    const envelope=encryptUpstreamTokens(context,tokens,key);
    const result=await f.commit({11:envelope}); assert.equal(result.kind,'committed');
    const stored=(await db.query('SELECT token_envelope FROM jls_auth.session_credentials WHERE session_id=$1',[a.session])).rows[0];
    assert.deepEqual(decryptUpstreamTokens(context,stored.token_envelope,key),tokens);
    assert.equal(JSON.stringify(result).includes('fixture_access'),false);
    assert.equal(JSON.stringify(result).includes(envelope),false);
  }],
  ['O29 skips orphan revocation when another live app session uses the upstream identity', async db => {
    const a=OAUTH; const f=await ready(db); await f.commit();
    const browserHash='1'.repeat(64); const flowHash='2'.repeat(64);
    await oauthRpc(db,0,[a.claim,a.fingerprint,a.close,browserHash,a.candidate,'0'.repeat(64),'login','absent',null,a.close,null,null,null]);
    await oauthRpc(db,1,[browserHash,'0'.repeat(64),a.close,'absent',a.close,flowHash,a.pkceEnvelope,a.fingerprint]);
    await oauthRpc(db,2,[browserHash,flowHash,a.close,a.claim]); await oauthRpc(db,3,[browserHash,flowHash,a.close,a.claim]);
    assert.equal((await oauthRpc(db,4,[browserHash,flowHash,a.close,a.claim,a.close,a.fingerprint,a.candidate,a.subject,a.upstream,a.close,'3'.repeat(64),a.envelope,new Date(Date.now()+3_600_000)])).kind,'denied');
    assert.equal((await oauthRpc(db,6,[browserHash,flowHash,a.close,a.claim,a.close,a.fingerprint,a.candidate,a.subject,a.upstream,a.orphanEnvelope,'fixture'])).kind,'closed');
    const work=await oauthRpc(db,7,[a.close,a.cleanupClaim]); assert.deepEqual(work,{kind:'skipped'});
    assert.deepEqual(await scalar(db,'SELECT state,error_category FROM jls_auth.candidate_cleanup_work'),{state:'skipped',error_category:'identity_in_use'});
    assert.equal((await scalar(db,'SELECT count(*)::int AS n FROM jls_auth.app_sessions WHERE revoked_at IS NULL')).n,1);
  }],
  ['O30 prevents adopting an identity retained by pending, in-flight or completed candidate cleanup', async db => {
    const a=OAUTH; const f=await ready(db); await f.close();
    await f.issue({0:a.close,4:a.claim,5:'0'.repeat(64),9:a.close});
    await f.begin({1:'0'.repeat(64),2:a.close,4:a.close,5:'1'.repeat(64)});
    await oauthRpc(db,2,[a.browserSecret,'1'.repeat(64),a.close,a.claim]); await oauthRpc(db,3,[a.browserSecret,'1'.repeat(64),a.close,a.claim]);
    const args=[a.browserSecret,'1'.repeat(64),a.close,a.claim,a.commit,a.fingerprint,a.candidate,a.subject,a.upstream,a.session,a.secret,a.envelope,new Date(Date.now()+3_600_000)];
    assert.equal((await oauthRpc(db,4,args)).kind,'denied');
    assert.equal((await oauthRpc(db,7,[a.attempt,a.cleanupClaim])).kind,'cleanup'); assert.equal((await oauthRpc(db,4,args)).kind,'denied');
    await oauthRpc(db,8,[a.attempt,a.cleanupClaim,'completed']); assert.equal((await oauthRpc(db,4,args)).kind,'denied');
    args[8]=a.proof; assert.equal((await oauthRpc(db,4,args)).kind,'committed');
  }],
  ['O31 cleanup claim rechecks live identity even if work was queued before a session appeared', async db => {
    const a=OAUTH; const f=await ready(db); await f.close();
    await db.query('INSERT INTO jls_auth.app_sessions(session_id,secret_hash,owner_id,auth_subject,upstream_session_id,browser_id,browser_generation) VALUES ($1,$2,$3,$4,$5,$6,0)',[a.session,a.secret,a.owner,a.subject,a.upstream,a.browser]);
    assert.deepEqual(await oauthRpc(db,7,[a.attempt,a.cleanupClaim]),{kind:'skipped'});
    assert.equal((await scalar(db,'SELECT state FROM jls_auth.candidate_cleanup_work')).state,'skipped');
  }],
];
