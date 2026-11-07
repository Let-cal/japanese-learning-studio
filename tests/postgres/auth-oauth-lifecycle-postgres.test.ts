import { afterAll, beforeAll, beforeEach, describe, it, expect } from 'vitest';
import type { Pool } from 'pg';
import { createAuthProofPool, initializeOAuthFixture, resetOAuthFixture, cleanupOAuthFixture, oauthCases, oauthFlow, oauthRpc, OAUTH } from './oauthLifecycleFixture';

describe('owned disposable PostgreSQL OAuth lifecycle (TEST ONLY)', () => {
  let pool: Pool | undefined; let initialized=false;
  const db=()=>{if(!pool) throw new Error('OAuth fixture not initialized.'); return pool;};
  beforeAll(async()=>{pool=createAuthProofPool(); await initializeOAuthFixture(pool); initialized=true;});
  beforeEach(async()=>{await resetOAuthFixture(db());});
  afterAll(async()=>{
    const errors: unknown[]=[];
    if(initialized && pool) {try {await cleanupOAuthFixture(pool);} catch(error){errors.push(error);}}
    if(pool) {try {await pool.end();} catch(error){errors.push(error);}}
    if(errors.length) throw new AggregateError(errors,'OAuth fixture teardown failed.');
  });
  for(const [name,run] of oauthCases) it(name,async()=>{await run(db());});
  it('N01 competing callback claims permit exactly one worker before transmission',async()=>{
    const flow=oauthFlow(db()); await flow.issue(); await flow.begin();
    const results=await Promise.all([flow.claim(),flow.claim(OAUTH.close)]);
    expect(results.map(result=>result.kind).sort()).toEqual(['claimed','restart_required']);
  });
  it.each(['browser','owner','session'] as const)('N02 bounds callback waiting for a held %s row to 250ms',async lock=>{
    const flow=oauthFlow(db()); await flow.issue(); await flow.begin();
    const blocker=await db().connect();
    const errors:unknown[]=[];
    try {
      await blocker.query('BEGIN');
      if(lock==='browser') await blocker.query('SELECT browser_id FROM jls_auth.browser_bindings WHERE browser_id=$1 FOR UPDATE',[OAUTH.browser]);
      if(lock==='owner') await blocker.query('SELECT owner_id FROM jls_auth.owner_control WHERE owner_id=$1 FOR UPDATE',[OAUTH.owner]);
      if(lock==='session') {
        // First create a legitimate prior session, then a fresh bound attempt.
        await blocker.query('ROLLBACK');
        await flow.claim(); await flow.sent(); await flow.commit();
        await flow.issue({0:OAUTH.close,4:OAUTH.claim,5:'0'.repeat(64),7:OAUTH.cookie,8:OAUTH.secret,9:OAUTH.close});
        await flow.begin({1:'0'.repeat(64),2:OAUTH.close,3:OAUTH.cookie,4:OAUTH.close,5:'1'.repeat(64)});
        await blocker.query('BEGIN');
        await blocker.query('SELECT session_id FROM jls_auth.app_sessions WHERE session_id=$1 FOR UPDATE',[OAUTH.session]);
      }
      const request=lock==='session' ? oauthRpc(db(),2,[OAUTH.browserSecret,'1'.repeat(64),OAUTH.close,OAUTH.candidate]) : flow.claim();
      await expect(request).rejects.toMatchObject({code:'55P03'});
    } catch(error) {errors.push(error);}
    finally {
      try{await blocker.query('ROLLBACK');}catch(error){errors.push(error);}
      try{blocker.release(true);}catch(error){errors.push(error);}
      if(errors.length===1) throw errors[0];
      if(errors.length) throw new AggregateError(errors,'Callback row contention and cleanup failed.');
    }
  });
  it('N03 rechecks browser expiry after waiting on the mutation-proof credential lock',async()=>{
    const flow=oauthFlow(db()); await flow.issue(); await flow.begin(); await flow.claim(); await flow.sent(); await flow.commit();
    const blocker=await db().connect(); const waiter=await db().connect();
    let pending: Promise<{rows:{result:unknown}[]}>|undefined; let failure:unknown;
    try {
      await blocker.query('BEGIN'); await blocker.query('SELECT session_id FROM jls_auth.session_credentials FOR UPDATE');
      await waiter.query('BEGIN'); await waiter.query('SET LOCAL ROLE service_role');
      const pid=(await waiter.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
      await db().query("UPDATE jls_auth.browser_bindings SET expires_at=clock_timestamp()+interval '150 milliseconds'");
      pending=waiter.query('SELECT public.jls_auth_issue_proof_v1($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) AS result',
        [OAUTH.close,OAUTH.fingerprint,OAUTH.browser,OAUTH.browserSecret,OAUTH.claim,'0'.repeat(64),'mutation',OAUTH.cookie,OAUTH.secret,null,0,0,OAUTH.epoch]);
      void pending.catch(()=>{});
      let waiting=false; let expired=false; const deadline=Date.now()+210;
      while(Date.now()<deadline) {
        const row=(await db().query(`SELECT a.wait_event_type,pg_blocking_pids(a.pid) AS blockers,
          clock_timestamp()>=b.expires_at AS expired FROM pg_stat_activity a CROSS JOIN jls_auth.browser_bindings b WHERE a.pid=$1`,[pid])).rows[0];
        if(row?.wait_event_type==='Lock' && row.blockers.length) waiting=true;
        if(waiting && row?.expired===true) {expired=true; break;}
        await new Promise(resolve=>setTimeout(resolve,5));
      }
      expect(waiting).toBe(true); expect(expired).toBe(true);
      await blocker.query('COMMIT'); expect((await pending).rows[0]?.result).toEqual({kind:'denied'}); await waiter.query('COMMIT');
    } catch(error) {failure=error;}
    finally {
      const errors:unknown[]=[]; if(failure) errors.push(failure);
      try{await blocker.query('ROLLBACK');}catch(error){errors.push(error);} try{blocker.release(true);}catch(error){errors.push(error);}
      if(pending) {try{await pending;}catch(error){if(error!==failure) errors.push(error);}}
      try{await waiter.query('ROLLBACK');}catch(error){errors.push(error);} try{waiter.release(true);}catch(error){errors.push(error);}
      if(errors.length===1) throw errors[0]; if(errors.length) throw new AggregateError(errors,'Mutation proof expiry regression cleanup failed.');
    }
  });
  it('N04 serializes candidate commit with the shared upstream cleanup identity lock',async()=>{
    const flow=oauthFlow(db()); await flow.issue(); await flow.begin(); await flow.claim(); await flow.sent();
    const blocker=await db().connect();
    const errors:unknown[]=[];
    try {
      await blocker.query('BEGIN');
      await blocker.query("SELECT pg_advisory_xact_lock(hashtextextended('jls-auth-upstream-cleanup-v1:'||$1::uuid::text,0))",[OAUTH.upstream]);
      await expect(flow.commit()).rejects.toMatchObject({code:'55P03'});
      expect((await db().query('SELECT count(*)::int AS n FROM jls_auth.app_sessions')).rows[0].n).toBe(0);
    } catch(error) {errors.push(error);}
    finally {
      try{await blocker.query('ROLLBACK');}catch(error){errors.push(error);}
      try{blocker.release(true);}catch(error){errors.push(error);}
      if(errors.length===1) throw errors[0];
      if(errors.length) throw new AggregateError(errors,'Upstream identity contention and cleanup failed.');
    }
    expect((await flow.commit()).kind).toBe('committed');
  });
});
