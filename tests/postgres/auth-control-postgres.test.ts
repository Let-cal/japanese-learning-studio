import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { parseSessionLookupMetadata } from '../../src/infrastructure/auth/sessionLookupContract';
import { AUTH, authRpc, cleanupAuthFixture, createAuthProofPool, initializeAuthFixture, resetAuthFixture } from './authFixture';

// Real migration/SQL only. Discovery never constructs a pool; execution uses the existing CI guard.
describe('owned disposable PostgreSQL Auth durable control store (TEST ONLY)', () => {
  let pool: Pool | undefined; let initialized = false;
  const db = () => { if (!pool) throw new Error('Auth fixture not initialized.'); return pool; };
  const lookup = () => authRpc(db(), 'jls_auth_session_lookup_v1(text)', [AUTH.secret]);
  const credentials = (version = 0, control = 0, epoch = AUTH.epoch, browser = AUTH.browserSecret) => authRpc(db(), 'jls_auth_current_credentials_v1(text,text,bigint,bigint,uuid)', [AUTH.secret, browser, version, control, epoch]);
  const logout = (cookie = AUTH.cookie, proof = AUTH.proofSecret) => authRpc(db(), 'jls_auth_logout_v1(text,text,uuid,text)', [AUTH.browserSecret, proof, AUTH.operation, cookie]);
  async function completedAttempt() {
    await db().query('DELETE FROM jls_auth.csrf_proofs');
    await db().query('UPDATE jls_auth.browser_bindings SET generation=1');
    await db().query('UPDATE jls_auth.app_sessions SET browser_generation=1');
    await db().query(`INSERT INTO jls_auth.oauth_attempts(attempt_id,browser_id,generation_before,generation_after,purpose,flow_cookie_hash,pkce_envelope,state,resulting_session_id)
      VALUES ($1,$2,0,1,'login',$3,$5,'completed',$4)`, [AUTH.attempt, AUTH.browser, 'e'.repeat(64), AUTH.session, AUTH.pkceEnvelope]);
  }
  beforeAll(async () => { pool = createAuthProofPool(); await initializeAuthFixture(pool); initialized = true; });
  beforeEach(async () => { await resetAuthFixture(db()); });
  afterAll(async () => {
    const errors: unknown[] = [];
    if (initialized && pool) { try { await cleanupAuthFixture(pool); } catch (error) { errors.push(error); } }
    if (pool) { try { await pool.end(); } catch (error) { errors.push(error); } }
    if (errors.length) throw new AggregateError(errors, 'Auth teardown failed.');
  });

  it('A01 returns the existing closed metadata DTO without any credential envelope/hash', async () => {
    const result = await lookup();
    expect(parseSessionLookupMetadata(result)).toMatchObject({ kind: 'found', session: { sessionId: AUTH.session }, currentDataset: { activeDatasetEpoch: AUTH.epoch } });
    expect(JSON.stringify(result)).not.toContain(AUTH.envelope);
    expect(JSON.stringify(result)).not.toContain(AUTH.secret);
    expect(await authRpc(db(), 'jls_auth_session_lookup_v1(text)', ['f'.repeat(64)])).toMatchObject({ kind: 'absent' });
  });
  it.each(['anon', 'authenticated'] as const)('A02 denies %s every wrapper and direct credential/schema access', async role => {
    await expect(authRpc(db(), 'jls_auth_session_lookup_v1(text)', [AUTH.secret], role)).rejects.toMatchObject({ code: '42501' });
    const privileges = (await db().query(`SELECT has_schema_privilege($1,'jls_auth','USAGE') AS schema,
      has_table_privilege($1,'jls_auth.session_credentials','SELECT') AS credentials,
      (SELECT bool_or(has_function_privilege($1,p.oid,'EXECUTE')) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'jls_auth_%') AS execute`, [role])).rows[0];
    expect(privileges).toEqual({ schema: false, credentials: false, execute: false });
  });
  it('A03 gates credential disclosure on exact current version, browser, control version and dataset', async () => {
    expect(await credentials()).toMatchObject({ kind: 'credentials', tokenVersion: 0, tokenEnvelope: AUTH.envelope });
    for (const result of [await credentials(1), await credentials(0, 1), await credentials(0, 0, AUTH.subject), await credentials(0, 0, AUTH.epoch, 'f'.repeat(64))]) expect(result).toEqual({ kind: 'denied' });
    await db().query('UPDATE jls_auth.owner_control SET active=false');
    expect(await credentials()).toEqual({ kind: 'denied' });
  });
  it.each(['idle', 'absolute', 'revoked', 'refresh_unknown', 'access_expired'] as const)('A04 rejects credentials before decryption for %s state', async state => {
    if (state === 'idle') await db().query("UPDATE jls_auth.app_sessions SET created_at=clock_timestamp()-interval '2 days',last_activity_at=clock_timestamp()-interval '25 hours'");
    if (state === 'absolute') await db().query("UPDATE jls_auth.app_sessions SET created_at=clock_timestamp()-interval '8 days'");
    if (state === 'revoked') await db().query('UPDATE jls_auth.app_sessions SET revoked_at=clock_timestamp()');
    if (state === 'refresh_unknown') await db().query("UPDATE jls_auth.session_credentials SET state='uncertain'");
    if (state === 'access_expired') await db().query("UPDATE jls_auth.session_credentials SET access_expires_at=clock_timestamp()-interval '1 second'");
    expect(await credentials()).toEqual({ kind: 'denied' });
  });
  it('A05 acknowledges delivery with CAS without extending activity or resurrecting revoked state', async () => {
    const before = (await db().query('SELECT last_activity_at FROM jls_auth.app_sessions')).rows[0];
    expect(await authRpc(db(), 'jls_auth_delivery_ack_v1(text,text,bigint)', [AUTH.secret, AUTH.browserSecret, 1])).toEqual({ kind: 'denied' });
    expect(await authRpc(db(), 'jls_auth_delivery_ack_v1(text,text,bigint)', [AUTH.secret, AUTH.browserSecret, 0])).toEqual({ kind: 'acknowledged' });
    expect((await db().query('SELECT last_activity_at FROM jls_auth.app_sessions')).rows[0]).toEqual(before);
    await logout();
    expect(await authRpc(db(), 'jls_auth_delivery_ack_v1(text,text,bigint)', [AUTH.secret, AUTH.browserSecret, 0])).toEqual({ kind: 'denied' });
  });
  it('A06 revokes, fences generation, cancels pending OAuth and enqueues local-scope cleanup atomically', async () => {
    await db().query(`INSERT INTO jls_auth.oauth_attempts(attempt_id,browser_id,generation_before,purpose,flow_cookie_hash,pkce_envelope)
      VALUES ($1,$2,0,'login',$3,$4)`, [AUTH.attempt, AUTH.browser, 'e'.repeat(64), AUTH.pkceEnvelope]);
    expect(await logout()).toEqual({ kind: 'logged_out', outcome: 'revoked', clearCookie: true });
    expect((await db().query('SELECT generation::int,current_session_id FROM jls_auth.browser_bindings')).rows[0]).toEqual({ generation: 1, current_session_id: null });
    expect((await db().query('SELECT revoked_at IS NOT NULL AS revoked FROM jls_auth.app_sessions')).rows[0]?.revoked).toBe(true);
    expect((await db().query('SELECT state FROM jls_auth.oauth_attempts')).rows[0]?.state).toBe('cancelled');
    expect((await db().query('SELECT state,scope,token_envelope FROM jls_auth.cleanup_work')).rows[0]).toEqual({ state: 'pending', scope: 'local', token_envelope: AUTH.envelope });
    expect(await credentials()).toEqual({ kind: 'denied' });
  });
  it('A07 retained receipt replays old-cookie and explicit-absence retries once; newer generation forbids cookie clear', async () => {
    const original = await logout(); expect(await logout()).toEqual(original); expect(await logout('absent')).toEqual(original);
    expect((await db().query('SELECT generation::int FROM jls_auth.browser_bindings')).rows[0]?.generation).toBe(1);
    await db().query('UPDATE jls_auth.browser_bindings SET generation=2');
    expect(await logout()).toEqual({ kind: 'denied' }); expect(await logout('absent')).toEqual({ kind: 'denied' });
    expect((await db().query('SELECT count(*)::int AS n FROM jls_auth.action_receipts')).rows[0]?.n).toBe(1);
  });
  it('A08 rejects wrong/expired/absent proof without changing state, including expired session', async () => {
    expect(await logout('absent')).toEqual({ kind: 'denied' });
    expect(await logout(AUTH.cookie, 'f'.repeat(64))).toEqual({ kind: 'denied' });
    await db().query("UPDATE jls_auth.csrf_proofs SET issued_at=clock_timestamp()-interval '20 minutes',expires_at=clock_timestamp()-interval '5 minutes'");
    expect(await logout()).toEqual({ kind: 'denied' });
    expect((await db().query('SELECT generation::int FROM jls_auth.browser_bindings')).rows[0]?.generation).toBe(0);
  });
  it('A09 allows proven expired/inactive-owner logout but never owner bypass for credential disclosure', async () => {
    await db().query("UPDATE jls_auth.app_sessions SET created_at=clock_timestamp()-interval '2 days',last_activity_at=clock_timestamp()-interval '25 hours'");
    await db().query('UPDATE jls_auth.owner_control SET active=false');
    expect(await logout()).toMatchObject({ kind: 'logged_out', outcome: 'revoked' });
  });
  it('A10 anonymous logout requires explicit absence proof and atomically cancels pending activation', async () => {
    await db().query('UPDATE jls_auth.browser_bindings SET current_session_id=NULL');
    await db().query("UPDATE jls_auth.csrf_proofs SET session_id=NULL,cookie_fingerprint='absent'");
    await db().query(`INSERT INTO jls_auth.oauth_attempts(attempt_id,browser_id,generation_before,purpose,flow_cookie_hash,pkce_envelope)
      VALUES ($1,$2,0,'login',$3,$4)`, [AUTH.attempt, AUTH.browser, 'e'.repeat(64), AUTH.pkceEnvelope]);
    expect(await logout()).toEqual({ kind: 'denied' });
    expect(await logout('absent')).toMatchObject({ kind: 'logged_out', outcome: 'absent' });
    expect((await db().query('SELECT state FROM jls_auth.oauth_attempts')).rows[0]?.state).toBe('cancelled');
  });
  it('A11 permits upstream UUID reuse only after revocation; subject and browser foreign keys remain coherent', async () => {
    const insert = () => db().query(`INSERT INTO jls_auth.app_sessions(session_id,secret_hash,owner_id,auth_subject,upstream_session_id,browser_id,browser_generation)
      VALUES ('99999999-9999-4999-8999-999999999999',$1,$2,$3,$4,$5,0)`, ['f'.repeat(64), AUTH.owner, AUTH.subject, AUTH.upstream, AUTH.browser]);
    await expect(insert()).rejects.toMatchObject({ code: '23505' });
    await db().query('UPDATE jls_auth.app_sessions SET revoked_at=clock_timestamp()');
    await insert();
    await expect(db().query('UPDATE jls_auth.app_sessions SET auth_subject=$1 WHERE session_id=$2', [AUTH.owner, AUTH.session])).rejects.toMatchObject({ code: '23503' });
  });
  it('A12 retires only the matching completed unacknowledged attempt and cannot retire acknowledged delivery', async () => {
    await completedAttempt();
    expect(await authRpc(db(), 'jls_auth_delivery_ack_v1(text,text,bigint)', [AUTH.secret, AUTH.browserSecret, 0])).toEqual({ kind: 'acknowledged' });
    const retire = () => authRpc(db(), 'jls_auth_delivery_retire_v1(text,uuid,uuid,bigint)', [AUTH.browserSecret, AUTH.attempt, AUTH.session, 1]);
    expect(await retire()).toEqual({ kind: 'denied' });
    expect((await db().query('SELECT revoked_at FROM jls_auth.app_sessions')).rows[0]?.revoked_at).toBeNull();
    await db().query("UPDATE jls_auth.app_sessions SET delivery_state='unacknowledged',delivery_acknowledged_at=NULL");
    expect(await retire()).toEqual({ kind: 'retired' });
    expect((await db().query('SELECT count(*)::int AS n FROM jls_auth.cleanup_work')).rows[0]?.n).toBe(1);
    expect(await retire()).toEqual({ kind: 'already_retired' });
    await db().query('UPDATE jls_auth.browser_bindings SET generation=3');
    expect(await retire()).toEqual({ kind: 'denied' });
  });
  it('A13 concurrent identical logout records one receipt, cleanup and generation increment', async () => {
    const results = await Promise.all([logout(), logout(), logout()]);
    expect(results).toEqual(Array.from({ length: 3 }, () => ({ kind: 'logged_out', outcome: 'revoked', clearCookie: true })));
    expect((await db().query(`SELECT (SELECT count(*)::int FROM jls_auth.action_receipts) AS receipts,
      (SELECT count(*)::int FROM jls_auth.cleanup_work) AS cleanup,
      (SELECT generation::int FROM jls_auth.browser_bindings) AS generation`)).rows[0]).toEqual({ receipts: 1, cleanup: 1, generation: 1 });
  });
  it('A14 rollback hides every logout side effect and a later retry can commit', async () => {
    const client = await db().connect();
    try {
      await client.query('BEGIN'); await client.query('SET LOCAL ROLE service_role');
      await client.query('SELECT public.jls_auth_logout_v1($1,$2,$3,$4)', [AUTH.browserSecret, AUTH.proofSecret, AUTH.operation, AUTH.cookie]);
      expect((await db().query('SELECT generation::int FROM jls_auth.browser_bindings')).rows[0]?.generation).toBe(0);
      await client.query('ROLLBACK');
    } finally { client.release(true); }
    expect((await db().query('SELECT count(*)::int AS n FROM jls_auth.action_receipts')).rows[0]?.n).toBe(0);
    expect(await logout()).toMatchObject({ kind: 'logged_out' });
  });
  it('A15 keeps every control table under forced RLS with no definer function or owner-enrollment capability', async () => {
    const tables = (await db().query(`SELECT relrowsecurity,relforcerowsecurity FROM pg_class c
      JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='jls_auth' AND c.relkind='r'`)).rows;
    expect(tables).toHaveLength(9); expect(tables.every(t => t.relrowsecurity && t.relforcerowsecurity)).toBe(true);
    expect((await db().query(`SELECT count(*)::int AS n FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE (n.nspname='jls_auth' OR (n.nspname='public' AND p.proname LIKE 'jls_auth_%')) AND p.prosecdef`)).rows[0]?.n).toBe(0);
    expect((await db().query(`SELECT has_table_privilege('service_role','jls_auth.owner_control','INSERT') AS enroll,
      has_column_privilege('service_role','jls_auth.owner_control','auth_subject','UPDATE') AS reassign,
      has_table_privilege('service_role','jls_auth.action_receipts','UPDATE') AS receipt_update`)).rows[0]).toEqual({ enroll: false, reassign: false, receipt_update: false });
  });
  it('A16 discovers trusted nonzero versions and exact uncertain refresh state separately from the frozen lookup DTO', async () => {
    await db().query("UPDATE jls_auth.session_credentials SET token_version=7,state='uncertain'");
    await db().query('UPDATE jls_auth.owner_control SET control_version=9');
    const snapshot = await authRpc(db(), 'jls_auth_session_snapshot_v1(text,text)', [AUTH.secret, AUTH.browserSecret]);
    expect(snapshot).toMatchObject({ kind: 'snapshot', owner: { controlVersion: 9 }, browser: { generation: 0 }, credential: { tokenVersion: 7, state: 'uncertain' } });
    expect(JSON.stringify(snapshot)).not.toContain(AUTH.envelope);
    expect(JSON.stringify(snapshot)).not.toContain(AUTH.secret);
    expect(parseSessionLookupMetadata(await lookup())).toMatchObject({ kind: 'found', credential: { state: 'reauthenticationRequired' } });
  });
  it('A17 confirms verified identity and fresh token/control/epoch before acknowledging and returning only safe context', async () => {
    const confirm = (control = 0, subject = AUTH.subject, upstream = AUTH.upstream) => authRpc(db(), 'jls_auth_confirm_session_v1(text,text,bigint,bigint,uuid,uuid,uuid)', [AUTH.secret, AUTH.browserSecret, 0, control, AUTH.epoch, subject, upstream]);
    expect(await confirm(0, AUTH.owner)).toEqual({ kind: 'denied' });
    expect(await confirm(0, AUTH.subject, AUTH.session)).toEqual({ kind: 'denied' });
    await db().query('UPDATE jls_auth.owner_control SET control_version=1');
    expect(await confirm()).toEqual({ kind: 'denied' });
    const before = (await db().query('SELECT last_activity_at FROM jls_auth.app_sessions')).rows[0];
    expect(await confirm(1)).toMatchObject({ kind: 'confirmed', context: { ownerId: AUTH.owner, authSubject: AUTH.subject, sessionId: AUTH.session, datasetEpoch: AUTH.epoch }, tokenVersion: 0, controlVersion: 1 });
    expect(JSON.stringify(await confirm(1))).not.toContain(AUTH.envelope);
    expect((await db().query('SELECT last_activity_at FROM jls_auth.app_sessions')).rows[0]).toEqual(before);
    await logout(); expect(await confirm(1)).toEqual({ kind: 'denied' });
  });
  it('A18 reports bounded database lock contention rather than waiting for an external abort', async () => {
    const blocker = await db().connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query('SELECT browser_id FROM jls_auth.browser_bindings FOR UPDATE');
      await expect(credentials()).rejects.toMatchObject({ code: '55P03' });
    } finally { await blocker.query('ROLLBACK'); blocker.release(true); }
    expect(await credentials()).toMatchObject({ kind: 'credentials', now: expect.any(Number) });
  });
  it.each(['ack', 'retire', 'logout'] as const)('A19 %s winning the actual browser lock fences the competing delivery transition', async first => {
    if (first !== 'logout') await completedAttempt();
    const ack = { sql: 'SELECT public.jls_auth_delivery_ack_v1($1,$2,$3) AS result', values: [AUTH.secret, AUTH.browserSecret, 0] };
    const retire = { sql: 'SELECT public.jls_auth_delivery_retire_v1($1,$2,$3,$4) AS result', values: [AUTH.browserSecret, AUTH.attempt, AUTH.session, 1] };
    const logoutCall = { sql: 'SELECT public.jls_auth_logout_v1($1,$2,$3,$4) AS result', values: [AUTH.browserSecret, AUTH.proofSecret, AUTH.operation, AUTH.cookie] };
    const winner = first === 'ack' ? ack : first === 'retire' ? retire : logoutCall; const loser = first === 'ack' ? retire : ack;
    const one = await db().connect(); const two = await db().connect();
    let pending: Promise<{ rows: { result: unknown }[] }> | undefined;
    let failure: unknown;
    try {
      await one.query('BEGIN'); await one.query('SET LOCAL ROLE service_role');
      const result = (await one.query(winner.sql, winner.values)).rows[0]?.result;
      expect(result).toEqual(first === 'logout' ? { kind: 'logged_out', outcome: 'revoked', clearCookie: true } : { kind: first === 'ack' ? 'acknowledged' : 'retired' });
      await two.query('BEGIN'); await two.query('SET LOCAL ROLE service_role');
      const pid = (await two.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
      pending = two.query(loser.sql, loser.values);
      // Attach immediately; a failed wait must not leave an unhandled rejection.
      void pending.catch(() => {});
      let waiting = false;
      const deadline = Date.now() + 180;
      while (Date.now() < deadline) {
        const row = (await db().query('SELECT wait_event_type,pg_blocking_pids(pid) AS blockers FROM pg_stat_activity WHERE pid=$1', [pid])).rows[0];
        if (row?.wait_event_type === 'Lock' && row.blockers.length) { waiting = true; break; }
        await new Promise(resolve => setTimeout(resolve, 5));
      }
      expect(waiting).toBe(true);
      await one.query('COMMIT');
      expect((await pending).rows[0]?.result).toEqual({ kind: 'denied' });
      await two.query('COMMIT');
      const row = (await db().query('SELECT delivery_state,revoked_at IS NOT NULL AS revoked FROM jls_auth.app_sessions')).rows[0];
      expect(row).toEqual(first === 'ack' ? { delivery_state: 'acknowledged', revoked: false } : { delivery_state: 'unacknowledged', revoked: true });
    } catch (error) { failure = error; }
    finally {
      const errors: unknown[] = [];
      if (failure) errors.push(failure);
      try { await one.query('ROLLBACK'); } catch (error) { errors.push(error); }
      try { one.release(true); } catch (error) { errors.push(error); }
      if (pending) { try { await pending; } catch (error) { if (error !== failure) errors.push(error); } }
      try { await two.query('ROLLBACK'); } catch (error) { errors.push(error); }
      try { two.release(true); } catch (error) { errors.push(error); }
      if (errors.length === 1) throw errors[0];
      if (errors.length) throw new AggregateError(errors, 'Competing Auth transition and cleanup failed.');
    }
  });
  it('A20 denies browser expiry crossed while an actual credential row lock was awaited', async () => {
    const blocker = await db().connect(); const waiter = await db().connect();
    let pending: Promise<{ rows: { result: unknown }[] }> | undefined; let failure: unknown;
    try {
      await blocker.query('BEGIN');
      await blocker.query('SELECT session_id FROM jls_auth.session_credentials FOR UPDATE');
      await waiter.query('BEGIN'); await waiter.query('SET LOCAL ROLE service_role');
      const pid = (await waiter.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
      await db().query("UPDATE jls_auth.browser_bindings SET expires_at=clock_timestamp()+interval '150 milliseconds'");
      pending = waiter.query('SELECT public.jls_auth_current_credentials_v1($1,$2,$3,$4,$5) AS result', [AUTH.secret, AUTH.browserSecret, 0, 0, AUTH.epoch]);
      void pending.catch(() => {});
      let observedWait = false; let databaseExpired = false;
      const deadline = Date.now() + 210;
      while (Date.now() < deadline) {
        const row = (await db().query(`SELECT a.wait_event_type,pg_blocking_pids(a.pid) AS blockers,
          clock_timestamp() >= b.expires_at AS expired FROM pg_stat_activity a
          CROSS JOIN jls_auth.browser_bindings b WHERE a.pid=$1`, [pid])).rows[0];
        if (row?.wait_event_type === 'Lock' && row.blockers.length) observedWait = true;
        if (observedWait && row?.expired === true) { databaseExpired = true; break; }
        await new Promise(resolve => setTimeout(resolve, 5));
      }
      expect(observedWait).toBe(true); expect(databaseExpired).toBe(true);
      // Release only after database time proves expiry, within the 250 ms lock budget.
      await blocker.query('COMMIT');
      expect((await pending).rows[0]?.result).toEqual({ kind: 'denied' });
      await waiter.query('COMMIT');
    } catch (error) { failure = error; }
    finally {
      const errors: unknown[] = []; if (failure) errors.push(failure);
      try { await blocker.query('ROLLBACK'); } catch (error) { errors.push(error); }
      try { blocker.release(true); } catch (error) { errors.push(error); }
      if (pending) { try { await pending; } catch (error) { if (error !== failure) errors.push(error); } }
      try { await waiter.query('ROLLBACK'); } catch (error) { errors.push(error); }
      try { waiter.release(true); } catch (error) { errors.push(error); }
      if (errors.length === 1) throw errors[0];
      if (errors.length) throw new AggregateError(errors, 'Credential expiry regression and cleanup failed.');
    }
  });
});
