import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { authConfirmCases, confirmSession, prepareConfirm } from './authConfirmCases';
import {
  cleanupRefreshFixture, createRefreshProofPool, initializeRefreshFixture, REFRESH,
  refreshCases, refreshFlow, resetRefreshFixture,
} from './refreshFixture';

describe('owned disposable PostgreSQL refresh and cleanup (TEST ONLY)', () => {
  let pool: Pool | undefined;
  let initialized = false;
  const db = () => {
    if (!pool) throw new Error('Refresh fixture not initialized.');
    return pool;
  };
  beforeAll(async () => {
    pool = createRefreshProofPool();
    await initializeRefreshFixture(pool);
    initialized = true;
  });
  beforeEach(async () => { await resetRefreshFixture(db()); });
  afterAll(async () => {
    const errors: unknown[] = [];
    if (pool && initialized) {
      try { await cleanupRefreshFixture(pool); }
      catch (error) { errors.push(error); }
    }
    if (pool) {
      try { await pool.end(); }
      catch (error) { errors.push(error); }
    }
    if (errors.length) throw new AggregateError(errors, 'Refresh fixture teardown failed.');
  });

  for (const [name, run] of refreshCases) it(name, async () => { await run(db()); });
  for (const [name, run] of authConfirmCases) it(name, async () => { await run(db()); });

  it('N01 concurrent refresh claims expose the original envelope to exactly one holder', async () => {
    const flow = refreshFlow(db());
    const results = await Promise.all([flow.claim(), flow.claim({ 2: REFRESH.nextAttempt })]);
    expect(results.map(result => result.kind).sort()).toEqual(['busy', 'claimed']);
    const [winner] = results.filter(result => result.kind === 'claimed');
    expect(winner?.tokenEnvelope).toBe(REFRESH.envelope);
    expect(results.filter(result => 'tokenEnvelope' in result)).toHaveLength(1);
    expect((await flow.mark({ 2: winner?.attemptId })).kind).toBe('transmit');
  });

  it('N02 a mark versus pre-send release race has exactly one winning transition', async () => {
    const flow = refreshFlow(db());
    await flow.claim();
    const [mark, close] = await Promise.all([flow.mark(), flow.close({ 15: 'pre_send' })]);
    expect([['transmit', 'denied'], ['denied', 'released']]).toContainEqual([mark.kind, close.kind]);
    const { rows } = await db().query('SELECT state,transmission_intent_at IS NOT NULL AS sent FROM jls_auth.refresh_attempts');
    expect(rows).toEqual(mark.kind === 'transmit'
      ? [{ state: 'sent', sent: true }] : [{ state: 'released', sent: false }]);
  });

  it.each(['refresh', 'confirm'] as const)('N03 %s rechecks idle expiry after waiting for the shared identity lock', async operation => {
    const flow = refreshFlow(db());
    if (operation === 'refresh') { await flow.claim(); await flow.mark(); }
    else await prepareConfirm(db());
    const blocker = await db().connect();
    const waiter = await db().connect();
    const errors: unknown[] = [];
    let pending: Promise<Record<string, unknown>> | undefined;
    try {
      await blocker.query('BEGIN');
      const blockerPid = (await blocker.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
      await blocker.query("SELECT pg_advisory_xact_lock(hashtextextended('jls-auth-upstream-cleanup-v1:'||$1::uuid::text,0))", [REFRESH.upstream]);
      const waiterPid = (await waiter.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
      await db().query(`UPDATE jls_auth.app_sessions SET created_at=statement_timestamp()-interval '2 days',
        last_activity_at=statement_timestamp()-interval '24 hours'+interval '140 milliseconds'`);
      pending = operation === 'refresh' ? refreshFlow(waiter).finish() : confirmSession(waiter);
      void pending.catch(() => {});
      let observedWait = false;
      let expired = false;
      const deadline = Date.now() + 205;
      while (Date.now() < deadline) {
        const row = (await db().query(`SELECT $2::int=ANY(pg_blocking_pids($1)) AS waiting,
          last_activity_at<=clock_timestamp()-interval '24 hours' AS expired FROM jls_auth.app_sessions`,
        [waiterPid, blockerPid])).rows[0];
        if (row?.waiting && !row.expired) observedWait = true;
        if (observedWait && row?.expired) { expired = true; break; }
        await new Promise(resolve => setTimeout(resolve, 5));
      }
      expect(observedWait).toBe(true);
      expect(expired).toBe(true);
      await blocker.query('COMMIT');
      expect(await pending).toEqual({ kind: 'denied' });
      if (operation === 'refresh') expect(await flow.resolve()).toEqual({ kind: 'not_committed' });
      else expect((await db().query('SELECT delivery_state,delivery_acknowledged_at FROM jls_auth.app_sessions')).rows)
        .toEqual([{ delivery_state: 'unacknowledged', delivery_acknowledged_at: null }]);
    } catch (error) { errors.push(error); }
    finally {
      try { await blocker.query('ROLLBACK'); } catch (error) { errors.push(error); }
      try { blocker.release(true); } catch (error) { errors.push(error); }
      if (pending) {
        try { await pending; }
        catch (error) { if (!errors.includes(error)) errors.push(error); }
      }
      try { waiter.release(true); } catch (error) { errors.push(error); }
      if (errors.length) throw new AggregateError(errors, `${operation} expiry contention proof failed.`);
    }
  });

  it('N04 logout and late arrival serialize to one cleanup custody record', async () => {
    const flow = refreshFlow(db());
    await flow.claim(); await flow.mark();
    const [logout, late] = await Promise.all([flow.logout(), flow.late()]);
    expect(logout.kind).toBe('logged_out');
    expect(late.kind).toBe('late_pair_retained');
    expect((await flow.cleanupClaim()).tokenEnvelope).toBe(REFRESH.latePair);
    expect((await db().query('SELECT count(*)::int AS count FROM jls_auth.cleanup_work')).rows).toEqual([{ count: 1 }]);
  });

  it('N05 old completion cannot settle a concurrently attached new revision', async () => {
    const flow = refreshFlow(db());
    await flow.claim(); await flow.mark(); await flow.logout();
    await flow.cleanupClaim();
    const [old, late] = await Promise.all([flow.cleanupComplete(), flow.late()]);
    expect(['completed', 'denied']).toContain(old.kind);
    expect(late.kind).toBe('late_pair_retained');
    const current = await flow.cleanupClaim(REFRESH.nextCleanup);
    expect(current).toMatchObject({ kind: 'cleanup', tokenEnvelope: REFRESH.latePair, revision: 1 });
    expect(await flow.cleanupComplete(REFRESH.cleanup, 0)).toEqual({ kind: 'denied' });
    expect(await flow.cleanupComplete(REFRESH.nextCleanup, 1)).toEqual({ kind: 'completed' });
  });
});
