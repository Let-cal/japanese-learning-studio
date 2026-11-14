import type { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { oauthFlow, oauthRpc, OAUTH, type OAuthDatabase } from './oauthLifecycleFixture';
import { ageDelivery, beginOAuth, issueRecovery, oauthRecoveryCases, recoverOAuth } from './oauthRecoveryCases';
import {
  cleanupRefreshFixture, createRefreshProofPool, initializeRefreshFixture, resetRefreshFixture,
} from './refreshFixture';

describe('owned disposable PostgreSQL OAuth recovery (TEST ONLY)', () => {
  let pool: Pool | undefined;
  let initialized = false;
  const db = () => {
    if (!pool) throw new Error('OAuth recovery fixture not initialized.');
    return pool;
  };
  async function onClient<T>(run: (client: OAuthDatabase) => Promise<T>) {
    const client = await db().connect();
    try { return await run({ query: (sql, values) => client.query(sql, values) }); }
    finally { client.release(true); }
  }

  beforeAll(async () => {
    pool = createRefreshProofPool();
    await initializeRefreshFixture(pool, 'recovery');
    initialized = true;
  });
  beforeEach(async () => { await resetRefreshFixture(db(), false); });
  afterAll(async () => {
    if (!pool) return;
    const errors: unknown[] = [];
    if (initialized) {
      try { await cleanupRefreshFixture(pool, 'recovery'); }
      catch (error) { errors.push(error); }
    }
    try { await pool.end(); }
    catch (error) { errors.push(error); }
    if (errors.length) throw new AggregateError(errors, 'OAuth recovery fixture teardown failed.');
  });

  for (const [name, run] of oauthRecoveryCases) it(name, async () => { await onClient(run); });

  it('serializes pending recovery against the original callback claim', async () => {
    await onClient(async client => { await beginOAuth(client); await issueRecovery(client); });
    const [recover, claim] = await Promise.all([
      onClient(recoverOAuth),
      onClient(client => oauthFlow(client).claim()),
    ]);
    expect([['recovered', 'restart_required'], ['in_progress', 'claimed']]).toContainEqual([recover.kind, claim.kind]);
    const { rows } = await db().query('SELECT state,exchange_transmission_intent_at IS NOT NULL AS sent FROM jls_auth.oauth_attempts');
    expect(rows).toEqual([{ state: recover.kind === 'recovered' ? 'cancelled' : 'claimed', sent: false }]);
  });

  it('serializes retirement against a real acknowledgement of the resulting cookie', async () => {
    const a = OAUTH;
    await onClient(async client => {
      const flow = await beginOAuth(client);
      expect((await flow.claim()).kind).toBe('claimed');
      expect((await flow.sent()).kind).toBe('send_intent');
      expect((await flow.commit()).kind).toBe('committed');
      await issueRecovery(client);
      await ageDelivery(client);
    });
    const [recover, ack] = await Promise.all([
      onClient(recoverOAuth),
      onClient(client => oauthRpc(client, 11, [a.secret, a.browserSecret, 0])),
    ]);
    expect([['recovered', 'denied'], ['denied', 'acknowledged']]).toContainEqual([recover.kind, ack.kind]);
    const { rows } = await db().query('SELECT delivery_state,revoked_at IS NOT NULL AS revoked FROM jls_auth.app_sessions');
    expect(rows).toEqual(recover.kind === 'recovered'
      ? [{ delivery_state: 'unacknowledged', revoked: true }]
      : [{ delivery_state: 'acknowledged', revoked: false }]);
  });
});
