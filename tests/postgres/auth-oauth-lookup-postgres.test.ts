import type { Pool } from 'pg';
import { afterAll, beforeAll, describe, it } from 'vitest';
import { oauthLookupCases } from './oauthLookupCases';
import {
  cleanupRefreshFixture, createRefreshProofPool, initializeRefreshFixture, resetRefreshFixture,
} from './refreshFixture';

describe('owned disposable PostgreSQL OAuth lookup (TEST ONLY)', () => {
  let pool: Pool | undefined;
  let initialized = false;

  beforeAll(async () => {
    pool = createRefreshProofPool();
    await initializeRefreshFixture(pool, true);
    initialized = true;
  });

  afterAll(async () => {
    if (!pool) return;
    const errors: unknown[] = [];
    if (initialized) {
      try { await cleanupRefreshFixture(pool, true); }
      catch (error) { errors.push(error); }
    }
    try { await pool.end(); }
    catch (error) { errors.push(error); }
    if (errors.length) throw new AggregateError(errors, 'OAuth lookup fixture teardown failed.');
  });

  for (const [name, withSession, run] of oauthLookupCases) {
    it(name, async () => {
      if (!pool) throw new Error('OAuth lookup fixture not initialized.');
      await resetRefreshFixture(pool, withSession);
      const client = await pool.connect();
      try { await run({ query: (sql, values) => client.query(sql, values) }); }
      finally { client.release(true); }
    });
  }
});
