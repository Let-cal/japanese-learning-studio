import { Pool, type PoolClient } from 'pg';
import { readFile } from 'node:fs/promises';
import { assertExecutionGuard, assertServerIdentity, fixedConnectionOptions, closeAll, type ProofClient, type ProofEnvironment } from './protocol';

export const OWNER = '11111111-1111-4111-8111-111111111111';
export const OTHER = '22222222-2222-4222-8222-222222222222';
export const EPOCH = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
export const NEXT_EPOCH = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
export const TARGET = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
export const operation = (n: number) => `dddddddd-dddd-4ddd-8ddd-${n.toString(16).padStart(12, '0')}`;
export const adapt = (client: PoolClient): ProofClient => ({
  query: async (sql, values) => client.query(sql, values), release: destroy => client.release(destroy),
});
// The guard executes before constructing even a lazy pool. pg never receives a caller DSN.
export function createProofPool(environment: ProofEnvironment = process.env): Pool {
  assertExecutionGuard(environment);
  return new Pool(fixedConnectionOptions(environment));
}
export async function verifySentinel(client: ProofClient): Promise<void> {
  await assertServerIdentity(client);
  const result = await client.query('SELECT marker FROM jls_command_proof.fixture_marker');
  if (result.rows.length !== 1 || result.rows[0]?.marker !== 'jls-command-proof-v1') throw new Error('Fixture sentinel mismatch: cleanup refused.');
}
export async function initializeFixture(pool: Pool): Promise<void> {
  const native = await pool.connect(); const client = adapt(native);
  try {
    await assertServerIdentity(client);
    // This service must be fresh: even a previous known fixture aborts rather than clobbering it.
    const { rows } = await client.query(`SELECT
      (SELECT count(*)::int FROM pg_namespace WHERE nspname NOT IN ('public','information_schema') AND nspname NOT LIKE 'pg_%') AS schemas,
      (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') AS public_objects,
      (SELECT count(*)::int FROM pg_roles WHERE rolname='jls_command_actor') AS actor_roles`);
    if (rows[0]?.schemas !== 0 || rows[0]?.public_objects !== 0 || rows[0]?.actor_roles !== 0) throw new Error('Disposable database is not fresh and empty; no DDL authorized.');
    await client.query('BEGIN');
    try {
      await client.query(await readFile(new URL('../../tools/ci/task2-command-fixture.sql', import.meta.url), 'utf8'));
      await client.query('COMMIT');
    } catch (cause) {
      try { await client.query('ROLLBACK'); } catch (rollback) { throw new AggregateError([cause, rollback], 'Fixture DDL and rollback failed.'); }
      throw cause;
    }
  } finally { client.release(true); }
}
export async function resetFixture(pool: Pool, version = 0): Promise<void> {
  const native = await pool.connect(); const client = adapt(native);
  try {
    await verifySentinel(client);
    await client.query('BEGIN');
    try {
      await client.query('TRUNCATE jls_command_proof.receipts, jls_command_proof.outbox, jls_command_proof.proposals, jls_command_proof.aggregates, jls_command_proof.datasets, jls_command_proof.owners');
      await client.query('INSERT INTO jls_command_proof.owners(owner_id,active,current_epoch) VALUES ($1,true,$2),($3,true,$2)', [OWNER, EPOCH, OTHER]);
      await client.query('INSERT INTO jls_command_proof.datasets(owner_id,dataset_epoch,active) VALUES ($1,$2,true),($3,$2,true)', [OWNER, EPOCH, OTHER]);
      await client.query("INSERT INTO jls_command_proof.aggregates VALUES ($1,$2,$3,$4,'open','initial'),($5,$2,$3,0,'open','other')", [OWNER, EPOCH, TARGET, version, OTHER]);
      await client.query('COMMIT');
    } catch (cause) {
      try { await client.query('ROLLBACK'); } catch (rollback) { throw new AggregateError([cause, rollback], 'Fixture reset and rollback failed.'); }
      throw cause;
    }
  } finally { client.release(true); }
}
export async function cleanupFixture(pool: Pool): Promise<void> {
  const native = await pool.connect(); const client = adapt(native);
  try {
    await verifySentinel(client);
    await client.query('BEGIN');
    try {
      await client.query('DROP SCHEMA jls_command_proof CASCADE');
      await client.query('DROP ROLE jls_command_actor');
      await client.query('COMMIT');
    } catch (cause) {
      try { await client.query('ROLLBACK'); } catch (rollback) { throw new AggregateError([cause, rollback], 'Fixture teardown and rollback failed.'); }
      throw cause;
    }
  } finally { client.release(true); }
}
export async function closeProofPools(pools: readonly Pool[]) { await closeAll(pools); }
