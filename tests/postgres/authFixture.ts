import { readFile } from 'node:fs/promises';
import type { Pool, PoolClient } from 'pg';
import { adapt, createProofPool } from './fixture';
import { assertServerIdentity } from './protocol';

export { createProofPool as createAuthProofPool };
export const AUTH = {
  owner: '11111111-1111-4111-8111-111111111111', subject: '22222222-2222-4222-8222-222222222222',
  epoch: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', browser: '33333333-3333-4333-8333-333333333333',
  session: '44444444-4444-4444-8444-444444444444', upstream: '55555555-5555-4555-8555-555555555555',
  proof: '66666666-6666-4666-8666-666666666666', operation: '77777777-7777-4777-8777-777777777777',
  attempt: '88888888-8888-4888-8888-888888888888',
  secret: 'a'.repeat(64), browserSecret: 'b'.repeat(64), proofSecret: 'c'.repeat(64),
  cookie: `present:${'d'.repeat(64)}`,
  envelope: `v1.fixture.${'A'.repeat(16)}.${'A'.repeat(64)}.${'A'.repeat(22)}`,
  pkceEnvelope: `pkce-v1.fixture.${'A'.repeat(16)}.${'A'.repeat(58)}.${'A'.repeat(22)}`,
};
const migration = new URL('../../supabase/migrations/20261106155504_auth_control.sql', import.meta.url);
const signatures = [
  'jls_auth_session_lookup_v1(text)',
  'jls_auth_session_snapshot_v1(text,text)',
  'jls_auth_current_credentials_v1(text,text,bigint,bigint,uuid)',
  'jls_auth_confirm_session_v1(text,text,bigint,bigint,uuid,uuid,uuid)',
  'jls_auth_delivery_ack_v1(text,text,bigint)',
  'jls_auth_delivery_retire_v1(text,uuid,uuid,bigint)',
  'jls_auth_logout_v1(text,text,uuid,text)',
] as const;
async function sentinel(client: PoolClient) {
  await assertServerIdentity(adapt(client));
  const { rows } = await client.query('SELECT marker FROM jls_auth_fixture.marker');
  if (rows.length !== 1 || rows[0]?.marker !== 'jls-auth-control-proof-v1') throw new Error('Auth sentinel mismatch; refusing DDL.');
  const roles = (await client.query("SELECT rolname, rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname IN ('anon','authenticated','service_role') ORDER BY rolname")).rows;
  if (roles.length !== 3 || roles.some(row => row.rolsuper || row.rolbypassrls || row.rolcanlogin)) throw new Error('Auth fixture role identity mismatch; refusing cleanup.');
}
export async function initializeAuthFixture(pool: Pool) {
  const client = await pool.connect();
  try {
    await assertServerIdentity(adapt(client));
    const { rows } = await client.query(`SELECT
      (SELECT count(*)::int FROM pg_namespace WHERE nspname NOT IN ('public','information_schema') AND nspname NOT LIKE 'pg_%') AS schemas,
      (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') AS objects,
      (SELECT count(*)::int FROM pg_roles WHERE rolname IN ('anon','authenticated','service_role')) AS roles`);
    if (rows[0]?.schemas !== 0 || rows[0]?.objects !== 0 || rows[0]?.roles !== 0) throw new Error('Auth fixture requires fresh empty disposable database; refusing DDL.');
    await client.query('BEGIN');
    try {
      await client.query(`CREATE SCHEMA jls_auth_fixture;
        CREATE TABLE jls_auth_fixture.marker(marker text PRIMARY KEY);
        INSERT INTO jls_auth_fixture.marker VALUES ('jls-auth-control-proof-v1');
        CREATE ROLE anon NOLOGIN NOSUPERUSER NOBYPASSRLS;
        CREATE ROLE authenticated NOLOGIN NOSUPERUSER NOBYPASSRLS;
        CREATE ROLE service_role NOLOGIN NOSUPERUSER NOBYPASSRLS;`);
      // Execute the exact DDL inside this fixture's atomic setup transaction;
      // remove only the migration's outer transaction commands, not any SQL body.
      const source = await readFile(migration, 'utf8');
      if ((source.match(/^BEGIN;$/gm) ?? []).length !== 1 || (source.match(/^COMMIT;$/gm) ?? []).length !== 1) throw new Error('Unexpected migration transaction framing.');
      await client.query(source.replace(/^BEGIN;$/m, '').replace(/^COMMIT;$/m, ''));
      await client.query('COMMIT');
    } catch (cause) {
      try { await client.query('ROLLBACK'); } catch (rollback) { throw new AggregateError([cause, rollback], 'Auth initialization rollback failed.'); }
      throw cause;
    }
  } finally { client.release(true); }
}
export async function resetAuthFixture(pool: Pool) {
  const client = await pool.connect();
  try {
    await sentinel(client);
    await client.query('BEGIN');
    try {
      // Only this fixture's known tables. No CASCADE/TRUNCATE of unrelated schemas.
      await client.query(`TRUNCATE jls_auth.cleanup_work, jls_auth.action_receipts, jls_auth.csrf_proofs,
        jls_auth.oauth_attempts, jls_auth.session_credentials, jls_auth.app_sessions,
        jls_auth.browser_bindings, jls_auth.datasets, jls_auth.owner_control`);
      await client.query('INSERT INTO jls_auth.owner_control(owner_id,auth_subject) VALUES ($1,$2)', [AUTH.owner, AUTH.subject]);
      await client.query('INSERT INTO jls_auth.datasets(owner_id,dataset_epoch) VALUES ($1,$2)', [AUTH.owner, AUTH.epoch]);
      await client.query('UPDATE jls_auth.owner_control SET current_dataset_epoch=$2,active=true WHERE owner_id=$1', [AUTH.owner, AUTH.epoch]);
      await client.query("INSERT INTO jls_auth.browser_bindings(browser_id,secret_hash,expires_at) VALUES ($1,$2,clock_timestamp()+interval '8 days')", [AUTH.browser, AUTH.browserSecret]);
      await client.query(`INSERT INTO jls_auth.app_sessions(session_id,secret_hash,owner_id,auth_subject,upstream_session_id,browser_id,browser_generation)
        VALUES ($1,$2,$3,$4,$5,$6,0)`, [AUTH.session, AUTH.secret, AUTH.owner, AUTH.subject, AUTH.upstream, AUTH.browser]);
      await client.query('UPDATE jls_auth.browser_bindings SET current_session_id=$2 WHERE browser_id=$1', [AUTH.browser, AUTH.session]);
      await client.query(`INSERT INTO jls_auth.session_credentials(session_id,token_envelope,access_expires_at)
        VALUES ($1,$2,clock_timestamp()+interval '1 hour')`, [AUTH.session, AUTH.envelope]);
      await client.query(`INSERT INTO jls_auth.csrf_proofs(proof_id,secret_hash,browser_id,generation,purpose,cookie_fingerprint,session_id,operation_id)
        VALUES ($1,$2,$3,0,'logout',$4,$5,$6)`, [AUTH.proof, AUTH.proofSecret, AUTH.browser, AUTH.cookie, AUTH.session, AUTH.operation]);
      await client.query('COMMIT');
    } catch (cause) {
      try { await client.query('ROLLBACK'); } catch (rollback) { throw new AggregateError([cause, rollback], 'Auth reset rollback failed.'); }
      throw cause;
    }
  } finally { client.release(true); }
}
export async function authRpc(pool: Pool, name: typeof signatures[number], values: unknown[], role: 'service_role' | 'anon' | 'authenticated' = 'service_role') {
  if (!signatures.includes(name) || !['service_role', 'anon', 'authenticated'].includes(role)) throw new Error('Unknown Auth fixture capability.');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL ROLE ${role}`);
    // Function names are a compile-time closed list; arguments remain parameters.
    const functionName = name.slice(0, name.indexOf('('));
    const result = await client.query(`SELECT public.${functionName}(${values.map((_, i) => `$${i + 1}`).join(',')}) AS result`, values);
    await client.query('COMMIT');
    return result.rows[0]?.result;
  } catch (cause) {
    try { await client.query('ROLLBACK'); } catch (rollback) { throw new AggregateError([cause, rollback], 'Auth RPC rollback failed.'); }
    throw cause;
  } finally { client.release(true); }
}
export async function cleanupAuthFixture(pool: Pool) {
  const client = await pool.connect();
  try {
    await sentinel(client);
    await client.query('BEGIN');
    try {
      for (const signature of signatures) await client.query(`DROP FUNCTION public.${signature}`);
      await client.query('DROP SCHEMA jls_auth CASCADE');
      await client.query('DROP SCHEMA jls_auth_fixture CASCADE');
      // These roles were created only after the fresh-DB check; no DROP OWNED.
      await client.query('DROP ROLE anon; DROP ROLE authenticated; DROP ROLE service_role');
      await client.query('COMMIT');
    } catch (cause) {
      try { await client.query('ROLLBACK'); } catch (rollback) { throw new AggregateError([cause, rollback], 'Auth cleanup rollback failed.'); }
      throw cause;
    }
  } finally { client.release(true); }
}
