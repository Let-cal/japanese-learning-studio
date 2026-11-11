import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Pool } from 'pg';
import { AUTH } from './authFixture';
import { oauthFlow, oauthSignatures, OAUTH } from './oauthLifecycleFixture';
import { adapt, createProofPool, operation } from './fixture';
import { assertServerIdentity } from './protocol';

export { createProofPool as createRefreshProofPool };
export const REFRESH = {
  ...AUTH,
  attempt: operation(41),
  nextAttempt: operation(42),
  finish: operation(43),
  close: operation(44),
  late: operation(45),
  cleanup: operation(46),
  nextCleanup: operation(47),
  other: operation(48),
  request: '1'.repeat(64),
  finishFingerprint: '2'.repeat(64),
  closeFingerprint: '3'.repeat(64),
  lateFingerprint: '4'.repeat(64),
  nextPair: AUTH.envelope.replace('fixture', 'rotated'),
  latePair: AUTH.envelope.replace('fixture', 'late'),
};
const commonSignature = 'text,text,uuid,text,uuid,uuid,bigint,uuid,uuid,uuid,bigint,bigint,uuid';
const finishSignature = 'uuid,text,uuid,uuid,text,timestamptz';
const signatures = {
  claim: `jls_auth_refresh_claim_v1(${commonSignature})`,
  mark: `jls_auth_refresh_mark_sent_v1(${commonSignature})`,
  finish: `jls_auth_refresh_finish_v1(${commonSignature},${finishSignature})`,
  resolve: `jls_auth_refresh_resolve_v1(${commonSignature},${finishSignature})`,
  close: `jls_auth_refresh_close_v1(${commonSignature},uuid,text,text,uuid,uuid,text)`,
  cleanupClaim: 'jls_auth_session_cleanup_claim_v1(uuid,uuid)',
  cleanupComplete: 'jls_auth_session_cleanup_complete_v1(uuid,uuid,bigint,text)',
  logout: 'jls_auth_logout_v1(text,text,uuid,text)',
  retire: 'jls_auth_delivery_retire_v1(text,uuid,uuid,bigint)',
} as const;
const foundationSignatures = [
  'jls_auth_session_lookup_v1(text)',
  'jls_auth_session_snapshot_v1(text,text)',
  'jls_auth_current_credentials_v1(text,text,bigint,bigint,uuid)',
  'jls_auth_confirm_session_v1(text,text,bigint,bigint,uuid,uuid,uuid)',
  'jls_auth_delivery_ack_v1(text,text,bigint)',
  signatures.retire, signatures.logout,
];
const sourceFiles = ['20261106155504_auth_control.sql', '20261107050258_auth_oauth_lifecycle.sql', '20261111153831_auth_refresh.sql'];
export const refreshSources = () => Promise.all(sourceFiles.map(file =>
  readFile(new URL(`../../supabase/migrations/${file}`, import.meta.url), 'utf8')));

type Row = Record<string, unknown>;
type Queryable = { query(sql: string, values?: unknown[]): Promise<{ rows: Row[] }> };
type Capability = keyof typeof signatures;
type Role = 'service_role' | 'anon' | 'authenticated' | 'jls_refresh_rls_probe';

export const refreshFixtureSetup = `
  CREATE SCHEMA jls_refresh_fixture;
  CREATE TABLE jls_refresh_fixture.marker(marker text PRIMARY KEY);
  INSERT INTO jls_refresh_fixture.marker VALUES ('jls-auth-refresh-proof-v1');
  CREATE ROLE anon NOLOGIN NOSUPERUSER NOBYPASSRLS;
  CREATE ROLE authenticated NOLOGIN NOSUPERUSER NOBYPASSRLS;
  CREATE ROLE service_role NOLOGIN NOSUPERUSER BYPASSRLS;
  CREATE ROLE supabase_auth_admin NOLOGIN NOSUPERUSER NOBYPASSRLS;
  CREATE ROLE jls_refresh_rls_probe NOLOGIN NOSUPERUSER NOBYPASSRLS;
  CREATE SCHEMA auth AUTHORIZATION supabase_auth_admin;
  CREATE TABLE auth.sessions (id uuid PRIMARY KEY, user_id uuid NOT NULL, not_after timestamptz, fixture_extra text);
  ALTER TABLE auth.sessions OWNER TO supabase_auth_admin;
  ALTER TABLE auth.sessions ENABLE ROW LEVEL SECURITY;
  GRANT USAGE ON SCHEMA auth TO jls_refresh_rls_probe;
  GRANT SELECT(id,user_id,not_after) ON auth.sessions TO jls_refresh_rls_probe;
`;

export async function assertRefreshSentinel(db: Queryable) {
  const { rows } = await db.query('SELECT marker FROM jls_refresh_fixture.marker');
  assert.deepEqual(rows, [{ marker: 'jls-auth-refresh-proof-v1' }]);
  const roles = (await db.query(`SELECT rolname, rolsuper, rolbypassrls, rolcanlogin
    FROM pg_roles WHERE rolname IN ('anon','authenticated','service_role','supabase_auth_admin','jls_refresh_rls_probe')
    ORDER BY rolname`)).rows;
  assert.deepEqual(roles, ['anon', 'authenticated', 'jls_refresh_rls_probe', 'service_role', 'supabase_auth_admin'].map(rolname =>
    ({ rolname, rolsuper: false, rolbypassrls: rolname === 'service_role', rolcanlogin: false })));
}

async function transaction<T>(db: Queryable, run: () => Promise<T>): Promise<T> {
  await db.query('BEGIN');
  try {
    const result = await run();
    await db.query('COMMIT');
    return result;
  } catch (cause) {
    try { await db.query('ROLLBACK'); }
    catch (rollback) { throw new AggregateError([cause, rollback], 'Refresh fixture transaction and rollback failed.'); }
    throw cause;
  }
}

export async function initializeRefreshFixture(pool: Pool) {
  const db = await pool.connect();
  try {
    await assertServerIdentity(adapt(db));
    const { rows } = await db.query(`SELECT
      (SELECT count(*)::int FROM pg_namespace WHERE nspname NOT IN ('public','information_schema') AND nspname NOT LIKE 'pg_%') AS schemas,
      (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') AS objects,
      (SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public') AS functions,
      (SELECT count(*)::int FROM pg_roles WHERE rolname IN ('anon','authenticated','service_role','supabase_auth_admin','jls_refresh_rls_probe')) AS roles`);
    assert.deepEqual(rows, [{ schemas: 0, objects: 0, functions: 0, roles: 0 }], 'Refresh fixture requires a fresh disposable database.');
    const sources = await refreshSources();
    await transaction(db, async () => {
      await db.query(refreshFixtureSetup);
      for (const sql of sources) {
        assert.equal((sql.match(/^BEGIN;\r?$/gm) ?? []).length, 1);
        assert.equal((sql.match(/^COMMIT;\r?$/gm) ?? []).length, 1);
        await db.query(sql.replace(/^BEGIN;\r?$/m, '').replace(/^COMMIT;\r?$/m, ''));
      }
    });
  } finally { db.release(true); }
}

export async function cleanupRefreshFixture(pool: Pool) {
  const db = await pool.connect();
  try {
    await assertServerIdentity(adapt(db));
    await assertRefreshSentinel(db);
    await transaction(db, async () => {
      const newSignatures = Object.values(signatures).filter(signature => !foundationSignatures.includes(signature));
      for (const signature of [...newSignatures, ...oauthSignatures, ...foundationSignatures]) {
        await db.query(`DROP FUNCTION public.${signature}`);
      }
      // The sentinel and role checks above establish ownership of these exact schemas.
      await db.query(`DROP SCHEMA jls_auth CASCADE;
        DROP TABLE auth.sessions;
        DROP SCHEMA auth;
        DROP TABLE jls_refresh_fixture.marker;
        DROP SCHEMA jls_refresh_fixture;
        DROP ROLE anon, authenticated, service_role, supabase_auth_admin, jls_refresh_rls_probe;`);
    });
  } finally { db.release(true); }
}

export async function resetRefreshFixture(database: Queryable | Pool, withSession = true) {
  const owned = database instanceof Pool ? await database.connect() : undefined;
  const db: Queryable = owned ?? database;
  try {
    if (owned) await assertServerIdentity(adapt(owned));
    await assertRefreshSentinel(db);
    const f = REFRESH;
    await transaction(db, async () => {
      const schema = (await db.query("SELECT to_regclass('jls_auth.refresh_attempts') AS refresh")).rows[0];
      const historyTables = schema?.refresh ? 'jls_auth.refresh_receipts, jls_auth.refresh_attempts,' : '';
      await db.query(`TRUNCATE ${historyTables} auth.sessions, jls_auth.candidate_cleanup_work, jls_auth.proof_issuances,
        jls_auth.cleanup_work, jls_auth.action_receipts, jls_auth.csrf_proofs, jls_auth.oauth_attempts, jls_auth.session_credentials,
        jls_auth.app_sessions, jls_auth.browser_bindings, jls_auth.datasets, jls_auth.owner_control`);
      await db.query('INSERT INTO jls_auth.owner_control(owner_id,auth_subject) VALUES ($1,$2)', [f.owner, f.subject]);
      await db.query('INSERT INTO jls_auth.datasets(owner_id,dataset_epoch) VALUES ($1,$2)', [f.owner, f.epoch]);
      await db.query('UPDATE jls_auth.owner_control SET active=true,current_dataset_epoch=$2 WHERE owner_id=$1', [f.owner, f.epoch]);
      if (!withSession) return;
      await db.query("INSERT INTO jls_auth.browser_bindings(browser_id,secret_hash,expires_at) VALUES ($1,$2,statement_timestamp()+interval '8 days')", [f.browser, f.browserSecret]);
      await db.query(`INSERT INTO jls_auth.app_sessions(session_id,secret_hash,owner_id,auth_subject,upstream_session_id,browser_id,browser_generation)
        VALUES ($1,$2,$3,$4,$5,$6,0)`, [f.session, f.secret, f.owner, f.subject, f.upstream, f.browser]);
      await db.query('UPDATE jls_auth.browser_bindings SET current_session_id=$2 WHERE browser_id=$1', [f.browser, f.session]);
      await db.query(`INSERT INTO jls_auth.session_credentials(session_id,token_envelope,access_expires_at)
        VALUES ($1,$2,statement_timestamp()-interval '1 minute')`, [f.session, f.envelope]);
      await db.query(`INSERT INTO jls_auth.csrf_proofs(proof_id,secret_hash,browser_id,generation,purpose,cookie_fingerprint,session_id,operation_id)
        VALUES ($1,$2,$3,0,'logout',$4,$5,$6)`, [f.proof, f.proofSecret, f.browser, f.cookie, f.session, f.operation]);
      await db.query('INSERT INTO auth.sessions(id,user_id) VALUES ($1,$2)', [f.upstream, f.subject]);
    });
  } finally { owned?.release(true); }
}

export async function refreshRpc(database: Queryable | Pool, capability: Capability, values: unknown[], role: Role = 'service_role') {
  const name = signatures[capability].split('(')[0];
  if (!['service_role', 'anon', 'authenticated', 'jls_refresh_rls_probe'].includes(role)) throw new Error('Unexpected refresh fixture role.');
  const owned = database instanceof Pool ? await database.connect() : undefined;
  const db: Queryable = owned ?? database;
  try {
    return await transaction(db, async () => {
      await db.query(`SET LOCAL ROLE ${role}`);
      const result = (await db.query(`SELECT public.${name}(${values.map((_, i) => `$${i + 1}`).join(',')}) AS result`, values)).rows[0]?.result;
      assert(result && typeof result === 'object');
      return result as Row;
    });
  } finally { owned?.release(true); }
}

export function refreshFlow(db: Queryable | Pool, initialBinding: Record<number, unknown> = {}) {
  const f = REFRESH;
  const binding = Object.assign([f.secret, f.browserSecret, f.attempt, f.request, f.session, f.browser, 0, f.owner, f.subject, f.upstream, 0, 0, f.epoch], initialBinding);
  const finish = [...binding, f.finish, f.finishFingerprint, f.subject, f.upstream, f.nextPair, new Date(Date.now() + 3_600_000)];
  const close = [...binding, f.close, f.closeFingerprint, 'unknown', null, null, null];
  const late = [...binding, f.late, f.lateFingerprint, 'late_pair', f.subject, f.upstream, f.latePair];
  const args = (values: unknown[], overrides: Record<number, unknown> = {}) => Object.assign([...values], overrides);
  return {
    claim: (overrides?: Record<number, unknown>, role?: Role) => refreshRpc(db, 'claim', args(binding, overrides), role),
    mark: (overrides?: Record<number, unknown>, role?: Role) => refreshRpc(db, 'mark', args(binding, overrides), role),
    finish: (overrides?: Record<number, unknown>, role?: Role) => refreshRpc(db, 'finish', args(finish, overrides), role),
    resolve: (overrides?: Record<number, unknown>, role?: Role) => refreshRpc(db, 'resolve', args(finish, overrides), role),
    close: (overrides?: Record<number, unknown>, role?: Role) => refreshRpc(db, 'close', args(close, overrides), role),
    late: (overrides?: Record<number, unknown>) => refreshRpc(db, 'close', args(late, overrides)),
    cleanupClaim: (id = f.cleanup, role?: Role) => refreshRpc(db, 'cleanupClaim', [f.session, id], role),
    cleanupComplete: (claim = f.cleanup, revision = 0, outcome = 'completed', role?: Role) =>
      refreshRpc(db, 'cleanupComplete', [f.session, claim, revision, outcome], role),
    logout: () => refreshRpc(db, 'logout', [f.browserSecret, f.proofSecret, f.operation, f.cookie]),
  };
}

export const refreshCases: [string, (db: Queryable | Pool) => Promise<void>][] = [
  ['R01 fences the original pair and transmission to the matching prepared holder', async db => {
    const flow = refreshFlow(db);
    const first = await flow.claim();
    assert.equal(first.kind, 'claimed');
    assert.equal(first.tokenEnvelope, REFRESH.envelope);
    const lease = (await db.query('SELECT extract(epoch FROM lease_expires_at-claimed_at)::int AS seconds FROM jls_auth.refresh_attempts')).rows[0];
    assert.deepEqual(lease, { seconds: 25 });
    assert.deepEqual(await flow.claim(), first);
    assert.deepEqual(await flow.claim({ 3: REFRESH.finishFingerprint }), { kind: 'denied' });
    assert.deepEqual(await flow.claim({ 2: REFRESH.nextAttempt }), { kind: 'busy' });
    assert.deepEqual(await flow.mark({ 8: REFRESH.other }), { kind: 'denied' });
    assert.deepEqual(await flow.mark(), { kind: 'transmit' });
    assert.deepEqual(await flow.mark(), { kind: 'already_sent' });
    assert.deepEqual(await flow.claim(), { kind: 'busy' });
    assert.deepEqual(await flow.claim({ 2: REFRESH.nextAttempt }), { kind: 'busy' });
  }],
  ['R02 releases a demonstrably unsent attempt without renewing its lease or reusing its ID', async db => {
    const flow = refreshFlow(db);
    assert.equal((await flow.claim()).kind, 'claimed');
    assert.deepEqual(await flow.close(), { kind: 'denied' });
    assert.deepEqual(await flow.close({ 15: 'pre_send' }), { kind: 'released' });
    assert.deepEqual(await flow.close({ 15: 'pre_send' }), { kind: 'released' });
    assert.deepEqual(await flow.close({ 14: REFRESH.lateFingerprint, 15: 'pre_send' }), { kind: 'denied' });
    assert.deepEqual(await flow.mark(), { kind: 'denied' });
    assert.deepEqual(await flow.claim(), { kind: 'denied' });
    assert.equal((await flow.claim({ 2: REFRESH.nextAttempt })).kind, 'claimed');
    assert.deepEqual(await flow.mark({ 2: REFRESH.nextAttempt }), { kind: 'transmit' });
    assert.deepEqual(await flow.close({ 2: REFRESH.nextAttempt, 13: REFRESH.late, 15: 'pre_send' }), { kind: 'denied' });
  }],
  ['R03 commits the whole pair exactly once and resolves only the original typed finish payload', async db => {
    const flow = refreshFlow(db);
    assert.equal((await flow.claim()).kind, 'claimed');
    assert.deepEqual(await flow.resolve(), { kind: 'not_committed' });
    assert.deepEqual(await flow.finish(), { kind: 'denied' });
    await flow.mark();
    const before = (await db.query('SELECT created_at,last_activity_at,reauthenticated_at,browser_generation FROM jls_auth.app_sessions')).rows;
    const receipt = { kind: 'committed', attemptId: REFRESH.attempt, sessionId: REFRESH.session, tokenVersion: 1 };
    assert.deepEqual(await flow.finish(), receipt);
    assert.deepEqual(await flow.finish(), receipt);
    assert.deepEqual(await flow.resolve(), receipt);
    for (const overrides of [{ 3: REFRESH.closeFingerprint }, { 10: 1 }, { 13: REFRESH.other }, { 14: REFRESH.closeFingerprint },
      { 15: REFRESH.other }, { 16: REFRESH.other }, { 17: REFRESH.latePair }, { 18: new Date(Date.now() + 7_200_000) }]) {
      assert.deepEqual(await flow.resolve(overrides), { kind: 'denied' });
    }
    assert.deepEqual(await flow.close(), { kind: 'denied' });
    assert.deepEqual((await db.query('SELECT token_version::int,token_envelope,state FROM jls_auth.session_credentials')).rows,
      [{ token_version: 1, token_envelope: REFRESH.nextPair, state: 'usable' }]);
    assert.deepEqual((await db.query('SELECT created_at,last_activity_at,reauthenticated_at,browser_generation FROM jls_auth.app_sessions')).rows, before);
    await flow.logout();
    assert.deepEqual(await flow.resolve(), receipt);
    assert.deepEqual(await flow.late(), { kind: 'denied' });
    assert.equal((await flow.cleanupClaim()).tokenEnvelope, REFRESH.nextPair);
  }],
  ['R04 settles a sent unknown attempt without releasing or resending its pair', async db => {
    const flow = refreshFlow(db);
    await flow.claim(); await flow.mark();
    await db.query(`UPDATE jls_auth.refresh_attempts SET claimed_at=statement_timestamp()-interval '26 seconds',
      lease_expires_at=statement_timestamp()-interval '1 second', transmission_intent_at=statement_timestamp()-interval '25 seconds'`);
    await db.query("UPDATE jls_auth.session_credentials SET refresh_lease_expires_at=(SELECT lease_expires_at FROM jls_auth.refresh_attempts)");
    assert.deepEqual(await flow.claim({ 2: REFRESH.nextAttempt }), { kind: 'reauthentication_required' });
    assert.deepEqual(await flow.finish(), { kind: 'denied' });
    assert.deepEqual(await flow.close(), { kind: 'closed' });
    assert.deepEqual(await flow.close(), { kind: 'closed' });
    assert.deepEqual(await flow.close({ 15: 'pre_send' }), { kind: 'denied' });
    assert.deepEqual(await flow.resolve(), { kind: 'not_committed' });
    assert.deepEqual(await flow.claim({ 2: REFRESH.nextAttempt }), { kind: 'reauthentication_required' });
  }],
  ...([
    ['missing managed session', 'DELETE FROM auth.sessions'],
    ['wrong managed subject', `UPDATE auth.sessions SET user_id='${REFRESH.other}'`],
    ['expired managed session', "UPDATE auth.sessions SET not_after=statement_timestamp()-interval '1 second'"],
    ['changed dataset control', 'UPDATE jls_auth.owner_control SET control_version=control_version+1'],
    ['expired app session', "UPDATE jls_auth.app_sessions SET created_at=statement_timestamp()-interval '8 days'"],
  ] as const).map(([reason, sql]): [string, (db: Queryable | Pool) => Promise<void>] => [`R05 rejects finish with ${reason}`, async db => {
    const flow = refreshFlow(db); await flow.claim(); await flow.mark();
    await db.query(sql);
    assert.deepEqual(await flow.finish(), { kind: 'denied' });
    assert.deepEqual(await flow.resolve(), { kind: 'not_committed' });
    assert.deepEqual(await flow.close(), { kind: 'closed' });
  }]),
  ['R06 retains a late pair until local revocation then transfers cleanup custody', async db => {
    const flow = refreshFlow(db); await flow.claim(); await flow.mark();
    assert.deepEqual(await flow.close(), { kind: 'closed' });
    assert.deepEqual(await flow.late({ 16: REFRESH.other }), { kind: 'denied' });
    assert.deepEqual(await flow.late(), { kind: 'late_pair_retained' });
    assert.deepEqual(await flow.late(), { kind: 'late_pair_retained' });
    assert.deepEqual(await flow.late({ 18: REFRESH.nextPair }), { kind: 'denied' });
    assert.deepEqual(await flow.cleanupClaim(), { kind: 'denied' });
    assert.deepEqual((await db.query('SELECT count(*)::int AS total FROM jls_auth.candidate_cleanup_work')).rows, [{ total: 0 }]);
    assert.equal((await flow.logout()).kind, 'logged_out');
    assert.deepEqual(await flow.finish(), { kind: 'denied' });
    assert.deepEqual(await flow.cleanupClaim(), { kind: 'cleanup', sessionId: REFRESH.session, ownerId: REFRESH.owner, authSubject: REFRESH.subject,
      upstreamSessionId: REFRESH.upstream, scope: 'local', claimId: REFRESH.cleanup, revision: 0, tokenEnvelope: REFRESH.latePair });
  }],
  ['R07 fences an old cleanup completion when logout precedes the late pair', async db => {
    const flow = refreshFlow(db); await flow.claim(); await flow.mark();
    assert.equal((await flow.logout()).kind, 'logged_out');
    assert.equal((await flow.cleanupClaim()).tokenEnvelope, REFRESH.envelope);
    assert.deepEqual(await flow.late(), { kind: 'late_pair_retained' });
    assert.deepEqual(await flow.cleanupComplete(), { kind: 'denied' });
    assert.deepEqual(await flow.cleanupClaim(), { kind: 'denied' });
    const second = await flow.cleanupClaim(REFRESH.nextCleanup);
    assert.equal(second.tokenEnvelope, REFRESH.latePair);
    assert.equal(second.revision, 1);
    assert.deepEqual(await flow.cleanupComplete(REFRESH.nextCleanup, 1), { kind: 'completed' });
    assert.deepEqual((await db.query('SELECT attempts,revision::int,token_envelope FROM jls_auth.cleanup_work')).rows,
      [{ attempts: 2, revision: 1, token_envelope: null }]);
  }],
  ['R08 enforces fixed service-only invoker privileges including managed column access', async db => {
    const flow = refreshFlow(db);
    for (const role of ['anon', 'authenticated'] as const) {
      await assert.rejects(() => flow.claim({}, role), { code: '42501' });
      await assert.rejects(() => flow.mark({}, role), { code: '42501' });
      await assert.rejects(() => flow.finish({}, role), { code: '42501' });
      await assert.rejects(() => flow.resolve({}, role), { code: '42501' });
      await assert.rejects(() => flow.close({}, role), { code: '42501' });
      await assert.rejects(() => flow.cleanupClaim(REFRESH.cleanup, role), { code: '42501' });
      await assert.rejects(() => flow.cleanupComplete(REFRESH.cleanup, 0, 'completed', role), { code: '42501' });
    }
    assert.deepEqual((await db.query(`SELECT has_column_privilege('service_role','auth.sessions','id','SELECT') AS id,
      has_column_privilege('service_role','auth.sessions','user_id','SELECT') AS user_id,
      has_column_privilege('service_role','auth.sessions','not_after','SELECT') AS not_after,
      has_column_privilege('service_role','auth.sessions','fixture_extra','SELECT') AS extra,
      has_table_privilege('service_role','auth.sessions','UPDATE') AS can_write,
      has_column_privilege('authenticated','auth.sessions','id','SELECT') AS client_read`)).rows,
    [{ id: true, user_id: true, not_after: true, extra: false, can_write: false, client_read: false }]);
    const acl = (await db.query(`SELECT p.prosecdef, p.proconfig, has_function_privilege('service_role',p.oid,'EXECUTE') AS service
      FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='public' AND p.proname ~ '^jls_auth_(refresh_|session_cleanup_)'`)).rows;
    assert.equal(acl.length, 7);
    assert(acl.every(row => row.prosecdef === false && row.service === true
      && Array.isArray(row.proconfig) && row.proconfig.includes('search_path=""')));
    const owned = db instanceof Pool ? await db.connect() : undefined;
    const client: Queryable = owned ?? db;
    try {
      await transaction(client, async () => {
        await client.query('SET LOCAL ROLE jls_refresh_rls_probe');
        assert.deepEqual((await client.query('SELECT id FROM auth.sessions')).rows, []);
      });
      await transaction(client, async () => {
        await client.query('SET LOCAL ROLE service_role');
        assert.deepEqual((await client.query('SELECT id FROM auth.sessions')).rows, [{ id: REFRESH.upstream }]);
      });
    } finally { owned?.release(true); }
  }],
  ['R09 replaces only an expired prepare whose marker was never written', async db => {
    const flow = refreshFlow(db);
    assert.equal((await flow.claim()).kind, 'claimed');
    await db.query(`UPDATE jls_auth.refresh_attempts SET claimed_at=statement_timestamp()-interval '26 seconds',
      lease_expires_at=statement_timestamp()-interval '1 second'`);
    await db.query('UPDATE jls_auth.session_credentials SET refresh_lease_expires_at=(SELECT lease_expires_at FROM jls_auth.refresh_attempts)');
    assert.deepEqual(await flow.mark(), { kind: 'denied' });
    assert.deepEqual(await flow.claim(), { kind: 'denied' });
    assert.equal((await flow.claim({ 2: REFRESH.nextAttempt })).tokenEnvelope, REFRESH.envelope);
    assert.deepEqual(await flow.mark(), { kind: 'denied' });
    assert.deepEqual(await flow.mark({ 2: REFRESH.nextAttempt }), { kind: 'transmit' });
  }],
  ['R10 retains the original deadline, attempt count and claim history through late pair replacement', async db => {
    const flow = refreshFlow(db);
    await flow.claim(); await flow.mark(); await flow.logout();
    const budget = await db.query('SELECT created_at,deadline_at FROM jls_auth.cleanup_work');
    assert.equal((await flow.cleanupClaim()).kind, 'cleanup');
    assert.deepEqual((await db.query(`SELECT lease_expires_at>clock_timestamp()+interval '14 seconds'
      AND lease_expires_at<=clock_timestamp()+interval '15 seconds' AS lease FROM jls_auth.cleanup_work`)).rows, [{ lease: true }]);
    assert.deepEqual(await flow.cleanupComplete(REFRESH.cleanup, 0, 'timeout'), { kind: 'pending' });
    assert.equal((await flow.cleanupClaim(REFRESH.nextCleanup)).kind, 'cleanup');
    assert.deepEqual(await flow.cleanupComplete(REFRESH.nextCleanup, 0, 'transport'), { kind: 'pending' });
    assert.equal((await flow.cleanupClaim(REFRESH.other)).kind, 'cleanup');
    assert.deepEqual(await flow.cleanupComplete(REFRESH.other, 0, 'timeout'), { kind: 'failed' });
    assert.deepEqual(await flow.late(), { kind: 'late_pair_retained' });
    assert.deepEqual((await db.query('SELECT created_at,deadline_at FROM jls_auth.cleanup_work')).rows, budget.rows);
    assert.deepEqual((await db.query('SELECT state,attempts,revision::int,claim_history FROM jls_auth.cleanup_work')).rows, [
      { state: 'failed', attempts: 3, revision: 1, claim_history: [REFRESH.cleanup, REFRESH.nextCleanup, REFRESH.other] },
    ]);
    assert.deepEqual(await flow.cleanupClaim(REFRESH.finish), { kind: 'denied' });
  }],
  ['R11 cleanup whose deadline already passed never returns a bearer', async db => {
    const flow = refreshFlow(db);
    await flow.logout();
    await db.query(`UPDATE jls_auth.cleanup_work SET created_at=statement_timestamp()-interval '2 hours',
      deadline_at=statement_timestamp()-interval '1 hour'`);
    assert.deepEqual(await flow.cleanupClaim(), { kind: 'failed' });
    assert.deepEqual((await db.query('SELECT attempts,state FROM jls_auth.cleanup_work')).rows, [{ attempts: 0, state: 'failed' }]);
  }],
  ['R12 transfers late pair custody on OAuth replacement without touching the new session', async db => {
    const flow = refreshFlow(db); await flow.claim(); await flow.mark();
    assert.deepEqual(await flow.late(), { kind: 'late_pair_retained' });
    const oauth = oauthFlow(db);
    assert.equal((await oauth.issue({ 4: REFRESH.other, 5: '0'.repeat(64), 7: REFRESH.cookie, 8: REFRESH.secret, 9: REFRESH.close })).kind, 'issued');
    assert.equal((await oauth.begin({ 1: '0'.repeat(64), 2: REFRESH.close, 3: REFRESH.cookie })).kind, 'begun');
    assert.equal((await oauth.claim()).kind, 'claimed');
    assert.equal((await oauth.sent()).kind, 'send_intent');
    const replacement = await oauth.commit({ 8: REFRESH.other, 9: REFRESH.nextAttempt, 10: '9'.repeat(64) });
    assert.equal(replacement.kind, 'committed');
    assert.deepEqual(await flow.finish(), { kind: 'denied' });
    assert.deepEqual((await db.query('SELECT current_session_id,generation::int FROM jls_auth.browser_bindings')).rows,
      [{ current_session_id: REFRESH.nextAttempt, generation: 1 }]);
    assert.equal((await flow.cleanupClaim()).tokenEnvelope, REFRESH.latePair);
  }],
  ['R13 transfers a late pair on retirement of an unacknowledged OAuth result', async db => {
    await resetRefreshFixture(db, false);
    const oauth = oauthFlow(db);
    assert.equal((await oauth.issue()).kind, 'issued');
    assert.equal((await oauth.begin()).kind, 'begun');
    assert.equal((await oauth.claim()).kind, 'claimed');
    assert.equal((await oauth.sent()).kind, 'send_intent');
    assert.equal((await oauth.commit()).kind, 'committed');
    await db.query("UPDATE jls_auth.session_credentials SET access_expires_at=statement_timestamp()-interval '1 minute'");
    const flow = refreshFlow(db, { 6: 1 }); await flow.claim(); await flow.mark();
    assert.deepEqual(await flow.late(), { kind: 'late_pair_retained' });
    const result = await refreshRpc(db, 'retire', [REFRESH.browserSecret, OAUTH.attempt, REFRESH.session, 1]);
    assert.equal(result.kind, 'retired');
    assert.equal((await flow.cleanupClaim()).tokenEnvelope, REFRESH.latePair);
  }],
  ['R14 logout settles a pre-revoked app row with a usable credential and no cleanup work', async db => {
    const flow = refreshFlow(db);
    const revoked = await db.query('UPDATE jls_auth.app_sessions SET revoked_at=clock_timestamp() RETURNING revoked_at');
    assert.equal((await flow.logout()).kind, 'logged_out');
    assert.equal((await flow.logout()).kind, 'logged_out');
    assert.deepEqual((await db.query('SELECT revoked_at FROM jls_auth.app_sessions')).rows, revoked.rows);
    assert.deepEqual((await db.query('SELECT state,token_version::int FROM jls_auth.session_credentials')).rows,
      [{ state: 'revoked', token_version: 1 }]);
    assert.equal((await flow.cleanupClaim()).tokenEnvelope, REFRESH.envelope);
  }],
];
