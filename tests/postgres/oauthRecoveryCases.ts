import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { operation } from './fixture';
import { oauthFlow, oauthRpc, OAUTH, type OAuthDatabase } from './oauthLifecycleFixture';

const a = OAUTH;
const recovery = { issuance: operation(70), proof: operation(71), operation: operation(72), hash: '7'.repeat(64) };
const newer = { issuance: operation(73), proof: operation(74), operation: operation(75), hash: '8'.repeat(64),
  attempt: operation(76), flow: '9'.repeat(64) };
const denied = { kind: 'denied' };
const recovered = { kind: 'recovered' };
const inProgress = { kind: 'in_progress' };

export async function recoverOAuth(
  db: OAuthDatabase,
  overrides: Record<number, unknown> = {},
  role: 'service_role' | 'anon' | 'authenticated' | 'jls_refresh_rls_probe' = 'service_role',
) {
  const values = Object.assign([a.browserSecret, a.flow, recovery.hash, 'absent', null], overrides);
  await db.query('BEGIN');
  try {
    await db.query(`SET LOCAL ROLE ${role}`);
    const result = (await db.query('SELECT public.jls_auth_recover_login_v1($1,$2,$3,$4,$5) AS result', values)).rows[0].result;
    await db.query('COMMIT');
    return result;
  } catch (cause) {
    try { await db.query('ROLLBACK'); }
    catch (rollback) { throw new AggregateError([cause, rollback], 'OAuth recovery and rollback failed.'); }
    throw cause;
  }
}

export async function beginOAuth(db: OAuthDatabase) {
  const flow = oauthFlow(db);
  assert.equal((await flow.issue()).kind, 'issued');
  assert.equal((await flow.begin()).kind, 'begun');
  return flow;
}

export async function issueRecovery(db: OAuthDatabase, options: {
  flowHash?: string; purpose?: 'login' | 'logout'; fingerprint?: string; sessionHash?: string | null; ordinary?: boolean;
} = {}) {
  const { flowHash = a.flow, purpose = 'login', fingerprint = 'absent', sessionHash = null, ordinary = false } = options;
  const proofFingerprint = ordinary ? a.fingerprint : createHash('sha256')
    .update(`jls-oauth-recovery-proof-v1:${recovery.hash}:${flowHash}`, 'utf8').digest('hex');
  await db.query('SELECT pg_sleep(0.002)');
  assert.equal((await oauthFlow(db).issue({ 0: recovery.issuance, 1: proofFingerprint, 4: recovery.proof,
    5: recovery.hash, 6: purpose, 7: fingerprint, 8: sessionHash, 9: recovery.operation })).kind, 'issued');
}

export async function beginNewOAuth(db: OAuthDatabase) {
  const flow = oauthFlow(db);
  assert.equal((await flow.issue({ 0: newer.issuance, 4: newer.proof, 5: newer.hash, 9: newer.operation })).kind, 'issued');
  return flow.begin({ 1: newer.hash, 2: newer.operation, 4: newer.attempt, 5: newer.flow });
}

async function complete(db: OAuthDatabase) {
  const flow = await beginOAuth(db);
  assert.equal((await flow.claim()).kind, 'claimed');
  assert.equal((await flow.sent()).kind, 'send_intent');
  assert.equal((await flow.commit()).kind, 'committed');
  return flow;
}

export const expireOAuth = (db: OAuthDatabase) => db.query(`UPDATE jls_auth.oauth_attempts
  SET issued_at=clock_timestamp()-interval '1 minute', expires_at=clock_timestamp()`);
export const ageDelivery = (db: OAuthDatabase) => db.query(`UPDATE jls_auth.app_sessions
  SET created_at=clock_timestamp()-interval '31 seconds'`);

export const oauthRecoveryCases: readonly [name: string, run: (db: OAuthDatabase) => Promise<void>][] = [
  ['cancels an exact unsent attempt and consumes the proof once', async db => {
    const flow = await beginOAuth(db);
    await issueRecovery(db);
    assert.deepEqual(await recoverOAuth(db), recovered);
    assert.deepEqual(await recoverOAuth(db), recovered);
    assert.equal((await flow.claim()).kind, 'restart_required');
    assert.deepEqual((await db.query(`SELECT state, exchange_transmission_intent_at IS NULL AS unsent
      FROM jls_auth.oauth_attempts`)).rows, [{ state: 'cancelled', unsent: true }]);
    assert.deepEqual((await db.query(`SELECT count(*)::int AS consumed FROM jls_auth.csrf_proofs WHERE consumed_at IS NOT NULL`)).rows,
      [{ consumed: 2 }]);
    assert.deepEqual((await db.query('SELECT generation::int,current_session_id FROM jls_auth.browser_bindings')).rows,
      [{ generation: 0, current_session_id: null }]);
  }],
  ['requires exact hashes and presentation for mutation and replay', async db => {
    await beginOAuth(db);
    await issueRecovery(db, { fingerprint: a.cookie, sessionHash: a.secret });
    const exact = { 3: a.cookie, 4: a.secret };
    for (const overrides of [{ 0: a.proofSecret }, { 1: null }, { 1: newer.flow }, { 2: a.proofSecret },
      { 3: 'absent' }, { 4: null }, { 4: a.proofSecret }, { 4: a.secret.toUpperCase() }]) {
      assert.deepEqual(await recoverOAuth(db, { ...exact, ...overrides }), denied);
    }
    assert.deepEqual(await recoverOAuth(db, exact), recovered);
    assert.deepEqual(await recoverOAuth(db, { ...exact, 4: null }), denied);
    assert.deepEqual(await recoverOAuth(db, exact), recovered);
  }],
  ['rejects an ordinary login proof for recovery', async db => {
    await beginOAuth(db);
    await issueRecovery(db, { ordinary: true });
    assert.deepEqual(await recoverOAuth(db), denied);
  }],
  ['rejects a purpose mismatch even with an exact recovery fingerprint', async db => {
    await beginOAuth(db);
    await issueRecovery(db, { purpose: 'logout' });
    assert.deepEqual(await recoverOAuth(db), denied);
  }],
  ['rejects a proof issued before its target attempt', async db => {
    await issueRecovery(db);
    await beginOAuth(db);
    assert.deepEqual(await recoverOAuth(db), denied);
  }],
  ['denies recovery after proof expiry without a retained receipt', async db => {
    await beginOAuth(db);
    await issueRecovery(db);
    await db.query(`UPDATE jls_auth.csrf_proofs SET issued_at=clock_timestamp()-interval '1 minute',
      expires_at=clock_timestamp() WHERE proof_id=$1`, [recovery.proof]);
    assert.deepEqual(await recoverOAuth(db), denied);
  }],
  ['denies a prior proof against a successor flow in the same generation', async db => {
    const flow = await beginOAuth(db);
    assert.equal((await flow.claim()).kind, 'claimed');
    await issueRecovery(db);
    assert.equal((await flow.close({ 6: null, 7: null, 8: null, 9: null, 10: null })).kind, 'closed');
    assert.equal((await beginNewOAuth(db)).kind, 'begun');
    assert.deepEqual(await recoverOAuth(db, { 1: newer.flow }), denied);
    assert.deepEqual(await recoverOAuth(db), denied);
  }],
  ['does not replay a completed recovery while a successor attempt exists', async db => {
    await beginOAuth(db);
    await issueRecovery(db);
    assert.deepEqual(await recoverOAuth(db), recovered);
    assert.equal((await beginNewOAuth(db)).kind, 'begun');
    assert.deepEqual(await recoverOAuth(db), denied);
  }],
  ['does not replay a completed recovery after a successor attempt has closed', async db => {
    await beginOAuth(db);
    await issueRecovery(db);
    assert.deepEqual(await recoverOAuth(db), recovered);
    assert.equal((await beginNewOAuth(db)).kind, 'begun');
    assert.equal((await oauthRpc(db, 6, [a.browserSecret, newer.flow, newer.attempt, null, a.close,
      a.fingerprint, null, null, null, null, null])).kind, 'closed');
    assert.deepEqual(await recoverOAuth(db), denied);
  }],
  ['rejects a replay after receipt expiry or browser generation change', async db => {
    await beginOAuth(db);
    await issueRecovery(db);
    assert.deepEqual(await recoverOAuth(db), recovered);
    await db.query('UPDATE jls_auth.browser_bindings SET generation=1');
    assert.deepEqual(await recoverOAuth(db), denied);
    await db.query('UPDATE jls_auth.browser_bindings SET generation=0');
    await db.query(`UPDATE jls_auth.oauth_recovery_receipts SET committed_at=clock_timestamp()-interval '1 minute',
      expires_at=clock_timestamp()`);
    assert.deepEqual(await recoverOAuth(db), denied);
  }],
  ['waits for a live claimant and abandons it only after expiry', async db => {
    const flow = await beginOAuth(db);
    assert.equal((await flow.claim()).kind, 'claimed');
    await issueRecovery(db);
    assert.deepEqual(await recoverOAuth(db), inProgress);
    await expireOAuth(db);
    assert.deepEqual(await recoverOAuth(db), recovered);
    assert.equal((await flow.sent()).kind, 'restart_required');
    assert.deepEqual((await db.query('SELECT * FROM jls_auth.oauth_exchange_expirations')).rows, []);
  }],
  ['settles an expired exchange and retains a verified late candidate for its exact claimant', async db => {
    const flow = await beginOAuth(db);
    assert.equal((await flow.claim()).kind, 'claimed');
    assert.equal((await flow.sent()).kind, 'send_intent');
    await issueRecovery(db);
    assert.deepEqual(await recoverOAuth(db), inProgress);
    await expireOAuth(db);
    assert.deepEqual(await recoverOAuth(db), recovered);
    assert.deepEqual((await db.query('SELECT attempt_id,state FROM jls_auth.oauth_exchange_expirations')).rows,
      [{ attempt_id: a.attempt, state: 'credential_unavailable' }]);
    assert.equal((await beginNewOAuth(db)).kind, 'begun');
    assert.equal((await flow.sent()).kind, 'restart_required');
    assert.equal((await flow.commit()).kind, 'denied');
    assert.equal((await flow.close({ 3: a.close })).kind, 'denied');
    assert.equal((await flow.close()).kind, 'closed');
    assert.equal((await flow.close()).kind, 'closed');
    assert.deepEqual((await db.query('SELECT attempt_id,state FROM jls_auth.candidate_cleanup_work')).rows,
      [{ attempt_id: a.attempt, state: 'pending' }]);
  }],
  ['lets a proof-bound fresh begin settle an expired exchange without its lost flow cookie', async db => {
    const flow = await beginOAuth(db);
    assert.equal((await flow.claim()).kind, 'claimed');
    assert.equal((await flow.sent()).kind, 'send_intent');
    assert.equal((await beginNewOAuth(db)).kind, 'restart_required');
    await expireOAuth(db);
    assert.equal((await beginNewOAuth(db)).kind, 'begun');
    assert.deepEqual((await db.query('SELECT attempt_id,state FROM jls_auth.oauth_exchange_expirations')).rows,
      [{ attempt_id: a.attempt, state: 'credential_unavailable' }]);
    assert.equal((await flow.close()).kind, 'closed');
  }],
  ['keeps a late candidate from revoking an upstream identity used by a successor', async db => {
    const flow = await beginOAuth(db);
    assert.equal((await flow.claim()).kind, 'claimed');
    assert.equal((await flow.sent()).kind, 'send_intent');
    await expireOAuth(db);
    assert.equal((await beginNewOAuth(db)).kind, 'begun');
    assert.equal((await oauthRpc(db, 2, [a.browserSecret, newer.flow, newer.attempt, a.cleanupClaim])).kind, 'claimed');
    assert.equal((await oauthRpc(db, 3, [a.browserSecret, newer.flow, newer.attempt, a.cleanupClaim])).kind, 'send_intent');
    assert.equal((await flow.commit({ 1: newer.flow, 2: newer.attempt, 3: a.cleanupClaim })).kind, 'committed');
    assert.equal((await flow.close()).kind, 'closed');
    assert.deepEqual((await db.query('SELECT attempt_id,state,error_category FROM jls_auth.candidate_cleanup_work')).rows,
      [{ attempt_id: a.attempt, state: 'skipped', error_category: 'identity_in_use' }]);
    assert.deepEqual((await db.query('SELECT revoked_at IS NOT NULL AS revoked FROM jls_auth.app_sessions')).rows,
      [{ revoked: false }]);
  }],
  ['protects an unacknowledged result during delivery grace and retires only its exact pointer afterwards', async db => {
    await complete(db);
    await issueRecovery(db);
    assert.deepEqual(await recoverOAuth(db), inProgress);
    await ageDelivery(db);
    assert.deepEqual(await recoverOAuth(db), recovered);
    assert.deepEqual(await recoverOAuth(db), recovered);
    assert.deepEqual((await db.query(`SELECT b.generation::int,b.current_session_id,a.state,
      s.revoked_at IS NOT NULL AS revoked,w.state AS cleanup
      FROM jls_auth.browser_bindings b JOIN jls_auth.oauth_attempts a USING (browser_id)
      JOIN jls_auth.app_sessions s ON s.session_id=a.resulting_session_id JOIN jls_auth.cleanup_work w USING (session_id)`)).rows,
    [{ generation: 2, current_session_id: null, state: 'retired', revoked: true, cleanup: 'pending' }]);
    assert.equal((await oauthRpc(db, 11, [a.secret, a.browserSecret, 0])).kind, 'denied');
  }],
  ['accepts a malformed present cookie fingerprint without mistaking it for an authenticated bearer', async db => {
    await complete(db);
    await issueRecovery(db, { fingerprint: a.cookie });
    await ageDelivery(db);
    assert.deepEqual(await recoverOAuth(db, { 3: a.cookie }), recovered);
  }],
  ['protects the exact current bearer even when its delivery is still unacknowledged', async db => {
    await complete(db);
    await issueRecovery(db, { fingerprint: a.cookie, sessionHash: a.secret });
    await ageDelivery(db);
    assert.deepEqual(await recoverOAuth(db, { 3: a.cookie, 4: a.secret }), denied);
  }],
  ['protects acknowledged delivery from a separately valid recovery proof', async db => {
    await complete(db);
    await issueRecovery(db);
    await ageDelivery(db);
    assert.equal((await oauthRpc(db, 11, [a.secret, a.browserSecret, 0])).kind, 'acknowledged');
    assert.deepEqual(await recoverOAuth(db), denied);
  }],
  ['rolls back retirement and proof consumption when the recovery receipt fails', async db => {
    await complete(db);
    await issueRecovery(db);
    await ageDelivery(db);
    await db.query('ALTER TABLE jls_auth.oauth_recovery_receipts ADD CONSTRAINT fixture_reject_receipt CHECK (false) NOT VALID');
    try { await assert.rejects(recoverOAuth(db), { code: '23514' }); }
    finally { await db.query('ALTER TABLE jls_auth.oauth_recovery_receipts DROP CONSTRAINT fixture_reject_receipt'); }
    assert.deepEqual((await db.query(`SELECT b.generation::int,b.current_session_id,a.state,
      s.revoked_at IS NOT NULL AS revoked,p.consumed_at IS NOT NULL AS consumed
      FROM jls_auth.browser_bindings b JOIN jls_auth.oauth_attempts a USING (browser_id)
      JOIN jls_auth.app_sessions s ON s.session_id=a.resulting_session_id
      JOIN jls_auth.csrf_proofs p ON p.proof_id=$1`, [recovery.proof])).rows,
    [{ generation: 1, current_session_id: a.session, state: 'completed', revoked: false, consumed: false }]);
    assert.deepEqual((await db.query('SELECT * FROM jls_auth.cleanup_work')).rows, []);
    assert.deepEqual(await recoverOAuth(db), recovered);
  }],
  ['protects the prior result while its successor attempt is open', async db => {
    await complete(db);
    await issueRecovery(db);
    await ageDelivery(db);
    assert.equal((await beginNewOAuth(db)).kind, 'begun');
    assert.deepEqual(await recoverOAuth(db), denied);
    assert.deepEqual((await db.query('SELECT generation::int,current_session_id FROM jls_auth.browser_bindings')).rows,
      [{ generation: 1, current_session_id: a.session }]);
  }],
  ['protects the prior result after its successor attempt has closed', async db => {
    await complete(db);
    await issueRecovery(db);
    await ageDelivery(db);
    assert.equal((await beginNewOAuth(db)).kind, 'begun');
    assert.equal((await oauthRpc(db, 6, [a.browserSecret, newer.flow, newer.attempt, null, a.close,
      a.fingerprint, null, null, null, null, null])).kind, 'closed');
    assert.deepEqual(await recoverOAuth(db), denied);
    assert.deepEqual((await db.query('SELECT generation::int,current_session_id FROM jls_auth.browser_bindings')).rows,
      [{ generation: 1, current_session_id: a.session }]);
  }],
  ['restricts recovery and receipt metadata to the service role', async db => {
    await beginOAuth(db);
    await issueRecovery(db);
    for (const role of ['anon', 'authenticated', 'jls_refresh_rls_probe'] as const) {
      await assert.rejects(recoverOAuth(db, {}, role), { code: '42501' });
    }
    const metadata = (await db.query(`SELECT prosecdef AS definer,proconfig AS config FROM pg_proc
      WHERE oid='public.jls_auth_recover_login_v1(text,text,text,text,text)'::regprocedure`)).rows[0];
    assert.equal(metadata.definer, false);
    assert.deepEqual(metadata.config, ['search_path=""', 'lock_timeout=250ms']);
    for (const table of ['oauth_recovery_receipts', 'oauth_exchange_expirations']) {
      assert.deepEqual((await db.query(`SELECT relrowsecurity,relforcerowsecurity,
        has_table_privilege('authenticated',oid,'SELECT') AS authenticated_read,
        has_table_privilege('anon',oid,'SELECT') AS anon_read FROM pg_class WHERE oid=$1::regclass`, [`jls_auth.${table}`])).rows,
      [{ relrowsecurity: true, relforcerowsecurity: true, authenticated_read: false, anon_read: false }]);
    }
  }],
];
