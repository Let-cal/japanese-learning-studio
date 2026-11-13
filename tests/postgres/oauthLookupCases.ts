import assert from 'node:assert/strict';
import { oauthFlow, oauthRpc, OAUTH, type OAuthDatabase } from './oauthLifecycleFixture';
import { oauthLookupSignatures, refreshRpc } from './refreshFixture';

const a = OAUTH;
const denied = { kind: 'denied' };
const restart = { kind: 'restart_required' };
const absent = { kind: 'absent_or_expired' };
const active = { kind: 'active', browserId: a.browser, generation: 0 };
const pending = { kind: 'pending', attemptId: a.attempt, browserId: a.browser };
const completed = { kind: 'completed_with_cookie', attemptId: a.attempt, sessionId: a.session, generation: 1 };
const resolved = { kind: 'resolved', browserId: a.browser, operationId: a.operation, generation: 0 };
const logoutReplay = { ...resolved, generation: 1 };

async function lookup(
  db: OAuthDatabase,
  name: keyof typeof oauthLookupSignatures,
  args: (string | null)[],
  role: 'service_role' | 'anon' | 'authenticated' | 'jls_refresh_rls_probe' = 'service_role',
): Promise<unknown> {
  const nameOnly = oauthLookupSignatures[name].split('(')[0];
  await db.query('BEGIN READ ONLY');
  try {
    await db.query(`SET LOCAL ROLE ${role}`);
    const result = (await db.query(
      `SELECT public.${nameOnly}(${args.map((_, index) => `$${index + 1}`).join(',')}) AS result`, args,
    )).rows[0].result;
    await db.query('COMMIT');
    return result;
  } catch (cause) {
    try { await db.query('ROLLBACK'); }
    catch (rollback) { throw new AggregateError([cause, rollback], 'OAuth lookup and rollback failed.'); }
    throw cause;
  }
}

const browser = (db: OAuthDatabase, hash: string | null = a.browserSecret) => lookup(db, 'browser', [hash]);
const action = (
  db: OAuthDatabase,
  purpose: string | null,
  fingerprint: string | null = 'absent',
  browserHash: string | null = a.browserSecret,
  proofHash: string | null = a.proofSecret,
) => lookup(db, 'action', [browserHash, proofHash, purpose, fingerprint]);
const callback = (
  db: OAuthDatabase,
  sessionHash: string | null = null,
  browserHash: string | null = a.browserSecret,
  flowHash: string | null = a.flow,
) => lookup(db, 'callback', [browserHash, flowHash, sessionHash]);

async function begin(db: OAuthDatabase) {
  const flow = oauthFlow(db);
  assert.equal((await flow.issue()).kind, 'issued');
  assert.equal((await flow.begin()).kind, 'begun');
  return flow;
}

async function complete(db: OAuthDatabase) {
  const flow = await begin(db);
  assert.equal((await flow.claim()).kind, 'claimed');
  assert.equal((await flow.sent()).kind, 'send_intent');
  assert.equal((await flow.commit()).kind, 'committed');
}

export const oauthLookupCases: readonly [name: string, withSession: boolean, run: (db: OAuthDatabase) => Promise<void>][] = [
  ['resolves only an exact unexpired browser hash', true, async db => {
    assert.deepEqual(await browser(db), active);
    assert.deepEqual(await browser(db, a.proofSecret), absent);
    assert.deepEqual(await browser(db, a.browserSecret.toUpperCase()), absent);
    assert.deepEqual(await browser(db, null), absent);
    await db.query(`UPDATE jls_auth.browser_bindings SET created_at=clock_timestamp()-interval '1 day', expires_at=clock_timestamp()`);
    assert.deepEqual(await browser(db), absent);
  }],
  ['resolves only the fresh login proof with exact purpose, browser and cookie binding', false, async db => {
    const flow = oauthFlow(db);
    assert.equal((await flow.issue({ 7: a.cookie })).kind, 'issued');
    assert.deepEqual(await action(db, 'login', a.cookie), resolved);
    assert.deepEqual(await action(db, 'login'), denied);
    assert.deepEqual(await action(db, 'login', null), denied);
    assert.deepEqual(await action(db, 'login', a.cookie, a.proofSecret), denied);
    assert.deepEqual(await action(db, 'login', a.cookie, a.browserSecret, a.browserSecret), denied);
    assert.deepEqual(await action(db, 'logout', a.cookie), denied);
    assert.deepEqual(await action(db, 'mutation', a.cookie), denied);
    assert.deepEqual(await action(db, null, a.cookie), denied);
    assert.equal((await flow.begin({ 3: a.cookie })).kind, 'begun');
    assert.deepEqual(await action(db, 'login', a.cookie), denied);
  }],
  ['rejects login proofs outside the database time window and browser generation', false, async db => {
    assert.equal((await oauthFlow(db).issue()).kind, 'issued');
    await db.query(`UPDATE jls_auth.csrf_proofs SET issued_at=clock_timestamp()+interval '1 minute',
      expires_at=clock_timestamp()+interval '2 minutes'`);
    assert.deepEqual(await action(db, 'login'), denied);
    await db.query(`UPDATE jls_auth.csrf_proofs SET issued_at=clock_timestamp()-interval '1 minute',
      expires_at=clock_timestamp()`);
    assert.deepEqual(await action(db, 'login'), denied);
    await db.query(`UPDATE jls_auth.csrf_proofs SET expires_at=clock_timestamp()+interval '1 minute'`);
    await db.query('UPDATE jls_auth.browser_bindings SET generation=1');
    assert.deepEqual(await action(db, 'login'), denied);
  }],
  ['requires the current session pointer for a fresh bound logout proof', true, async db => {
    assert.deepEqual(await action(db, 'logout', a.cookie), resolved);
    assert.deepEqual(await action(db, 'logout'), denied);
    await db.query('UPDATE jls_auth.browser_bindings SET current_session_id=NULL');
    assert.deepEqual(await action(db, 'logout', a.cookie), denied);
  }],
  ['requires explicit cookie absence for a fresh logout proof without a session', false, async db => {
    const flow = oauthFlow(db);
    assert.equal((await flow.issue({ 6: 'logout', 7: a.cookie })).kind, 'issued');
    assert.deepEqual(await action(db, 'logout', a.cookie), denied);
    await db.query(`UPDATE jls_auth.csrf_proofs SET cookie_fingerprint='absent'`);
    assert.deepEqual(await action(db, 'logout'), resolved);
    assert.deepEqual(await action(db, 'logout', null), denied);
  }],
  ['resolves an exact retained logout operation after proof expiry until receipt expiry', true, async db => {
    assert.equal((await refreshRpc(db, 'logout', [a.browserSecret, a.proofSecret, a.operation, a.cookie])).kind, 'logged_out');
    await db.query(`UPDATE jls_auth.csrf_proofs SET issued_at=clock_timestamp()-interval '1 minute',
      expires_at=clock_timestamp()`);
    assert.deepEqual(await action(db, 'logout', a.cookie), logoutReplay);
    assert.deepEqual(await action(db, 'logout'), logoutReplay);
    assert.deepEqual(await action(db, 'logout', `present:${a.proofSecret}`), denied);
    assert.deepEqual(await action(db, 'logout', 'absent', a.browserSecret, a.secret), denied);
    await db.query(`UPDATE jls_auth.action_receipts SET committed_at=clock_timestamp()-interval '1 minute', expires_at=clock_timestamp()`);
    assert.deepEqual(await action(db, 'logout'), denied);
  }],
  ['rejects a logout replay after the browser pointer or generation changes', true, async db => {
    assert.equal((await refreshRpc(db, 'logout', [a.browserSecret, a.proofSecret, a.operation, a.cookie])).kind, 'logged_out');
    await db.query('UPDATE jls_auth.browser_bindings SET current_session_id=$1', [a.session]);
    assert.deepEqual(await action(db, 'logout'), denied);
    await db.query('UPDATE jls_auth.browser_bindings SET generation=2,current_session_id=NULL');
    assert.deepEqual(await action(db, 'logout'), denied);
  }],
  ['binds the callback to its exact browser and flow and rejects malformed session hashes', false, async db => {
    await begin(db);
    assert.deepEqual(await callback(db), pending);
    assert.deepEqual(await callback(db, a.secret), pending);
    for (const value of ['', 'absent', a.secret.toUpperCase(), `${a.secret}\n`]) {
      assert.deepEqual(await callback(db, value), denied);
    }
    assert.deepEqual(await callback(db, null, a.proofSecret), denied);
    assert.deepEqual(await callback(db, null, a.browserSecret, a.proofSecret), denied);
    assert.deepEqual(await callback(db, null, a.browserSecret, null), denied);
  }],
  ['rejects a reauthentication flow in the login callback lookup', false, async db => {
    await begin(db);
    await db.query("UPDATE jls_auth.oauth_attempts SET purpose='reauthentication'");
    assert.deepEqual(await callback(db), denied);
  }],
  ['reports another callback worker without disclosing its claim or verifier', false, async db => {
    const flow = await begin(db);
    assert.equal((await flow.claim()).kind, 'claimed');
    assert.deepEqual(await callback(db), { kind: 'in_progress' });
    assert.equal((await flow.sent()).kind, 'send_intent');
    assert.deepEqual(await callback(db), { kind: 'in_progress' });
    await db.query(`UPDATE jls_auth.oauth_attempts SET issued_at=clock_timestamp()-interval '1 minute', expires_at=clock_timestamp()`);
    assert.deepEqual(await callback(db), restart);
  }],
  ['restarts a known pending callback after owner fencing changes or cancellation', false, async db => {
    await begin(db);
    await db.query('UPDATE jls_auth.owner_control SET control_version=control_version+1');
    assert.deepEqual(await callback(db), restart);
    await db.query('UPDATE jls_auth.owner_control SET control_version=control_version-1');
    await db.query("UPDATE jls_auth.oauth_attempts SET state='cancelled'");
    assert.deepEqual(await callback(db), restart);
  }],
  ['reports a completed callback only with its exact current unrevoked session cookie', false, async db => {
    await complete(db);
    assert.deepEqual(await callback(db, a.secret), completed);
    assert.deepEqual(await callback(db), restart);
    assert.deepEqual(await callback(db, a.proofSecret), restart);
    assert.deepEqual(await callback(db, ''), denied);
    assert.equal((await oauthRpc(db, 11, [a.secret, a.browserSecret, 0])).kind, 'acknowledged');
    assert.deepEqual(await callback(db, a.secret), completed);
    await db.query('UPDATE jls_auth.app_sessions SET revoked_at=clock_timestamp()');
    assert.deepEqual(await callback(db, a.secret), restart);
  }],
  ['restarts a completed callback once its browser generation changes', false, async db => {
    await complete(db);
    await db.query('UPDATE jls_auth.browser_bindings SET generation=2');
    assert.deepEqual(await callback(db, a.secret), restart);
  }],
  ['reports no metadata to anon, authenticated or an unrelated role', true, async db => {
    for (const role of ['anon', 'authenticated', 'jls_refresh_rls_probe'] as const) {
      await assert.rejects(lookup(db, 'browser', [a.browserSecret], role), { code: '42501' });
      await assert.rejects(lookup(db, 'action', [a.browserSecret, a.proofSecret, 'logout', a.cookie], role), { code: '42501' });
      await assert.rejects(lookup(db, 'callback', [a.browserSecret, a.flow, null], role), { code: '42501' });
    }
  }],
];
