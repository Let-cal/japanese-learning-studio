import assert from 'node:assert/strict';
import { REFRESH, refreshRpc } from './refreshFixture';

type ConfirmDb = Parameters<typeof refreshRpc>[0];
type FixtureRole = Parameters<typeof refreshRpc>[3];

export const confirmSession = (db: ConfirmDb, role?: FixtureRole) => refreshRpc(db, 'confirm',
  [REFRESH.secret, REFRESH.browserSecret, 0, 0, REFRESH.epoch, REFRESH.subject, REFRESH.upstream], role);

export async function prepareConfirm(db: ConfirmDb) {
  await db.query("UPDATE jls_auth.session_credentials SET access_expires_at=clock_timestamp()+interval '1 hour'");
}

const delivery = `SELECT delivery_state, delivery_acknowledged_at::text, last_activity_at::text
  FROM jls_auth.app_sessions`;

export const authConfirmCases: [string, (db: ConfirmDb) => Promise<void>][] = [
  ...([
    ['a different managed session for the same subject', 'UPDATE auth.sessions SET id=$1', [REFRESH.other]],
    ['the exact managed session with a different subject', 'UPDATE auth.sessions SET user_id=$1', [REFRESH.other]],
    ['an expired managed session', "UPDATE auth.sessions SET not_after=clock_timestamp()-interval '1 second'", []],
  ] as const).map(([reason, sql, params]): [string, (db: ConfirmDb) => Promise<void>] => [
    `denies confirmation with ${reason}`,
    async db => {
      await prepareConfirm(db);
      await db.query(sql, [...params]);
      const before = (await db.query(delivery)).rows;
      assert.deepEqual(await confirmSession(db), { kind: 'denied' });
      assert.deepEqual((await db.query(delivery)).rows, before);
    },
  ]),
  ['acknowledges the exact live managed session without extending activity, then denies after deletion', async db => {
    await prepareConfirm(db);
    const before = (await db.query(delivery)).rows[0];
    const expected = {
      kind: 'confirmed',
      context: { ownerId: REFRESH.owner, authSubject: REFRESH.subject, sessionId: REFRESH.session, datasetEpoch: REFRESH.epoch },
      tokenVersion: 0, controlVersion: 0, browserGeneration: 0,
    };
    assert.deepEqual(await confirmSession(db), expected);
    const acknowledged = (await db.query(delivery)).rows[0];
    assert.equal(acknowledged?.delivery_state, 'acknowledged');
    assert.equal(typeof acknowledged?.delivery_acknowledged_at, 'string');
    assert.equal(acknowledged?.last_activity_at, before?.last_activity_at);
    await db.query("UPDATE auth.sessions SET not_after=clock_timestamp()+interval '1 hour'");
    assert.deepEqual(await confirmSession(db), expected);
    assert.deepEqual((await db.query(delivery)).rows, [acknowledged]);
    await db.query('DELETE FROM auth.sessions');
    assert.deepEqual(await confirmSession(db), { kind: 'denied' });
    assert.deepEqual((await db.query(delivery)).rows, [acknowledged]);
  }],
  ['preserves service-only invoker access to confirmation', async db => {
    await prepareConfirm(db);
    for (const role of ['anon', 'authenticated', 'jls_refresh_rls_probe'] as const) {
      await assert.rejects(() => confirmSession(db, role), { code: '42501' });
    }
    const configurations = (await db.query(`SELECT n.nspname, p.prosecdef, p.proconfig,
      has_function_privilege('service_role',p.oid,'EXECUTE') AS service
      FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE (n.nspname='public' AND p.proname='jls_auth_confirm_session_v1')
        OR (n.nspname='jls_auth' AND p.proname='confirm_session')
      ORDER BY n.nspname`)).rows;
    assert.deepEqual(configurations, [
      { nspname: 'jls_auth', prosecdef: false, proconfig: ['search_path=""', 'lock_timeout=250ms'], service: true },
      { nspname: 'public', prosecdef: false, proconfig: ['search_path=""'], service: true },
    ]);
  }],
];
