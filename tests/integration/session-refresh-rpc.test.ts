import { describe, expect, it, vi } from 'vitest';
import { createSessionRuntimeRepository } from '../../src/infrastructure/auth/sessionRuntimeRepository';
import { hashAuthActionSecret } from '../../src/infrastructure/auth/authActionSecrets';
import { hashSessionSecret } from '../../src/infrastructure/auth/sessionSecrets';

const config = {
  supabaseOrigin: 'https://abcdefghijklmnopqrst.supabase.co',
  secretKey: 'sb_secret_fixture_only_1234567890123456',
};
const uuid = (digit: string) => `${digit.repeat(8)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(12)}`;
const sessionSecret = 'A'.repeat(43);
const browserSecret = `jls-browser-v1.${sessionSecret}`;
const envelope = `v1.fixture.${'A'.repeat(16)}.${'A'.repeat(64)}.${'A'.repeat(22)}`;
const base = {
  sessionSecret, browserSecret, attemptId: uuid('a'), requestFingerprint: 'a'.repeat(64),
  sessionId: uuid('1'), browserId: uuid('2'), browserGeneration: 4, ownerId: uuid('3'),
  authSubject: uuid('4'), upstreamSessionId: uuid('5'), tokenVersion: 7,
  controlVersion: 9, datasetEpoch: uuid('6'),
};
const finish = {
  ...base, finishOperationId: uuid('b'), finishFingerprint: 'b'.repeat(64), verifiedAuthSubject: base.authSubject,
  verifiedUpstreamSessionId: base.upstreamSessionId, tokenEnvelope: envelope, accessExpiresAt: 1_800_000_010_000,
};
const close = {
  ...base, closeOperationId: uuid('c'), closeFingerprint: 'c'.repeat(64), disposition: 'pre_send',
};
const args = {
  p_session_secret_hash: hashSessionSecret(sessionSecret), p_browser_secret_hash: hashAuthActionSecret('browser', browserSecret),
  p_attempt_id: base.attemptId, p_request_fingerprint: base.requestFingerprint, p_session_id: base.sessionId,
  p_browser_id: base.browserId, p_browser_generation: base.browserGeneration, p_owner_id: base.ownerId,
  p_auth_subject: base.authSubject, p_upstream_session_id: base.upstreamSessionId, p_expected_token_version: base.tokenVersion,
  p_expected_control_version: base.controlVersion, p_expected_dataset_epoch: base.datasetEpoch,
};
const finishArgs = {
  ...args, p_finish_operation_id: finish.finishOperationId, p_finish_fingerprint: finish.finishFingerprint,
  p_verified_subject: base.authSubject, p_verified_upstream_session_id: base.upstreamSessionId,
  p_token_envelope: envelope, p_access_expires_at: new Date(finish.accessExpiresAt).toISOString(),
};
const claimed = { kind: 'claimed', attemptId: base.attemptId, tokenEnvelope: envelope, leaseExpiresAt: 1_800_000_025_000 };
const committed = { kind: 'committed', attemptId: base.attemptId, sessionId: base.sessionId, tokenVersion: 8 };
const json = (data: unknown) => new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });

describe('fixed refresh control RPCs', () => {
  const cases = [
    ['claimRefresh', 'claim', base, args, claimed],
    ['markRefreshSent', 'mark_sent', base, args, { kind: 'transmit' }],
    ['finishRefresh', 'finish', finish, finishArgs, committed],
    ['resolveRefresh', 'resolve', finish, finishArgs, committed],
    ['closeRefresh', 'close', close, { ...args, p_close_operation_id: close.closeOperationId,
      p_close_fingerprint: close.closeFingerprint, p_disposition: 'pre_send', p_verified_subject: null,
      p_verified_upstream_session_id: null, p_token_envelope: null }, { kind: 'released' }],
  ] as const;

  it.each(cases)('%s forwards only its fixed RPC and arguments', async (method, rpc, input, expectedArgs, reply) => {
    const fetcher = vi.fn<typeof fetch>(async () => json(reply));
    const repository = createSessionRuntimeRepository(config, fetcher);
    const result = await repository[method](input);

    expect(result).toEqual(reply);
    expect(Object.isFrozen(result)).toBe(true);
    expect(fetcher).toHaveBeenCalledOnce();
    const [destination, options] = fetcher.mock.calls[0];
    expect(destination).toBe(`${config.supabaseOrigin}/rest/v1/rpc/jls_auth_refresh_${rpc}_v1`);
    expect(options).toMatchObject({ method: 'POST', credentials: 'omit', cache: 'no-store', redirect: 'error' });
    expect(new Headers(options?.headers).get('apikey')).toBe(config.secretKey);
    expect(new Headers(options?.headers).has('Authorization')).toBe(false);
    expect(JSON.parse(String(options?.body))).toEqual(expectedArgs);
  });

  it('refuses misbound or malformed inputs without contacting the database', async () => {
    const fetcher = vi.fn<typeof fetch>(async () => json({ kind: 'denied' }));
    const repository = createSessionRuntimeRepository(config, fetcher);
    expect(await repository.claimRefresh({ ...base, requestFingerprint: 'garbage' })).toEqual({ kind: 'invalid_input' });
    expect(await repository.markRefreshSent({ ...base, path: '/rest/v1' })).toEqual({ kind: 'invalid_input' });
    expect(await repository.finishRefresh({ ...finish, verifiedUpstreamSessionId: uuid('f') })).toEqual({ kind: 'invalid_input' });
    expect(await repository.resolveRefresh({ ...finish, accessExpiresAt: Number.MAX_SAFE_INTEGER })).toEqual({ kind: 'invalid_input' });
    expect(await repository.closeRefresh({ ...close, disposition: 'unknown', tokenEnvelope: envelope })).toEqual({ kind: 'invalid_input' });
    expect(await repository.closeRefresh({ ...close, disposition: 'late_pair' })).toEqual({ kind: 'invalid_input' });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('binds a late pair to the same verified subject and upstream session', async () => {
    const fetcher = vi.fn<typeof fetch>(async () => json({ kind: 'late_pair_retained' }));
    const repository = createSessionRuntimeRepository(config, fetcher);
    const late = { ...close, disposition: 'late_pair', verifiedAuthSubject: base.authSubject,
      verifiedUpstreamSessionId: base.upstreamSessionId, tokenEnvelope: envelope };
    expect(await repository.closeRefresh({ ...late, verifiedAuthSubject: uuid('f') })).toEqual({ kind: 'invalid_input' });
    expect(await repository.closeRefresh(late)).toEqual({ kind: 'late_pair_retained' });
    expect(fetcher).toHaveBeenCalledOnce();
    expect(JSON.parse(String(fetcher.mock.calls[0][1]?.body))).toMatchObject({
      p_disposition: 'late_pair', p_verified_subject: base.authSubject, p_verified_upstream_session_id: base.upstreamSessionId,
      p_token_envelope: envelope,
    });
  });

  it('refuses a success tag that belongs to a different close disposition', async () => {
    const fetcher = vi.fn<typeof fetch>().mockImplementationOnce(async () => json({ kind: 'released' }))
      .mockImplementationOnce(async () => json({ kind: 'late_pair_retained' }));
    const repository = createSessionRuntimeRepository(config, fetcher);

    expect(await repository.closeRefresh({ ...close, disposition: 'unknown' }))
      .toEqual({ kind: 'outcome_unknown', reason: 'invalid_response' });
    expect(await repository.closeRefresh(close)).toEqual({ kind: 'outcome_unknown', reason: 'invalid_response' });
  });

  it.each([
    { ...committed, tokenVersion: 9 },
    { ...committed, attemptId: uuid('f') },
    { ...committed, sessionId: uuid('f') },
    { ...committed, tokenEnvelope: envelope },
  ])('refuses unexpected commit receipt fields or bindings %#', async receipt => {
    const repository = createSessionRuntimeRepository(config, async () => json(receipt));
    expect(await repository.finishRefresh(finish)).toEqual({ kind: 'outcome_unknown', reason: 'invalid_response' });
    expect(await repository.resolveRefresh(finish)).toEqual({ kind: 'unavailable', reason: 'invalid_response' });
  });

  it('keeps an unreadable send marker distinct from permission to transmit', async () => {
    const fetcher = vi.fn<typeof fetch>().mockRejectedValueOnce(new Error('private diagnostic'))
      .mockImplementationOnce(async () => json({ kind: 'already_sent' }));
    const repository = createSessionRuntimeRepository(config, fetcher);

    expect(await repository.markRefreshSent(base)).toEqual({ kind: 'outcome_unknown', reason: 'transport' });
    expect(fetcher).toHaveBeenCalledOnce();
    expect(await repository.markRefreshSent(base)).toEqual({ kind: 'already_sent' });
  });

  it('refuses a claim envelope bound to another attempt', async () => {
    const repository = createSessionRuntimeRepository(config, async () => json({ ...claimed, attemptId: uuid('f') }));
    expect(await repository.claimRefresh(base)).toEqual({ kind: 'outcome_unknown', reason: 'invalid_response' });
  });

  it('returns unknown instead of transmit when cancellation races the reply', async () => {
    const controller = new AbortController();
    const clock = vi.fn().mockReturnValue(0);
    for (let check = 0; check < 4; check++) clock.mockReturnValueOnce(0);
    clock.mockImplementationOnce(() => { queueMicrotask(() => controller.abort()); return 0; });
    const fetcher = vi.fn<typeof fetch>(async () => json({ kind: 'transmit' }));
    const repository = createSessionRuntimeRepository(config, fetcher, clock);

    expect(await repository.markRefreshSent(base, controller.signal)).toEqual({ kind: 'outcome_unknown', reason: 'cancelled' });
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it('does not record a send marker when cancellation occurs during preflight', async () => {
    const controller = new AbortController();
    const fetcher = vi.fn<typeof fetch>(async () => json({ kind: 'transmit' }));
    const repository = createSessionRuntimeRepository(config, fetcher, () => {
      controller.abort();
      return 0;
    });

    expect(await repository.markRefreshSent(base, controller.signal)).toEqual({ kind: 'unavailable', reason: 'cancelled' });
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe('local-scope session cleanup RPCs', () => {
  const sessionId = base.sessionId;
  const claimId = uuid('d');
  const claim = { sessionId, claimId };
  const reply = { kind: 'cleanup', sessionId, claimId, revision: 1, scope: 'local',
    ownerId: base.ownerId, authSubject: base.authSubject, upstreamSessionId: base.upstreamSessionId, tokenEnvelope: envelope };

  it('uses fixed claim and completion RPCs without any client-selected signout scope', async () => {
    const fetcher = vi.fn<typeof fetch>().mockImplementationOnce(async () => json(reply))
      .mockImplementationOnce(async () => json({ kind: 'completed' }));
    const repository = createSessionRuntimeRepository(config, fetcher);
    expect(await repository.claimSessionCleanup(claim)).toEqual(reply);
    expect(await repository.completeSessionCleanup({ ...claim, revision: 1, outcome: 'completed' })).toEqual({ kind: 'completed' });
    expect(fetcher.mock.calls.map(([url, options]) => [url, JSON.parse(String(options?.body))])).toEqual([
      [config.supabaseOrigin + '/rest/v1/rpc/jls_auth_session_cleanup_claim_v1', { p_session_id: sessionId, p_claim_id: claimId }],
      [config.supabaseOrigin + '/rest/v1/rpc/jls_auth_session_cleanup_complete_v1',
        { p_session_id: sessionId, p_claim_id: claimId, p_revision: 1, p_outcome: 'completed' }],
    ]);
  });

  it.each([{ scope: 'global' }, { claimId: uuid('f') }, { sessionId: uuid('f') }, { revision: -1 }, { ownerId: undefined }])
    ('does not trust misbound cleanup authority %#', async overrides => {
      const repository = createSessionRuntimeRepository(config, async () => json({ ...reply, ...overrides }));
      expect(await repository.claimSessionCleanup(claim)).toEqual({ kind: 'outcome_unknown', reason: 'invalid_response' });
    });

  it('refuses missing revision and unknown outcomes before requesting completion', async () => {
    const fetcher = vi.fn<typeof fetch>();
    const repository = createSessionRuntimeRepository(config, fetcher);
    expect(await repository.completeSessionCleanup({ ...claim, outcome: 'completed' })).toEqual({ kind: 'invalid_input' });
    expect(await repository.completeSessionCleanup({ ...claim, revision: 1, outcome: 'global' })).toEqual({ kind: 'invalid_input' });
    expect(fetcher).not.toHaveBeenCalled();
  });
});
