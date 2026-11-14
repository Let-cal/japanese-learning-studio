import { describe, expect, it, vi } from 'vitest';
import { createGoogleOAuthRuntime } from '../../src/application/auth/googleOAuthRuntime';
import { createGoogleOAuthHttp } from '../../src/application/auth/googleOAuthHttp';
import { createOwnerSessionVerifier } from '../../src/application/auth/ownerSession';
import { encryptUpstreamTokens } from '../../src/infrastructure/auth/tokenEnvelope';
import type { RuntimeSnapshot, SessionRuntimeRepository } from '../../src/infrastructure/auth/sessionRuntimeRepository';
import type { AuthIdentityVerifier } from '../../src/infrastructure/auth/authAdapter';

vi.mock('server-only', () => ({}));

const now = 1_800_000_000_000;
const expires = now + 60_000;
const uid = (digit: string) => `${digit.repeat(8)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(12)}`;
const ownerId = uid('1'), authSubject = uid('2'), sessionId = uid('3'), upstreamSessionId = uid('4'), datasetEpoch = uid('5');
const context = { ownerId, authSubject, sessionId, datasetEpoch };
const input = { sessionSecret: 'A'.repeat(43), browserSecret: `jls-browser-v1.${'E'.repeat(43)}` };
const configuration = { environment: 'fixture', sessionTokenKey: { keyId: 'fixture', keyBytes: new Uint8Array(32).fill(7) } };
const facts = { ...context, upstreamSessionId, tokenVersion: 7, controlVersion: 9, browserGeneration: 10 };
const tokenPair = { accessToken: 'fixture.access.jwt', refreshToken: 'fixture_refresh' };
const validSnapshot = (): RuntimeSnapshot => ({
  kind: 'snapshot', now,
  session: { sessionId, ownerId, authSubject, upstreamSessionId, createdAt: now - 1000, lastActivityAt: now - 200,
    revokedAt: null, reauthenticatedAt: null, deliveryState: 'unacknowledged', deliveryAcknowledgedAt: null },
  owner: { ownerId, authSubject, active: true, datasetEpoch, controlVersion: facts.controlVersion },
  browser: { browserId: uid('6'), currentSessionId: sessionId, expiresAt: expires, generation: 10, sessionGeneration: 10 },
  credential: { tokenVersion: 7, state: 'usable', accessExpiresAt: expires, refreshAttemptId: null,
    refreshLeaseExpiresAt: null, refreshTransmissionIntentAt: null },
});

function setup(clock: () => number = () => 20) {
  const repository = {
    snapshot: vi.fn<SessionRuntimeRepository['snapshot']>().mockResolvedValue(validSnapshot()),
    credentials: vi.fn<SessionRuntimeRepository['credentials']>().mockResolvedValue({
      ...facts, kind: 'credentials', now, accessExpiresAt: expires,
      tokenEnvelope: encryptUpstreamTokens({ environment: configuration.environment, ownerId, sessionId, authSubject },
        tokenPair, configuration.sessionTokenKey),
    }),
    confirm: vi.fn<SessionRuntimeRepository['confirm']>().mockResolvedValue({
      kind: 'confirmed', context, tokenVersion: 7, controlVersion: 9, browserGeneration: 10,
    }),
  };
  const identity = { verify: vi.fn<AuthIdentityVerifier['verify']>().mockResolvedValue({
    kind: 'verified', authSubject, upstreamSessionId, expiresAt: expires,
  }) };
  const verifier = createOwnerSessionVerifier(configuration, { repository, identity, monotonicClock: clock });
  return { verifier, repository, identity };
}

describe('current owner session verification', () => {
  it('returns only the confirmed owner context and never refreshes or returns credentials', async () => {
    const { verifier, repository, identity } = setup();
    expect(await verifier.verify(input)).toEqual({ kind: 'authorized', context });
    expect(repository.snapshot).toHaveBeenCalledExactlyOnceWith(input, expect.any(AbortSignal));
    expect(repository.credentials).toHaveBeenCalledExactlyOnceWith({ ...input, ...facts }, expect.any(AbortSignal));
    expect(identity.verify).toHaveBeenCalledExactlyOnceWith({
      accessToken: tokenPair.accessToken, expectedAuthSubject: authSubject, expectedUpstreamSessionId: upstreamSessionId,
      trustedNow: now,
    }, expect.any(AbortSignal));
    expect(repository.confirm).toHaveBeenCalledExactlyOnceWith({
      ...input, ...facts, verifiedAuthSubject: authSubject, verifiedUpstreamSessionId: upstreamSessionId,
    }, expect.any(AbortSignal));
    expect(identity.verify.mock.invocationCallOrder[0]).toBeLessThan(repository.confirm.mock.invocationCallOrder[0]);
  });

  it.each([
    ['revoked', (s: RuntimeSnapshot) => { s.session.revokedAt = now; }],
    ['wrong browser generation', (s: RuntimeSnapshot) => { s.browser.generation++; }],
    ['different browser session', (s: RuntimeSnapshot) => { s.browser.currentSessionId = uid('f'); }],
    ['expired browser', (s: RuntimeSnapshot) => { s.browser.expiresAt = now; }],
    ['inactive owner', (s: RuntimeSnapshot) => { s.owner.active = false; }],
    ['wrong owner identity', (s: RuntimeSnapshot) => { s.owner.authSubject = uid('f'); }],
    ['missing dataset', (s: RuntimeSnapshot) => { s.owner.datasetEpoch = null; }],
    ['idle expiry', (s: RuntimeSnapshot) => { s.session.createdAt = now - 86_400_000; s.session.lastActivityAt = now - 86_400_000; }],
    ['absolute expiry', (s: RuntimeSnapshot) => { s.session.createdAt = now - 604_800_000; }],
  ])('denies %s before loading or decrypting credentials', async (_name, change) => {
    const { verifier, repository, identity } = setup();
    const snapshot = validSnapshot();
    change(snapshot);
    repository.snapshot.mockResolvedValueOnce(snapshot);
    expect(await verifier.verify(input)).toEqual({ kind: 'denied' });
    expect(repository.credentials).not.toHaveBeenCalled();
    expect(identity.verify).not.toHaveBeenCalled();
  });

  it('distinguishes absent session, expired access token, competing refresh, and reauthentication', async () => {
    const { verifier, repository } = setup();
    repository.snapshot.mockResolvedValueOnce({ kind: 'absent', now });
    expect(await verifier.verify(input)).toEqual({ kind: 'anonymous' });
    const snapshot = validSnapshot();
    snapshot.credential.accessExpiresAt = now;
    repository.snapshot.mockResolvedValueOnce(snapshot);
    expect(await verifier.verify(input)).toEqual({ kind: 'refresh_required' });
    snapshot.credential.state = 'sent_or_unknown';
    snapshot.credential.refreshLeaseExpiresAt = expires;
    repository.snapshot.mockResolvedValueOnce(snapshot);
    expect(await verifier.verify(input)).toEqual({ kind: 'unavailable' });
    snapshot.credential.refreshLeaseExpiresAt = now;
    repository.snapshot.mockResolvedValueOnce(snapshot);
    expect(await verifier.verify(input)).toEqual({ kind: 'reauthentication_required' });
    expect(repository.credentials).not.toHaveBeenCalled();
  });

  it('keeps authorization closed on Auth refusal, mismatched claims, or uncertain acknowledgement', async () => {
    const { verifier, repository, identity } = setup();
    identity.verify.mockResolvedValueOnce({ kind: 'rejected', reason: 'invalid_token' });
    expect(await verifier.verify(input)).toEqual({ kind: 'reauthentication_required' });
    identity.verify.mockResolvedValueOnce({ kind: 'verified', authSubject, upstreamSessionId, expiresAt: expires - 1 });
    expect(await verifier.verify(input)).toEqual({ kind: 'unavailable' });
    expect(repository.confirm).not.toHaveBeenCalled();
    repository.confirm.mockResolvedValueOnce({ kind: 'outcome_unknown', reason: 'transport' });
    expect(await verifier.verify(input)).toEqual({ kind: 'unavailable' });
  });

  it('never authorizes a different callback session or a stale post-network CAS', async () => {
    const { verifier, repository } = setup();
    expect(await verifier.verifyForCallback({ ...input, sessionId: uid('f') }, new AbortController().signal)).toEqual({ kind: 'denied' });
    expect(repository.credentials).not.toHaveBeenCalled();
    repository.confirm.mockResolvedValueOnce({ kind: 'denied' });
    expect(await verifier.verifyForCallback({ ...input, sessionId }, new AbortController().signal)).toEqual({ kind: 'denied' });
  });

  it('detects ordinary expiry when Auth rejects the bearer at the expiry boundary', async () => {
    let clock = 0;
    const { verifier, repository, identity } = setup(() => clock);
    const snapshot = validSnapshot();
    snapshot.credential.accessExpiresAt = now + 20;
    repository.snapshot.mockResolvedValueOnce(snapshot);
    repository.credentials.mockResolvedValueOnce({
      ...facts, kind: 'credentials', now, accessExpiresAt: now + 20,
      tokenEnvelope: encryptUpstreamTokens({ environment: configuration.environment, ownerId, sessionId, authSubject },
        tokenPair, configuration.sessionTokenKey),
    });
    identity.verify.mockImplementationOnce(async () => {
      clock = 20;
      return { kind: 'rejected', reason: 'invalid_token' };
    });
    expect(await verifier.verify(input)).toEqual({ kind: 'refresh_required' });
    expect(repository.confirm).not.toHaveBeenCalled();
  });

  it('stops before Auth when the envelope is from a different local session', async () => {
    const { verifier, repository, identity } = setup();
    repository.credentials.mockResolvedValueOnce({
      ...facts, kind: 'credentials', now, accessExpiresAt: expires,
      tokenEnvelope: encryptUpstreamTokens({ environment: configuration.environment, ownerId,
        sessionId: uid('f'), authSubject }, tokenPair, configuration.sessionTokenKey),
    });
    expect(await verifier.verify(input)).toEqual({ kind: 'unavailable' });
    expect(identity.verify).not.toHaveBeenCalled();
    expect(repository.confirm).not.toHaveBeenCalled();
  });

  it('stops before confirmation when the request was cancelled during Auth verification', async () => {
    const { verifier, repository, identity } = setup();
    const controller = new AbortController();
    identity.verify.mockImplementationOnce(async () => {
      controller.abort();
      return { kind: 'verified', authSubject, upstreamSessionId, expiresAt: expires };
    });
    expect(await verifier.verify(input, controller.signal)).toEqual({ kind: 'unavailable' });
    expect(repository.confirm).not.toHaveBeenCalled();
  });

  it('does not return a context when the confirmed access token expires during acknowledgement', async () => {
    let clock = 0;
    const { repository, identity, verifier } = setup(() => clock);
    const credential = {
      ...facts, kind: 'credentials' as const, now, accessExpiresAt: now + 20,
      tokenEnvelope: encryptUpstreamTokens({ environment: configuration.environment, ownerId, sessionId, authSubject },
        tokenPair, configuration.sessionTokenKey),
    };
    const snapshot = validSnapshot();
    snapshot.credential.accessExpiresAt = now + 20;
    repository.snapshot.mockResolvedValueOnce(snapshot);
    repository.credentials.mockResolvedValueOnce(credential);
    repository.confirm.mockImplementationOnce(async () => {
      clock = 20;
      return { kind: 'confirmed', context, tokenVersion: 7, controlVersion: 9, browserGeneration: 10 };
    });
    identity.verify.mockResolvedValueOnce({ kind: 'verified', authSubject, upstreamSessionId, expiresAt: now + 20 });
    expect(await verifier.verify(input)).toEqual({ kind: 'refresh_required' });
  });
});


describe('confirmed owner session in a repeated Google callback', () => {
  const origin = 'https://studio.example.test';
  const attemptId = uid('7');

  function callback() {
    const cookie = `__Host-jls-browser=${input.browserSecret}; __Host-jls-session=${input.sessionSecret}; __Host-jls-oauth=jls-oauth-v1.${'I'.repeat(43)}`;
    return new Request(origin + '/api/v1/auth/callback?code=fixture_code', { headers: { Cookie: cookie } });
  }

  it.each([['confirmed', 303], ['denied', 409], ['outcome_unknown', 503]] as const)(
    'maps %s confirmation without issuing a new cookie', async (kind, status) => {
      const { verifier, repository } = setup();
      if (kind === 'denied') repository.confirm.mockResolvedValueOnce({ kind });
      if (kind === 'outcome_unknown') repository.confirm.mockResolvedValueOnce({ kind, reason: 'transport' });
      const finish = vi.fn();
      const handlers = createGoogleOAuthHttp(origin, {
        resolveAction: vi.fn(), begin: vi.fn(), recoverLogin: vi.fn(), finish,
        inspectCallback: vi.fn().mockResolvedValue({ kind: 'completed_with_cookie', attemptId, sessionId, generation: 10 }),
        verifyCurrent: verifier.verifyForCallback,
      });
      const response = await handlers.callback(callback());
      expect(response.status).toBe(status);
      expect(response.headers.get('Location')).toBe(status === 303 ? '/today' : null);
      expect(response.headers.getSetCookie()).toEqual([]);
      expect(finish).not.toHaveBeenCalled();
      expect(repository.confirm).toHaveBeenCalledOnce();
    },
  );
});


it('separates the real control gateway key from the bearer sent to the Auth identity endpoint', async () => {
  const supabaseOrigin = 'https://abcdefghijklmnopqrst.supabase.co';
  const publishableKey = 'sb_publishable_fixture_1234567890123456';
  const secretKey = 'sb_secret_fixture_only_1234567890123456';
  const canonicalClaims = {
    sub: authSubject, session_id: upstreamSessionId, iss: `${supabaseOrigin}/auth/v1`,
    aud: 'authenticated', role: 'authenticated', is_anonymous: false, exp: expires / 1000,
  };
  const accessToken = [Buffer.from('{"alg":"ES256"}').toString('base64url'),
    Buffer.from(JSON.stringify(canonicalClaims)).toString('base64url'), 'c2ln'].join('.');
  const tokenEnvelope = encryptUpstreamTokens({ environment: configuration.environment, ownerId, sessionId, authSubject },
    { accessToken, refreshToken: tokenPair.refreshToken }, configuration.sessionTokenKey);
  const calls: string[] = [];
  const json = (value: unknown) => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
  const fetcher: typeof fetch = async (destination, options) => {
    const url = new URL(String(destination));
    calls.push(url.pathname);
    expect(url.origin).toBe(supabaseOrigin);
    const headers = new Headers(options?.headers);
    expect(options).toMatchObject({ credentials: 'omit', redirect: 'error', cache: 'no-store' });
    if (url.pathname === '/auth/v1/user') {
      expect(headers.get('Authorization')).toBe('Bearer ' + accessToken);
      expect(headers.get('apikey')).toBe(publishableKey);
      return json({ id: authSubject, is_anonymous: false });
    }
    expect(headers.get('apikey')).toBe(secretKey);
    expect(headers.has('Authorization')).toBe(false);
    expect(String(options?.body)).not.toContain(accessToken);
    expect(String(options?.body)).not.toContain(tokenPair.refreshToken);
    if (url.pathname.endsWith('/jls_auth_session_snapshot_v1')) return json(validSnapshot());
    if (url.pathname.endsWith('/jls_auth_current_credentials_v1')) return json({ ...facts, kind: 'credentials',
      now, tokenEnvelope, accessExpiresAt: expires });
    if (url.pathname.endsWith('/jls_auth_confirm_session_v1')) return json({ kind: 'confirmed', context,
      tokenVersion: 7, controlVersion: 9, browserGeneration: 10 });
    throw Error('Unexpected fixture endpoint');
  };
  const runtime = createGoogleOAuthRuntime({
    ...configuration, supabaseOrigin, publishableKey, secretKey, appOrigin: 'https://studio.example.test',
    pkceKey: { keyId: 'pkce', keyBytes: new Uint8Array(32).fill(8) },
    orphanTokenKey: { keyId: 'orphan', keyBytes: new Uint8Array(32).fill(9) },
  }, fetcher);
  expect(await runtime.verifyOwnerSession(input)).toEqual({ kind: 'authorized', context });
  expect(calls).toEqual([
    '/rest/v1/rpc/jls_auth_session_snapshot_v1', '/rest/v1/rpc/jls_auth_current_credentials_v1',
    '/auth/v1/user', '/rest/v1/rpc/jls_auth_confirm_session_v1',
  ]);
});
