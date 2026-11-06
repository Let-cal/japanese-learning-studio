import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAuthCandidateVerifier, createAuthIdentityVerifier } from '../../src/infrastructure/auth/authAdapter';

const origin = 'https://abcdefghijklmnopqrst.supabase.co';
const configuration = { supabaseOrigin: origin, publishableKey: 'sb_publishable_abcdefghijklmnop' };
const subject = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const session = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const other = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
const claims = { sub: subject, session_id: session, iss: `${origin}/auth/v1`, aud: 'authenticated',
  role: 'authenticated', is_anonymous: false, exp: 200 };
function token(overrides: Record<string, unknown> = {}): string {
  return [Buffer.from('{"alg":"ES256"}').toString('base64url'),
    Buffer.from(JSON.stringify({ ...claims, ...overrides })).toString('base64url'), 'c2ln'].join('.');
}
function facts(accessToken: unknown = token()) {
  return { accessToken, expectedAuthSubject: subject, expectedUpstreamSessionId: session, trustedNow: 100_000 };
}
function response(body: unknown = { id: subject, is_anonymous: false }, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}
function transport(result: () => Response | Promise<Response>) {
  return vi.fn<typeof fetch>(async () => result());
}
afterEach(() => vi.useRealTimers());

describe('Auth identity verifier', () => {
  it('forwards the exact bearer only to Auth and returns closed verified identity', async () => {
    const fetcher = transport(() => response({ id: subject.toUpperCase(), is_anonymous: false,
      email: 'must-not-retain@example.test', user_metadata: { admin: true } }));
    const verifier = createAuthIdentityVerifier(configuration, fetcher, () => 10);
    const accessToken = token({ sub: subject.toUpperCase(), session_id: session.toUpperCase() });
    const result = await verifier.verify(facts(accessToken));
    expect(result).toEqual({ kind: 'verified', authSubject: subject, upstreamSessionId: session, expiresAt: 200_000 });
    expect(Object.isFrozen(verifier)).toBe(true);
    expect(Object.keys(verifier)).toEqual(['verify']);
    expect(Object.isFrozen(result)).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledWith(`${origin}/auth/v1/user`, {
      method: 'GET', headers: { apikey: configuration.publishableKey, Authorization: `Bearer ${accessToken}`, Accept: 'application/json',
        'X-Supabase-Api-Version': '2024-01-01' },
      cache: 'no-store', credentials: 'omit', redirect: 'error', signal: expect.any(AbortSignal),
    });
  });

  it('snapshots closed configuration and trusted facts without invoking accessors', async () => {
    const config = { ...configuration };
    let finish!: (value: Response) => void;
    const fetcher = transport(() => new Promise(resolve => { finish = resolve; }));
    const verifier = createAuthIdentityVerifier(config, fetcher, () => 0);
    config.supabaseOrigin = 'https://attacker.example';
    config.publishableKey = 'secret';
    const input = facts();
    const pending = verifier.verify(input);
    input.expectedAuthSubject = other;
    input.trustedNow = 900_000;
    finish(response());
    expect(await pending).toEqual({ kind: 'verified', authSubject: subject, upstreamSessionId: session, expiresAt: 200_000 });
    const getter = vi.fn(() => origin);
    const guarded = Object.defineProperty({ ...configuration }, 'supabaseOrigin', { get: getter });
    expect(await createAuthIdentityVerifier(guarded, fetcher).verify(facts())).toEqual({ kind: 'unavailable', reason: 'configuration' });
    expect(getter).not.toHaveBeenCalled();
  });

  it.each([
    { ...configuration, extra: true }, { ...configuration, secretKey: 'sb_secret_never' },
    { ...configuration, supabaseOrigin: `${origin}/` }, { ...configuration, supabaseOrigin: 'http://abcdefghijklmnopqrst.supabase.co' },
    { ...configuration, publishableKey: 'sb_secret_abcdefghijklmnop' }, { ...configuration, publishableKey: 'sb_publishable_short' },
  ])('rejects unsafe configuration without transport (%j)', async config => {
    const fetcher = transport(() => response());
    expect(await createAuthIdentityVerifier(config, fetcher).verify(facts())).toEqual({ kind: 'unavailable', reason: 'configuration' });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([
    { ...facts(), expectedAuthSubject: null }, { ...facts(), expectedUpstreamSessionId: 'bad' },
    { ...facts(), trustedNow: -1 }, { ...facts(), trustedNow: 1.5 }, { ...facts(), trustedNow: Number.MAX_SAFE_INTEGER + 1 },
    { ...facts(), extra: true }, Object.create(facts()),
  ])('rejects invalid trusted facts without transport (case %#)', async input => {
    const fetcher = transport(() => response());
    expect(await createAuthIdentityVerifier(configuration, fetcher).verify(input)).toEqual({ kind: 'unavailable', reason: 'invalid_facts' });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([null, '', 'a.b.', 'a.b.c', `${token()} `, token() + '.c2ln', 'A'.repeat(8193),
    'e30._w.c2ln', 'e30.W10.c2ln', 'e30.eyJzdWIiOiJhIn1=.c2ln'])('rejects malformed compact tokens locally (case %#)', async accessToken => {
    const fetcher = transport(() => response());
    expect(await createAuthIdentityVerifier(configuration, fetcher).verify(facts(accessToken))).toEqual({ kind: 'rejected', reason: 'invalid_token' });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('never grants authority from decoded claims when Auth fails and does not retry', async () => {
    const fetcher = transport(() => { throw new Error(`leak ${token()} ${configuration.publishableKey} ${origin}`); });
    expect(await createAuthIdentityVerifier(configuration, fetcher).verify(facts())).toEqual({ kind: 'unavailable', reason: 'transport' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it.each([
    [{ sub: other }, 'identity_mismatch'], [{ session_id: other }, 'identity_mismatch'],
    [{ sub: null }, 'invalid_token'], [{ session_id: null }, 'invalid_token'],
    [{ iss: 'https://attacker.example/auth/v1' }, 'invalid_token'], [{ aud: ['authenticated'] }, 'invalid_token'],
    [{ role: 'service_role' }, 'invalid_token'], [{ is_anonymous: true }, 'anonymous'],
    [{ is_anonymous: undefined }, 'invalid_token'], [{ exp: null }, 'invalid_token'],
    [{ exp: 100 }, 'invalid_token'], [{ exp: 0 }, 'invalid_token'], [{ exp: 100.5 }, 'invalid_token'],
    [{ exp: Number.MAX_SAFE_INTEGER }, 'invalid_token'], [{ nbf: 101 }, 'invalid_token'],
    [{ nbf: -1 }, 'invalid_token'], [{ nbf: null }, 'invalid_token'],
  ] as const)('binds verified claims to trusted state (%j)', async (overrides, reason) => {
    const fetcher = transport(() => response());
    expect(await createAuthIdentityVerifier(configuration, fetcher, () => 0).verify(facts(token(overrides))))
      .toEqual({ kind: 'rejected', reason });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it.each([
    [{ id: other, is_anonymous: false }, 'rejected', 'identity_mismatch'],
    [{ id: subject, is_anonymous: true }, 'rejected', 'anonymous'],
    [{ id: subject }, 'unavailable', 'invalid_response'],
    [{ id: null, is_anonymous: false }, 'unavailable', 'invalid_response'],
    [{ user: { id: subject, is_anonymous: false } }, 'unavailable', 'invalid_response'],
  ] as const)('validates the raw Auth user response (%j)', async (body, kind, reason) => {
    expect(await createAuthIdentityVerifier(configuration, transport(() => response(body)), () => 0).verify(facts()))
      .toEqual({ kind, reason });
  });

  it('accounts for network/body elapsed time at the expiry boundary', async () => {
    let elapsed = 10;
    const fetcher = transport(() => { elapsed = 1010; return response(); });
    expect(await createAuthIdentityVerifier(configuration, fetcher, () => elapsed).verify(facts(token({ exp: 101, nbf: 100 }))))
      .toEqual({ kind: 'rejected', reason: 'invalid_token' });
  });

  it('does not round fractional elapsed time forward across a not-before boundary', async () => {
    let elapsed = 0;
    const fetcher = transport(() => { elapsed = 0.5; return response(); });
    expect(await createAuthIdentityVerifier(configuration, fetcher, () => elapsed)
      .verify({ ...facts(token({ nbf: 101 })), trustedNow: 100_999 }))
      .toEqual({ kind: 'rejected', reason: 'invalid_token' });
  });

  it.each([NaN, Infinity, -1])('fails closed on an invalid monotonic clock (%s)', async value => {
    const fetcher = transport(() => response());
    expect(await createAuthIdentityVerifier(configuration, fetcher, () => value).verify(facts()))
      .toEqual({ kind: 'unavailable', reason: 'invalid_facts' });
  });

  it('fails closed on a decreasing clock or unsafe effective timestamp', async () => {
    let clock = 10;
    const fetcher = transport(() => { clock = 9; return response(); });
    expect(await createAuthIdentityVerifier(configuration, fetcher, () => clock).verify(facts()))
      .toEqual({ kind: 'unavailable', reason: 'invalid_facts' });
    clock = 0;
    const late = transport(() => { clock = 2; return response(); });
    expect(await createAuthIdentityVerifier(configuration, late, () => clock).verify({ ...facts(), trustedNow: Number.MAX_SAFE_INTEGER }))
      .toEqual({ kind: 'unavailable', reason: 'invalid_facts' });
  });

  it.each([
    [401, { code: 'bad_jwt' }, 'rejected', 'invalid_token'],
    [401, { code: 'bad_jwt_extra', message: 'bad jwt' }, 'unavailable', 'upstream_rejected'],
    [401, { message: 'invalid JWT' }, 'unavailable', 'upstream_rejected'],
    [401, { code: 'invalid_api_key' }, 'unavailable', 'upstream_rejected'],
    [403, { code: 'bad_jwt' }, 'unavailable', 'upstream_rejected'],
    [429, { code: 'bad_jwt' }, 'unavailable', 'upstream_rejected'],
    [500, { code: 'bad_jwt' }, 'unavailable', 'upstream_rejected'],
  ] as const)('distinguishes ambiguous Auth failures using only bounded bad_jwt code (%s %j)', async (status, body, kind, reason) => {
    const fetcher = transport(() => response(body, status));
    expect(await createAuthIdentityVerifier(configuration, fetcher).verify(facts())).toEqual({ kind, reason });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it.each([
    () => new Response('[]', { headers: { 'Content-Type': 'application/json' } }),
    () => new Response('{}', { headers: { 'Content-Type': 'text/plain' } }),
    () => new Response(new Uint8Array([0xff]), { headers: { 'Content-Type': 'application/json' } }),
    () => new Response(' '.repeat(65537), { headers: { 'Content-Type': 'application/json' } }),
    () => new Response(' '.repeat(65537), { status: 401, headers: { 'Content-Type': 'application/json' } }),
    () => new Response('{', { status: 401, headers: { 'Content-Type': 'application/json' } }),
  ])('bounds and strictly decodes Auth bodies', async makeResponse => {
    expect(await createAuthIdentityVerifier(configuration, transport(makeResponse)).verify(facts()))
      .toEqual({ kind: 'unavailable', reason: 'invalid_response' });
  });

  it.each(['fetch', 'body'] as const)('enforces the five second deadline when %s ignores abort', async stage => {
    vi.useFakeTimers();
    const cancel = vi.fn(() => new Promise<void>(() => {}));
    const stalled = new Response(new ReadableStream<Uint8Array>({ pull: () => new Promise(() => {}), cancel }),
      { headers: { 'Content-Type': 'application/json' } });
    const fetcher = transport(() => stage === 'fetch' ? new Promise(() => {}) : stalled);
    const pending = createAuthIdentityVerifier(configuration, fetcher, () => 0).verify(facts());
    await vi.advanceTimersByTimeAsync(4999);
    await vi.advanceTimersByTimeAsync(1);
    expect(await pending).toEqual({ kind: 'unavailable', reason: 'timeout' });
    expect(fetcher.mock.calls[0][1]?.signal?.aborted).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(1);
    if (stage === 'body') expect(cancel).toHaveBeenCalledTimes(1);
  });

  it('cancels non-200 response bodies without reading or awaiting stuck cancellation', async () => {
    const cancel = vi.fn(() => new Promise<void>(() => {}));
    const body = new ReadableStream<Uint8Array>({ cancel });
    const fetcher = transport(() => new Response(body, { status: 503 }));
    expect(await createAuthIdentityVerifier(configuration, fetcher).verify(facts()))
      .toEqual({ kind: 'unavailable', reason: 'upstream_rejected' });
    expect(cancel).toHaveBeenCalledTimes(1);
  });
});

describe('initial Auth candidate verifier', () => {
  const candidateInput = (accessToken: unknown = token()) => ({ accessToken, trustedNow: 100_000 });

  it('returns a frozen candidate without inventing existing DB session facts', async () => {
    const verifier = createAuthCandidateVerifier(configuration, transport(() => response()), () => 0);
    const result = await verifier.verifyCandidate(candidateInput());
    expect(result).toEqual({ kind: 'verified_candidate', authSubject: subject, upstreamSessionId: session, expiresAt: 200_000 });
    expect(Object.keys(verifier)).toEqual(['verifyCandidate']);
    expect(Object.isFrozen(verifier)).toBe(true);
    expect(Object.isFrozen(result)).toBe(true);
  });

  it('returns a nonowner upstream identity only as a candidate using the same exact bearer profile', async () => {
    const fetcher = transport(() => response({ id: other, is_anonymous: false }));
    const accessToken = token({ sub: other });
    expect(await createAuthCandidateVerifier(configuration, fetcher, () => 0).verifyCandidate(candidateInput(accessToken)))
      .toEqual({ kind: 'verified_candidate', authSubject: other, upstreamSessionId: session, expiresAt: 200_000 });
    expect(fetcher).toHaveBeenCalledExactlyOnceWith(`${origin}/auth/v1/user`, {
      method: 'GET', headers: { apikey: configuration.publishableKey, Authorization: `Bearer ${accessToken}`, Accept: 'application/json',
        'X-Supabase-Api-Version': '2024-01-01' },
      cache: 'no-store', credentials: 'omit', redirect: 'error', signal: expect.any(AbortSignal),
    });
  });

  it('binds candidate subject to the verified raw Auth response', async () => {
    expect(await createAuthCandidateVerifier(configuration, transport(() => response({ id: other, is_anonymous: false })), () => 0)
      .verifyCandidate(candidateInput())).toEqual({ kind: 'rejected', reason: 'identity_mismatch' });
  });

  it('rejects malformed tokens and anonymous users without creating candidates', async () => {
    const fetcher = transport(() => response());
    expect(await createAuthCandidateVerifier(configuration, fetcher).verifyCandidate(candidateInput('a.b.')))
      .toEqual({ kind: 'rejected', reason: 'invalid_token' });
    expect(fetcher).not.toHaveBeenCalled();
    expect(await createAuthCandidateVerifier(configuration, transport(() => response({ id: subject, is_anonymous: true })), () => 0)
      .verifyCandidate(candidateInput())).toEqual({ kind: 'rejected', reason: 'anonymous' });
    expect(await createAuthCandidateVerifier(configuration, transport(() => response()), () => 0)
      .verifyCandidate(candidateInput(token({ is_anonymous: true })))).toEqual({ kind: 'rejected', reason: 'anonymous' });
  });

  it('accepts only exact own candidate input and refuses JSON mode or expected DB fields', async () => {
    const fetcher = transport(() => response());
    const verifier = createAuthCandidateVerifier(configuration, fetcher);
    for (const input of [{ accessToken: token() }, { trustedNow: 100_000 },
      { ...candidateInput(), mode: 'bound' }, { ...candidateInput(), expectedAuthSubject: subject },
      { ...candidateInput(), expectedUpstreamSessionId: session }, Object.create(candidateInput())]) {
      expect(await verifier.verifyCandidate(input)).toEqual({ kind: 'unavailable', reason: 'invalid_facts' });
    }
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('cannot downgrade continuation verification by omitting DB expectations or selecting candidate mode', async () => {
    const fetcher = transport(() => response());
    const verifier = createAuthIdentityVerifier(configuration, fetcher);
    for (const input of [candidateInput(), { ...candidateInput(), expectedAuthSubject: subject },
      { ...candidateInput(), mode: 'candidate' }, { ...facts(), mode: 'candidate' }]) {
      expect(await verifier.verify(input)).toEqual({ kind: 'unavailable', reason: 'invalid_facts' });
    }
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('shares lifetime, role and ambiguous Auth error constraints with continuation verification', async () => {
    const verifier = createAuthCandidateVerifier(configuration, transport(() => response()), () => 0);
    expect(await verifier.verifyCandidate(candidateInput(token({ exp: 100 })))).toEqual({ kind: 'rejected', reason: 'invalid_token' });
    expect(await verifier.verifyCandidate(candidateInput(token({ role: 'service_role' })))).toEqual({ kind: 'rejected', reason: 'invalid_token' });
    expect(await createAuthCandidateVerifier(configuration, transport(() => response({ error_code: 'bad_jwt' }, 401)))
      .verifyCandidate(candidateInput())).toEqual({ kind: 'unavailable', reason: 'upstream_rejected' });
  });

  it('enforces the shared deadline when a candidate response body ignores abort', async () => {
    vi.useFakeTimers();
    const fetcher = transport(() => new Response(new ReadableStream<Uint8Array>({ pull: () => new Promise(() => {}) }),
      { headers: { 'Content-Type': 'application/json' } }));
    const pending = createAuthCandidateVerifier(configuration, fetcher, () => 0).verifyCandidate(candidateInput());
    await vi.advanceTimersByTimeAsync(5000);
    expect(await pending).toEqual({ kind: 'unavailable', reason: 'timeout' });
    expect(fetcher.mock.calls[0][1]?.signal?.aborted).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});
