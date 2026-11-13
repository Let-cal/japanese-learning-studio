import { describe, expect, it, vi } from 'vitest';
import { createGoogleOAuthBegin } from '../../src/application/auth/googleOAuthBegin';
import { decryptPkceVerifier, fingerprintSessionCookie, hashAuthActionSecret } from '../../src/infrastructure/auth/authActionSecrets';
import type { OAuthActionRepository } from '../../src/infrastructure/auth/oauthActionRepository';
import type { OAuthTransport } from '../../src/infrastructure/auth/oauthTransport';

const browserId = '22222222-2222-4222-8222-222222222222';
const operationId = '33333333-3333-4333-8333-333333333333';
const browserSecret = `jls-browser-v1.${'A'.repeat(43)}`;
const csrfToken = `jls-csrf-v1.${'E'.repeat(43)}`;
const configuration = {
  environment: 'fixture',
  pkceKey: { keyId: 'pkce-fixture', keyBytes: new Uint8Array(32).fill(1) },
};
const input = { browserId, browserSecret, csrfToken, operationId, generation: 7 };
const authorizationUrl = 'https://abcdefghijklmnopqrst.supabase.co/auth/v1/authorize?provider=google';
const expiresAt = 1_800_000_600_000;
const unknown = { kind: 'outcome_unknown', reason: 'transport' } as const;

function setup(monotonicClock?: () => number) {
  const beginLogin = vi.fn<OAuthActionRepository['beginLogin']>().mockImplementation(async request => ({
    kind: 'begun', attemptId: request.attemptId, generation: 7, expiresAt,
  }));
  const authorize = vi.fn<OAuthTransport['authorizationUrl']>().mockReturnValue({ kind: 'ready', url: authorizationUrl });
  const run = createGoogleOAuthBegin(configuration, { beginLogin, authorizationUrl: authorize, monotonicClock });
  return { run, beginLogin, authorize };
}

describe('begin a Google OAuth attempt', () => {
  it('binds the exact proof and cookie presentation and returns a redirect only after persistence', async () => {
    const { run, beginLogin, authorize } = setup();
    const presentedSession = 'malformed-but-bounded-opaque-cookie';
    const result = await run({ ...input, presentedSession });
    expect(result.kind).toBe('redirect');
    if (result.kind !== 'redirect') throw Error('Missing durable redirect');
    expect(Object.keys(result).sort()).toEqual(['expiresAt', 'flowSecret', 'kind', 'location']);
    expect(result.location).toBe(authorizationUrl);
    expect(result.expiresAt).toBe(expiresAt);
    const stored = beginLogin.mock.calls[0][0];
    expect(stored).toMatchObject({
      browserHash: hashAuthActionSecret('browser', browserSecret),
      proofHash: hashAuthActionSecret('csrf-login', csrfToken),
      flowHash: hashAuthActionSecret('oauth', result.flowSecret),
      cookieFingerprint: fingerprintSessionCookie(presentedSession),
      operationId,
    });
    expect(decryptPkceVerifier({ environment: configuration.environment, bindingId: browserId, attemptId: stored.attemptId },
      stored.pkceEnvelope, configuration.pkceKey)).toBe(authorize.mock.calls[0][0]);
    expect(authorizationUrl).not.toContain(result.flowSecret);
  });

  it('replays at most once after an uncertain write using exactly the same arguments', async () => {
    const { run, beginLogin, authorize } = setup();
    beginLogin.mockResolvedValueOnce(unknown);
    expect(await run(input)).toMatchObject({ kind: 'redirect' });
    expect(beginLogin).toHaveBeenCalledTimes(2);
    expect(beginLogin.mock.calls[1]).toEqual(beginLogin.mock.calls[0]);
    expect(beginLogin.mock.calls[0][0].cookieFingerprint).toBe('absent');
    expect(authorize).toHaveBeenCalledOnce();
  });

  it('withholds the redirect and flow bearer when exact replay cannot confirm persistence', async () => {
    const { run, beginLogin } = setup();
    beginLogin.mockResolvedValue(unknown);
    expect(await run(input)).toEqual({ kind: 'unavailable' });
    expect(beginLogin).toHaveBeenCalledTimes(2);
  });

  it('reports an existing attempt without starting a new provider request', async () => {
    const { run, beginLogin } = setup();
    beginLogin.mockResolvedValueOnce({ kind: 'restart_required' });
    expect(await run(input)).toEqual({ kind: 'restart_required' });
    expect(beginLogin).toHaveBeenCalledOnce();
  });

  it('does not write if the browser/proof input or the configured destination is invalid', async () => {
    const { run, beginLogin, authorize } = setup();
    expect(await run({ ...input, csrfToken: browserSecret })).toEqual({ kind: 'denied' });
    authorize.mockReturnValueOnce({ kind: 'not_sent', reason: 'configuration' });
    expect(await run(input)).toEqual({ kind: 'unavailable' });
    expect(beginLogin).not.toHaveBeenCalled();
  });

  it('rejects stale generation and withholds cookies after cancellation', async () => {
    const { run, beginLogin } = setup();
    beginLogin.mockImplementationOnce(async request => ({ kind: 'begun', attemptId: request.attemptId, generation: 8, expiresAt }));
    expect(await run(input)).toEqual({ kind: 'unavailable' });
    const controller = new AbortController();
    beginLogin.mockImplementationOnce(async request => {
      controller.abort();
      return { kind: 'begun', attemptId: request.attemptId, generation: 7, expiresAt };
    });
    expect(await run(input, controller.signal)).toEqual({ kind: 'unavailable' });
    expect(beginLogin).toHaveBeenCalledTimes(2);
  });

  it('withholds the redirect when persistence returns after the monotonic deadline', async () => {
    let elapsed = 0;
    const { run, beginLogin } = setup(() => elapsed);
    beginLogin.mockImplementationOnce(async request => {
      elapsed = 10_000;
      return { kind: 'begun', attemptId: request.attemptId, generation: 7, expiresAt };
    });
    expect(await run(input)).toEqual({ kind: 'unavailable' });
    expect(beginLogin).toHaveBeenCalledOnce();
  });
});
