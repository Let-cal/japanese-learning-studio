import { describe, expect, it, vi } from 'vitest';
import { createGoogleOAuthCallback } from '../../src/application/auth/googleOAuthCallback';
import { encryptPkceVerifier, hashAuthActionSecret } from '../../src/infrastructure/auth/authActionSecrets';
import { decryptOrphanTokens } from '../../src/infrastructure/auth/orphanTokenEnvelope';
import { hashSessionSecret } from '../../src/infrastructure/auth/sessionSecrets';
import { decryptUpstreamTokens } from '../../src/infrastructure/auth/tokenEnvelope';
import type { OAuthActionRepository } from '../../src/infrastructure/auth/oauthActionRepository';

const uuid = (digit: string) => `${digit.repeat(8)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(12)}`;
const attemptId = uuid('1');
const browserId = uuid('2');
const ownerId = uuid('3');
const authSubject = uuid('4');
const upstreamSessionId = uuid('5');
const datasetEpoch = uuid('6');
const authorizationCode = 'sample_authorization_code';
const browserSecret = `jls-browser-v1.${'A'.repeat(43)}`;
const flowSecret = `jls-oauth-v1.${'E'.repeat(43)}`;
const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const now = 1_800_000_000_000;
const tokenPair = { accessToken: 'sample.access.jwt', refreshToken: 'sample_refresh_token' };
const configuration = {
  environment: 'fixture',
  pkceKey: { keyId: 'pkce-fixture', keyBytes: new Uint8Array(32).fill(1) },
  sessionTokenKey: { keyId: 'session-fixture', keyBytes: new Uint8Array(32).fill(2) },
  orphanTokenKey: { keyId: 'orphan-fixture', keyBytes: new Uint8Array(32).fill(3) },
};
const input = { attemptId, browserId, browserSecret, flowSecret, authorizationCode };
const unknown = { kind: 'outcome_unknown', reason: 'transport' } as const;

function setup(clock = () => 100) {
  const actions = {
    callbackClaim: vi.fn<OAuthActionRepository['callbackClaim']>().mockImplementation(async request => ({
      kind: 'claimed', attemptId, claimId: request.claimId, browserId, ownerId, authSubject,
      datasetEpoch, controlVersion: 9, generation: 7, now,
      pkceEnvelope: encryptPkceVerifier({ environment: configuration.environment, bindingId: browserId, attemptId }, verifier, configuration.pkceKey),
    })),
    callbackMarkSent: vi.fn<OAuthActionRepository['callbackMarkSent']>().mockResolvedValue({ kind: 'send_intent' }),
    callbackCommit: vi.fn<OAuthActionRepository['callbackCommit']>().mockImplementation(async request => ({
      kind: 'committed', attemptId, sessionId: request.newSessionId, generation: 8,
    })),
    callbackResolve: vi.fn<OAuthActionRepository['callbackResolve']>().mockImplementation(async request => ({
      kind: 'committed', attemptId, sessionId: request.newSessionId, generation: 8,
    })),
    callbackClose: vi.fn<OAuthActionRepository['callbackClose']>().mockResolvedValue({ kind: 'closed' }),
  };
  const exchange = vi.fn().mockResolvedValue({ kind: 'tokens', ...tokenPair });
  const verifyCandidate = vi.fn().mockResolvedValue({
    kind: 'verified_candidate', authSubject, upstreamSessionId, expiresAt: now + 60_000,
  });
  const run = createGoogleOAuthCallback(configuration, { actions, exchange, verifyCandidate, monotonicClock: clock });
  return { run, actions, exchange, verifyCandidate };
}

describe('fresh Google OAuth callback', () => {
  it('sends only after a durable marker and returns the opaque session secret after commit', async () => {
    const { run, actions, exchange, verifyCandidate } = setup();
    const result = await run(input);

    expect(result.kind).toBe('signed_in');
    if (result.kind !== 'signed_in') throw Error('Missing opaque session secret');
    expect(Object.keys(result).sort()).toEqual(['kind', 'sessionSecret']);
    expect(exchange).toHaveBeenCalledExactlyOnceWith({ authorizationCode, codeVerifier: verifier }, expect.any(AbortSignal));
    expect(actions.callbackMarkSent.mock.invocationCallOrder[0]).toBeLessThan(exchange.mock.invocationCallOrder[0]);
    expect(verifyCandidate.mock.invocationCallOrder[0]).toBeLessThan(actions.callbackCommit.mock.invocationCallOrder[0]);
    expect(actions.callbackClaim.mock.calls[0][0]).toMatchObject({
      browserHash: hashAuthActionSecret('browser', browserSecret), flowHash: hashAuthActionSecret('oauth', flowSecret), browserId, attemptId,
    });
    const commit = actions.callbackCommit.mock.calls[0][0];
    expect(commit).toMatchObject({ verifiedSubject: authSubject, verifiedUpstreamSessionId: upstreamSessionId, generation: 7,
      accessExpiresAt: now + 60_000, newSessionHash: hashSessionSecret(result.sessionSecret) });
    expect(decryptUpstreamTokens({ environment: configuration.environment, ownerId, authSubject, sessionId: commit.newSessionId },
      commit.tokenEnvelope, configuration.sessionTokenKey)).toEqual(tokenPair);
    expect(actions.callbackResolve).not.toHaveBeenCalled();
    expect(actions.callbackClose).not.toHaveBeenCalled();
  });

  it('does not read or mutate state for malformed inputs or an already cancelled request', async () => {
    const { run, actions } = setup();
    expect(await run({ ...input, authorizationCode: 'not a transport code' })).toEqual({ kind: 'denied' });
    expect(await run(input, AbortSignal.abort())).toEqual({ kind: 'unavailable' });
    expect(actions.callbackClaim).not.toHaveBeenCalled();
  });

  it('does not exchange if the claim indicates an already processed or stale callback', async () => {
    const { run, actions, exchange } = setup();
    actions.callbackClaim.mockResolvedValueOnce({ kind: 'restart_required' });
    expect(await run(input)).toEqual({ kind: 'restart_required' });
    expect(actions.callbackMarkSent).not.toHaveBeenCalled();
    expect(exchange).not.toHaveBeenCalled();
  });

  it('closes an unknown marker without sending any authorization code', async () => {
    const { run, actions, exchange } = setup();
    actions.callbackMarkSent.mockResolvedValueOnce(unknown);
    expect(await run(input)).toEqual({ kind: 'restart_required' });
    expect(exchange).not.toHaveBeenCalled();
    expect(actions.callbackClose).toHaveBeenCalledOnce();
    expect(actions.callbackClose.mock.calls[0][0]).toMatchObject({ candidateId: null, tokenEnvelope: null });
  });

  it('does not retransmit or recover a session from a failed upstream exchange', async () => {
    const { run, actions, exchange, verifyCandidate } = setup();
    exchange.mockResolvedValueOnce(unknown);
    expect(await run(input)).toEqual({ kind: 'restart_required' });
    expect(exchange).toHaveBeenCalledOnce();
    expect(verifyCandidate).not.toHaveBeenCalled();
    expect(actions.callbackCommit).not.toHaveBeenCalled();
    expect(actions.callbackClose).toHaveBeenCalledOnce();
  });

  it('queues only a verified non-owner candidate, encrypted to its exact cleanup identity', async () => {
    const { run, actions, verifyCandidate } = setup();
    const other = uuid('f');
    verifyCandidate.mockResolvedValueOnce({ kind: 'verified_candidate', authSubject: other, upstreamSessionId, expiresAt: now + 1000 });

    expect(await run(input)).toEqual({ kind: 'denied' });
    expect(actions.callbackCommit).not.toHaveBeenCalled();
    const close = actions.callbackClose.mock.calls[0][0];
    expect(close).toMatchObject({ verifiedSubject: other, verifiedUpstreamSessionId: upstreamSessionId, cleanupEnvironment: configuration.environment });
    expect(decryptOrphanTokens({ environment: configuration.environment, attemptId, candidateId: close.candidateId,
      authSubject: other, upstreamSessionId }, close.tokenEnvelope, configuration.orphanTokenKey)).toEqual(tokenPair);
  });

  it('never writes unverified tokens to session or cleanup custody', async () => {
    const { run, actions, verifyCandidate } = setup();
    verifyCandidate.mockResolvedValueOnce({ kind: 'rejected', reason: 'identity_mismatch' });
    expect(await run(input)).toEqual({ kind: 'restart_required' });
    expect(actions.callbackCommit).not.toHaveBeenCalled();
    expect(actions.callbackClose.mock.calls[0][0]).toMatchObject({ candidateId: null, tokenEnvelope: null });
  });

  it('looks up an unknown commit once with the same identifiers and only returns the exact session', async () => {
    const { run, actions, exchange } = setup();
    actions.callbackCommit.mockResolvedValueOnce(unknown);
    expect(await run(input)).toMatchObject({ kind: 'signed_in' });
    const commit = actions.callbackCommit.mock.calls[0][0];
    expect(actions.callbackResolve).toHaveBeenCalledOnce();
    expect(actions.callbackResolve.mock.calls[0][0]).toMatchObject({
      commitOperationId: commit.commitOperationId, requestFingerprint: commit.requestFingerprint,
      newSessionId: commit.newSessionId, generation: commit.generation,
    });
    expect(exchange).toHaveBeenCalledOnce();
    expect(actions.callbackClose).not.toHaveBeenCalled();
  });

  it('withholds the bearer when the commit could not be resolved', async () => {
    const { run, actions } = setup();
    actions.callbackCommit.mockResolvedValueOnce(unknown);
    actions.callbackResolve.mockResolvedValueOnce({ kind: 'unresolved' });
    expect(await run(input)).toEqual({ kind: 'unavailable' });
    expect(actions.callbackClose).toHaveBeenCalledOnce();
  });

  it('does not reissue a bearer or close a committed result after the client cancels', async () => {
    const { run, actions } = setup();
    const controller = new AbortController();
    actions.callbackCommit.mockImplementationOnce(async request => {
      controller.abort();
      return { kind: 'committed', attemptId, sessionId: request.newSessionId, generation: 8 };
    });
    expect(await run(input, controller.signal)).toEqual({ kind: 'unavailable' });
    expect(actions.callbackClose).not.toHaveBeenCalled();
  });

  it('uses time elapsed since the trusted database claim when verifying the JWT', async () => {
    const clock = vi.fn().mockReturnValueOnce(100).mockReturnValue(340.2);
    const { run, verifyCandidate } = setup(clock);
    await run(input);
    expect(verifyCandidate).toHaveBeenCalledExactlyOnceWith({ accessToken: tokenPair.accessToken, trustedNow: now + 241 }, expect.any(AbortSignal));
  });

  it('retries an uncertain close once with the same binding and settlement budget', async () => {
    const { run, actions, exchange } = setup();
    exchange.mockResolvedValueOnce(unknown);
    actions.callbackClose.mockResolvedValueOnce(unknown);

    expect(await run(input)).toEqual({ kind: 'restart_required' });
    expect(actions.callbackClose).toHaveBeenCalledTimes(2);
    expect(actions.callbackClose.mock.calls[1]).toEqual(actions.callbackClose.mock.calls[0]);
    expect(exchange).toHaveBeenCalledOnce();
  });

  it('enforces the work deadline even when the timer callback has not fired', async () => {
    let elapsed = 0;
    const { run, actions, exchange, verifyCandidate } = setup(() => elapsed);
    exchange.mockImplementationOnce(async () => {
      elapsed = 10_000;
      return { kind: 'tokens', ...tokenPair };
    });

    expect(await run(input)).toEqual({ kind: 'restart_required' });
    expect(verifyCandidate).not.toHaveBeenCalled();
    expect(actions.callbackCommit).not.toHaveBeenCalled();
    expect(actions.callbackClose).toHaveBeenCalledOnce();
  });
});
