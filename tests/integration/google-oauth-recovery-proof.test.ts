import { describe, expect, it, vi } from 'vitest';
import { createGoogleOAuthRecoveryProof, recoveryProofHash, recoveryIssuanceFingerprint, sessionPresentation }
  from '../../src/application/auth/googleOAuthRecoveryProof';
import { hashAuthActionSecret } from '../../src/infrastructure/auth/authActionSecrets';
import type { OAuthActionRepository } from '../../src/infrastructure/auth/oauthActionRepository';

const browserSecret = `jls-browser-v1.${'A'.repeat(43)}`;
const flowSecret = `jls-oauth-v1.${'E'.repeat(43)}`;
const flowHash = hashAuthActionSecret('oauth', flowSecret);
const browserId = '22222222-2222-4222-8222-222222222222';
const expiresAt = 1_800_000_900_000;
const input = { browserSecret, flowSecret, presentedSession: 'old-cookie' };
const pending = { kind: 'pending', browserId, attemptId: '33333333-3333-4333-8333-333333333333' } as const;

function setup() {
  const resolveBrowser = vi.fn<OAuthActionRepository['resolveBrowser']>().mockResolvedValue({ kind: 'active', browserId, generation: 7 });
  const issueProof = vi.fn<OAuthActionRepository['issueProof']>().mockImplementation(async data => ({
    kind: 'issued', browserId, proofId: data.proofId, generation: 7, expiresAt,
  }));
  const inspectCallback = vi.fn<OAuthActionRepository['inspectCallback']>().mockResolvedValue(pending);
  return { run: createGoogleOAuthRecoveryProof({ resolveBrowser, issueProof, inspectCallback }), resolveBrowser, issueProof, inspectCallback };
}

describe('server-side issuance of a recovery-specific proof', () => {
  it('binds the persisted proof to the exact flow and excludes ordinary login and successor flow hashes', async () => {
    const { run, issueProof, inspectCallback } = setup();
    const result = await run(input);
    expect(result.kind).toBe('issued');
    if (result.kind !== 'issued') throw Error('Missing proof');
    expect(result.expiresAt).toBe(expiresAt);
    const data = issueProof.mock.calls[0][0];
    expect(data).toMatchObject({ browserId, purpose: 'login', ...sessionPresentation(input.presentedSession) });
    expect(data.proofHash).toBe(recoveryProofHash(result.csrfToken, flowHash));
    expect(data.requestFingerprint).toBe(recoveryIssuanceFingerprint(data.proofHash, flowHash));
    expect(data.proofHash).not.toBe(hashAuthActionSecret('csrf-login', result.csrfToken));
    expect(data.proofHash).not.toBe(recoveryProofHash(result.csrfToken, '1'.repeat(64)));
    expect(inspectCallback.mock.calls[0][0].presentedSessionHash).toMatch(/^[a-f0-9]{64}$/);
    expect(data.presentedSessionHash).toBeNull();
    expect(data.cookieFingerprint).toMatch(/^present:[a-f0-9]{64}$/);
  });

  it('never issues a recovery proof for an unknown flow, missing binding, or current result cookie', async () => {
    const { run, resolveBrowser, issueProof, inspectCallback } = setup();
    inspectCallback.mockResolvedValueOnce({ kind: 'denied' });
    expect(await run(input)).toEqual({ kind: 'denied' });
    inspectCallback.mockResolvedValueOnce({ kind: 'completed_with_cookie', attemptId: pending.attemptId,
      sessionId: '44444444-4444-4444-8444-444444444444', generation: 7 });
    expect(await run(input)).toEqual({ kind: 'denied' });
    resolveBrowser.mockResolvedValueOnce({ kind: 'absent_or_expired' });
    expect(await run(input)).toEqual({ kind: 'denied' });
    expect(issueProof).not.toHaveBeenCalled();
  });

  it('replays only the same issuance tuple after an uncertain write', async () => {
    const { run, issueProof } = setup();
    issueProof.mockResolvedValueOnce({ kind: 'outcome_unknown', reason: 'transport' });
    expect(await run(input)).toMatchObject({ kind: 'issued' });
    expect(issueProof.mock.calls[0]).toEqual(issueProof.mock.calls[1]);
  });

  it('withholds the token if the proof is returned for a different generation', async () => {
    const { run, issueProof } = setup();
    issueProof.mockImplementationOnce(async data => ({ kind: 'issued', browserId, proofId: data.proofId, generation: 8, expiresAt }));
    expect(await run(input)).toEqual({ kind: 'unavailable' });
  });
});
