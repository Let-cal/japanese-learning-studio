import { createHash, randomUUID } from 'node:crypto';
import { createAuthActionSecret, fingerprintSessionCookie, hashAuthActionSecret } from '../../infrastructure/auth/authActionSecrets';
import type { OAuthActionRepository } from '../../infrastructure/auth/oauthActionRepository';
import { hashSessionSecret } from '../../infrastructure/auth/sessionSecrets';
import { createOAuthRequestBudget } from './oauthRequestBudget';

export function sessionPresentation(cookie: string | undefined) {
  const cookieFingerprint = fingerprintSessionCookie(cookie);
  let presentedSessionHash: string | null = null;
  if (cookie !== undefined) {
    try { presentedSessionHash = hashSessionSecret(cookie); }
    catch { /* The exact malformed presentation remains bound by the separate fingerprint. */ }
  }
  return { cookieFingerprint, presentedSessionHash };
}

export function recoveryProofHash(secret: string, flowHash: string): string {
  return createHash('sha256').update(
    `jls-oauth-recovery-secret-v1:${hashAuthActionSecret('csrf-login', secret)}:${flowHash}`, 'utf8',
  ).digest('hex');
}

export function recoveryIssuanceFingerprint(proofHash: string, flowHash: string): string {
  return createHash('sha256').update(`jls-oauth-recovery-proof-v1:${proofHash}:${flowHash}`, 'utf8').digest('hex');
}

interface Presentation {
  readonly browserSecret: string;
  readonly flowSecret: string;
  readonly presentedSession?: string;
}
type RecoveryProofResult =
  | { readonly kind: 'issued'; readonly csrfToken: string; readonly expiresAt: number }
  | { readonly kind: 'denied' | 'unavailable' };

/** Server-rendered recovery form only. Do not expose through generic CSRF issuance. */
export function createGoogleOAuthRecoveryProof(deps: Pick<OAuthActionRepository, 'resolveBrowser' | 'inspectCallback' | 'issueProof'>) {
  return async function issue(input: Presentation, signal?: AbortSignal): Promise<RecoveryProofResult> {
    let browserHash: string;
    let flowHash: string;
    let presentation: ReturnType<typeof sessionPresentation>;
    try {
      browserHash = hashAuthActionSecret('browser', input.browserSecret);
      flowHash = hashAuthActionSecret('oauth', input.flowSecret);
      presentation = sessionPresentation(input.presentedSession);
    } catch { return { kind: 'denied' }; }

    const budget = createOAuthRequestBudget(10_000, () => performance.now(), signal);
    if (budget.expired()) return { kind: 'unavailable' };
    try {
      const browser = await deps.resolveBrowser({ browserHash }, budget.signal);
      if (budget.expired()) return { kind: 'unavailable' };
      if (browser.kind !== 'active') return { kind: browser.kind === 'absent_or_expired' ? 'denied' : 'unavailable' };
      const inspectionHash = presentation.presentedSessionHash
        ?? (input.presentedSession === undefined ? null : presentation.cookieFingerprint.slice('present:'.length));
      const attempt = await deps.inspectCallback({ browserHash, flowHash, presentedSessionHash: inspectionHash }, budget.signal);
      if (budget.expired()) return { kind: 'unavailable' };
      switch (attempt.kind) {
        case 'denied': case 'completed_with_cookie': return { kind: 'denied' };
        case 'unavailable': case 'outcome_unknown': case 'invalid_input': return { kind: 'unavailable' };
        case 'pending': if (attempt.browserId !== browser.browserId) return { kind: 'denied' };
      }

      const csrfToken = createAuthActionSecret('csrf-login');
      const proofHash = recoveryProofHash(csrfToken, flowHash);
      const request = {
        issuanceId: randomUUID(), proofId: randomUUID(), operationId: randomUUID(), proofHash,
        requestFingerprint: recoveryIssuanceFingerprint(proofHash, flowHash), browserId: browser.browserId, browserHash,
        purpose: 'login' as const, ...presentation,
        expectedTokenVersion: null, expectedControlVersion: null, expectedDatasetEpoch: null,
      };
      if (budget.expired()) return { kind: 'unavailable' };
      let result = await deps.issueProof(request, budget.signal);
      if (result.kind === 'outcome_unknown' && !budget.expired()) result = await deps.issueProof(request, budget.signal);
      if (budget.expired() || result.kind !== 'issued' || result.browserId !== browser.browserId
        || result.generation !== browser.generation || result.proofId !== request.proofId) return { kind: 'unavailable' };
      return { kind: 'issued', csrfToken, expiresAt: result.expiresAt };
    } catch { return { kind: 'unavailable' }; }
  };
}
