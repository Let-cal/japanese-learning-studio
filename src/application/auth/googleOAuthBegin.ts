import { createHash, randomUUID } from 'node:crypto';
import {
  createAuthActionSecret, encryptPkceVerifier, fingerprintSessionCookie, hashAuthActionSecret, type PkceKey,
} from '../../infrastructure/auth/authActionSecrets';
import type { OAuthActionRepository } from '../../infrastructure/auth/oauthActionRepository';
import { createPkceVerifier, type OAuthTransport } from '../../infrastructure/auth/oauthTransport';
import { createOAuthRequestBudget } from './oauthRequestBudget';

interface Dependencies {
  readonly beginLogin: OAuthActionRepository['beginLogin'];
  readonly authorizationUrl: OAuthTransport['authorizationUrl'];
  readonly monotonicClock?: () => number;
}

interface ResolvedLoginProof {
  readonly browserId: string;
  readonly operationId: string;
  readonly generation: number;
  readonly browserSecret: string;
  readonly csrfToken: string;
  readonly presentedSession?: string;
}

type BeginResult =
  | { readonly kind: 'redirect'; readonly location: string; readonly flowSecret: string; readonly expiresAt: number }
  | { readonly kind: 'denied' | 'restart_required' | 'unavailable' };

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** The route must resolve the proof and enforce exact Origin before invoking this use case. */
export function createGoogleOAuthBegin(config: { readonly environment: string; readonly pkceKey: PkceKey }, deps: Dependencies) {
  const clock = deps.monotonicClock ?? (() => performance.now());
  return async function begin(input: ResolvedLoginProof, requestSignal?: AbortSignal): Promise<BeginResult> {
    if (requestSignal?.aborted) return { kind: 'unavailable' };
    const { browserId, operationId, generation } = input;
    if (!uuid.test(browserId) || !uuid.test(operationId) || !Number.isSafeInteger(generation) || generation < 0) {
      return { kind: 'denied' };
    }
    let browserHash: string;
    let proofHash: string;
    let cookieFingerprint: string;
    try {
      browserHash = hashAuthActionSecret('browser', input.browserSecret);
      proofHash = hashAuthActionSecret('csrf-login', input.csrfToken);
      cookieFingerprint = fingerprintSessionCookie(input.presentedSession);
    } catch { return { kind: 'denied' }; }

    try {
      const work = createOAuthRequestBudget(10_000, clock, requestSignal);
      const { signal } = work;
      const verifier = createPkceVerifier();
      const destination = deps.authorizationUrl(verifier);
      if (destination.kind !== 'ready') return { kind: 'unavailable' };

      const attemptId = randomUUID();
      const flowSecret = createAuthActionSecret('oauth');
      const flowHash = hashAuthActionSecret('oauth', flowSecret);
      const pkceEnvelope = encryptPkceVerifier({ environment: config.environment, bindingId: browserId, attemptId },
        verifier, config.pkceKey);
      const requestFingerprint = createHash('sha256').update(JSON.stringify(['jls-google-begin-v1',
        browserHash, proofHash, operationId, cookieFingerprint, attemptId, flowHash, pkceEnvelope]), 'utf8').digest('hex');
      const request = { browserHash, proofHash, operationId, cookieFingerprint, attemptId, flowHash, pkceEnvelope, requestFingerprint };
      if (work.expired()) return { kind: 'unavailable' };

      let result = await deps.beginLogin(request, signal);
      if (result.kind === 'outcome_unknown' && !work.expired()) {
        // The database accepts only the same operation, exact binding, and still-pending attempt.
        result = await deps.beginLogin(request, signal);
        if (result.kind !== 'begun') return { kind: 'unavailable' };
      }
      if (work.expired()) return { kind: 'unavailable' };
      if (result.kind !== 'begun') {
        return { kind: result.kind === 'denied' || result.kind === 'restart_required' ? result.kind : 'unavailable' };
      }
      if (result.attemptId !== attemptId || result.generation !== generation) return { kind: 'unavailable' };
      return { kind: 'redirect', location: destination.url, flowSecret, expiresAt: result.expiresAt };
    } catch { return { kind: 'unavailable' }; }
  };
}
