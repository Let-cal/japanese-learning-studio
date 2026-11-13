import { createHash, randomUUID } from 'node:crypto';
import { decryptPkceVerifier, hashAuthActionSecret, type PkceKey } from '../../infrastructure/auth/authActionSecrets';
import type { AuthCandidateVerifier } from '../../infrastructure/auth/authAdapter';
import type { OAuthActionRepository } from '../../infrastructure/auth/oauthActionRepository';
import type { OAuthTransport } from '../../infrastructure/auth/oauthTransport';
import { encryptOrphanTokens, type OrphanTokenKey } from '../../infrastructure/auth/orphanTokenEnvelope';
import { createSessionSecret, hashSessionSecret } from '../../infrastructure/auth/sessionSecrets';
import { encryptUpstreamTokens, type UpstreamTokenKey } from '../../infrastructure/auth/tokenEnvelope';
import { createOAuthRequestBudget } from './oauthRequestBudget';

type Actions = Pick<OAuthActionRepository,
  'callbackClaim' | 'callbackMarkSent' | 'callbackCommit' | 'callbackResolve' | 'callbackClose'>;

interface Configuration {
  readonly environment: string;
  readonly pkceKey: PkceKey;
  readonly sessionTokenKey: UpstreamTokenKey;
  readonly orphanTokenKey: OrphanTokenKey;
}

interface Dependencies {
  readonly actions: Actions;
  readonly exchange: OAuthTransport['exchange'];
  readonly verifyCandidate: AuthCandidateVerifier['verifyCandidate'];
  readonly monotonicClock?: () => number;
}

interface FreshCallback {
  readonly browserId: string;
  readonly attemptId: string;
  readonly browserSecret: string;
  readonly flowSecret: string;
  readonly authorizationCode: string;
}

type Failure = 'denied' | 'restart_required' | 'unavailable';
type CallbackResult = { readonly kind: Failure } | { readonly kind: 'signed_in'; readonly sessionSecret: string };

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const noCandidate = {
  candidateId: null, verifiedSubject: null, verifiedUpstreamSessionId: null, tokenEnvelope: null, cleanupEnvironment: null,
};

function fingerprint(operation: 'commit' | 'close', values: readonly unknown[]): string {
  return createHash('sha256').update(JSON.stringify(['jls-google-callback-v1', operation, ...values]), 'utf8').digest('hex');
}

/** Fresh callback only. The caller resolves IDs from the exact cookies on the server. */
export function createGoogleOAuthCallback(config: Configuration, deps: Dependencies) {
  const clock = deps.monotonicClock ?? (() => performance.now());

  return async function finishFreshCallback(input: FreshCallback, requestSignal?: AbortSignal): Promise<CallbackResult> {
    if (requestSignal?.aborted) return { kind: 'unavailable' };
    const { browserId, attemptId, authorizationCode } = input;
    if (!uuid.test(browserId) || !uuid.test(attemptId) || !/^[\x21-\x7e]{1,2048}$/.test(authorizationCode)) {
      return { kind: 'denied' };
    }

    let browserHash: string;
    let flowHash: string;
    try {
      browserHash = hashAuthActionSecret('browser', input.browserSecret);
      flowHash = hashAuthActionSecret('oauth', input.flowSecret);
    } catch { return { kind: 'denied' }; }

    const claimId = randomUUID();
    const binding = { browserHash, flowHash, attemptId, claimId };
    let verifiedPair: {
      candidateId: string; verifiedSubject: string; verifiedUpstreamSessionId: string;
      tokenEnvelope: string; cleanupEnvironment: string;
    } | null = null;
    let settlement: ReturnType<typeof createOAuthRequestBudget> | undefined;
    // A disconnected browser cannot cancel durable recovery. The shared reserve bounds both RPCs.
    const settlementBudget = () => settlement ??= createOAuthRequestBudget(4_000, () => performance.now());

    async function close(kind: Failure): Promise<CallbackResult> {
      const closeOperationId = randomUUID();
      const candidate = verifiedPair ?? noCandidate;
      const requestFingerprint = fingerprint('close', [attemptId, claimId, closeOperationId, candidate]);
      try {
        const budget = settlementBudget();
        if (budget.expired()) return { kind: 'unavailable' };
        const request = { ...binding, closeOperationId, requestFingerprint, ...candidate };
        let result = await deps.actions.callbackClose(request, budget.signal);
        if (result.kind === 'outcome_unknown' && !budget.expired()) {
          result = await deps.actions.callbackClose(request, budget.signal);
        }
        return { kind: result.kind === 'closed' ? kind : 'unavailable' };
      } catch { return { kind: 'unavailable' }; }
    }

    let ownsClaim = false;
    try {
      const work = createOAuthRequestBudget(10_000, clock, requestSignal);
      const { signal } = work;
      if (work.expired()) return { kind: 'unavailable' };
      const claim = await deps.actions.callbackClaim({ ...binding, browserId }, signal);
      if (claim.kind !== 'claimed') {
        if (claim.kind === 'outcome_unknown') return close('unavailable');
        return { kind: claim.kind === 'denied' || claim.kind === 'restart_required' ? claim.kind : 'unavailable' };
      }
      if (claim.attemptId !== attemptId || claim.claimId !== claimId || claim.browserId !== browserId) {
        return { kind: 'unavailable' };
      }
      ownsClaim = true;
      if (work.expired()) return close('unavailable');

      const codeVerifier = decryptPkceVerifier({ environment: config.environment, bindingId: browserId, attemptId },
        claim.pkceEnvelope, config.pkceKey);
      if (work.expired()) return close('unavailable');
      const mark = await deps.actions.callbackMarkSent(binding, signal);
      if (mark.kind !== 'send_intent' || work.expired()) return close('restart_required');

      const tokens = await deps.exchange({ authorizationCode, codeVerifier }, signal);
      if (tokens.kind !== 'tokens') return close('restart_required');
      const elapsed = work.elapsed();
      const trustedNow = claim.now + Math.ceil(elapsed);
      if (!Number.isSafeInteger(trustedNow) || elapsed < 0 || work.expired()) return close('restart_required');

      const verified = await deps.verifyCandidate({ accessToken: tokens.accessToken, trustedNow }, signal);
      if (verified.kind !== 'verified_candidate') return close('restart_required');

      const candidateId = randomUUID();
      const authSubject = verified.authSubject;
      const upstreamSessionId = verified.upstreamSessionId;
      const pair = { accessToken: tokens.accessToken, refreshToken: tokens.refreshToken };
      verifiedPair = {
        candidateId, verifiedSubject: authSubject, verifiedUpstreamSessionId: upstreamSessionId,
        cleanupEnvironment: config.environment,
        tokenEnvelope: encryptOrphanTokens({ environment: config.environment, attemptId, candidateId, authSubject, upstreamSessionId },
          pair, config.orphanTokenKey),
      };
      if (authSubject !== claim.authSubject) return close('denied');
      if (work.expired()) return close('unavailable');

      const newSessionId = randomUUID();
      const sessionSecret = createSessionSecret();
      const newSessionHash = hashSessionSecret(sessionSecret);
      const tokenEnvelope = encryptUpstreamTokens({ environment: config.environment, ownerId: claim.ownerId,
        sessionId: newSessionId, authSubject }, pair, config.sessionTokenKey);
      const commitOperationId = randomUUID();
      const requestFingerprint = fingerprint('commit', [attemptId, claimId, commitOperationId, candidateId, authSubject,
        upstreamSessionId, newSessionId, newSessionHash, tokenEnvelope, verified.expiresAt]);
      const settlementInput = { ...binding, commitOperationId, requestFingerprint, newSessionId, generation: claim.generation };
      if (work.expired()) return close('unavailable');
      const commit = await deps.actions.callbackCommit({
        ...settlementInput, candidateId, verifiedSubject: authSubject, verifiedUpstreamSessionId: upstreamSessionId,
        newSessionHash, tokenEnvelope, accessExpiresAt: verified.expiresAt,
      }, signal);
      const receipt = commit.kind === 'outcome_unknown'
        ? await deps.actions.callbackResolve(settlementInput, settlementBudget().signal) : commit;
      if (receipt.kind !== 'committed') return close(commit.kind === 'denied' ? 'restart_required' : 'unavailable');
      if (receipt.attemptId !== attemptId || receipt.sessionId !== newSessionId || receipt.generation !== claim.generation + 1
        || work.expired()) return { kind: 'unavailable' };
      return { kind: 'signed_in', sessionSecret };
    } catch {
      return ownsClaim ? close('unavailable') : { kind: 'unavailable' };
    }
  };
}
