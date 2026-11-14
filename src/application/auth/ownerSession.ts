import type { AuthIdentityVerifier } from '../../infrastructure/auth/authAdapter';
import type { RuntimeSnapshot, SessionRuntimeRepository } from '../../infrastructure/auth/sessionRuntimeRepository';
import { evaluateOwnerSession, type OwnerPolicyContext } from '../../infrastructure/auth/sessionPolicy';
import { decryptUpstreamTokens, type UpstreamTokenKey } from '../../infrastructure/auth/tokenEnvelope';
import { createOAuthRequestBudget } from './oauthRequestBudget';

interface SessionCookies {
  readonly sessionSecret?: string;
  readonly browserSecret?: string;
}

type Failure = 'anonymous' | 'denied' | 'unavailable' | 'refresh_required' | 'reauthentication_required';
type Result = { readonly kind: Failure } | { readonly kind: 'authorized'; readonly context: OwnerPolicyContext };
type CallbackResult = { readonly kind: 'authorized' | 'denied' | 'unavailable' };

interface Dependencies {
  readonly repository: Pick<SessionRuntimeRepository, 'snapshot' | 'credentials' | 'confirm'>;
  readonly identity: AuthIdentityVerifier;
  readonly monotonicClock?: () => number;
}

type Configuration = { readonly environment: string; readonly sessionTokenKey: UpstreamTokenKey };

function credentialStatus(snapshot: RuntimeSnapshot) {
  const { credential, now } = snapshot;
  switch (credential.state) {
    case 'usable': return credential.accessExpiresAt > now ? 'usable' : 'refreshRequired';
    case 'prepared': return 'unavailable';
    case 'sent_or_unknown': return (credential.refreshLeaseExpiresAt ?? 0) > now ? 'unavailable' : 'reauthenticationRequired';
    case 'uncertain': case 'reauthentication_required': case 'revoked': return 'reauthenticationRequired';
  }
}

/** Verify one current credential and record delivery. Refresh and data access are separate capabilities. */
export function createOwnerSessionVerifier(config: Configuration, deps: Dependencies) {
  const clock = deps.monotonicClock ?? (() => performance.now());
  async function verify(cookies: SessionCookies, signal?: AbortSignal, expectedSessionId?: string): Promise<Result> {
    const { browserSecret, sessionSecret } = cookies;
    if (signal?.aborted) return { kind: 'unavailable' };
    if (sessionSecret === undefined) return { kind: 'anonymous' };
    if (browserSecret === undefined) return { kind: 'denied' };
    const presented = { browserSecret, sessionSecret };
    try {
      const budget = createOAuthRequestBudget(10_000, clock, signal);
      if (budget.expired()) return { kind: 'unavailable' };
      const snapshot = await deps.repository.snapshot(presented, budget.signal);
      if (budget.expired()) return { kind: 'unavailable' };
      if (snapshot.kind === 'absent') return { kind: 'anonymous' };
      if (snapshot.kind === 'invalid_input') return { kind: 'denied' };
      if (snapshot.kind !== 'snapshot') return { kind: 'unavailable' };

      const { owner, browser, session, credential } = snapshot;
      if ((expectedSessionId !== undefined && session.sessionId !== expectedSessionId)
        || browser.currentSessionId !== session.sessionId || browser.generation !== browser.sessionGeneration
        || browser.expiresAt <= snapshot.now || owner.datasetEpoch === null || credential.state === 'revoked') {
        return { kind: 'denied' };
      }
      const policy = evaluateOwnerSession({
        now: snapshot.now, session,
        currentOwner: { ownerId: owner.ownerId, authorizedAuthSubject: owner.authSubject, active: owner.active },
        currentDataset: { ownerId: owner.ownerId, activeDatasetEpoch: owner.datasetEpoch },
        upstreamCredential: credentialStatus(snapshot),
        requiresDatasetEpoch: false, requiresRecentReauthentication: false,
      });
      if (policy.kind !== 'authorized') {
        switch (policy.kind) {
          case 'unavailable': case 'refresh_required': case 'reauthentication_required': return { kind: policy.kind };
          default: return { kind: 'denied' };
        }
      }
      const facts = {
        ...presented, ...policy.context, upstreamSessionId: session.upstreamSessionId, browserGeneration: browser.generation,
        tokenVersion: credential.tokenVersion, controlVersion: owner.controlVersion,
      };
      const beforeCredentials = clock();
      if (budget.expired()) return { kind: 'unavailable' };
      const stored = await deps.repository.credentials(facts, budget.signal);
      if (budget.expired()) return { kind: 'unavailable' };
      if (stored.kind === 'denied') return { kind: 'denied' };
      if (stored.kind !== 'credentials') return { kind: 'unavailable' };
      if (stored.now < snapshot.now || stored.accessExpiresAt !== credential.accessExpiresAt) return { kind: 'unavailable' };

      const { accessToken } = decryptUpstreamTokens({
        environment: config.environment, ownerId: facts.ownerId, sessionId: facts.sessionId, authSubject: facts.authSubject,
      }, stored.tokenEnvelope, config.sessionTokenKey);
      // Elapsed time from before the DB read conservatively covers its full round trip.
      const databaseTime = () => {
        const elapsed = clock() - beforeCredentials;
        return Number.isFinite(elapsed) && elapsed >= 0 ? stored.now + Math.ceil(elapsed) : Number.NaN;
      };
      const trustedNow = databaseTime();
      if (!Number.isSafeInteger(trustedNow) || budget.expired()) return { kind: 'unavailable' };
      if (trustedNow >= stored.accessExpiresAt) return { kind: 'refresh_required' };
      const identity = await deps.identity.verify({
        accessToken, expectedAuthSubject: facts.authSubject, expectedUpstreamSessionId: facts.upstreamSessionId, trustedNow,
      }, budget.signal);
      const verifiedAt = databaseTime();
      if (!Number.isSafeInteger(verifiedAt) || budget.expired()) return { kind: 'unavailable' };
      if (verifiedAt >= stored.accessExpiresAt && (identity.kind === 'verified'
        || (identity.kind === 'rejected' && identity.reason === 'invalid_token'))) return { kind: 'refresh_required' };
      if (identity.kind === 'rejected') {
        return { kind: identity.reason === 'invalid_token' ? 'reauthentication_required' : 'denied' };
      }
      if (identity.kind !== 'verified' || identity.authSubject !== facts.authSubject
        || identity.upstreamSessionId !== facts.upstreamSessionId || identity.expiresAt !== stored.accessExpiresAt) {
        return { kind: 'unavailable' };
      }

      const confirmed = await deps.repository.confirm({
        ...facts, verifiedAuthSubject: identity.authSubject, verifiedUpstreamSessionId: identity.upstreamSessionId,
      }, budget.signal);
      if (budget.expired()) return { kind: 'unavailable' };
      if (confirmed.kind === 'denied') return { kind: 'denied' };
      if (confirmed.kind !== 'confirmed') return { kind: 'unavailable' };
      const finalTime = databaseTime();
      if (!Number.isSafeInteger(finalTime)) return { kind: 'unavailable' };
      if (finalTime >= identity.expiresAt) return { kind: 'refresh_required' };
      return { kind: 'authorized', context: confirmed.context };
    } catch { return { kind: 'unavailable' }; }
  }
  return Object.freeze({
    verify: (cookies: SessionCookies, signal?: AbortSignal) => verify(cookies, signal),
    async verifyForCallback(input: Required<SessionCookies> & { sessionId: string }, signal: AbortSignal): Promise<CallbackResult> {
      const result = await verify(input, signal, input.sessionId);
      if (signal.aborted || result.kind === 'unavailable' || result.kind === 'refresh_required') return { kind: 'unavailable' };
      return { kind: result.kind === 'authorized' ? 'authorized' : 'denied' };
    },
  });
}
