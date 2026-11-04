import { ownField, parseUuid } from '../../contracts/common';

/** A future server verifier must produce this outcome after checking session binding. */
export type ServerVerifiedCsrfOutcome =
  | { readonly kind: 'verified'; readonly sessionId: string }
  | { readonly kind: 'unverified' | 'unavailable' };

/** Trusted internal port: a browser-supplied "verified" tag is never security proof. */
export interface TrustedRequestPolicyFacts {
  readonly method: string;
  readonly appOrigin: string;
  readonly receivedOrigin: string | null;
  readonly sessionId: string;
  readonly csrf: ServerVerifiedCsrfOutcome | null;
}

/** Neither successful decision authenticates a caller or authorizes an owner. */
export type OwnerRequestDecision =
  | { readonly kind: 'safe_method' | 'mutation_allowed' }
  | { readonly kind: 'denied'; readonly reason: 'invalid_facts' | 'unsupported_method'
    | 'invalid_configuration' | 'invalid_session' | 'invalid_origin' | 'invalid_csrf' };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** HTTPS only, including local development; no implicit HTTP loopback exception. */
function isCanonicalAppOrigin(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value && url.username === '' && url.password === '' && !url.hostname.includes('*');
  } catch {
    return false;
  }
}

/**
 * Pure method/origin/verified-CSRF decision, not a CSRF verifier or auth guard.
 * No cookies, token comparisons, forwarded-host inference, CORS or network access.
 */
export function evaluateOwnerRequest(input: TrustedRequestPolicyFacts): OwnerRequestDecision {
  if (!isRecord(input)) return { kind: 'denied', reason: 'invalid_facts' };
  switch (ownField(input, 'method')) {
    case 'GET': case 'HEAD': case 'OPTIONS': return { kind: 'safe_method' };
    case 'POST': case 'PUT': case 'PATCH': case 'DELETE': break;
    default: return { kind: 'denied', reason: 'unsupported_method' };
  }

  const appOrigin = ownField(input, 'appOrigin');
  if (!isCanonicalAppOrigin(appOrigin)) return { kind: 'denied', reason: 'invalid_configuration' };
  const session = parseUuid(ownField(input, 'sessionId'));
  if (!session.ok) return { kind: 'denied', reason: 'invalid_session' };
  if (ownField(input, 'receivedOrigin') !== appOrigin) return { kind: 'denied', reason: 'invalid_origin' };
  const csrf = ownField(input, 'csrf');
  if (!isRecord(csrf) || ownField(csrf, 'kind') !== 'verified') return { kind: 'denied', reason: 'invalid_csrf' };
  const csrfSession = parseUuid(ownField(csrf, 'sessionId'));
  if (!csrfSession.ok || csrfSession.value.toLowerCase() !== session.value.toLowerCase()) {
    return { kind: 'denied', reason: 'invalid_csrf' };
  }
  return { kind: 'mutation_allowed' };
}
