import { ownField, parseUuid } from '../../contracts/common';

export interface ServerSessionRecord {
  readonly sessionId: string;
  readonly ownerId: string;
  readonly authSubject: string;
  readonly createdAt: number;
  readonly lastActivityAt: number;
  readonly reauthenticatedAt: number | null;
  readonly revokedAt: number | null;
}

/** These facts must come from a future verified server adapter, never a request body. */
export interface TrustedSessionPolicyFacts {
  readonly now: number;
  readonly session: ServerSessionRecord | null;
  /** null means a confirmed absent owner; unavailable means the lookup failed. */
  readonly currentOwner: {
    readonly ownerId: string;
    readonly authorizedAuthSubject: string;
    readonly active: boolean;
  } | null | 'unavailable';
  readonly currentDataset: {
    readonly ownerId: string;
    readonly activeDatasetEpoch: string;
  } | 'unavailable';
  readonly upstreamCredential: 'usable' | 'refreshRequired' | 'reauthenticationRequired' | 'unavailable';
  readonly assertedDatasetEpoch?: string;
  readonly requiresDatasetEpoch: boolean;
  readonly requiresRecentReauthentication: boolean;
}

export interface OwnerPolicyContext {
  readonly ownerId: string;
  readonly authSubject: string;
  readonly datasetEpoch: string;
  readonly sessionId: string;
}

/** Internal policy decisions; these are not public HTTP statuses or authentication proof. */
export type OwnerSessionDecision =
  | { readonly kind: 'authorized'; readonly context: OwnerPolicyContext }
  | { readonly kind: 'anonymous' | 'denied' | 'unavailable' | 'idle_expired' | 'absolute_expired'
    | 'refresh_required' | 'reauthentication_required' | 'missing_epoch' | 'stale_epoch' };

const IDLE_LIFETIME_MS = 24 * 60 * 60 * 1000;
const ABSOLUTE_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
const RECENT_REAUTHENTICATION_MS = 15 * 60 * 1000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isTimestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function canonicalUuid(value: unknown): string | null {
  const parsed = parseUuid(value);
  return parsed.ok ? parsed.value.toLowerCase() : null;
}

/**
 * Pure synchronous rules only: no cookie/JWT verification, refresh, store lookup,
 * freshness guarantee, activity persistence or revocation. A future server adapter
 * must establish those facts before calling this policy; it is not requireOwnerSession.
 */
export function evaluateOwnerSession(input: TrustedSessionPolicyFacts): OwnerSessionDecision {
  if (!isRecord(input)) return { kind: 'unavailable' };
  const now = ownField(input, 'now');
  const requiresDatasetEpoch = ownField(input, 'requiresDatasetEpoch');
  const requiresReauthentication = ownField(input, 'requiresRecentReauthentication');
  if (!isTimestamp(now) || typeof requiresDatasetEpoch !== 'boolean' || typeof requiresReauthentication !== 'boolean') {
    return { kind: 'unavailable' };
  }

  const session = ownField(input, 'session');
  if (session === null) return { kind: 'anonymous' };
  if (!isRecord(session)) return { kind: 'unavailable' };
  const sessionId = canonicalUuid(ownField(session, 'sessionId'));
  const ownerId = canonicalUuid(ownField(session, 'ownerId'));
  const authSubject = canonicalUuid(ownField(session, 'authSubject'));
  const createdAt = ownField(session, 'createdAt');
  const lastActivityAt = ownField(session, 'lastActivityAt');
  const reauthenticatedAt = ownField(session, 'reauthenticatedAt');
  const revokedAt = ownField(session, 'revokedAt');
  if (!sessionId || !ownerId || !authSubject || !isTimestamp(createdAt) || !isTimestamp(lastActivityAt)
    || createdAt > lastActivityAt || lastActivityAt > now) return { kind: 'unavailable' };
  // Reauthentication is recorded independently of activity: it may be newer than
  // lastActivityAt, but cannot precede this session's creation or be in the future.
  if (reauthenticatedAt !== null && (!isTimestamp(reauthenticatedAt) || reauthenticatedAt < createdAt || reauthenticatedAt > now)) {
    return { kind: 'unavailable' };
  }
  if (revokedAt !== null && (!isTimestamp(revokedAt) || revokedAt < createdAt || revokedAt > now)) {
    return { kind: 'unavailable' };
  }

  const owner = ownField(input, 'currentOwner');
  if (owner === null) return { kind: 'denied' };
  if (!isRecord(owner)) return { kind: 'unavailable' };
  const currentOwnerId = canonicalUuid(ownField(owner, 'ownerId'));
  const authorizedAuthSubject = canonicalUuid(ownField(owner, 'authorizedAuthSubject'));
  const active = ownField(owner, 'active');
  const dataset = ownField(input, 'currentDataset');
  if (!isRecord(dataset)) return { kind: 'unavailable' };
  const datasetOwnerId = canonicalUuid(ownField(dataset, 'ownerId'));
  const datasetEpoch = canonicalUuid(ownField(dataset, 'activeDatasetEpoch'));
  if (!currentOwnerId || !authorizedAuthSubject || typeof active !== 'boolean' || !datasetOwnerId || !datasetEpoch) {
    return { kind: 'unavailable' };
  }
  if (!active || currentOwnerId !== ownerId || authorizedAuthSubject !== authSubject || datasetOwnerId !== ownerId || revokedAt !== null) {
    return { kind: 'denied' };
  }

  // Expiry is checked before any upstream refresh decision: refresh cannot revive it.
  if (now - createdAt >= ABSOLUTE_LIFETIME_MS) return { kind: 'absolute_expired' };
  if (now - lastActivityAt >= IDLE_LIFETIME_MS) return { kind: 'idle_expired' };
  switch (ownField(input, 'upstreamCredential')) {
    case 'usable': break;
    case 'refreshRequired': return { kind: 'refresh_required' };
    case 'reauthenticationRequired': return { kind: 'reauthentication_required' };
    default: return { kind: 'unavailable' };
  }

  const assertedEpoch = ownField(input, 'assertedDatasetEpoch');
  if (assertedEpoch === undefined) {
    if (requiresDatasetEpoch) return { kind: 'missing_epoch' };
  } else {
    const canonicalEpoch = canonicalUuid(assertedEpoch);
    if (!canonicalEpoch) return { kind: 'unavailable' };
    if (canonicalEpoch !== datasetEpoch) return { kind: 'stale_epoch' };
  }
  if (requiresReauthentication && (reauthenticatedAt === null || now - reauthenticatedAt >= RECENT_REAUTHENTICATION_MS)) {
    return { kind: 'reauthentication_required' };
  }
  return { kind: 'authorized', context: { ownerId, authSubject, datasetEpoch, sessionId } };
}
