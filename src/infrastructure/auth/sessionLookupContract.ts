/** Stored metadata only: neither a verified JWT nor an owner authorization proof. */
export interface SessionLookupFound {
  readonly kind: 'found';
  readonly now: number;
  readonly session: {
    readonly sessionId: string;
    readonly ownerId: string;
    readonly authSubject: string;
    readonly upstreamSessionId: string;
    readonly createdAt: number;
    readonly lastActivityAt: number;
    readonly reauthenticatedAt: number | null;
    readonly revokedAt: number | null;
  };
  readonly currentOwner: {
    readonly ownerId: string;
    readonly authorizedAuthSubject: string;
    readonly active: boolean;
  } | null;
  readonly currentDataset: {
    readonly ownerId: string;
    readonly activeDatasetEpoch: string;
  } | null;
  readonly credential: {
    readonly state: 'usable' | 'refreshRequired' | 'reauthenticationRequired';
    readonly accessExpiresAt: number | null;
  };
}

export type SessionLookupMetadata = SessionLookupFound | { readonly kind: 'absent'; readonly now: number };
export type SessionLookupUnavailableReason = 'configuration' | 'timeout' | 'transport' | 'upstream_rejected' | 'invalid_response';
export type SessionLookupResult = SessionLookupMetadata
  | { readonly kind: 'input_absent' | 'input_invalid' }
  | { readonly kind: 'unavailable'; readonly reason: SessionLookupUnavailableReason };

function exact(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Reflect.ownKeys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

function timestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function uuid(value: unknown): string | null {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
    ? value.toLowerCase() : null;
}

/** Internal wire decoder. Copies only closed, immutable metadata; it never authorizes. */
export function parseSessionLookupMetadata(value: unknown): SessionLookupMetadata | null {
  if (exact(value, ['kind', 'now']) && value.kind === 'absent' && timestamp(value.now)) {
    return Object.freeze({ kind: 'absent', now: value.now });
  }
  if (!exact(value, ['kind', 'now', 'session', 'currentOwner', 'currentDataset', 'credential'])
    || value.kind !== 'found' || !timestamp(value.now)) return null;
  const { now, session, currentOwner: owner, currentDataset: dataset, credential } = value;
  if (!exact(session, ['sessionId', 'ownerId', 'authSubject', 'upstreamSessionId', 'createdAt', 'lastActivityAt',
    'reauthenticatedAt', 'revokedAt'])) return null;
  const sessionId = uuid(session.sessionId);
  const ownerId = uuid(session.ownerId);
  const authSubject = uuid(session.authSubject);
  const upstreamSessionId = uuid(session.upstreamSessionId);
  const { createdAt, lastActivityAt, reauthenticatedAt, revokedAt } = session;
  if (!sessionId || !ownerId || !authSubject || !upstreamSessionId || !timestamp(createdAt) || !timestamp(lastActivityAt)
    || createdAt > lastActivityAt || lastActivityAt > now) return null;
  if (reauthenticatedAt !== null && (!timestamp(reauthenticatedAt) || reauthenticatedAt < createdAt || reauthenticatedAt > now)) return null;
  if (revokedAt !== null && (!timestamp(revokedAt) || revokedAt < createdAt || revokedAt > now)) return null;

  let currentOwner: SessionLookupFound['currentOwner'] = null;
  if (owner !== null) {
    if (!exact(owner, ['ownerId', 'authorizedAuthSubject', 'active']) || typeof owner.active !== 'boolean') return null;
    const currentOwnerId = uuid(owner.ownerId);
    const authorizedAuthSubject = uuid(owner.authorizedAuthSubject);
    if (!currentOwnerId || !authorizedAuthSubject) return null;
    currentOwner = Object.freeze({ ownerId: currentOwnerId, authorizedAuthSubject, active: owner.active });
  }
  let currentDataset: SessionLookupFound['currentDataset'] = null;
  if (dataset !== null) {
    if (!exact(dataset, ['ownerId', 'activeDatasetEpoch'])) return null;
    const datasetOwnerId = uuid(dataset.ownerId);
    const activeDatasetEpoch = uuid(dataset.activeDatasetEpoch);
    if (!datasetOwnerId || !activeDatasetEpoch) return null;
    currentDataset = Object.freeze({ ownerId: datasetOwnerId, activeDatasetEpoch });
  }
  if (!exact(credential, ['state', 'accessExpiresAt'])) return null;
  const { state, accessExpiresAt } = credential;
  if (state !== 'usable' && state !== 'refreshRequired' && state !== 'reauthenticationRequired') return null;
  if (accessExpiresAt !== null && !timestamp(accessExpiresAt)) return null;
  if (state === 'usable' && (accessExpiresAt === null || accessExpiresAt <= now)) return null;
  return Object.freeze({ kind: 'found', now,
    session: Object.freeze({ sessionId, ownerId, authSubject, upstreamSessionId, createdAt, lastActivityAt, reauthenticatedAt, revokedAt }),
    currentOwner, currentDataset, credential: Object.freeze({ state, accessExpiresAt }) });
}
