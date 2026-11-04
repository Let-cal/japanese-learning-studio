import { describe, expect, it } from 'vitest';
import { evaluateOwnerSession, type TrustedSessionPolicyFacts } from '../../src/infrastructure/auth/sessionPolicy';

const ownerId = 'aaaaaaa1-1111-4111-8111-111111111111';
const authSubject = 'bbbbbbb2-2222-4222-8222-222222222222';
const sessionId = 'ccccccc3-3333-4333-8333-333333333333';
const datasetEpoch = 'ddddddd4-4444-4444-8444-444444444444';
const otherId = 'eeeeeee5-5555-4555-8555-555555555555';
const now = 2_000_000_000;
const hour = 3_600_000;
const day = 86_400_000;

function facts(): TrustedSessionPolicyFacts {
  return {
    now,
    session: { sessionId, ownerId, authSubject, createdAt: now - day, lastActivityAt: now - hour, reauthenticatedAt: null, revokedAt: null },
    currentOwner: { ownerId, authorizedAuthSubject: authSubject, active: true },
    currentDataset: { ownerId, activeDatasetEpoch: datasetEpoch },
    upstreamCredential: 'usable',
    requiresDatasetEpoch: true,
    assertedDatasetEpoch: datasetEpoch,
    requiresRecentReauthentication: false,
  };
}

function evaluate(input: unknown) {
  return evaluateOwnerSession(input as TrustedSessionPolicyFacts);
}

describe('pure owner-session policy over trusted server snapshots', () => {
  it('returns only the four canonical authority fields for an active owner', () => {
    const upper = (value: string) => value.toUpperCase();
    const input = { ...facts(),
      session: { ...facts().session!, sessionId: upper(sessionId), ownerId: upper(ownerId), authSubject: upper(authSubject) },
      currentDataset: { ownerId: upper(ownerId), activeDatasetEpoch: upper(datasetEpoch) },
      assertedDatasetEpoch: upper(datasetEpoch),
    };
    expect(evaluateOwnerSession(input)).toEqual({ kind: 'authorized', context: { ownerId, authSubject, datasetEpoch, sessionId } });
  });

  it('never bootstraps an owner for a first visitor or an absent owner row', () => {
    expect(evaluateOwnerSession({ ...facts(), session: null })).toEqual({ kind: 'anonymous' });
    expect(evaluateOwnerSession({ ...facts(), currentOwner: null })).toEqual({ kind: 'denied' });
  });

  it.each([
    { currentOwner: { ownerId, authorizedAuthSubject: authSubject, active: false } },
    { currentOwner: { ownerId: otherId, authorizedAuthSubject: authSubject, active: true } },
    { currentOwner: { ownerId, authorizedAuthSubject: otherId, active: true } },
    { currentDataset: { ownerId: otherId, activeDatasetEpoch: datasetEpoch } },
    { session: { ...facts().session!, ownerId: otherId } },
    { session: { ...facts().session!, authSubject: otherId } },
    { session: { ...facts().session!, revokedAt: now - 1 } },
  ])('denies mismatched, inactive or revoked authority: %j', patch => {
    expect(evaluateOwnerSession({ ...facts(), ...patch })).toEqual({ kind: 'denied' });
  });

  it.each([
    [24 * hour - 1, 'authorized'], [24 * hour, 'idle_expired'], [24 * hour + 1, 'idle_expired'],
  ])('enforces the idle boundary at %s ms', (age, kind) => {
    expect(evaluateOwnerSession({ ...facts(), session: { ...facts().session!, createdAt: now - 2 * day, lastActivityAt: now - age } }).kind).toBe(kind);
  });

  it.each([
    [7 * day - 1, 'authorized'], [7 * day, 'absolute_expired'], [7 * day + 1, 'absolute_expired'],
  ])('activity cannot extend the absolute boundary at %s ms', (age, kind) => {
    expect(evaluateOwnerSession({ ...facts(), session: { ...facts().session!, createdAt: now - age, lastActivityAt: now } }).kind).toBe(kind);
  });

  it.each([
    [15 * 60_000 - 1, 'authorized'], [15 * 60_000, 'reauthentication_required'], [15 * 60_000 + 1, 'reauthentication_required'],
  ])('requires destructive reauthentication strictly younger than 15 minutes: %s', (age, kind) => {
    expect(evaluateOwnerSession({ ...facts(), requiresRecentReauthentication: true, session: { ...facts().session!, reauthenticatedAt: now - age } }).kind).toBe(kind);
  });

  it('does not infer reauthentication from login, activity or usable refreshed credentials', () => {
    expect(evaluateOwnerSession({ ...facts(), requiresRecentReauthentication: true, session: { ...facts().session!, createdAt: now, lastActivityAt: now } })).toEqual({ kind: 'reauthentication_required' });
  });

  it('accepts independent recent reauthentication after last activity but never repairs expiry', () => {
    const input = { ...facts(), requiresRecentReauthentication: true, session: { ...facts().session!, reauthenticatedAt: now } };
    expect(evaluateOwnerSession(input).kind).toBe('authorized');
    expect(evaluateOwnerSession({ ...input, session: { ...input.session, lastActivityAt: now - day } })).toEqual({ kind: 'idle_expired' });
    expect(evaluateOwnerSession({ ...input, session: { ...input.session, createdAt: now - 7 * day } })).toEqual({ kind: 'absolute_expired' });
  });

  it.each([
    ['refreshRequired', 'refresh_required'], ['reauthenticationRequired', 'reauthentication_required'], ['unavailable', 'unavailable'], ['unknown', 'unavailable'],
  ])('grants no context for upstream state %s', (upstreamCredential, kind) => {
    expect(evaluate({ ...facts(), upstreamCredential })).toEqual({ kind });
  });

  it('does not let a refresh-required credential revive an expired session', () => {
    expect(evaluateOwnerSession({ ...facts(), upstreamCredential: 'refreshRequired', session: { ...facts().session!, lastActivityAt: now - day } })).toEqual({ kind: 'idle_expired' });
  });

  it('binds current dataset authority and rejects stale or absent required assertions', () => {
    expect(evaluateOwnerSession({ ...facts(), assertedDatasetEpoch: otherId })).toEqual({ kind: 'stale_epoch' });
    expect(evaluateOwnerSession({ ...facts(), assertedDatasetEpoch: undefined })).toEqual({ kind: 'missing_epoch' });
    expect(evaluateOwnerSession({ ...facts(), requiresDatasetEpoch: false, assertedDatasetEpoch: undefined })).toEqual({ kind: 'authorized', context: { ownerId, authSubject, datasetEpoch, sessionId } });
    expect(evaluateOwnerSession({ ...facts(), requiresDatasetEpoch: false, assertedDatasetEpoch: otherId })).toEqual({ kind: 'stale_epoch' });
  });

  it.each([NaN, Infinity, -1, 0.1, Number.MAX_SAFE_INTEGER + 1, '2000000000', null, undefined])('rejects invalid server clock %j', now => {
    expect(evaluate({ ...facts(), now })).toEqual({ kind: 'unavailable' });
  });

  it.each([
    { createdAt: now + 1 }, { lastActivityAt: now + 1 }, { createdAt: now, lastActivityAt: now - 1 },
    { reauthenticatedAt: now + 1 }, { reauthenticatedAt: now - 2 * day }, { revokedAt: now + 1 },
    { createdAt: NaN }, { lastActivityAt: Infinity }, { lastActivityAt: -1 },
    { reauthenticatedAt: 0.1 }, { revokedAt: Number.MAX_SAFE_INTEGER + 1 },
  ])('fails closed on invalid or inconsistent session timestamps: %j', patch => {
    expect(evaluate({ ...facts(), session: { ...facts().session!, ...patch } })).toEqual({ kind: 'unavailable' });
  });

  it.each([
    null, [], { session: undefined }, { session: {} }, { currentOwner: 'unavailable' },
    { currentOwner: undefined }, { currentOwner: { ownerId, authorizedAuthSubject: authSubject } },
    { currentDataset: 'unavailable' }, { currentDataset: null }, { currentDataset: {} },
    { session: { ...facts().session!, sessionId: 'not-a-uuid' } },
    { currentDataset: { ownerId, activeDatasetEpoch: 'x'.repeat(1000) } },
    { requiresRecentReauthentication: undefined }, { requiresDatasetEpoch: undefined },
    { assertedDatasetEpoch: null },
  ])('fails closed on missing or malformed trusted facts: %j', patch => {
    expect(evaluate(patch === null || Array.isArray(patch) ? patch : { ...facts(), ...patch }).kind).toBe('unavailable');
  });

  it('does not use email or user metadata to grant access or copy sensitive fields', () => {
    const input = { ...facts(), email: 'private@example.test', user_metadata: { owner: true }, token: 'private', currentOwner: { ownerId, authorizedAuthSubject: authSubject, active: false } };
    expect(evaluate(input)).toEqual({ kind: 'denied' });
    expect(evaluate({ ...input, currentOwner: facts().currentOwner })).toEqual({ kind: 'authorized', context: { ownerId, authSubject, datasetEpoch, sessionId } });
  });

  it('does not mutate frozen snapshots or persist activity', () => {
    const input = facts();
    Object.freeze(input.session); Object.freeze(input.currentOwner); Object.freeze(input.currentDataset); Object.freeze(input);
    expect(evaluateOwnerSession(input).kind).toBe('authorized');
    expect(input.session!.lastActivityAt).toBe(1_996_400_000);
  });
});
