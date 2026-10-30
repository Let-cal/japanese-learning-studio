import { describe, expect, it } from 'vitest';
import { formatVersionETag, parseAbility, parseCommandContext, parseGradeOutcome, parseUuid, parseVersion, parseVersionETag } from '../../src/contracts/common';

const id = 'f78cc651-146d-4502-8c85-2cab2a474179';
const context = { ownerId: id, datasetEpoch: id, operationId: id, expectedVersion: 0 };

describe('common contract validation', () => {
  it('accepts opaque UUIDs without changing case or treating them as authorization', () => {
    expect(parseUuid(id.toUpperCase())).toEqual({ ok: true, value: id.toUpperCase() });
  });
  it.each([null, 1, '', 'owner-1', ` ${id}`, `${id}\n`])('rejects a non-UUID identifier: %j', value => {
    expect(parseUuid(value).ok).toBe(false);
  });
  it.each([0, 1, Number.MAX_SAFE_INTEGER])('accepts nonnegative safe version %s', value => {
    expect(parseVersion(value)).toEqual({ ok: true, value });
  });
  it.each([-1, 0.5, '0', null, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])('rejects invalid versions without coercion: %j', value => {
    expect(parseVersion(value).ok).toBe(false);
  });
  it('validates command context and leaves the caller object untouched', () => {
    const input = Object.freeze(context);
    expect(parseCommandContext(input)).toEqual({ ok: true, value: context });
    expect(parseCommandContext({ ownerId: id, datasetEpoch: id, operationId: id }).ok).toBe(true);
    expect(input.expectedVersion).toBe(0);
  });
  it.each([
    null, [], {}, { ...context, ownerId: 3 }, { ...context, datasetEpoch: 'old' },
    { ...context, operationId: undefined }, { ...context, expectedVersion: -1 },
    { ...context, expectedVersion: undefined }, { ...context, payloadHash: 'client-trusted' },
  ])('returns explicit context errors: %j', input => {
    const result = parseCommandContext(input);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.length).toBeGreaterThan(0);
  });
  it('accepts only the approved ability and grade vocabulary', () => {
    for (const value of ['meaning', 'kana', 'kanji']) expect(parseAbility(value)).toEqual({ ok: true, value });
    for (const value of ['correct', 'incorrect', 'pending', 'needsReview', 'skipped']) expect(parseGradeOutcome(value)).toEqual({ ok: true, value });
    expect(parseAbility('reading').ok).toBe(false);
    expect(parseGradeOutcome('approved').ok).toBe(false);
  });
  it.each([[0, '"v0"'], [1, '"v1"'], [Number.MAX_SAFE_INTEGER, '"v9007199254740991"']] as const)('round trips strong version ETag %s', (version, etag) => {
    expect(formatVersionETag(version)).toEqual({ ok: true, value: etag });
    expect(parseVersionETag(etag)).toEqual({ ok: true, value: version });
  });
  it.each(['W/"v0"', 'v0', '"0"', '"v00"', '"v01"', '"v-1"', '"v1.0"', '"v1e1"', '"v9007199254740992"', ' "v0"', '"v0"\n', '*', '"v1", "v2"', null, 0])('rejects weak/malformed/noncanonical ETag %j', value => {
    expect(parseVersionETag(value).ok).toBe(false);
  });
  it.each([-1, 0.1, Number.MAX_SAFE_INTEGER + 1])('does not emit an ETag for invalid version %s', value => {
    expect(formatVersionETag(value).ok).toBe(false);
  });
});
