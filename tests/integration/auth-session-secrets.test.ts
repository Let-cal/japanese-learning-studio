import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as crypto from 'node:crypto';
import { createSessionSecret, hashSessionSecret, verifySessionSecret } from '../../src/infrastructure/auth/sessionSecrets';

vi.mock('node:crypto', async importOriginal => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return { ...actual, randomBytes: vi.fn(actual.randomBytes) };
});

const zeroSecret = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

afterEach(() => vi.restoreAllMocks());

describe('disconnected opaque session-secret primitives', () => {
  it('creates independent canonical 256-bit secrets', () => {
    const first = createSessionSecret();
    const second = createSessionSecret();
    expect(first).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(first, 'base64url')).toHaveLength(32);
    expect(Buffer.from(first, 'base64url').toString('base64url')).toBe(first);
    expect(second).not.toBe(first);
  });

  it('hashes the decoded secret with a fixed versioned application purpose', () => {
    const expected = 'ccdc3b124c1b268674bd7d9cd8d14a8512e99ac85a9a5b7e6482b455cba47cf0';
    expect(hashSessionSecret(zeroSecret)).toBe(expected);
    expect(expected).toMatch(/^[0-9a-f]{64}$/);
    expect(expected).not.toBe(createHash('sha256').update(Buffer.alloc(32)).digest('hex'));
    expect(expected).not.toBe(createHash('sha256').update(zeroSecret).digest('hex'));
  });

  it.each([undefined, null, 7, {}, '', 'a'.repeat(42), 'a'.repeat(44), `${zeroSecret}=`,
    '/'.repeat(43), '+'.repeat(43), `${zeroSecret.slice(0, -1)}B`, ' '.repeat(43)])(
    'rejects malformed/noncanonical secrets without echoing them: %j', invalid => {
      expect(() => hashSessionSecret(invalid)).toThrowError('Invalid session secret');
      expect(verifySessionSecret(invalid, '0'.repeat(64))).toBe(false);
    },
  );

  it('accepts only a matching lowercase digest, never a digest as bearer', () => {
    const digest = hashSessionSecret(zeroSecret);
    expect(verifySessionSecret(zeroSecret, digest)).toBe(true);
    expect(verifySessionSecret(createSessionSecret(), digest)).toBe(false);
    for (const invalid of [digest.toUpperCase(), `${digest}0`, `${digest}\n`, `${digest}\r`, '0'.repeat(63), null, {}, digest.replace(/./, 'g')]) {
      expect(verifySessionSecret(zeroSecret, invalid)).toBe(false);
    }
    expect(verifySessionSecret(digest, digest)).toBe(false);
  });

  it('fails closed with a sanitized error when secure RNG fails', () => {
    vi.mocked(crypto.randomBytes).mockImplementationOnce(() => { throw new Error('sensitive RNG details'); });
    expect(() => createSessionSecret()).toThrowError(/^Session secret generation failed$/);
  });
});
