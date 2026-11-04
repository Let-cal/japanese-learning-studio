import { createCipheriv, randomBytes } from 'node:crypto';
import { describe, expect, it, vi, afterEach } from 'vitest';
import * as crypto from 'node:crypto';
import { encryptUpstreamTokens, decryptUpstreamTokens } from '../../src/infrastructure/auth/tokenEnvelope';

vi.mock('node:crypto', async importOriginal => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return { ...actual, randomBytes: vi.fn(actual.randomBytes) };
});

const context = Object.freeze({ environment: 'test-local', ownerId: 'aaaaaaaa-1111-4111-8111-111111111111',
  sessionId: 'bbbbbbbb-2222-4222-8222-222222222222', authSubject: 'cccccccc-3333-4333-8333-333333333333' });
const key = Object.freeze({ keyId: 'key_1', keyBytes: Buffer.alloc(32, 19) });
const tokens = Object.freeze({ accessToken: ' 日本語 opaque +/=\n', refreshToken: 'tiếng Việt 🔒.opaque' });
const failure = 'Upstream token decryption failed';
const encryptionFailure = 'Upstream token encryption failed';

// Independently built authenticated fixtures exercise validation after GCM final().
function sealPlaintext(plaintext: string | Buffer) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key.keyBytes, iv, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(JSON.stringify(['japanese-learning-studio:upstream-tokens', 'v1', key.keyId,
    context.environment, context.ownerId, context.sessionId, context.authSubject]), 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return ['v1', key.keyId, iv.toString('base64url'), ciphertext.toString('base64url'), cipher.getAuthTag().toString('base64url')].join('.');
}

function rejectEnvelope(envelope: unknown, expectedContext: unknown = context, expectedKey: unknown = key) {
  expect(() => decryptUpstreamTokens(expectedContext, envelope, expectedKey)).toThrowError(new Error(failure));
}

function atSerializedSize(size: number) {
  const fixed = Buffer.byteLength(JSON.stringify({ accessToken: 'a', refreshToken: 'r' }));
  const extra = size - fixed;
  return { accessToken: 'a' + '\0'.repeat(Math.floor(extra / 6)) + 'x'.repeat(extra % 6), refreshToken: 'r' };
}

afterEach(() => vi.restoreAllMocks());

describe('disconnected AES-256-GCM upstream-token envelopes', () => {
  it('roundtrips opaque JA/VI bytes and does not mutate caller inputs', () => {
    const before = Buffer.from(key.keyBytes);
    const envelope = encryptUpstreamTokens(context, tokens, key);
    expect(envelope).toMatch(/^v1\.key_1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{22}$/);
    expect(decryptUpstreamTokens(context, envelope, key)).toEqual(tokens);
    expect(key.keyBytes).toEqual(before);
    expect(tokens.accessToken).toBe(' 日本語 opaque +/=\n');
  });

  it('uses a fresh cryptographic IV on repeated encryption', () => {
    const first = encryptUpstreamTokens(context, tokens, key).split('.');
    const second = encryptUpstreamTokens(context, tokens, key).split('.');
    expect(second[2]).not.toBe(first[2]);
    expect(Buffer.from(first[2], 'base64url')).toHaveLength(12);
  });

  it('binds every independently trusted identity and environment field', () => {
    const envelope = encryptUpstreamTokens(context, tokens, key);
    for (const field of ['ownerId', 'sessionId', 'authSubject'] as const) {
      rejectEnvelope(envelope, { ...context, [field]: 'dddddddd-4444-4444-8444-444444444444' });
    }
    rejectEnvelope(envelope, { ...context, environment: 'production' });
    rejectEnvelope(envelope, context, { ...key, keyBytes: Buffer.alloc(32, 20) });
    rejectEnvelope(envelope, context, { ...key, keyId: 'key_2' });
    const parts = envelope.split('.'); parts[1] = 'key_2';
    rejectEnvelope(parts.join('.'), context, { ...key, keyId: 'key_2' });
  });

  it('requires explicit old/new keys during rotation and never searches or falls back', () => {
    const nextKey = { keyId: 'key_2', keyBytes: Buffer.alloc(32, 20) };
    const old = encryptUpstreamTokens(context, tokens, key);
    const next = encryptUpstreamTokens(context, tokens, nextKey);
    expect(decryptUpstreamTokens(context, old, key)).toEqual(tokens);
    expect(decryptUpstreamTokens(context, next, nextKey)).toEqual(tokens);
    rejectEnvelope(old, context, nextKey);
    rejectEnvelope(next, context, key);
    expect(() => decryptUpstreamTokens(context, old, undefined)).toThrowError(failure);
  });

  it('rejects IV/ciphertext/tag tampering and truncation without partial plaintext', () => {
    const envelope = encryptUpstreamTokens(context, tokens, key);
    for (const index of [2, 3, 4]) {
      const parts = envelope.split('.');
      const bytes = Buffer.from(parts[index], 'base64url'); bytes[0] ^= 1;
      parts[index] = bytes.toString('base64url'); rejectEnvelope(parts.join('.'));
    }
    rejectEnvelope(envelope.slice(0, -1));
  });

  it('rejects malformed/versioned/noncanonical grammar and bounded decoding inputs', () => {
    const envelope = encryptUpstreamTokens(context, tokens, key);
    const parts = envelope.split('.');
    for (const invalid of [null, {}, 3, '', envelope + '.extra', envelope.replace('v1.', 'v2.'), parts.slice(1).join('.'),
      envelope.replace('.key_1.', '._key.'), 'x'.repeat(48 * 1024), 'x'.repeat(48 * 1024 + 1)]) rejectEnvelope(invalid);
    for (const index of [2, 3, 4]) {
      for (const value of ['', `${parts[index]}=`, '/', '+']) {
        const changed = [...parts]; changed[index] = value; rejectEnvelope(changed.join('.'));
      }
    }
    const tag = Buffer.alloc(16).toString('base64url');
    const noncanonical = [...parts]; noncanonical[4] = `${tag.slice(0, -1)}B`; rejectEnvelope(noncanonical.join('.'));
    for (const [index, length] of [[2, 11], [2, 13], [4, 15], [4, 17], [3, 33 * 1024 + 1]]) {
      const changed = [...parts]; changed[index] = Buffer.alloc(length).toString('base64url'); rejectEnvelope(changed.join('.'));
    }
  });

  it('rejects base64url aliases of otherwise authentic ciphertext and tag bytes', () => {
    const parts = encryptUpstreamTokens(context, { accessToken: 'a', refreshToken: 'r' }, key).split('.');
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    for (const index of [3, 4]) {
      const original = parts[index];
      expect(original.length % 4).not.toBe(0);
      const alias = original.slice(0, -1) + alphabet[alphabet.indexOf(original.at(-1)!) ^ 1];
      expect(Buffer.from(alias, 'base64url')).toEqual(Buffer.from(original, 'base64url'));
      const changed = [...parts]; changed[index] = alias;
      rejectEnvelope(changed.join('.'));
    }
  });

  it('uses only the supplied 32-byte view without mutating the backing key bytes', () => {
    const backing = new Uint8Array(40).fill(19);
    const viewKey = { keyId: key.keyId, keyBytes: backing.subarray(4, 36) };
    const before = Uint8Array.from(backing);
    const envelope = encryptUpstreamTokens(context, tokens, viewKey);
    expect(decryptUpstreamTokens(context, envelope, key)).toEqual(tokens);
    expect(backing).toEqual(before);
  });

  it.each([{}, { accessToken: 'a' }, { accessToken: 'a', refreshToken: 'r', extra: true },
    { accessToken: '', refreshToken: 'r' }, { accessToken: '\t\n\u0000\u200b', refreshToken: 'r' },
    { accessToken: '\ud800', refreshToken: 'r' }, { accessToken: 1, refreshToken: 'r' },
    Object.create({ accessToken: 'a', refreshToken: 'r' }), [['a', 'r']], null])(
    'rejects invalid own plaintext token schema before encryption: %j', invalid => {
      expect(() => encryptUpstreamTokens(context, invalid, key)).toThrowError(encryptionFailure);
    },
  );

  it('rejects accessor/symbol/non-enumerable extras without invoking caller accessors', () => {
    let reads = 0;
    const accessor = { get accessToken() { reads++; return 'secret'; }, refreshToken: 'r' };
    for (const invalid of [accessor, { ...tokens, [Symbol('extra')]: true },
      Object.defineProperty({ ...tokens }, 'hidden', { value: true })]) {
      expect(() => encryptUpstreamTokens(context, invalid, key)).toThrowError(encryptionFailure);
    }
    expect(reads).toBe(0);
  });

  it.each(['{', 'null', '[]', '{"accessToken":"a"}', '{"accessToken":"a","refreshToken":"r","extra":true}',
    '{"accessToken":"\\ud800","refreshToken":"r"}', '{"accessToken":" ","refreshToken":"r"}'])(
    'rejects authenticated malformed JSON/schema: %s', plaintext => rejectEnvelope(sealPlaintext(plaintext)),
  );

  it('rejects authenticated invalid UTF-8 rather than replacing bytes', () => {
    const plaintext = Buffer.concat([Buffer.from('{"accessToken":"'), Buffer.from([0xff]), Buffer.from('","refreshToken":"r"}')]);
    rejectEnvelope(sealPlaintext(plaintext));
  });

  it('enforces per-token UTF-8 limits at 8192 bytes and +1 on encryption and decryption', () => {
    const accepted = { accessToken: '日'.repeat(2730) + 'ab', refreshToken: 'r'.repeat(8192) };
    expect(Buffer.byteLength(accepted.accessToken)).toBe(8192);
    expect(decryptUpstreamTokens(context, encryptUpstreamTokens(context, accepted, key), key)).toEqual(accepted);
    for (const field of ['accessToken', 'refreshToken'] as const) {
      const invalid = { ...accepted, [field]: accepted[field] + 'x' };
      expect(() => encryptUpstreamTokens(context, invalid, key)).toThrowError(encryptionFailure);
      rejectEnvelope(sealPlaintext(JSON.stringify(invalid)));
    }
  });

  it('enforces serialized plaintext/ciphertext at 33KiB and +1', () => {
    const accepted = atSerializedSize(33 * 1024);
    const oversized = atSerializedSize(33 * 1024 + 1);
    expect(Buffer.byteLength(JSON.stringify(accepted))).toBe(33 * 1024);
    const envelope = encryptUpstreamTokens(context, accepted, key);
    expect(decryptUpstreamTokens(context, envelope, key)).toEqual(accepted);
    expect(() => encryptUpstreamTokens(context, oversized, key)).toThrowError(encryptionFailure);
    rejectEnvelope(sealPlaintext(JSON.stringify(oversized)));
  });

  it('rejects untrusted/extra/noncanonical context and invalid explicit key configuration', () => {
    const envelope = encryptUpstreamTokens(context, tokens, key);
    for (const invalid of [{ ...context, environment: '' }, { ...context, environment: 'x'.repeat(65) },
      { ...context, environment: '日' }, { ...context, environment: 'test\n' }, { ...context, environment: 'test\r' },
      { ...context, ownerId: `${context.ownerId}\n` }, { ...context, ownerId: context.ownerId.toUpperCase() },
      { ...context, datasetEpoch: context.ownerId }, Object.create(context), null]) {
      expect(() => encryptUpstreamTokens(invalid, tokens, key)).toThrowError(encryptionFailure);
      rejectEnvelope(envelope, invalid);
    }
    for (const invalid of [null, {}, { ...key, keyId: '_bad' }, { ...key, keyId: 'key\n' }, { ...key, keyId: 'key\r' }, { ...key, keyId: 'a'.repeat(65) },
      { ...key, keyBytes: Buffer.alloc(31) }, { ...key, keyBytes: Buffer.alloc(33) }, { ...key, keyBytes: 'x'.repeat(32) }]) {
      expect(() => encryptUpstreamTokens(context, tokens, invalid)).toThrowError(encryptionFailure);
      rejectEnvelope(envelope, context, invalid);
    }
    const maxKey = { keyId: 'k'.repeat(64), keyBytes: new Uint8Array(32) };
    const maxContext = { ...context, environment: 'e'.repeat(64) };
    expect(decryptUpstreamTokens(maxContext, encryptUpstreamTokens(maxContext, tokens, maxKey), maxKey)).toEqual(tokens);
  });

  it('sanitizes secure RNG failure and emits no usable fallback envelope', () => {
    vi.mocked(crypto.randomBytes).mockImplementationOnce(() => { throw new Error('sensitive RNG details'); });
    expect(() => encryptUpstreamTokens(context, tokens, key)).toThrowError(new Error(encryptionFailure));
  });
});
