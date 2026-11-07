import { describe, expect, it } from 'vitest';
import { createAuthActionSecret, hashAuthActionSecret, fingerprintSessionCookie,
  encryptPkceVerifier, decryptPkceVerifier } from '../../src/infrastructure/auth/authActionSecrets';

const context = { environment: 'fixture', bindingId: '11111111-1111-4111-8111-111111111111', attemptId: '22222222-2222-4222-8222-222222222222' };
const key = { keyId: 'fixture-key', keyBytes: new Uint8Array(32).fill(7) };
const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

describe('Auth action secrets and separately bound PKCE envelope', () => {
  it('keeps browser, flow and proof wire formats separate and hashes login/logout independently', () => {
    const browser = createAuthActionSecret('browser');
    const flow = createAuthActionSecret('oauth');
    const proof = createAuthActionSecret('csrf-login');
    expect(browser).toMatch(/^jls-browser-v1\.[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/);
    expect(flow).toMatch(/^jls-oauth-v1\.[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/);
    expect(proof).toMatch(/^jls-csrf-v1\.[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/);
    const login = hashAuthActionSecret('csrf-login', proof);
    expect(login).toMatch(/^[a-f0-9]{64}$/);
    expect(hashAuthActionSecret('csrf-logout', proof)).not.toBe(login);
    expect(hashAuthActionSecret('csrf-mutation', proof)).not.toBe(login);
    expect(() => hashAuthActionSecret('browser', proof)).toThrow('Invalid Auth action secret');
    expect(() => hashAuthActionSecret('oauth', browser)).toThrow('Invalid Auth action secret');
  });
  it('rejects noncanonical base64 padding bits and unrecognized purposes before hashing', () => {
    expect(() => hashAuthActionSecret('browser', `jls-browser-v1.${'A'.repeat(42)}B`)).toThrow('Invalid Auth action secret');
    expect(() => hashAuthActionSecret('csrf-login', `jls-csrf-v1.${'A'.repeat(43)}=`)).toThrow('Invalid Auth action secret');
    expect(() => createAuthActionSecret('unexpected' as 'browser')).toThrow('Invalid Auth action purpose');
  });
  it('keeps explicit absence distinct from any present cookie, even empty or malformed values', () => {
    expect(fingerprintSessionCookie(undefined)).toBe('absent');
    expect(fingerprintSessionCookie(null)).toBe('absent');
    expect(fingerprintSessionCookie('')).toMatch(/^present:[a-f0-9]{64}$/);
    expect(fingerprintSessionCookie('')).not.toBe(fingerprintSessionCookie('malformed'));
    expect(fingerprintSessionCookie('a')).not.toBe(fingerprintSessionCookie('A'));
    expect(() => fingerprintSessionCookie('x'.repeat(8193))).toThrow('Invalid cookie presentation');
    expect(() => fingerprintSessionCookie({ toString() { throw new Error('must not run'); } })).toThrow('Invalid cookie presentation');
  });
  it('encrypts the PKCE verifier separately without raw text and with a new IV per envelope', () => {
    const envelope = encryptPkceVerifier(context, verifier, key);
    expect(envelope).toMatch(/^pkce-v1\.fixture-key\./);
    expect(envelope).not.toContain(verifier);
    expect(encryptPkceVerifier(context, verifier, key)).not.toBe(envelope);
    expect(decryptPkceVerifier(context, envelope, key)).toBe(verifier);
    expect(() => decryptPkceVerifier(context, envelope.replace('pkce-v1.', 'v1.'), key)).toThrow('PKCE decryption failed');
  });
  it.each([
    { ...context, environment: 'other' }, { ...context, bindingId: context.attemptId },
    { ...context, attemptId: context.bindingId },
  ])('rejects a replay under a different environment, browser or attempt', otherContext => {
    const envelope = encryptPkceVerifier(context, verifier, key);
    expect(() => decryptPkceVerifier(otherContext, envelope, key)).toThrow('PKCE decryption failed');
  });
  it('rejects wrong key bytes, key ID and tampered tag without disclosing details', () => {
    const envelope = encryptPkceVerifier(context, verifier, key);
    expect(() => decryptPkceVerifier(context, envelope, { ...key, keyBytes: new Uint8Array(32).fill(8) })).toThrow('PKCE decryption failed');
    expect(() => decryptPkceVerifier(context, envelope, { ...key, keyId: 'other-key' })).toThrow('PKCE decryption failed');
    const parts = envelope.split('.'); parts[4] = 'A'.repeat(22);
    expect(() => decryptPkceVerifier(context, parts.join('.'), key)).toThrow('PKCE decryption failed');
  });
  it('rejects oversized or extra context/envelope data and never invokes accessors', () => {
    const envelope = encryptPkceVerifier(context, verifier, key); let reads = 0;
    const accessor = { ...context, get environment() { reads++; return 'fixture'; } };
    expect(() => encryptPkceVerifier(accessor, verifier, key)).toThrow('PKCE encryption failed');
    expect(reads).toBe(0);
    expect(() => decryptPkceVerifier({ ...context, ownerId: 'invented' }, envelope, key)).toThrow('PKCE decryption failed');
    expect(() => decryptPkceVerifier(context, 'x'.repeat(2049), key)).toThrow('PKCE decryption failed');
    expect(() => encryptPkceVerifier(context, 'bad verifier', key)).toThrow('PKCE encryption failed');
  });
});
