import { describe, expect, it } from 'vitest';
import { encryptOrphanTokens, decryptOrphanTokens } from '../../src/infrastructure/auth/orphanTokenEnvelope';
import { decryptUpstreamTokens } from '../../src/infrastructure/auth/tokenEnvelope';

const context = { environment: 'fixture', attemptId: '11111111-1111-4111-8111-111111111111',
  candidateId: '22222222-2222-4222-8222-222222222222', authSubject: '33333333-3333-4333-8333-333333333333',
  upstreamSessionId: '44444444-4444-4444-8444-444444444444' };
const key = { keyId: 'fixture-key', keyBytes: new Uint8Array(32).fill(3) };
const tokens = { accessToken: 'header.payload.signature', refreshToken: 'fixture-refresh' };

describe('candidate cleanup token envelope without an app session or owner', () => {
  it('round trips a closed pair under its own prefix and hides raw credentials', () => {
    const envelope = encryptOrphanTokens(context,tokens,key);
    expect(envelope).toMatch(/^orphan-v1\.fixture-key\./);
    expect(envelope).not.toContain(tokens.accessToken); expect(envelope).not.toContain(tokens.refreshToken);
    expect(decryptOrphanTokens(context,envelope,key)).toEqual(tokens);
    expect(encryptOrphanTokens(context,tokens,key)).not.toBe(envelope);
  });
  it.each([
    { ...context, environment: 'other' },
    { ...context, attemptId: context.candidateId },
    { ...context, candidateId: context.attemptId },
    { ...context, authSubject: context.upstreamSessionId },
    { ...context, upstreamSessionId: context.authSubject },
  ])('binds cleanup ciphertext to each exact context field', changed => {
    const envelope = encryptOrphanTokens(context,tokens,key);
    expect(() => decryptOrphanTokens(changed,envelope,key)).toThrow('Orphan token decryption failed');
  });
  it('cannot be substituted for an app-session envelope even with the same key', () => {
    const envelope = encryptOrphanTokens(context,tokens,key);
    expect(() => decryptUpstreamTokens({ environment: context.environment, ownerId: context.candidateId,
      sessionId: context.attemptId, authSubject: context.authSubject },envelope,key)).toThrow('Upstream token decryption failed');
    expect(() => decryptUpstreamTokens({ environment: context.environment, ownerId: context.candidateId,
      sessionId: context.attemptId, authSubject: context.authSubject },envelope.replace('orphan-v1.','v1.'),key)).toThrow('Upstream token decryption failed');
    expect(() => decryptOrphanTokens(context,envelope.replace('orphan-v1.','v1.'),key)).toThrow('Orphan token decryption failed');
  });
  it('rejects owner/session context expansion rather than pretending a candidate is authorized', () => {
    expect(() => encryptOrphanTokens({ ...context, ownerId: context.candidateId },tokens,key)).toThrow('Orphan token encryption failed');
    expect(() => encryptOrphanTokens({ ...context, sessionId: context.attemptId },tokens,key)).toThrow('Orphan token encryption failed');
  });
  it('rejects ciphertext/tag/key tampering with generic errors', () => {
    const envelope = encryptOrphanTokens(context,tokens,key);
    expect(() => decryptOrphanTokens(context,envelope,{ ...key, keyBytes: new Uint8Array(32).fill(4) })).toThrow('Orphan token decryption failed');
    expect(() => decryptOrphanTokens(context,envelope,{ ...key, keyId: 'other' })).toThrow('Orphan token decryption failed');
    const parts = envelope.split('.'); parts[4] = 'A'.repeat(22);
    expect(() => decryptOrphanTokens(context,parts.join('.'),key)).toThrow('Orphan token decryption failed');
  });
  it.each(['', ' '.repeat(5), 'a\nb', '\u0000a', 'a'.repeat(8193), '日本語'])('rejects invalid or oversized token text', accessToken => {
    expect(() => encryptOrphanTokens(context,{ ...tokens, accessToken },key)).toThrow('Orphan token encryption failed');
  });
  it('rejects oversized/expanded envelopes and noncanonical base64 before decryption', () => {
    const envelope = encryptOrphanTokens(context,tokens,key);
    expect(() => decryptOrphanTokens(context,'x'.repeat(49153),key)).toThrow('Orphan token decryption failed');
    expect(() => decryptOrphanTokens(context,envelope+'.extra',key)).toThrow('Orphan token decryption failed');
    const parts = envelope.split('.'); parts[2] += '=';
    expect(() => decryptOrphanTokens(context,parts.join('.'),key)).toThrow('Orphan token decryption failed');
  });
  it('never invokes context or credential getters', () => {
    let reads = 0;
    expect(() => encryptOrphanTokens({ ...context, get environment() { reads++; return 'fixture'; } },tokens,key)).toThrow('Orphan token encryption failed');
    expect(() => encryptOrphanTokens(context,{ ...tokens, get refreshToken() { reads++; return 'fixture'; } },key)).toThrow('Orphan token encryption failed');
    expect(reads).toBe(0);
  });
});
