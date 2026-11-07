import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

export type AuthActionSecretPurpose = 'browser' | 'oauth' | 'csrf-login' | 'csrf-logout' | 'csrf-mutation';
export interface PkceContext { readonly environment: string; readonly bindingId: string; readonly attemptId: string }
export interface PkceKey { readonly keyId: string; readonly keyBytes: Uint8Array }
const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const RANDOM = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

function prefix(purpose: unknown): string {
  switch (purpose) {
    case 'browser': return 'jls-browser-v1.';
    case 'oauth': return 'jls-oauth-v1.';
    case 'csrf-login': case 'csrf-logout': case 'csrf-mutation': return 'jls-csrf-v1.';
    default: throw new Error('Invalid Auth action purpose');
  }
}
export function createAuthActionSecret(purpose: AuthActionSecretPurpose): string {
  const tag = prefix(purpose);
  try { return tag + randomBytes(32).toString('base64url'); }
  catch { throw new Error('Auth action generation failed'); }
}
/** Syntax and hashing only: the durable store must verify purpose, generation, expiry and presentation. */
export function hashAuthActionSecret(purpose: AuthActionSecretPurpose, secret: unknown): string {
  const tag = prefix(purpose);
  if (typeof secret !== 'string' || !secret.startsWith(tag) || !RANDOM.test(secret.slice(tag.length))) {
    throw new Error('Invalid Auth action secret');
  }
  return createHash('sha256').update('japanese-learning-studio:auth-action:v1\0').update(purpose).update('\0')
    .update(Buffer.from(secret.slice(tag.length), 'base64url')).digest('hex');
}
/** Fingerprints the bounded, exact parsed cookie value, including malformed values; never authenticates. */
export function fingerprintSessionCookie(cookie: unknown): string {
  if (cookie === undefined || cookie === null) return 'absent';
  if (typeof cookie !== 'string' || cookie.length > 8192 || !cookie.isWellFormed() || Buffer.byteLength(cookie, 'utf8') > 8192) {
    throw new Error('Invalid cookie presentation');
  }
  return `present:${createHash('sha256').update('japanese-learning-studio:cookie-presentation:v1\0').update(cookie, 'utf8').digest('hex')}`;
}
function fields(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== names.length) throw new Error('Invalid input');
  return Object.fromEntries(names.map(name => {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !('value' in descriptor)) throw new Error('Invalid input');
    return [name, descriptor.value];
  }));
}
function readContext(value: unknown): PkceContext {
  const context = fields(value, ['environment', 'bindingId', 'attemptId']);
  if (typeof context.environment !== 'string' || !ID.test(context.environment)
    || typeof context.bindingId !== 'string' || !UUID.test(context.bindingId)
    || typeof context.attemptId !== 'string' || !UUID.test(context.attemptId)) throw new Error('Invalid context');
  return context as unknown as PkceContext;
}
function readKey(value: unknown): { keyId: string; keyBytes: Buffer } {
  const key = fields(value, ['keyId', 'keyBytes']);
  if (typeof key.keyId !== 'string' || !ID.test(key.keyId) || !(key.keyBytes instanceof Uint8Array) || key.keyBytes.byteLength !== 32) {
    throw new Error('Invalid key');
  }
  return { keyId: key.keyId, keyBytes: Buffer.from(key.keyBytes) };
}
function aad(context: PkceContext, keyId: string): Buffer {
  return Buffer.from(JSON.stringify(['japanese-learning-studio:pkce', 'v1', keyId,
    context.environment, context.bindingId, context.attemptId]), 'utf8');
}
function component(value: string, size: number): Buffer {
  if (value.length > Math.ceil(size * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid envelope');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== size || bytes.toString('base64url') !== value) throw new Error('Invalid envelope');
  return bytes;
}
/** Separate purpose from upstream-token envelopes; binding/attempt facts must be server-established. */
export function encryptPkceVerifier(context: unknown, verifier: unknown, key: unknown): string {
  try {
    const binding = readContext(context); const secret = readKey(key);
    if (typeof verifier !== 'string' || !RANDOM.test(verifier)) throw new Error('Invalid verifier');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', secret.keyBytes, iv, { authTagLength: 16 });
    cipher.setAAD(aad(binding, secret.keyId));
    const ciphertext = Buffer.concat([cipher.update(verifier, 'ascii'), cipher.final()]);
    return ['pkce-v1', secret.keyId, iv.toString('base64url'), ciphertext.toString('base64url'), cipher.getAuthTag().toString('base64url')].join('.');
  } catch { throw new Error('PKCE encryption failed'); }
}
export function decryptPkceVerifier(context: unknown, envelope: unknown, key: unknown): string {
  try {
    if (typeof envelope !== 'string' || envelope.length > 2048) throw new Error('Invalid envelope');
    const binding = readContext(context); const secret = readKey(key); const parts = envelope.split('.');
    if (parts.length !== 5 || parts[0] !== 'pkce-v1' || parts[1] !== secret.keyId) throw new Error('Invalid envelope');
    const decipher = createDecipheriv('aes-256-gcm', secret.keyBytes, component(parts[2], 12), { authTagLength: 16 });
    decipher.setAAD(aad(binding, secret.keyId));
    decipher.setAuthTag(component(parts[4], 16));
    const plaintext = Buffer.concat([decipher.update(component(parts[3], 43)), decipher.final()]);
    const verifier = plaintext.toString('ascii');
    if (!RANDOM.test(verifier) || !Buffer.from(verifier, 'ascii').equals(plaintext)) throw new Error('Invalid verifier');
    return verifier;
  } catch { throw new Error('PKCE decryption failed'); }
}
