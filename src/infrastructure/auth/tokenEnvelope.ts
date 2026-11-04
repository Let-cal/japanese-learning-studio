import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export interface UpstreamTokenContext {
  environment: string;
  ownerId: string;
  sessionId: string;
  authSubject: string;
}

export interface UpstreamTokenKey {
  keyId: string;
  keyBytes: Uint8Array;
}

export interface UpstreamTokens {
  accessToken: string;
  refreshToken: string;
}

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TOKEN_BYTES = 8192;
const PLAINTEXT_BYTES = 33 * 1024;
const ENVELOPE_CHARACTERS = 48 * 1024;

// Snapshot only closed data objects, without invoking caller-provided accessors.
function fields(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object') throw new Error('Invalid input');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new Error('Invalid input');
  if (Reflect.ownKeys(value).length !== names.length) throw new Error('Invalid input');
  return Object.fromEntries(names.map(name => {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !('value' in descriptor)) throw new Error('Invalid input');
    return [name, descriptor.value];
  }));
}

function readContext(value: unknown): UpstreamTokenContext {
  const context = fields(value, ['environment', 'ownerId', 'sessionId', 'authSubject']);
  if (typeof context.environment !== 'string' || !IDENTIFIER.test(context.environment)) throw new Error('Invalid context');
  for (const name of ['ownerId', 'sessionId', 'authSubject']) {
    if (typeof context[name] !== 'string' || !UUID.test(context[name])) throw new Error('Invalid context');
  }
  return context as unknown as UpstreamTokenContext;
}

function readKey(value: unknown): { keyId: string; keyBytes: Buffer } {
  const key = fields(value, ['keyId', 'keyBytes']);
  if (typeof key.keyId !== 'string' || !IDENTIFIER.test(key.keyId)
      || !(key.keyBytes instanceof Uint8Array) || key.keyBytes.byteLength !== 32) throw new Error('Invalid key');
  return { keyId: key.keyId, keyBytes: Buffer.from(key.keyBytes) };
}

function readTokens(value: unknown): UpstreamTokens {
  const tokens = fields(value, ['accessToken', 'refreshToken']);
  for (const name of ['accessToken', 'refreshToken']) {
    const token = tokens[name];
    if (typeof token !== 'string' || token.length === 0 || token.length > TOKEN_BYTES
        || !token.isWellFormed() || !/[^\s\p{Cc}\p{Cf}]/u.test(token)
        || Buffer.byteLength(token, 'utf8') > TOKEN_BYTES) throw new Error('Invalid tokens');
  }
  return tokens as unknown as UpstreamTokens;
}

function aad(context: UpstreamTokenContext, keyId: string): Buffer {
  return Buffer.from(JSON.stringify(['japanese-learning-studio:upstream-tokens', 'v1', keyId,
    context.environment, context.ownerId, context.sessionId, context.authSubject]), 'utf8');
}

function decodeComponent(value: string, maxBytes: number, exactBytes?: number): Buffer {
  if (!value || value.length > Math.ceil(maxBytes * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid envelope');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length > maxBytes || (exactBytes !== undefined && bytes.length !== exactBytes)
      || bytes.toString('base64url') !== value) throw new Error('Invalid envelope');
  return bytes;
}

/** Server-only primitive: context must come from independently trusted server state. */
export function encryptUpstreamTokens(context: unknown, tokens: unknown, key: unknown): string {
  try {
    const binding = readContext(context);
    const suppliedKey = readKey(key);
    const plaintext = Buffer.from(JSON.stringify(readTokens(tokens)), 'utf8');
    if (plaintext.length > PLAINTEXT_BYTES) throw new Error('Invalid tokens');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', suppliedKey.keyBytes, iv, { authTagLength: 16 });
    cipher.setAAD(aad(binding, suppliedKey.keyId));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return ['v1', suppliedKey.keyId, iv.toString('base64url'), ciphertext.toString('base64url'),
      cipher.getAuthTag().toString('base64url')].join('.');
  } catch {
    throw new Error('Upstream token encryption failed');
  }
}

/** Integrity does not establish authorization or prevent replay for the same binding. */
export function decryptUpstreamTokens(context: unknown, envelope: unknown, key: unknown): UpstreamTokens {
  try {
    // Bound attacker-controlled encoded input before split or binary allocation.
    if (typeof envelope !== 'string' || envelope.length > ENVELOPE_CHARACTERS) throw new Error('Invalid envelope');
    const binding = readContext(context);
    const suppliedKey = readKey(key);
    const parts = envelope.split('.');
    if (parts.length !== 5 || parts[0] !== 'v1' || parts[1] !== suppliedKey.keyId) throw new Error('Invalid envelope');
    const iv = decodeComponent(parts[2], 12, 12);
    const ciphertext = decodeComponent(parts[3], PLAINTEXT_BYTES);
    const tag = decodeComponent(parts[4], 16, 16);
    const decipher = createDecipheriv('aes-256-gcm', suppliedKey.keyBytes, iv, { authTagLength: 16 });
    decipher.setAAD(aad(binding, suppliedKey.keyId));
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext);
    return readTokens(JSON.parse(text));
  } catch {
    throw new Error('Upstream token decryption failed');
  }
}
