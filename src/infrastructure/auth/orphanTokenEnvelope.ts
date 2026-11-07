import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export interface OrphanTokenContext {
  readonly environment: string;
  readonly attemptId: string;
  readonly candidateId: string;
  readonly authSubject: string;
  readonly upstreamSessionId: string;
}
export interface OrphanTokenKey { readonly keyId: string; readonly keyBytes: Uint8Array }
export interface OrphanTokens { readonly accessToken: string; readonly refreshToken: string }
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PLAINTEXT_BYTES = 33 * 1024;
const ENVELOPE_CHARACTERS = 48 * 1024;

function fields(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object') throw new Error('Invalid input');
  const prototype = Object.getPrototypeOf(value);
  if ((prototype !== Object.prototype && prototype !== null) || Reflect.ownKeys(value).length !== names.length) throw new Error('Invalid input');
  return Object.fromEntries(names.map(name => {
    const descriptor = Object.getOwnPropertyDescriptor(value,name);
    if (!descriptor || !('value' in descriptor)) throw new Error('Invalid input');
    return [name,descriptor.value];
  }));
}
function readContext(value: unknown): OrphanTokenContext {
  const context = fields(value,['environment','attemptId','candidateId','authSubject','upstreamSessionId']);
  if (typeof context.environment !== 'string' || !IDENTIFIER.test(context.environment)) throw new Error('Invalid context');
  for (const name of ['attemptId','candidateId','authSubject','upstreamSessionId']) {
    if (typeof context[name] !== 'string' || !UUID.test(context[name])) throw new Error('Invalid context');
  }
  return context as unknown as OrphanTokenContext;
}
function readKey(value: unknown): { keyId: string; keyBytes: Buffer } {
  const key = fields(value,['keyId','keyBytes']);
  if (typeof key.keyId !== 'string' || !IDENTIFIER.test(key.keyId)
    || !(key.keyBytes instanceof Uint8Array) || key.keyBytes.byteLength !== 32) throw new Error('Invalid key');
  return { keyId: key.keyId, keyBytes: Buffer.from(key.keyBytes) };
}
function readTokens(value: unknown): OrphanTokens {
  const tokens = fields(value,['accessToken','refreshToken']);
  for (const name of ['accessToken','refreshToken']) {
    const token = tokens[name];
    if (typeof token !== 'string' || token.length === 0 || token.length > 8192 || !/^[\x21-\x7e]+$/.test(token)) throw new Error('Invalid tokens');
  }
  return tokens as unknown as OrphanTokens;
}
function aad(context: OrphanTokenContext,keyId: string): Buffer {
  return Buffer.from(JSON.stringify(['japanese-learning-studio:oauth-orphan','v1',keyId,context.environment,
    context.attemptId,context.candidateId,context.authSubject,context.upstreamSessionId]),'utf8');
}
function component(value: string,maximum: number,exact?: number): Buffer {
  if (!value || value.length > Math.ceil(maximum*4/3) || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid envelope');
  const bytes = Buffer.from(value,'base64url');
  if (bytes.length > maximum || (exact !== undefined && bytes.length !== exact) || bytes.toString('base64url') !== value) throw new Error('Invalid envelope');
  return bytes;
}
/** Cleanup capability only. Context is established from durable attempt/candidate facts; it grants no app ownership. */
export function encryptOrphanTokens(context: unknown,tokens: unknown,key: unknown): string {
  try {
    const binding = readContext(context); const secret = readKey(key);
    const plaintext = Buffer.from(JSON.stringify(readTokens(tokens)),'utf8');
    if (plaintext.length > PLAINTEXT_BYTES) throw new Error('Invalid tokens');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm',secret.keyBytes,iv,{authTagLength:16});
    cipher.setAAD(aad(binding,secret.keyId));
    const ciphertext = Buffer.concat([cipher.update(plaintext),cipher.final()]);
    return ['orphan-v1',secret.keyId,iv.toString('base64url'),ciphertext.toString('base64url'),cipher.getAuthTag().toString('base64url')].join('.');
  } catch { throw new Error('Orphan token encryption failed'); }
}
/** Same-context replay is fenced by durable cleanup leases, not by encryption alone. */
export function decryptOrphanTokens(context: unknown,envelope: unknown,key: unknown): OrphanTokens {
  try {
    if (typeof envelope !== 'string' || envelope.length > ENVELOPE_CHARACTERS) throw new Error('Invalid envelope');
    const binding = readContext(context); const secret = readKey(key); const parts = envelope.split('.');
    if (parts.length !== 5 || parts[0] !== 'orphan-v1' || parts[1] !== secret.keyId) throw new Error('Invalid envelope');
    const decipher = createDecipheriv('aes-256-gcm',secret.keyBytes,component(parts[2],12,12),{authTagLength:16});
    decipher.setAAD(aad(binding,secret.keyId));
    decipher.setAuthTag(component(parts[4],16,16));
    const plaintext = Buffer.concat([decipher.update(component(parts[3],PLAINTEXT_BYTES)),decipher.final()]);
    return readTokens(JSON.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(plaintext)));
  } catch { throw new Error('Orphan token decryption failed'); }
}
