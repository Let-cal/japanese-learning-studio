import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

const HASH_PURPOSE = 'japanese-learning-studio:session-secret:v1\0';

function decodeSecret(secret: unknown): Buffer | null {
  if (typeof secret !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(secret)) return null;
  const bytes = Buffer.from(secret, 'base64url');
  return bytes.length === 32 && bytes.toString('base64url') === secret ? bytes : null;
}

/** Possession alone does not establish owner authority, session validity or CSRF validity. */
export function createSessionSecret(): string {
  try {
    return randomBytes(32).toString('base64url');
  } catch {
    throw new Error('Session secret generation failed');
  }
}

export function hashSessionSecret(secret: unknown): string {
  const bytes = decodeSecret(secret);
  if (!bytes) throw new Error('Invalid session secret');
  return createHash('sha256').update(HASH_PURPOSE, 'utf8').update(bytes).digest('hex');
}

/** Only the equal-length digest comparison is constant time, not this whole function. */
export function verifySessionSecret(secret: unknown, storedDigest: unknown): boolean {
  if (typeof storedDigest !== 'string' || !/^[0-9a-f]{64}$/.test(storedDigest)) return false;
  const bytes = decodeSecret(secret);
  if (!bytes) return false;
  const actual = createHash('sha256').update(HASH_PURPOSE, 'utf8').update(bytes).digest();
  return timingSafeEqual(actual, Buffer.from(storedDigest, 'hex'));
}
