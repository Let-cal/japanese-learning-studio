import { z } from 'zod';
import { UtcInstantSchema, UuidSchema } from './learning.ts';
import { fieldError } from './common.ts';
import type { ValidationResult } from './common.ts';

/** Syntax only: these values grant no authority without a server-side verifier. */
const purposeSecret = (prefix: string) => z.string().length(prefix.length + 43)
  .regex(new RegExp(`^${prefix.replaceAll('.', '\\.')}[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`));
export const AuthCsrfTokenSchema = purposeSecret('jls-csrf-v1.');
export const BrowserBindingSecretSchema = purposeSecret('jls-browser-v1.');
export const OAuthAttemptSecretSchema = purposeSecret('jls-oauth-v1.');
export const AuthCsrfPurposeSchema = z.enum(['login', 'logout', 'mutation']);
export const AuthCsrfBodySchema = z.strictObject({ purpose: AuthCsrfPurposeSchema });
export const AuthLoginFormSchema = z.strictObject({ csrfToken: AuthCsrfTokenSchema });
export type AuthLoginForm = z.infer<typeof AuthLoginFormSchema>;

/** Already-decoded form entries; future handlers separately enforce raw byte and media-type limits. */
export function parseAuthLoginForm(form: URLSearchParams): ValidationResult<AuthLoginForm> {
  const invalid = (): ValidationResult<AuthLoginForm> => ({
    ok: false, errors: [fieldError([], 'invalid_value', 'Malformed login form.')],
  });
  const entries = [...form];
  // Check cardinality and decoded name before constructing the closed form object.
  if (entries.length !== 1 || entries[0][0] !== 'csrfToken') return invalid();
  const result = AuthLoginFormSchema.safeParse({ csrfToken: entries[0][1] });
  return result.success ? { ok: true, value: result.data } : invalid();
}
export const AuthCsrfSuccessSchema = z.strictObject({
  data: z.strictObject({ purpose: AuthCsrfPurposeSchema, token: AuthCsrfTokenSchema, expiresAt: UtcInstantSchema }),
  meta: z.strictObject({ requestId: UuidSchema }),
});
export const MeSuccessSchema = z.strictObject({
  data: z.strictObject({ authenticated: z.literal(true) }),
  meta: z.strictObject({ requestId: UuidSchema, datasetEpoch: UuidSchema }),
});

const callbackText = (minimum: number, maximum: number) => z.string().min(minimum).max(maximum)
  .regex(/^[^\u0000-\u001f\u007f-\u009f]*$/);
export const AuthCallbackQuerySchema = z.union([
  z.strictObject({ code: callbackText(1, 2048) }),
  z.strictObject({
    error: callbackText(1, 128), error_code: callbackText(1, 128).optional(),
    error_description: callbackText(0, 2048).optional(),
  }),
]);
export type AuthCallbackQuery = z.infer<typeof AuthCallbackQuerySchema>;

/** URLSearchParams has already decoded once. Never decode again or expose query text in errors. */
export function parseAuthCallbackQuery(query: URLSearchParams): ValidationResult<AuthCallbackQuery> {
  const invalid = (): ValidationResult<AuthCallbackQuery> => ({
    ok: false, errors: [fieldError([], 'invalid_value', 'Malformed callback query.')],
  });
  const seen = new Set<string>();
  for (const [key] of query) {
    if (seen.has(key) || !['code', 'error', 'error_code', 'error_description'].includes(key)) return invalid();
    seen.add(key);
  }
  // Construct only after inspecting multiplicity; Object.fromEntries alone loses duplicates.
  const result = AuthCallbackQuerySchema.safeParse(Object.fromEntries(query));
  return result.success ? { ok: true, value: result.data } : invalid();
}
