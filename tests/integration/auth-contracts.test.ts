import { expect, it } from 'vitest';
import { buildOpenApiDocument } from '../../src/contracts/apiSchemas';
import {
  AuthCallbackQuerySchema, AuthCsrfBodySchema, AuthCsrfSuccessSchema,
  AuthCsrfTokenSchema, BrowserBindingSecretSchema, OAuthAttemptSecretSchema,
  MeSuccessSchema, parseAuthCallbackQuery, AuthLoginFormSchema, parseAuthLoginForm,
} from '../../src/contracts/auth';
import { createProblem, ProblemSchema, problemSchemaForCodes } from '../../src/contracts/problems';

const id = '11111111-1111-4111-8111-111111111111';
const rawSecret = 'A'.repeat(43);
const token = `jls-csrf-v1.${rawSecret}`;

it('publishes the six planned Auth operations without domain prerequisites', () => {
  const document = buildOpenApiDocument();
  expect(document.paths['/api/v1/auth/csrf']?.post).toBeDefined();
  expect(document.paths['/api/v1/auth/login']?.post).toBeDefined();
  expect(document.paths['/api/v1/auth/callback']?.get).toBeDefined();
  expect(document.paths['/api/v1/auth/logout']?.post).toBeDefined();
  expect(document.paths['/api/v1/me']?.get).toBeDefined();
  expect(Object.entries(document.paths).filter(([path]) => path.startsWith('/api/v1/auth/') || path === '/api/v1/me')
    .flatMap(([path, operations]) => Object.keys(operations).map(method => `${method} ${path}`)).sort()).toEqual([
    'get /api/v1/auth/callback', 'get /api/v1/me', 'post /api/v1/auth/csrf', 'post /api/v1/auth/login', 'post /api/v1/auth/logout', 'post /api/v1/auth/recover',
  ]);
});

it('requires purpose-specific security with AND browser binding and no domain headers', () => {
  const document = buildOpenApiDocument();
  const cases = [
    ['/api/v1/auth/csrf', 'post', [], 200],
    ['/api/v1/auth/login', 'post', [{ BrowserBinding: [] }], 303],
    ['/api/v1/auth/callback', 'get', [{ OAuthAttempt: [], BrowserBinding: [] }], 303],
    ['/api/v1/auth/logout', 'post', [{ AuthActionProof: [], BrowserBinding: [] }], 204],
    ['/api/v1/me', 'get', [{ OwnerSession: [] }], 200],
  ] as const;
  for (const [path, method, security, success] of cases) {
    const operation = document.paths[path][method];
    expect(operation.security).toEqual(security);
    expect(operation['x-implementationStatus']).toBe('planned');
    expect(operation['x-commandKind']).toBeUndefined();
    for (const name of ['DatasetEpoch', 'IdempotencyKey', 'IfMatch', 'CsrfToken']) {
      expect(operation.parameters.some(parameter => parameter.$ref === `#/components/parameters/${name}`)).toBe(false);
    }
    expect(operation.parameters.some(parameter => parameter.$ref === '#/components/parameters/Origin')).toBe(method === 'post');
    expect(operation.responses[success]).toBeDefined();
    for (const response of Object.values(operation.responses)) {
      expect(response.headers?.['Cache-Control']?.schema).toEqual({ type: 'string', const: 'private, no-store' });
      expect(response.headers?.['X-Request-Id']).toBeDefined();
      expect(response.headers?.ETag).toBeUndefined();
      if (path === '/api/v1/auth/callback') expect(response.headers?.['Referrer-Policy']?.schema).toEqual({ type: 'string', const: 'no-referrer' });
    }
    if (success === 303 || success === 204) expect(operation.responses[success].content).toBeUndefined();
    if (path !== '/api/v1/auth/csrf' && path !== '/api/v1/auth/login') {
      expect(operation.requestBody).toBeUndefined();
      expect(operation['x-body-byte-length']).toBe(0);
    }
  }
  const schemes = document.components.securitySchemes;
  expect(schemes.AuthActionProof).toMatchObject({ type: 'apiKey', in: 'header', name: 'X-CSRF-Token' });
  expect(schemes.BrowserBinding).toMatchObject({ type: 'apiKey', in: 'cookie', name: '__Host-jls-browser' });
  expect(schemes.OAuthAttempt).toMatchObject({ type: 'apiKey', in: 'cookie', name: '__Host-jls-oauth' });
  expect(schemes.AuthActionProof['x-value-schema']).toEqual({ $ref: '#/components/schemas/AuthCsrfToken' });
  expect(schemes.BrowserBinding['x-value-schema']).toEqual({ $ref: '#/components/schemas/BrowserBindingSecret' });
  expect(schemes.OAuthAttempt['x-value-schema']).toEqual({ $ref: '#/components/schemas/OAuthAttemptSecret' });
  expect(document.components.parameters.Origin).toMatchObject({ name: 'Origin', in: 'header', required: true });
  const csrf = document.paths['/api/v1/auth/csrf'].post;
  expect(csrf.requestBody?.content['application/json'].schema.$ref).toBe('#/components/schemas/AuthCsrfBody');
  expect(csrf.responses[200].content?.['application/json'].schema.$ref).toBe('#/components/schemas/AuthCsrfSuccess');
  expect(document.paths['/api/v1/me'].get.responses[200].content?.['application/json'].schema.$ref).toBe('#/components/schemas/MeSuccess');
  expect(csrf['x-auth-purpose-authorizations']).toEqual({ login: [], logout: [], mutation: ['OwnerSession'] });
  expect(document.paths['/api/v1/auth/login'].post.responses[303].headers?.Location).toMatchObject({ description: expect.stringContaining('server-only') });
  expect(document.paths['/api/v1/auth/callback'].get.responses[303].headers?.Location?.schema).toEqual({ type: 'string', const: '/today' });
});

it('requires a closed login form proof body for native top-level 303 navigation', () => {
  const login = buildOpenApiDocument().paths['/api/v1/auth/login'].post;
  expect(login.requestBody).toEqual({ required: true, content: {
    'application/x-www-form-urlencoded': { schema: { $ref: '#/components/schemas/AuthLoginForm' } },
  } });
  expect(login.security).toEqual([{ BrowserBinding: [] }]);
  expect(login['x-body-byte-length']).toBeUndefined();
  expect(login['x-max-body-bytes']).toBe(256);
  expect(login['x-auth-proof']).toEqual({ in: 'body', name: 'csrfToken', purpose: 'login', authoritative: true });
  expect(login.parameters.some(parameter => parameter.$ref === '#/components/parameters/CsrfToken')).toBe(false);
});

it('accepts only one canonical login form token and sanitizes duplicate, unknown and malformed fields', () => {
  expect(AuthLoginFormSchema.safeParse({ csrfToken: token }).success).toBe(true);
  expect(parseAuthLoginForm(new URLSearchParams({ csrfToken: token }))).toEqual({ ok: true, value: { csrfToken: token } });
  for (const body of [{}, { csrfToken: rawSecret }, { csrfToken: `${token}=` }, { csrfToken: token, returnTo: '/today' }, { csrfToken: token, ownerId: id }, { csrfToken: token, provider: 'google' }]) {
    expect(AuthLoginFormSchema.safeParse(body).success).toBe(false);
  }
  for (const form of [
    '', 'csrfToken=', `csrfToken=${token}&csrfToken=${token}`, `csrfToken=${token}&%63srfToken=${token}`,
    `csrfToken=${token}&returnTo=%2Ftoday`, `csrfToken=${token}&ownerId=${id}`, `csrfToken=${token}&provider=google`,
    `csrfToken=${token}&X-CSRF-Token=${token}`, `csrfToken=${token}%0A`, `csrfToken=${rawSecret}`,
    `csrfToken=jls-csrf-v1.${'A'.repeat(42)}B`, `csrfToken=jls-browser-v1.${rawSecret}`, `csrfToken=${token}%253D`,
  ]) {
    expect(parseAuthLoginForm(new URLSearchParams(form))).toEqual({ ok: false, errors: [
      { path: [], code: 'invalid_value', message: 'Malformed login form.' },
    ] });
  }
});

it('limits Auth problem responses to the closed route-specific sanitized cases', () => {
  const document = buildOpenApiDocument();
  for (const [path, method, statuses] of [
    ['/api/v1/auth/csrf', 'post', ['200', '400', '401', '403', '429', '503']],
    ['/api/v1/auth/login', 'post', ['303', '400', '403', '429', '503']],
    ['/api/v1/auth/callback', 'get', ['303', '400', '403', '409', '429', '503']],
    ['/api/v1/auth/logout', 'post', ['204', '400', '403', '429', '503']],
    ['/api/v1/me', 'get', ['200', '400', '401', '403', '429', '503']],
  ] as const) {
    const operation = document.paths[path][method];
    expect(Object.keys(operation.responses).sort()).toEqual([...statuses].sort());
    for (const [status, response] of Object.entries(operation.responses)) {
      if (Number(status) >= 400) expect(response.content?.['application/problem+json'].schema.$ref).toBe(`#/components/schemas/AuthProblem${status}`);
    }
    expect(operation.responses[429].headers?.['Retry-After']?.schema).toMatchObject({ type: 'integer', minimum: 1, maximum: 3600 });
  }
  const restart = createProblem('sign_in_restart_required', id);
  expect(restart).toMatchObject({ status: 409, detail: 'Sign-in must be restarted.' });
  expect(ProblemSchema.safeParse({ ...restart, detail: 'provider supplied secret' }).success).toBe(false);
  const authConflict = problemSchemaForCodes(['sign_in_restart_required']);
  expect(authConflict.safeParse(restart).success).toBe(true);
  for (const code of ['session_closed', 'test_reference_locked', 'execution_conflict'] as const) expect(authConflict.safeParse(createProblem(code, id)).success).toBe(false);
  const authUnavailable = problemSchemaForCodes(['temporarily_unavailable']);
  expect(authUnavailable.safeParse(createProblem('temporarily_unavailable', id)).success).toBe(true);
  expect(authUnavailable.safeParse(createProblem('receipt_integrity_error', id)).success).toBe(false);
});

it('keeps Auth DTOs strict and authority-free while using the existing UTC instant contract', () => {
  for (const purpose of ['login', 'logout', 'mutation']) expect(AuthCsrfBodySchema.safeParse({ purpose }).success).toBe(true);
  for (const body of [{}, { purpose: 'admin' }, { purpose: 'login', ownerId: id }, { purpose: 'login', returnTo: '/admin' }]) {
    expect(AuthCsrfBodySchema.safeParse(body).success).toBe(false);
  }
  const success = { data: { purpose: 'login', token, expiresAt: '2026-11-06T00:00:00Z' }, meta: { requestId: id } };
  expect(AuthCsrfSuccessSchema.safeParse(success).success).toBe(true);
  for (const expiresAt of ['tomorrow', '2026-11-06T00:00:00+07:00', '2026-11-06']) expect(AuthCsrfSuccessSchema.safeParse({ ...success, data: { ...success.data, expiresAt } }).success).toBe(false);
  expect(AuthCsrfSuccessSchema.safeParse({ ...success, meta: { requestId: id, datasetEpoch: id } }).success).toBe(false);
  const me = { data: { authenticated: true }, meta: { requestId: id, datasetEpoch: id } };
  expect(MeSuccessSchema.safeParse(me).success).toBe(true);
  expect(MeSuccessSchema.safeParse({ ...me, data: { authenticated: false } }).success).toBe(false);
  for (const key of ['ownerId', 'sessionId', 'authSubject', 'email', 'accessToken', 'refreshToken', 'providerUrl']) {
    expect(MeSuccessSchema.safeParse({ ...me, data: { ...me.data, [key]: id } }).success).toBe(false);
    expect(MeSuccessSchema.safeParse({ ...me, meta: { ...me.meta, [key]: id } }).success).toBe(false);
    expect(AuthCsrfSuccessSchema.safeParse({ ...success, data: { ...success.data, [key]: id } }).success).toBe(false);
  }
});

it('accepts only canonical 32-byte secrets in their separate versioned purpose formats', () => {
  const cases = [[AuthCsrfTokenSchema, 'jls-csrf-v1.'], [BrowserBindingSecretSchema, 'jls-browser-v1.'], [OAuthAttemptSecretSchema, 'jls-oauth-v1.']] as const;
  for (const [schema, prefix] of cases) {
    for (const last of 'AEIMQUYcgkosw048') expect(schema.safeParse(`${prefix}${'A'.repeat(42)}${last}`).success).toBe(true);
    for (const invalid of [rawSecret, `${prefix}${'A'.repeat(42)}B`, `${prefix}${rawSecret}=`, `${prefix}${'A'.repeat(42)}`, `${prefix}${'A'.repeat(44)}`, `${prefix}${'A'.repeat(42)}+`, `${prefix}${rawSecret}\n`]) {
      expect(schema.safeParse(invalid).success).toBe(false);
    }
    for (const [, otherPrefix] of cases) if (prefix !== otherPrefix) expect(schema.safeParse(`${otherPrefix}${rawSecret}`).success).toBe(false);
  }
});

it('parses an exclusive bounded callback query once and rejects duplicates before object construction', () => {
  expect(parseAuthCallbackQuery(new URLSearchParams('code=abc%252Fdef'))).toEqual({ ok: true, value: { code: 'abc%2Fdef' } });
  expect(parseAuthCallbackQuery(new URLSearchParams('error=access_denied&error_code=denied&error_description='))).toEqual({ ok: true, value: { error: 'access_denied', error_code: 'denied', error_description: '' } });
  for (const query of [
    '', 'code=', 'code=a&code=b', 'code=a&%63ode=b', 'error=a&error=a', 'error=a&error_code=b&error_code=c',
    'error=a&error_description=x&error_description=y', 'code=a&error=b', 'code=a&error_code=b',
    'error_description=description', 'code=a&state=x', 'code=a&returnTo=%2Ftoday',
    'code=%00', 'code=%0A', 'error=%7F', 'error=a&error_description=%C2%85',
    `code=${'a'.repeat(2049)}`, `error=${'a'.repeat(129)}`, `error=a&error_code=${'a'.repeat(129)}`,
    `error=a&error_description=${'a'.repeat(2049)}`,
  ]) {
    const result = parseAuthCallbackQuery(new URLSearchParams(query));
    expect(result, query).toEqual({ ok: false, errors: [{ path: [], code: 'invalid_value', message: 'Malformed callback query.' }] });
  }
  for (const value of [{ code: 'a'.repeat(2048) }, { error: 'a'.repeat(128), error_code: 'b'.repeat(128), error_description: 'c'.repeat(2048) }]) expect(AuthCallbackQuerySchema.safeParse(value).success).toBe(true);
  expect(AuthCallbackQuerySchema.safeParse({ code: 'a', ownerId: id }).success).toBe(false);
});


it('declares the exact flow-bound recovery proof, empty acknowledgement and no cookie writes', () => {
  const operation = buildOpenApiDocument().paths['/api/v1/auth/recover'].post;
  expect(operation['x-implementationStatus']).toBe('planned');
  expect(operation.security).toEqual([{ BrowserBinding: [], OAuthAttempt: [] }]);
  expect(operation.parameters).toEqual([{ $ref: '#/components/parameters/Origin' }]);
  expect(operation.requestBody?.content['application/x-www-form-urlencoded'].schema.$ref).toBe('#/components/schemas/AuthLoginForm');
  expect(operation['x-max-body-bytes']).toBe(256);
  expect(operation['x-auth-proof']).toEqual({
    in: 'body', name: 'csrfToken', purpose: 'login', operation: 'recovery', scope: 'oauth-attempt', authoritative: true,
  });
  expect(Object.keys(operation.responses).sort()).toEqual(['204', '400', '403', '429', '503']);
  expect(operation.responses[204].content).toBeUndefined();
  for (const outcome of Object.values(operation.responses)) {
    expect(outcome.headers?.['Cache-Control']).toBeDefined();
    expect(outcome.headers?.['X-Request-Id']).toBeDefined();
    expect(outcome.headers?.['Set-Cookie']).toBeUndefined();
  }
});
