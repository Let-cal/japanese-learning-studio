import { describe, expect, it } from 'vitest';
import { evaluateOwnerRequest, type TrustedRequestPolicyFacts } from '../../src/infrastructure/auth/requestPolicy';

const sessionId = 'ccccccc3-3333-4333-8333-333333333333';
const otherId = 'eeeeeee5-5555-4555-8555-555555555555';
const appOrigin = 'https://studio.example.test';
function facts(): TrustedRequestPolicyFacts {
  return { method: 'POST', appOrigin, receivedOrigin: appOrigin, sessionId, csrf: { kind: 'verified', sessionId } };
}
function evaluate(input: unknown) { return evaluateOwnerRequest(input as TrustedRequestPolicyFacts); }

describe('pure owner-request mutation policy', () => {
  it.each(['GET', 'HEAD', 'OPTIONS'])('classifies %s as safe without granting authenticated context', method => {
    expect(evaluateOwnerRequest({ ...facts(), method, receivedOrigin: null, csrf: null })).toEqual({ kind: 'safe_method' });
  });
  it.each(['POST', 'PUT', 'PATCH', 'DELETE'])('requires origin and session-bound verified CSRF for %s', method => {
    expect(evaluateOwnerRequest({ ...facts(), method })).toEqual({ kind: 'mutation_allowed' });
    expect(evaluateOwnerRequest({ ...facts(), method, receivedOrigin: null })).toEqual({ kind: 'denied', reason: 'invalid_origin' });
    expect(evaluateOwnerRequest({ ...facts(), method, csrf: null })).toEqual({ kind: 'denied', reason: 'invalid_csrf' });
  });
  it('ignores a caller assertion that POST is a read', () => {
    expect(evaluate({ ...facts(), isMutation: false, receivedOrigin: null })).toEqual({ kind: 'denied', reason: 'invalid_origin' });
  });
  it.each([
    null, undefined, '', 'null', `${appOrigin}/`, `${appOrigin}/path`, `${appOrigin}?x=1`, `${appOrigin}#x`,
    'https://sub.studio.example.test', 'https://studio.example.test.evil.test', 'http://studio.example.test',
    `${appOrigin}, https://other.test`, ` ${appOrigin}`, 'https://STUDIO.example.test', `${appOrigin}:443`, 1, [],
  ])('rejects a non-exact received Origin %j even when CSRF is verified', receivedOrigin => {
    expect(evaluate({ ...facts(), receivedOrigin })).toEqual({ kind: 'denied', reason: 'invalid_origin' });
  });
  it.each([
    null, undefined, {}, 'verified', { kind: 'unverified', sessionId }, { kind: 'invalid', sessionId },
    { kind: 'verified' }, { kind: 'verified', sessionId: otherId }, { kind: 'verified', sessionId: 'bad' },
  ])('rejects absent, unverified or other-session CSRF %j', csrf => {
    expect(evaluate({ ...facts(), csrf })).toEqual({ kind: 'denied', reason: 'invalid_csrf' });
  });
  it('matches UUID spelling canonically without trusting a token string', () => {
    expect(evaluateOwnerRequest({ ...facts(), csrf: { kind: 'verified', sessionId: sessionId.toUpperCase() } })).toEqual({ kind: 'mutation_allowed' });
    expect(evaluate({ ...facts(), csrf: { kind: 'unverified', sessionId, token: 'same-token' }, token: 'same-token' })).toEqual({ kind: 'denied', reason: 'invalid_csrf' });
  });
  it.each([
    '', 'https://studio.example.test/', 'https://studio.example.test/path', 'https://studio.example.test?q=1',
    'https://studio.example.test#hash', 'https://user:pass@studio.example.test', 'https://STUDIO.example.test',
    'https://studio.example.test:443', 'http://studio.example.test', 'http://localhost:3000', 'null', '*', undefined,
  ])('requires a canonical HTTPS configured origin %j', appOrigin => {
    expect(evaluate({ ...facts(), appOrigin, receivedOrigin: appOrigin })).toEqual({ kind: 'denied', reason: 'invalid_configuration' });
  });
  it('allows a canonical HTTPS origin with an explicit nondefault port', () => {
    expect(evaluateOwnerRequest({ ...facts(), appOrigin: 'https://studio.example.test:8443', receivedOrigin: 'https://studio.example.test:8443' })).toEqual({ kind: 'mutation_allowed' });
  });
  it.each(['TRACE', 'CONNECT', 'post', 'get', '', null, undefined, 4])('denies unsupported method %j', method => {
    expect(evaluate({ ...facts(), method })).toEqual({ kind: 'denied', reason: 'unsupported_method' });
  });
  it.each([null, undefined, '', 'invalid', `${sessionId}\n`])('denies invalid current session identity %j', sessionId => {
    expect(evaluate({ ...facts(), sessionId })).toEqual({ kind: 'denied', reason: 'invalid_session' });
  });
  it.each([null, [], undefined])('fails closed on malformed facts %j', input => {
    expect(evaluate(input)).toEqual({ kind: 'denied', reason: 'invalid_facts' });
  });
  it('does not mutate the snapshots or leak arbitrary fields', () => {
    const input = Object.freeze({ ...facts(), csrf: Object.freeze({ kind: 'verified' as const, sessionId }), email: 'private@example.test', token: 'private' });
    expect(evaluate(input)).toEqual({ kind: 'mutation_allowed' });
    expect(input.csrf.sessionId).toBe(sessionId);
  });
});
