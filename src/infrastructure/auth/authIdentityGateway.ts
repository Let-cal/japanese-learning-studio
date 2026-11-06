import 'server-only';
import { createAuthCandidateVerifier, createAuthIdentityVerifier,
  type AuthIdentityConfiguration, type AuthIdentityVerifier } from './authAdapter';

// Distinct guarded factories: a caller cannot select verification stage in input JSON.
export { createAuthCandidateVerifier, createAuthIdentityVerifier };

/**
 * Application entry point. Supplies only a verified Auth identity capability,
 * never owner authority. The caller supplies approved configuration and fresh
 * same-request trusted DB facts; this module neither reads environment nor wires routes.
 */
export function createAuthIdentityGateway(
  configuration: AuthIdentityConfiguration,
  fetcher: typeof fetch = fetch,
  monotonicClock: () => number = () => performance.now(),
): AuthIdentityVerifier {
  return createAuthIdentityVerifier(configuration, fetcher, monotonicClock);
}
