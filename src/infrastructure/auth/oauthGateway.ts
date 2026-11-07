import 'server-only';
import { createOAuthTransport, type OAuthTransport, type OAuthTransportConfiguration } from './oauthTransport';

/** No route wiring or key reads: only approved server configuration creates this capability. */
export function createOAuthGateway(configuration: OAuthTransportConfiguration, fetcher: typeof fetch = fetch): OAuthTransport {
  return createOAuthTransport(configuration, fetcher);
}
