import 'server-only';
import { createOAuthActionRepository, type OAuthActionRepository } from './oauthActionRepository';

export type { OAuthActionFault, OAuthActionRepository } from './oauthActionRepository';

/** The caller supplies approved server configuration for these fixed control operations. */
export function createOAuthActionGateway(configuration: unknown, fetcher: typeof fetch = fetch): OAuthActionRepository {
  return createOAuthActionRepository(configuration, fetcher);
}
