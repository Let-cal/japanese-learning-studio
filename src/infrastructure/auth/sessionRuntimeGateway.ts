import 'server-only';
import { createSessionRuntimeRepository, type SessionRuntimeRepository } from './sessionRuntimeRepository';
import type { SessionControlConfiguration } from './sessionControlRepository';

/** Separate from the user-JWT data client. No environment lookup or route activation. */
export function createSessionRuntimeGateway(configuration: SessionControlConfiguration, fetcher: typeof fetch = fetch): SessionRuntimeRepository {
  return createSessionRuntimeRepository(configuration,fetcher);
}
