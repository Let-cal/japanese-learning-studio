import 'server-only';
import { createSessionControlRepository, type SessionControlConfiguration, type SessionControlRepository } from './sessionControlRepository';

/**
 * The only application import for the control-plane capability. The caller supplies
 * approved server configuration; this module neither reads environment nor wires routes.
 * Results are stored metadata, never verified user JWTs or owner authorization proof.
 */
export function createSessionControlGateway(configuration: SessionControlConfiguration, fetcher: typeof fetch = fetch): SessionControlRepository {
  return createSessionControlRepository(configuration, fetcher);
}
