import 'server-only';
import { createAuthCandidateVerifier, createAuthIdentityGateway } from '../../infrastructure/auth/authIdentityGateway';
import type { PkceKey } from '../../infrastructure/auth/authActionSecrets';
import { createOAuthActionGateway } from '../../infrastructure/auth/oauthActionGateway';
import { createOAuthGateway } from '../../infrastructure/auth/oauthGateway';
import type { OrphanTokenKey } from '../../infrastructure/auth/orphanTokenEnvelope';
import { createSessionRuntimeGateway } from '../../infrastructure/auth/sessionRuntimeGateway';
import type { UpstreamTokenKey } from '../../infrastructure/auth/tokenEnvelope';
import { createGoogleOAuthBegin } from './googleOAuthBegin';
import { createGoogleOAuthCallback } from './googleOAuthCallback';
import { createGoogleOAuthHttp } from './googleOAuthHttp';
import { createGoogleOAuthRecoveryProof } from './googleOAuthRecoveryProof';
import { createOwnerSessionVerifier } from './ownerSession';

interface Configuration {
  readonly environment: string;
  readonly appOrigin: string;
  readonly supabaseOrigin: string;
  readonly publishableKey: string;
  readonly secretKey: string;
  readonly pkceKey: PkceKey;
  readonly sessionTokenKey: UpstreamTokenKey;
  readonly orphanTokenKey: OrphanTokenKey;
}

/** Compose with explicit server configuration after activation prerequisites are met. */
export function createGoogleOAuthRuntime(config: Configuration, fetcher: typeof fetch = fetch) {
  const { appOrigin, supabaseOrigin, publishableKey, secretKey } = config;
  const control = { supabaseOrigin, secretKey };
  const auth = { supabaseOrigin, publishableKey };
  const actions = createOAuthActionGateway(control, fetcher);
  const transport = createOAuthGateway({ ...auth, appOrigin }, fetcher);
  const identity = createAuthIdentityGateway(auth, fetcher);
  const candidate = createAuthCandidateVerifier(auth, fetcher);
  const ownerSession = createOwnerSessionVerifier(config, { repository: createSessionRuntimeGateway(control, fetcher), identity });

  const handlers = createGoogleOAuthHttp(appOrigin, {
    resolveAction: actions.resolveAction, inspectCallback: actions.inspectCallback, recoverLogin: actions.recoverLogin,
    begin: createGoogleOAuthBegin(config, { beginLogin: actions.beginLogin, authorizationUrl: transport.authorizationUrl }),
    finish: createGoogleOAuthCallback(config, { actions, exchange: transport.exchange, verifyCandidate: candidate.verifyCandidate }),
    verifyCurrent: ownerSession.verifyForCallback,
  });
  return Object.freeze({
    handlers: Object.freeze(handlers),
    verifyOwnerSession: ownerSession.verify,
    issueRecoveryProof: createGoogleOAuthRecoveryProof(actions),
  });
}
