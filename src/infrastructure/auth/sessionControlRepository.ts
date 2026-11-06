import { hashSessionSecret } from './sessionSecrets';
import { parseSessionLookupMetadata, type SessionLookupResult, type SessionLookupUnavailableReason } from './sessionLookupContract';

export interface SessionControlConfiguration {
  readonly supabaseOrigin: unknown;
  readonly secretKey: unknown;
}

export interface SessionControlRepository {
  lookup(rawSecret: unknown): Promise<SessionLookupResult>;
}

function unavailable(reason: SessionLookupUnavailableReason): SessionLookupResult {
  return Object.freeze({ kind: 'unavailable', reason });
}

/** Never read environment here. Application code imports the guarded sessionControlGateway entry. */
export function createSessionControlRepository(configuration: SessionControlConfiguration, fetcher: typeof fetch = fetch): SessionControlRepository {
  // Validate and snapshot once: caller mutation cannot change the destination or credential.
  let trusted: { origin: string; key: string } | null = null;
  try {
    const { supabaseOrigin, secretKey } = configuration;
    if (typeof supabaseOrigin === 'string' && /^https:\/\/[a-z0-9]{20}\.supabase\.co$/.test(supabaseOrigin)
      && typeof secretKey === 'string' && /^sb_secret_[A-Za-z0-9_-]{16,256}$/.test(secretKey)) {
      trusted = { origin: supabaseOrigin, key: secretKey };
    }
  } catch { /* Invalid configuration remains a sanitized, closed capability. */ }

  return Object.freeze({
    async lookup(rawSecret: unknown): Promise<SessionLookupResult> {
      if (rawSecret === undefined || rawSecret === null) return Object.freeze({ kind: 'input_absent' });
      let digest: string;
      try { digest = hashSessionSecret(rawSecret); }
      catch { return Object.freeze({ kind: 'input_invalid' }); }
      if (!trusted) return unavailable('configuration');
      const { origin, key } = trusted;
      const controller = new AbortController();
      let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
      let completed = false;
      const cancel = () => {
        controller.abort();
        // A broken or hostile cancel implementation must never extend the deadline.
        try { void reader?.cancel().catch(() => {}); } catch { /* Best-effort resource cleanup. */ }
      };
      let timer: ReturnType<typeof setTimeout> | undefined;
      const deadline = new Promise<SessionLookupResult>(resolve => {
        timer = setTimeout(() => { cancel(); resolve(unavailable('timeout')); }, 2000);
      });
      const request = (async (): Promise<SessionLookupResult> => {
        try {
          const response = await fetcher(`${origin}/rest/v1/rpc/jls_auth_session_lookup_v1`, {
            method: 'POST', headers: { apikey: key, 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify({ p_session_secret_hash: digest }),
            redirect: 'error', credentials: 'omit', cache: 'no-store', signal: controller.signal,
          });
          reader = response.body?.getReader();
          if (completed || controller.signal.aborted) { cancel(); return unavailable('timeout'); }
          if (response.status !== 200) return unavailable('upstream_rejected');
          const mediaType = response.headers.get('Content-Type')?.split(';', 1)[0].trim().toLowerCase();
          if (mediaType !== 'application/json' || !reader) return unavailable('invalid_response');
          const chunks: Uint8Array[] = [];
          let length = 0;
          while (true) {
            const chunk = await reader.read();
            if (completed || controller.signal.aborted) return unavailable('timeout');
            if (chunk.done) break;
            length += chunk.value.byteLength;
            if (length > 8192) return unavailable('invalid_response');
            chunks.push(chunk.value);
          }
          const bytes = new Uint8Array(length);
          let offset = 0;
          for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
          try {
            const metadata = parseSessionLookupMetadata(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
            return metadata ?? unavailable('invalid_response');
          } catch { return unavailable('invalid_response'); }
        } catch { return unavailable('transport'); }
      })();
      try {
        const result = await Promise.race([deadline, request]);
        if (result.kind === 'unavailable') cancel();
        return result;
      } finally {
        completed = true;
        clearTimeout(timer);
      }
    },
  });
}
