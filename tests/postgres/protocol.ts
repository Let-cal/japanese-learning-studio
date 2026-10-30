/** TEST-ONLY orchestration. Custom GUCs are trusted synthetic context, not JWT verification. */
export interface ProofClient {
  query(sql: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[]; rowCount?: number | null }>;
  release(destroy?: boolean): void;
}
export type ProofEnvironment = Record<string, string | undefined>;
export function assertExecutionGuard(environment: ProofEnvironment): void {
  if (environment.JLS_COMMAND_PROOF !== 'owned-disposable' || environment.GITHUB_ACTIONS !== 'true') {
    throw new Error('Postgres proof blocked before connect: requires JLS_COMMAND_PROOF=owned-disposable AND GITHUB_ACTIONS=true on an approved disposable CI service. Do not run against an existing database.');
  }
}
export function fixedConnectionOptions(_environment: ProofEnvironment) {
  // No DSN, libpq service, SSL file or inherited environment setting is consumed here.
  return {
    host: '127.0.0.1', port: 5433, database: 'jls_command_fixture', user: 'command_fixture_admin',
    password: 'disposable_command_fixture_only', ssl: false as const, sslnegotiation: 'postgres' as const, client_encoding: 'UTF8', replication: 'false',
    options: '-c search_path=pg_catalog -c statement_timeout=5000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=10000 -c transaction_timeout=10000',
    connectionTimeoutMillis: 5000, statement_timeout: 5000, lock_timeout: 3000,
    idle_in_transaction_session_timeout: 10000, application_name: 'jls-owned-command-proof',
    max: 6, idleTimeoutMillis: 1000,
  };
}
export async function assertServerIdentity(client: Pick<ProofClient, 'query'>): Promise<void> {
  const { rows } = await client.query("SELECT current_database() AS database, current_user AS username, current_setting('server_version_num') AS version");
  const row = rows[0];
  if (row?.database !== 'jls_command_fixture' || row.username !== 'command_fixture_admin' || !/^17[0-9]{4}$/.test(String(row.version))) {
    throw new Error('Disposable Postgres server identity mismatch; no DDL or cleanup authorized.');
  }
}
export class CommitOutcomeUnknown extends Error {
  constructor(cause: unknown) { super('COMMIT outcome unknown; destroy connection and resolve using a fresh same-key replay.', { cause }); this.name = 'CommitOutcomeUnknown'; }
}
export async function inTransaction<T>(client: ProofClient, subject: string, epoch: string, work: (client: ProofClient) => Promise<T>, options: { simulateLostCommitAcknowledgement?: boolean } = {}): Promise<T> {
  let began = false;
  let committing = false;
  let destroy = false;
  async function execute(): Promise<T> {
    try {
      await client.query('BEGIN'); began = true;
      await client.query('SET LOCAL ROLE jls_command_actor');
      await client.query("SELECT set_config('jls.subject', $1, true), set_config('jls.epoch', $2, true)", [subject, epoch]);
      const value = await work(client);
      committing = true;
      await client.query('COMMIT');
      if (options.simulateLostCommitAcknowledgement) throw new Error('Simulated transport acknowledgement loss AFTER actual COMMIT; not a database crash.');
      return value;
    } catch (cause) {
      if (committing) { destroy = true; throw new CommitOutcomeUnknown(cause); }
      if (began) {
        try { await client.query('ROLLBACK'); }
        catch (rollback) { destroy = true; throw new AggregateError([cause, rollback], 'Command failed and rollback failed.', { cause }); }
      } else { destroy = true; }
      throw cause;
    }
  }
  const result = await execute().then(value => ({ ok: true as const, value }), error => ({ ok: false as const, error: error as unknown }));
  try { client.release(destroy); }
  catch (release) {
    if (!result.ok) throw new AggregateError([result.error, release], 'Command failed and client release failed.', { cause: result.error });
    throw release;
  }
  if (!result.ok) throw result.error;
  return result.value;
}
export async function closeAll(handles: readonly { end(): Promise<void> }[]): Promise<void> {
  const results = await Promise.allSettled(handles.map(handle => handle.end()));
  const errors = results.flatMap(result => result.status === 'rejected' ? [result.reason] : []);
  if (errors.length) throw new AggregateError(errors, 'Disposable proof handle cleanup failed.');
}
