import { describe, expect, it } from 'vitest';
import { assertExecutionGuard, fixedConnectionOptions, assertServerIdentity, inTransaction, closeAll, type ProofClient } from '../postgres/protocol';

// These fake clients prove orchestration only. They do not simulate SQL, RLS or durability.
function fake(fail: (sql: string) => Error | undefined = () => undefined) {
  const statements: string[] = [];
  const releases: boolean[] = [];
  const client: ProofClient = {
    async query(sql) {
      statements.push(sql);
      const error = fail(sql); if (error) throw error;
      return { rows: [{ database: 'jls_command_fixture', username: 'command_fixture_admin', version: '170011' }] };
    },
    release(destroy = false) { releases.push(destroy); },
  };
  return { client, statements, releases };
}
const owned = { JLS_COMMAND_PROOF: 'owned-disposable', GITHUB_ACTIONS: 'true' };

describe('network-free disposable Postgres proof guards (fake orchestration only)', () => {
  it.each([{}, { JLS_COMMAND_PROOF: 'owned-disposable' }, { GITHUB_ACTIONS: 'true' }])('blocks before a connect factory can run: %j', environment => {
    let connected = false;
    expect(() => { assertExecutionGuard(environment); connected = true; }).toThrow(/owned-disposable.*GITHUB_ACTIONS/);
    expect(connected).toBe(false);
  });
  it('accepts only the explicit two-part execution acknowledgement', () => expect(() => assertExecutionGuard(owned)).not.toThrow());
  it('fixes endpoint, credentials, SSL and libpq options despite inherited remote configuration', () => {
    const config = fixedConnectionOptions({ ...owned, DATABASE_URL: 'postgres://remote/private', PGHOST: 'remote', PGPORT: '9999', PGDATABASE: 'private', PGUSER: 'private', PGPASSWORD: 'private', PGOPTIONS: '-c search_path=private', PGSSLMODE: 'require' });
    expect(config).toMatchObject({ host: '127.0.0.1', port: 5433, database: 'jls_command_fixture', user: 'command_fixture_admin', password: 'disposable_command_fixture_only', ssl: false, options: '-c search_path=pg_catalog -c statement_timeout=5000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=10000 -c transaction_timeout=10000', connectionTimeoutMillis: 5000 });
    expect(config).not.toHaveProperty('connectionString');
  });
  it.each([
    { database: 'private', username: 'command_fixture_admin', version: '170011' },
    { database: 'jls_command_fixture', username: 'private', version: '170011' },
    { database: 'jls_command_fixture', username: 'command_fixture_admin', version: '180001' },
  ])('rejects mismatched identity before any DDL: %j', async row => {
    const statements: string[] = [];
    await expect(assertServerIdentity({ async query(sql) { statements.push(sql); return { rows: [row] }; } })).rejects.toThrow(/identity/);
    expect(statements).toHaveLength(1);
    expect(statements[0]).toMatch(/^SELECT current_database/);
  });
  it('commits on the same checked-out client and releases it normally', async () => {
    const f = fake();
    await expect(inTransaction(f.client, 'subject', 'epoch', async client => { expect(client).toBe(f.client); await client.query('HANDLER'); return 42; })).resolves.toBe(42);
    expect(f.statements[0]).toBe('BEGIN'); expect(f.statements.at(-1)).toBe('COMMIT'); expect(f.releases).toEqual([false]);
    expect(f.statements.some(sql => sql.includes('SET LOCAL ROLE'))).toBe(true);
  });
  it('rolls back known pre-commit errors and preserves their cause', async () => {
    const original = new Error('handler'); const f = fake();
    await expect(inTransaction(f.client, 'subject', 'epoch', async () => { throw original; })).rejects.toBe(original);
    expect(f.statements.at(-1)).toBe('ROLLBACK'); expect(f.releases).toEqual([false]);
  });
  it('destroys on rollback failure and retains both errors', async () => {
    const original = new Error('handler'); const rollback = new Error('rollback'); const f = fake(sql => sql === 'ROLLBACK' ? rollback : undefined);
    await expect(inTransaction(f.client, 'subject', 'epoch', async () => { throw original; })).rejects.toMatchObject({ errors: [original, rollback] });
    expect(f.releases).toEqual([true]);
  });
  it('treats failed COMMIT acknowledgement as unknown, destroys and never claims rollback', async () => {
    const cause = new Error('transport'); const f = fake(sql => sql === 'COMMIT' ? cause : undefined);
    await expect(inTransaction(f.client, 'subject', 'epoch', async () => 1)).rejects.toMatchObject({ name: 'CommitOutcomeUnknown', cause });
    expect(f.statements).not.toContain('ROLLBACK'); expect(f.releases).toEqual([true]);
  });
  it('labels simulated transport loss after COMMIT as unknown and destroys', async () => {
    const f = fake();
    await expect(inTransaction(f.client, 'subject', 'epoch', async () => 1, { simulateLostCommitAcknowledgement: true })).rejects.toMatchObject({ name: 'CommitOutcomeUnknown' });
    expect(f.statements.at(-1)).toBe('COMMIT'); expect(f.releases).toEqual([true]);
  });
  it('retains original failure when checked-out client release also fails', async () => {
    const original = new Error('handler'); const release = new Error('release'); const f = fake();
    f.client.release = () => { throw release; };
    await expect(inTransaction(f.client, 'subject', 'epoch', async () => { throw original; })).rejects.toMatchObject({ errors: [original, release] });
  });
  it('propagates release failure after a successful commit without calling rollback', async () => {
    const release = new Error('release'); const f = fake(); f.client.release = () => { throw release; };
    await expect(inTransaction(f.client, 'subject', 'epoch', async () => 1)).rejects.toBe(release);
    expect(f.statements.at(-1)).toBe('COMMIT'); expect(f.statements).not.toContain('ROLLBACK');
  });
  it('destroys failed BEGIN without pretending that a transaction was rolled back', async () => {
    const error = new Error('begin'); const f = fake(sql => sql === 'BEGIN' ? error : undefined);
    await expect(inTransaction(f.client, 'subject', 'epoch', async () => 1)).rejects.toBe(error);
    expect(f.statements).toEqual(['BEGIN']); expect(f.releases).toEqual([true]);
  });  it('propagates every close failure while attempting all handles', async () => {
    const error = new Error('close'); let second = false;
    await expect(closeAll([{ async end() { throw error; } }, { async end() { second = true; } }])).rejects.toMatchObject({ errors: [error] });
    expect(second).toBe(true);
  });
});
