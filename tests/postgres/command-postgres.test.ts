import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { hashCommandInput } from '../../src/application/commands/commandFingerprint';
import { adapt, cleanupFixture, closeProofPools, createProofPool, EPOCH, initializeFixture, NEXT_EPOCH, operation, OTHER, OWNER, resetFixture, TARGET } from './fixture';
import { executeFixture } from './commandHarness';
import { inTransaction } from './protocol';
import { observe, signal, withConcurrentProof } from './concurrency';

const context = (id = 1, expectedVersion = 0) => ({ ownerId: OWNER, datasetEpoch: EPOCH, operationId: operation(id), expectedVersion });
const payload = (text = '日本語 và tiếng Việt', kind = 'fixture.update') => ({ kind, targetId: TARGET, body: { text } });
const countsSql = `SELECT (SELECT count(*)::int FROM jls_command_proof.receipts WHERE owner_id=$1) AS receipts,
 (SELECT count(*)::int FROM jls_command_proof.outbox WHERE owner_id=$1) AS outbox,
 (SELECT count(*)::int FROM jls_command_proof.proposals WHERE owner_id=$1) AS proposals,
 (SELECT version::text FROM jls_command_proof.aggregates WHERE owner_id=$1 AND dataset_epoch=$2 AND aggregate_id=$3) AS version`;
async function counts(pool: Pool) { return (await pool.query(countsSql, [OWNER, EPOCH, TARGET])).rows[0]; }
async function waitForLock(pool: Pool, pid: number) {
  const deadline = Date.now() + 2500;
  while (Date.now() < deadline) {
    const { rows } = await pool.query(`SELECT a.wait_event_type, pg_blocking_pids(a.pid) AS blockers,
      EXISTS (SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND NOT l.granted) AS ungranted
      FROM pg_stat_activity a WHERE a.pid=$1`, [pid]);
    if (rows[0]?.wait_event_type === 'Lock' && rows[0]?.blockers.length > 0 && rows[0]?.ungranted) return rows[0];
    // Poll spacing only; actual pg_stat_activity + pg_locks state proves ordering.
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  throw new Error(`No observable PostgreSQL lock wait for fixture backend ${pid}.`);
}
async function revocation(pool: Pool, epochChange: boolean, hooks: { onClient?: (pid: number) => void; afterUpdate?: () => Promise<void> } = {}) {
  const client = await pool.connect(); let began = false;
  try {
    await client.query('BEGIN'); began = true;
    hooks.onClient?.((await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
    // Same owner -> dataset ordering as command authorization; FOR UPDATE conflicts with FOR SHARE.
    await client.query('SELECT owner_id FROM jls_command_proof.owners WHERE owner_id=$1 FOR UPDATE', [OWNER]);
    await client.query('SELECT dataset_epoch FROM jls_command_proof.datasets WHERE owner_id=$1 AND dataset_epoch=$2 FOR UPDATE', [OWNER, EPOCH]);
    if (epochChange) {
      await client.query('INSERT INTO jls_command_proof.datasets(owner_id,dataset_epoch,active) VALUES ($1,$2,true)', [OWNER, NEXT_EPOCH]);
      await client.query('UPDATE jls_command_proof.owners SET current_epoch=$2 WHERE owner_id=$1', [OWNER, NEXT_EPOCH]);
    } else { await client.query('UPDATE jls_command_proof.owners SET active=false WHERE owner_id=$1', [OWNER]); }
    await hooks.afterUpdate?.(); await client.query('COMMIT'); began = false;
  } catch (cause) {
    if (began) { try { await client.query('ROLLBACK'); } catch (rollback) { throw new AggregateError([cause, rollback], 'Revocation rollback failed.'); } }
    throw cause;
  } finally { client.release(true); }
}

// No DB work at module discovery. A guarded beforeAll rejects unauthorized execution, never skips.
describe('owned disposable PostgreSQL 17 command conformance (real SQL; TEST ONLY)', () => {
  let pool: Pool | undefined;
  let initialized = false;
  const pools: Pool[] = [];
  const db = () => { if (!pool) throw new Error('Guarded fixture not initialized.'); return pool; };
  beforeAll(async () => { pool = createProofPool(); pools.push(pool); await initializeFixture(pool); initialized = true; });
  beforeEach(async () => { await resetFixture(db()); });
  afterAll(async () => {
    const errors: unknown[] = [];
    if (initialized && pool) { try { await cleanupFixture(pool); } catch (error) { errors.push(error); } }
    try { await closeProofPools(pools); } catch (error) { errors.push(error); }
    if (errors.length) throw new AggregateError(errors, 'Fixture teardown failed.');
  });

  it('P01 exposes mutation, safe receipt and outbox together only after actual COMMIT', async () => withConcurrentProof(async scope => {
    const gate = scope.barrier(); const task = scope.start(executeFixture(db(), context(), payload(), { afterReceipt: gate.hold }));
    try {
      await scope.wait(gate.arrival, task);
      expect(await counts(db())).toEqual({ version: '0', receipts: 0, outbox: 0, proposals: 0 });
    } finally { gate.release(); }
    const result = await task; expect(result.ok).toBe(true);
    expect(await counts(db())).toEqual({ version: '1', receipts: 1, outbox: 1, proposals: 0 });
    const stored = (await db().query('SELECT receipt::text FROM jls_command_proof.receipts')).rows;
    expect(JSON.stringify(stored)).not.toContain('日本語');
    expect(JSON.stringify((await db().query('SELECT acknowledgement FROM jls_command_proof.outbox')).rows)).not.toContain('tiếng Việt');
  }));
  it('P02 ends original pool, reconnects and replays persisted receipt without handler (not DB crash/WAL proof)', async () => {
    const original = await executeFixture(db(), context(), payload());
    await db().end(); pools.splice(pools.indexOf(db()), 1);
    pool = createProofPool(); pools.push(pool);
    let called = false;
    expect(await executeFixture(db(), context(), payload(), { onHandler: () => { called = true; } })).toEqual(original);
    expect(called).toBe(false); expect(await counts(db())).toMatchObject({ version: '1', receipts: 1, outbox: 1 });
  });
  it('P03 rejects same key with different input 409 without second effect', async () => {
    await executeFixture(db(), context(), payload());
    await expect(executeFixture(db(), context(), payload('different'))).rejects.toMatchObject({ code: 'idempotency_key_reused', status: 409 });
    expect(await counts(db())).toMatchObject({ version: '1', receipts: 1, outbox: 1 });
  });
  it.each([false, true])('P04/P05 contended same key, changed input=%s: observable advisory wait, exactly one effect', async changed => withConcurrentProof(async scope => {
    const gate = scope.barrier(); const pid = signal<number>(); let loserPid = 0;
    const first = scope.start(executeFixture(db(), context(), payload(), { afterReceipt: gate.hold }));
    let second: ReturnType<typeof observe<Awaited<ReturnType<typeof executeFixture>>>> | undefined;
    try {
      await scope.wait(gate.arrival, first);
      second = scope.start(executeFixture(db(), context(), payload(changed ? 'different' : undefined), { onClient: backendPid => { loserPid = backendPid; pid.resolve(backendPid); } }));
      await scope.wait(pid.promise, second!);
      expect((await waitForLock(db(), loserPid)).ungranted).toBe(true);
    } finally { gate.release(); }
    const winner = await first; const loser = await second!;
    expect(winner.ok).toBe(true);
    if (changed) { expect(loser).toMatchObject({ ok: false, error: { code: 'idempotency_key_reused', status: 409 } }); }
    else { expect(loser).toEqual(winner); }
    expect(await counts(db())).toEqual({ version: '1', receipts: 1, outbox: 1, proposals: 0 });
  }));
  it('P06 retains 412 proposal with canonical aggregate unchanged and no answer-bearing receipt', async () => {
    const result = await executeFixture(db(), context(1, 5), payload('private proposed answer'));
    expect(result.rejection).toMatchObject({ code: 'version_conflict', status: 412, currentVersion: 0 });
    expect(await counts(db())).toEqual({ version: '0', receipts: 1, outbox: 0, proposals: 1 });
    expect((await db().query('SELECT proposed_content FROM jls_command_proof.proposals')).rows[0].proposed_content).toBe('private proposed answer');
    expect(JSON.stringify(result)).not.toContain('private proposed answer');
  });
  it('P07 replays retained rejection without duplicate proposal or rerunning handler', async () => {
    const original = await executeFixture(db(), context(1, 5), payload()); let called = false;
    expect(await executeFixture(db(), context(1, 5), payload(), { onHandler: () => { called = true; } })).toEqual(original);
    expect(called).toBe(false); expect(await counts(db())).toEqual({ version: '0', receipts: 1, outbox: 0, proposals: 1 });
  });
  it.each(['afterDomain', 'afterOutbox', 'afterReceipt'] as const)('P08/P09 rolls back every effect on known pre-commit failure at %s', async stage => {
    const failure = new Error(`synthetic ${stage}`);
    await expect(executeFixture(db(), context(), payload(), { [stage]: async () => { throw failure; } })).rejects.toBe(failure);
    expect(await counts(db())).toEqual({ version: '0', receipts: 0, outbox: 0, proposals: 0 });
  });
  it('P10 unsafe acknowledgement rolls back preceding aggregate/outbox writes', async () => {
    await expect(executeFixture(db(), context(), payload(), { unsafeAcknowledgement: true })).rejects.toMatchObject({ code: 'unsafe_command_acknowledgement', status: 503 });
    expect(await counts(db())).toEqual({ version: '0', receipts: 0, outbox: 0, proposals: 0 });
  });
  it.each(['policy', 'hash', 'unsafeReceipt', 'unsafeVersion'] as const)('P11 corrupt/unsupported stored %s fails closed 503 without handler', async corruption => {
    await executeFixture(db(), context(), payload());
    if (corruption === 'policy') await db().query("UPDATE jls_command_proof.receipts SET policy='unsupported-v99'");
    if (corruption === 'hash') await db().query("UPDATE jls_command_proof.receipts SET fingerprint='broken'");
    if (corruption === 'unsafeReceipt') await db().query(`UPDATE jls_command_proof.receipts SET receipt=jsonb_set(receipt,'{data,answer}', '"secret"'::jsonb)`);
    if (corruption === 'unsafeVersion') await db().query(`UPDATE jls_command_proof.receipts SET receipt=jsonb_set(receipt,'{data,resourceVersion}', '9007199254740992'::jsonb)`);
    let called = false;
    await expect(executeFixture(db(), context(), payload(), { onHandler: () => { called = true; } })).rejects.toMatchObject({ status: 503 });
    expect(called).toBe(false); expect(await counts(db())).toMatchObject({ version: '1', receipts: 1, outbox: 1 });
  });
  it('P12 verifies real restricted role, forced RLS, grants, composite foreign keys and denies wrong/missing/revoked subjects', async () => {
    const flags = (await db().query("SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname='jls_command_actor'")).rows[0];
    expect(flags).toEqual({ rolsuper: false, rolbypassrls: false, rolcanlogin: false });
    const tables = (await db().query("SELECT relname, relrowsecurity, relforcerowsecurity, pg_get_userbyid(relowner) AS owner FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='jls_command_proof' AND c.relkind='r' AND c.relname <> 'fixture_marker' ORDER BY relname")).rows;
    expect(tables).toHaveLength(6); expect(tables.every(row => row.relrowsecurity && row.relforcerowsecurity && row.owner !== 'jls_command_actor')).toBe(true);
    const privileges = (await db().query(`SELECT has_column_privilege('jls_command_actor','jls_command_proof.owners','active','UPDATE') AS active,
      has_column_privilege('jls_command_actor','jls_command_proof.owners','current_epoch','UPDATE') AS epoch,
      has_column_privilege('jls_command_actor','jls_command_proof.owners','lock_token','UPDATE') AS lock,
      has_table_privilege('jls_command_actor','jls_command_proof.receipts','DELETE') AS receipt_delete`)).rows[0];
    expect(privileges).toEqual({ active: false, epoch: false, lock: true, receipt_delete: false });
    await expect(executeFixture(db(), context(), payload(), {}, OTHER)).rejects.toMatchObject({ name: 'FixtureAuthorizationError' });
    await expect(executeFixture(db(), context(), payload(), {}, '')).rejects.toMatchObject({ name: 'FixtureAuthorizationError' });
    await inTransaction(adapt(await db().connect()), '', EPOCH, async tx => {
      expect((await tx.query('SELECT * FROM jls_command_proof.aggregates')).rows).toEqual([]);
      expect((await tx.query('SELECT * FROM jls_command_proof.receipts')).rows).toEqual([]);
    });
    await expect(inTransaction(adapt(await db().connect()), OTHER, EPOCH, async tx => {
      await tx.query("UPDATE jls_command_proof.aggregates SET content='forbidden' WHERE owner_id=$1", [OWNER]);
      await tx.query('UPDATE jls_command_proof.owners SET active=false WHERE owner_id=$1', [OTHER]);
    })).rejects.toMatchObject({ code: '42501' });
    await expect(inTransaction(adapt(await db().connect()), OWNER, EPOCH, async tx => {
      await tx.query('INSERT INTO jls_command_proof.outbox VALUES ($1,$2,$3,$4,$5::jsonb)', [OWNER, EPOCH, operation(9), operation(99), '{}']);
    })).rejects.toMatchObject({ code: '23503' });
    await revocation(db(), false);
    await expect(executeFixture(db(), context(), payload())).rejects.toMatchObject({ name: 'FixtureAuthorizationError' });
    expect(await counts(db())).toEqual({ version: '0', receipts: 0, outbox: 0, proposals: 0 });
  });
  it('P13 old epoch cannot disclose a receipt or mutate after owner epoch rotation', async () => {
    await executeFixture(db(), context(), payload()); await revocation(db(), true); let called = false;
    await expect(executeFixture(db(), context(), payload(), { onHandler: () => { called = true; } })).rejects.toMatchObject({ name: 'FixtureAuthorizationError' });
    await inTransaction(adapt(await db().connect()), OWNER, EPOCH, async tx => { expect((await tx.query('SELECT * FROM jls_command_proof.receipts')).rows).toEqual([]); });
    expect(called).toBe(false); expect(await counts(db())).toMatchObject({ version: '1', receipts: 1, outbox: 1 });
  });
  it.each([false, true])('P14 command-first linearizes before revocation/epoch change=%s with actual owner lock wait', async epochChange => withConcurrentProof(async scope => {
    const gate = scope.barrier(); const pid = signal<number>(); let revokerPid = 0;
    const command = scope.start(executeFixture(db(), context(), payload(), { afterReceipt: gate.hold }));
    let revoke: ReturnType<typeof observe<void>> | undefined;
    try {
      await scope.wait(gate.arrival, command); revoke = scope.start(revocation(db(), epochChange, { onClient: backendPid => { revokerPid = backendPid; pid.resolve(backendPid); } }));
      await scope.wait(pid.promise, revoke!);
      await waitForLock(db(), revokerPid);
    } finally { gate.release(); }
    expect((await command).ok).toBe(true); expect((await revoke!).ok).toBe(true);
    await expect(executeFixture(db(), context(), payload())).rejects.toMatchObject({ name: 'FixtureAuthorizationError' });
    expect(await counts(db())).toMatchObject({ version: '1', receipts: 1, outbox: 1 });
  }));
  it.each([false, true])('P14 revocation/epoch-first=%s blocks then rejects command without effect', async epochChange => withConcurrentProof(async scope => {
    const gate = scope.barrier(); const pid = signal<number>(); let commandPid = 0;
    const revoke = scope.start(revocation(db(), epochChange, { afterUpdate: gate.hold }));
    let command: ReturnType<typeof observe<Awaited<ReturnType<typeof executeFixture>>>> | undefined;
    try {
      await scope.wait(gate.arrival, revoke); command = scope.start(executeFixture(db(), context(), payload(), { onClient: backendPid => { commandPid = backendPid; pid.resolve(backendPid); } }));
      await scope.wait(pid.promise, command!);
      await waitForLock(db(), commandPid);
    } finally { gate.release(); }
    expect((await revoke).ok).toBe(true); expect(await command!).toMatchObject({ ok: false, error: { name: 'FixtureAuthorizationError' } });
    expect(await counts(db())).toEqual({ version: '0', receipts: 0, outbox: 0, proposals: 0 });
  }));
  it('P15 different operations serialize on aggregate; loser retains proposal without double canonical update', async () => withConcurrentProof(async scope => {
    const gate = scope.barrier(); const pid = signal<number>(); let secondPid = 0;
    const first = scope.start(executeFixture(db(), context(1), payload('first'), { afterDomain: gate.hold }));
    let second: ReturnType<typeof observe<Awaited<ReturnType<typeof executeFixture>>>> | undefined;
    try {
      await scope.wait(gate.arrival, first); second = scope.start(executeFixture(db(), context(2), payload('second'), { onClient: backendPid => { secondPid = backendPid; pid.resolve(backendPid); } }));
      await scope.wait(pid.promise, second!);
      await waitForLock(db(), secondPid);
    } finally { gate.release(); }
    expect((await first).ok).toBe(true);
    expect(await second!).toMatchObject({ ok: true, value: { rejection: { status: 412 } } });
    expect(await counts(db())).toEqual({ version: '1', receipts: 2, outbox: 1, proposals: 1 });
  }));
  it.each([false, true])('P16 synthetic answer/finish both orderings; finishFirst=%s and historical replay (NOT product execution proof)', async finishFirst => withConcurrentProof(async scope => {
    const gate = scope.barrier(); const pid = signal<number>(); let secondPid = 0;
    const firstKind = finishFirst ? 'fixture.finish' : 'fixture.answer';
    const secondKind = finishFirst ? 'fixture.answer' : 'fixture.finish';
    const firstPayload = payload('first', firstKind);
    const first = scope.start(executeFixture(db(), context(1), firstPayload, { afterDomain: gate.hold }));
    let second: ReturnType<typeof observe<Awaited<ReturnType<typeof executeFixture>>>> | undefined;
    try {
      await scope.wait(gate.arrival, first);
      second = scope.start(executeFixture(db(), context(2, 1), payload('second', secondKind), { onClient: backendPid => { secondPid = backendPid; pid.resolve(backendPid); } }));
      await scope.wait(pid.promise, second!);
      await waitForLock(db(), secondPid);
    } finally { gate.release(); }
    const original = await first; expect(original.ok).toBe(true);
    if (finishFirst) expect(await second!).toMatchObject({ ok: true, value: { rejection: { code: 'execution_conflict', status: 409 } } });
    else expect(await second!).toMatchObject({ ok: true, value: { data: { resourceVersion: 2 } } });
    let called = false;
    expect(await scope.start(executeFixture(db(), context(1), firstPayload, { onHandler: () => { called = true; } }))).toEqual(original);
    expect(called).toBe(false);
    expect((await db().query('SELECT state FROM jls_command_proof.aggregates WHERE owner_id=$1', [OWNER])).rows[0].state).toBe('closed');
  }));
  it('P17 actual lock timeout rolls back and releases checked-out connection, next command can commit', async () => withConcurrentProof(async scope => {
    const gate = scope.barrier(); const pid = signal<number>(); let secondPid = 0;
    const first = scope.start(executeFixture(db(), context(1), payload('first'), { afterDomain: gate.hold }));
    let second: ReturnType<typeof observe<Awaited<ReturnType<typeof executeFixture>>>> | undefined;
    try {
      await scope.wait(gate.arrival, first); second = scope.start(executeFixture(db(), context(2), payload('second'), { lockTimeoutMs: 750, onClient: backendPid => { secondPid = backendPid; pid.resolve(backendPid); } }));
      await scope.wait(pid.promise, second!);
      await waitForLock(db(), secondPid);
      expect(await second).toMatchObject({ ok: false, error: { code: '55P03' } });
      expect(db().waitingCount).toBe(0);
      expect((await db().query('SELECT count(*)::int AS n FROM pg_locks WHERE pid=$1 AND NOT granted', [secondPid])).rows[0].n).toBe(0);
    } finally { gate.release(); }
    expect((await first).ok).toBe(true);
    await executeFixture(db(), context(3, 1), payload('after timeout'));
    expect(await counts(db())).toEqual({ version: '2', receipts: 2, outbox: 2, proposals: 0 });
  }));
  it('P18 simulated lost acknowledgement AFTER actual COMMIT resolves by fresh replay without duplicate (not DB crash)', async () => {
    await expect(executeFixture(db(), context(), payload(), { simulateLostCommitAcknowledgement: true })).rejects.toMatchObject({ name: 'CommitOutcomeUnknown' });
    let called = false;
    const receipt = await executeFixture(db(), context(), payload(), { onHandler: () => { called = true; } });
    expect(receipt.data.resourceVersion).toBe(1); expect(called).toBe(false);
    expect(await counts(db())).toEqual({ version: '1', receipts: 1, outbox: 1, proposals: 0 });
  });
  it('P19 transaction-local subject and epoch do not leak when exactly the same pooled backend is reused', async () => {
    const single = createProofPool(); pools.push(single);
    // Hold all but one? Use a separate pool configured max=1 before any connect.
    single.options.max = 1;
    let firstPid = 0;
    await inTransaction(adapt(await single.connect()), OWNER, EPOCH, async tx => {
      firstPid = Number((await tx.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);
      expect((await tx.query('SELECT * FROM jls_command_proof.aggregates')).rows).toHaveLength(1);
    });
    const native = await single.connect();
    try {
      const state = (await native.query("SELECT pg_backend_pid() AS pid, current_user AS actor, nullif(current_setting('jls.subject',true),'') AS subject, nullif(current_setting('jls.epoch',true),'') AS epoch")).rows[0];
      expect(state).toEqual({ pid: firstPid, actor: 'command_fixture_admin', subject: null, epoch: null });
    } finally { native.release(); }
    await inTransaction(adapt(await single.connect()), '', '', async tx => { expect((await tx.query('SELECT * FROM jls_command_proof.aggregates')).rows).toHaveLength(0); });
  });
  it('P20 JA/VI, UUID case and max-safe acknowledgement versions survive Node fingerprint + JSONB roundtrip', async () => {
    await resetFixture(db(), Number.MAX_SAFE_INTEGER - 1);
    const originalContext = context(1, Number.MAX_SAFE_INTEGER - 1);
    const upperContext = { ...originalContext, ownerId: OWNER.toUpperCase(), datasetEpoch: EPOCH.toUpperCase(), operationId: originalContext.operationId.toUpperCase() };
    const input = payload('日本語：が・が / Tiếng Việt: ắ, ắ');
    const upperInput = { ...input, targetId: TARGET.toUpperCase() };
    const expectedFingerprint = hashCommandInput(originalContext, input);
    expect(hashCommandInput(upperContext, upperInput)).toEqual(expectedFingerprint);
    const receipt = await executeFixture(db(), upperContext, upperInput);
    expect(receipt.data.resourceVersion).toBe(Number.MAX_SAFE_INTEGER);
    const stored = (await db().query('SELECT policy,fingerprint,receipt FROM jls_command_proof.receipts')).rows[0];
    expect({ policy: stored.policy, hash: stored.fingerprint }).toEqual(expectedFingerprint);
    expect(stored.receipt).toEqual(receipt);
    expect((await db().query('SELECT content FROM jls_command_proof.aggregates WHERE owner_id=$1', [OWNER])).rows[0].content).toBe(input.body.text);
    let called = false;
    expect(await executeFixture(db(), originalContext, input, { onHandler: () => { called = true; } })).toEqual(receipt);
    expect(called).toBe(false);
  });
});
