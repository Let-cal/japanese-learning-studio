import { describe, expect, it } from 'vitest';
import { committedCommandProblem, createCommandExecutor } from '../../src/application/commands/executeCommand';
import { hashCommandInput } from '../../src/application/commands/commandFingerprint';
import type { CommandTransaction, StoredCommandReceipt } from '../../src/contracts/commands';

const context = { ownerId: '10000000-0000-4000-8000-000000000001', datasetEpoch: '20000000-0000-4000-8000-000000000001', operationId: '30000000-0000-4000-8000-000000000001', expectedVersion: 7 };
const command = { kind: 'note.save', targetId: '40000000-0000-4000-8000-000000000001', body: { text: '記憶の手がかり' } };
const data = { resourceId: command.targetId, resourceVersion: 8 };

// A recording port proves orchestration only. It is neither a database nor a durable receipt store.
function recordingPort(found: StoredCommandReceipt | null = null) {
  const calls: string[] = [];
  const transaction: CommandTransaction = {
    authorizeCurrentDataset: async () => { calls.push('authorize'); },
    lockOperation: async () => { calls.push('lock'); },
    readReceipt: async () => { calls.push('read'); return found; },
    saveReceipt: async (ctx, fingerprint, acknowledgement, rejection) => {
      calls.push('save');
      return { ownerId: ctx.ownerId, fingerprint, receipt: { operationId: ctx.operationId, datasetEpoch: ctx.datasetEpoch, data: acknowledgement, ...(rejection ? { rejection } : {}) } };
    },
  };
  return { calls, transaction };
}
const stored = (): StoredCommandReceipt => ({ ownerId: context.ownerId, fingerprint: hashCommandInput(context, command), receipt: { operationId: context.operationId, datasetEpoch: context.datasetEpoch, data } });

describe('transaction-bound command orchestration (not database proof)', () => {
  it('authorizes and locks before reading; saves only after a valid handler acknowledgement', async () => {
    const { calls, transaction } = recordingPort();
    const result = await createCommandExecutor(transaction)(context, command, async () => { calls.push('handler'); return data; });
    expect(calls).toEqual(['authorize', 'lock', 'read', 'handler', 'save']);
    expect(result).toEqual({ operationId: context.operationId, datasetEpoch: context.datasetEpoch, data });
    expect(result).not.toHaveProperty('fingerprint');
  });
  it('replays the original safe receipt before stale resource/session preconditions', async () => {
    const { calls, transaction } = recordingPort(stored());
    const executeCommand = createCommandExecutor(transaction);
    expect(await executeCommand(context, command, async () => { throw new Error('stale ETag or session closed'); })).toEqual(stored().receipt);
    expect(calls).toEqual(['authorize', 'lock', 'read']);
  });
  it('does not reveal an old receipt after owner revocation or dataset replacement', async () => {
    const { calls, transaction } = recordingPort(stored());
    transaction.authorizeCurrentDataset = async () => { calls.push('authorize'); throw new Error('current authorization denied'); };
    await expect(createCommandExecutor(transaction)(context, command, async () => data)).rejects.toThrow('current authorization denied');
    expect(calls).toEqual(['authorize']);
  });
  it('rejects changed input under the same identity without invoking handler or saving', async () => {
    const { calls, transaction } = recordingPort(stored());
    await expect(createCommandExecutor(transaction)(context, { ...command, body: { text: 'different' } }, async () => data)).rejects.toMatchObject({ code: 'idempotency_key_reused', status: 409 });
    expect(calls).toEqual(['authorize', 'lock', 'read']);
  });
  it('propagates handler failures and creates no successful receipt', async () => {
    const { calls, transaction } = recordingPort();
    const error = new Error('domain failure');
    await expect(createCommandExecutor(transaction)(context, command, async () => { throw error; })).rejects.toBe(error);
    expect(calls).toEqual(['authorize', 'lock', 'read']);
  });
  it('rejects answer-bearing fields rather than persisting them as replayable acknowledgements', async () => {
    const { calls, transaction } = recordingPort();
    await expect(createCommandExecutor(transaction)(context, command, async () => ({ ...data, answer: 'secret answer' }))).rejects.toMatchObject({ code: 'unsafe_command_acknowledgement' });
    expect(calls).not.toContain('save');
  });
  it('rejects inherited acknowledgement fields instead of treating them as saved IDs', async () => {
    const { calls, transaction } = recordingPort();
    const inherited = Object.assign(Object.create({ resourceId: data.resourceId }), { resourceVersion: 8 });
    await expect(createCommandExecutor(transaction)(context, command, async () => inherited)).rejects.toMatchObject({ code: 'unsafe_command_acknowledgement' });
    expect(calls).not.toContain('save');
  });
  it('maps non-JSON input to a sanitized invalid-command error before receipt lookup', async () => {
    const { calls, transaction } = recordingPort();
    await expect(createCommandExecutor(transaction)(context, { ...command, body: { value: undefined } }, async () => data)).rejects.toMatchObject({ code: 'invalid_command', status: 422 });
    expect(calls).toEqual(['authorize']);
  });
  it('supplies an immutable snapshot so handler input cannot change after hashing', async () => {
    const payload = structuredClone(command);
    const { transaction } = recordingPort();
    transaction.readReceipt = async () => { payload.body.text = 'changed while waiting'; return null; };
    await createCommandExecutor(transaction)(context, payload, async snapshot => {
      expect(snapshot.body.text).toBe('記憶の手がかり');
      expect(Object.isFrozen(snapshot)).toBe(true);
      expect(Object.isFrozen(snapshot.body)).toBe(true);
      return data;
    });
  });
  it('returns a retained conflict through the unit of work instead of throwing away its proposal', async () => {
    const { calls, transaction } = recordingPort();
    const conflictId = '50000000-0000-4000-8000-000000000001';
    const result = await createCommandExecutor(transaction)(context, command, async () => ({ kind: 'proposalRetained' as const, data, rejection: { code: 'version_conflict' as const, status: 412 as const, conflictId, currentVersion: 8 } }));
    expect(calls).toEqual(['authorize', 'lock', 'read', 'save']);
    expect(result.rejection).toEqual({ code: 'version_conflict', status: 412, conflictId, currentVersion: 8 });
    // Call only after the caller's UoW resolves/commits; no raw proposal or note in the problem.
    expect(committedCommandProblem(result, context.operationId)).toEqual({ type: 'urn:japanese-learning-studio:problem:version_conflict', title: 'Resource version changed.', status: 412, detail: 'Resource version changed.', code: 'version_conflict', requestId: context.operationId, conflictId, currentVersion: 8 });
  });
  it('replays a retained conflict without running stale domain checks again', async () => {
    const rejection = { code: 'execution_conflict' as const, status: 409 as const, conflictId: '50000000-0000-4000-8000-000000000001', currentVersion: 8 };
    const cached = { ...stored(), receipt: { ...stored().receipt, rejection } };
    const { calls, transaction } = recordingPort(cached);
    const result = await createCommandExecutor(transaction)(context, command, async () => { throw new Error('must not execute again'); });
    expect(result.rejection).toEqual(rejection);
    expect(calls).toEqual(['authorize', 'lock', 'read']);
  });
  it('fails if an adapter silently drops a committed rejection', async () => {
    const { transaction } = recordingPort();
    transaction.saveReceipt = async () => stored();
    await expect(createCommandExecutor(transaction)(context, command, async () => ({ kind: 'proposalRetained' as const, data, rejection: { code: 'version_conflict' as const, status: 412 as const, conflictId: '50000000-0000-4000-8000-000000000001', currentVersion: 8 } }))).rejects.toMatchObject({ code: 'receipt_integrity_error' });
  });
  it.each(['owner', 'epoch', 'operation', 'policy'])('fails closed for a mismatched stored %s', async kind => {
    let cached = structuredClone(stored());
    if (kind === 'owner') cached = { ...cached, ownerId: '10000000-0000-4000-8000-000000000002' };
    if (kind === 'epoch') cached = { ...cached, receipt: { ...cached.receipt, datasetEpoch: '20000000-0000-4000-8000-000000000002' } };
    if (kind === 'operation') cached = { ...cached, receipt: { ...cached.receipt, operationId: '30000000-0000-4000-8000-000000000002' } };
    if (kind === 'policy') (cached.fingerprint as { policy: string }).policy = 'unknown';
    const { calls, transaction } = recordingPort(cached);
    await expect(createCommandExecutor(transaction)(context, command, async () => data)).rejects.toMatchObject({ status: 503 });
    expect(calls).not.toContain('save');
  });
  it('validates an adapter save result before returning it', async () => {
    const { transaction } = recordingPort();
    transaction.saveReceipt = async () => ({ ...stored(), receipt: { ...stored().receipt, operationId: '30000000-0000-4000-8000-000000000002' } });
    await expect(createCommandExecutor(transaction)(context, command, async () => data)).rejects.toMatchObject({ code: 'receipt_integrity_error' });
  });
  it('does not return the mutable receipt object owned by the port', async () => {
    const cached = stored(); const { transaction } = recordingPort(cached);
    const result = await createCommandExecutor(transaction)(context, command, async () => data);
    expect(result).not.toBe(cached.receipt);
    Reflect.set(result.data, 'resourceVersion', 999); // Simulate a JavaScript caller ignoring readonly types.
    expect(cached.receipt.data.resourceVersion).toBe(8);
  });
  it('validates a command-specific required output field on replay, rather than casting a cached base receipt', async () => {
    const { transaction } = recordingPort(stored());
    const output = { kind: 'note.save', parse(value: unknown) {
      if (!value || typeof value !== 'object' || !('jobId' in value) || typeof value.jobId !== 'string') throw new Error('jobId required');
      return { ...data, jobId: value.jobId };
    } };
    const executeCommand = createCommandExecutor(transaction, output);
    await expect(executeCommand(context, command, async () => ({ ...data, jobId: '60000000-0000-4000-8000-000000000001' }))).rejects.toMatchObject({ code: 'receipt_integrity_error' });
  });
  it('binds a precise output validator to its command kind', async () => {
    const { calls, transaction } = recordingPort();
    const executeCommand = createCommandExecutor(transaction, { kind: 'other.command', parse: () => data });
    await expect(executeCommand(context, command, async () => data)).rejects.toMatchObject({ code: 'invalid_command' });
    expect(calls).toEqual(['authorize']);
  });
  it('does not allow an output validator to fabricate or transform receipt data', async () => {
    const { transaction } = recordingPort(stored());
    const executeCommand = createCommandExecutor(transaction, { kind: 'note.save', parse: () => ({ ...data, jobId: '60000000-0000-4000-8000-000000000001' }) });
    await expect(executeCommand(context, command, async () => ({ ...data, jobId: '60000000-0000-4000-8000-000000000001' }))).rejects.toMatchObject({ code: 'receipt_integrity_error' });
  });
  it('accepts a valid precise output contract for fresh and replayed acknowledgements', async () => {
    const jobId = 'abcdefab-cdef-4abc-8abc-abcdefabcdef';
    const output = { kind: 'note.save', parse(value: unknown) {
      if (!value || typeof value !== 'object' || !('jobId' in value) || typeof value.jobId !== 'string') throw new Error('jobId required');
      return { ...data, jobId: value.jobId };
    } };
    const fresh = recordingPort();
    const result = await createCommandExecutor(fresh.transaction, output)(context, command, async () => ({ ...data, jobId }));
    expect(result.data.jobId).toBe(jobId);
    const cached = { ...stored(), receipt: { ...stored().receipt, data: { ...data, jobId } } };
    const replay = await createCommandExecutor(recordingPort(cached).transaction, output)(context, command, async () => { throw new Error('replay'); });
    expect(replay.data.jobId).toBe(jobId);
  });
  it('does not let a codec return noncanonical UUID casing after validation', async () => {
    const jobId = 'abcdefab-cdef-4abc-8abc-abcdefabcdef';
    const cached = { ...stored(), receipt: { ...stored().receipt, data: { ...data, jobId } } };
    const executor = createCommandExecutor(recordingPort(cached).transaction, { kind: 'note.save', parse: () => ({ ...data, jobId: jobId.toUpperCase() }) });
    await expect(executor(context, command, async () => ({ ...data, jobId }))).rejects.toMatchObject({ code: 'receipt_integrity_error' });
  });
  it('detects an adapter mutating acknowledgement data during save', async () => {
    const { transaction } = recordingPort();
    transaction.saveReceipt = async (ctx, fingerprint, acknowledgement) => {
      Reflect.set(acknowledgement, 'resourceVersion', 999);
      return { ownerId: ctx.ownerId, fingerprint, receipt: { operationId: ctx.operationId, datasetEpoch: ctx.datasetEpoch, data: acknowledgement } };
    };
    await expect(createCommandExecutor(transaction)(context, command, async () => data)).rejects.toMatchObject({ code: 'receipt_integrity_error' });
  });
});
