import { expect, it } from 'vitest';
import { committedCommandProblem, createCommandExecutor } from '../../src/application/commands/executeCommand';
import type { CommandTransaction } from '../../src/contracts/commands';
import { ProblemSchema } from '../../src/contracts/problems';
import { ManualDraftReceiptSchema } from '../../src/contracts/manualDrafts';
import { RepairReceiptSchema } from '../../src/contracts/repair';
import { RecheckReceiptSchema } from '../../src/contracts/rechecks';
import { JobAcknowledgementSchema } from '../../src/contracts/jobs';
import { SessionEventReceiptSchema } from '../../src/contracts/learning';
import { MemoryNoteReceiptSchema } from '../../src/contracts/memoryNotes';
import { acknowledgementSchemas, isAcknowledgementKind } from '../../src/contracts/acknowledgements';
import { buildOpenApiDocument } from '../../src/contracts/apiSchemas';
import { z } from 'zod';

const id = '10000000-0000-4000-8000-000000000001';
const other = '20000000-0000-4000-8000-000000000001';
const context = { ownerId: id, datasetEpoch: other, operationId: '30000000-0000-4000-8000-000000000001' };
it.each([{ code: 'version_conflict', status: 412 }, { code: 'execution_conflict', status: 409 }] as const)('emits a schema-valid committed $code problem', rejection => {
  const problem = committedCommandProblem({ operationId: context.operationId, datasetEpoch: other, data: { resourceId: id, resourceVersion: 2 }, rejection: { ...rejection, conflictId: id, currentVersion: 2 } }, context.operationId);
  expect(ProblemSchema.safeParse(problem).success).toBe(true);
  expect(problem).not.toHaveProperty('data');
});

const examples = [
  { kind: 'manual-draft-batches.create', schema: ManualDraftReceiptSchema, data: { batchId: id, lessonId: other, lessonVersion: 2, createdRows: [{ clientRowId: id, draftId: other }] } },
  { kind: 'guided-repairs.create', schema: RepairReceiptSchema, data: { repairId: id, repairVersion: 1 } },
  { kind: 'guided-repairs.events', schema: RepairReceiptSchema, data: { repairId: id, repairVersion: 2, eventId: other } },
  { kind: 'targeted-rechecks.decide', schema: RecheckReceiptSchema, data: { intentId: id, intentVersion: 2, status: 'accepted' } },
  { kind: 'jobs.cancel', schema: JobAcknowledgementSchema, data: { jobId: id, jobVersion: 3, state: 'cancelled' } },
  { kind: 'jobs.retry', schema: JobAcknowledgementSchema, data: { jobId: id, jobVersion: 4, state: 'queued' } },
  { kind: 'sessions.events', schema: SessionEventReceiptSchema, data: { sessionId: id, eventId: other, executionVersion: 4 } },
  { kind: 'memory-notes.save', schema: MemoryNoteReceiptSchema, data: { itemId: id, anchoredItemRevisionId: other, noteVersion: 1 } },
];
it.each(examples)('losslessly round-trips the advertised $kind receipt on fresh command and replay', async ({ kind, schema, data }) => {
  // A recording boundary only; this does not prove Postgres durability or concurrency.
  let captured: Awaited<ReturnType<CommandTransaction['readReceipt']>> = null;
  const transaction: CommandTransaction = {
    authorizeCurrentDataset: async () => {}, lockOperation: async () => {}, readReceipt: async () => captured,
    saveReceipt: async (ctx, fingerprint, acknowledgement, rejection) => {
      captured = { ownerId: ctx.ownerId, fingerprint, receipt: { operationId: ctx.operationId, datasetEpoch: ctx.datasetEpoch, data: acknowledgement, ...(rejection ? { rejection } : {}) } };
      return captured;
    },
  };
  const executeCommand = createCommandExecutor(transaction, { kind, parse: value => schema.parse(value) });
  const command = { kind, targetId: id, body: {} };
  const first = await executeCommand(context, command, async () => schema.parse(data));
  const replay = await executeCommand(context, command, async () => { throw new Error('must not execute on replay'); });
  expect(first.data).toEqual(data);
  expect(replay).toEqual(first);
  expect(schema.safeParse(replay.data).success).toBe(true);
});
it('binds every planned mutation to the same persisted schema as its documented response data', () => {
  const api = buildOpenApiDocument();
  for (const methods of Object.values(api.paths)) {
    for (const [method, operation] of Object.entries(methods)) {
      if (method === 'get') continue;
      const kind = operation['x-commandKind'];
      if (!kind || !isAcknowledgementKind(kind)) throw new Error('Mutation lacks a registered receipt contract.');
      const success = Object.entries(operation.responses).find(([status]) => Number(status) < 300)?.[1];
      if (!success) throw new Error('Missing successful response.');
      const name = success.content['application/json'].schema.$ref.replace('#/components/schemas/', '');
      const properties = api.components.schemas[name].properties as Record<string, unknown>;
      const { $schema, ...persistedSchema } = z.toJSONSchema(acknowledgementSchemas[kind], { target: 'draft-2020-12' });
      void $schema;
      expect(properties.data).toEqual(persistedSchema);
    }
  }
});
