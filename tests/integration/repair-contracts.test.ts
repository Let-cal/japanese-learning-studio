import { expect, it } from 'vitest';
import { RepairStartSchema, RepairEventInputSchema, RepairOriginSchema } from '../../src/contracts/repair';
import { ManualDraftReceiptSchema } from '../../src/contracts/manualDrafts';
const id = '11111111-1111-4111-8111-111111111111';
const origin = { kind: 'contentPractice', itemId: id, ability: 'meaning', itemRevisionId: id, sourceRevisionIds: [id], repairPolicyVersion: 1 };
it('separates client repair origin preconditions from trusted historical origin and execution versions', () => {
  expect(RepairStartSchema.safeParse({ origin }).success).toBe(true);
  expect(RepairStartSchema.safeParse({ origin: { ...origin, ownerId: id } }).success).toBe(false);
  expect(RepairStartSchema.safeParse({ origin, repairIfMatch: '"v1"' }).success).toBe(false);
  expect(RepairStartSchema.safeParse({ origin: { ...origin, kind: 'attempt' } }).success).toBe(false);
  expect(RepairOriginSchema.safeParse({ ...origin, ownerId: id, datasetEpoch: id }).success).toBe(true);
  expect(RepairEventInputSchema.safeParse({ repairId: id, expectedRepairVersion: 3, event: { kind: 'understood' } }).success).toBe(true);
  expect(RepairEventInputSchema.safeParse({ repairId: id, expectedSessionVersion: 3, event: { kind: 'understood' } }).success).toBe(false);
  for (const event of [{ kind: 'microcheckSubmitted', rawAnswer: '答え' }, { kind: 'deferred' }, { kind: 'cancelled' }, { kind: 'recheckProposed', requestedNotBefore: '2026-10-30T10:00:00Z' }, { kind: 'recheckAccepted', proposalId: id }]) {
    expect(RepairEventInputSchema.safeParse({ repairId: id, expectedRepairVersion: 3, event }).success).toBe(true);
  }
});
it('manual receipts retain actual row mapping without returning protected content', () => {
  const receipt = { batchId: id, lessonId: id, lessonVersion: 2, createdRows: [{ clientRowId: id, draftId: id }] };
  expect(ManualDraftReceiptSchema.safeParse(receipt).success).toBe(true);
  expect(ManualDraftReceiptSchema.safeParse({ ...receipt, rows: ['answer'] }).success).toBe(false);
  expect(ManualDraftReceiptSchema.safeParse({ ...receipt, createdRows: [...receipt.createdRows, ...receipt.createdRows] }).success).toBe(false);
});
