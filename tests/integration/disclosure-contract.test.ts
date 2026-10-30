import { expect, it } from 'vitest';
import { DisclosureRequestSchema, DisclosureDecisionSchema } from '../../src/contracts/disclosure';
import { RecheckDecisionSchema, TargetedRecheckProjectionInputSchema } from '../../src/contracts/rechecks';
const id = '11111111-1111-4111-8111-111111111111';
it('disclosure requests cannot claim trusted assistance or completeness of unfinished Test associations', () => {
  const request = { target: { kind: 'memoryNote', itemId: id }, presentation: 'direct' };
  expect(DisclosureRequestSchema.safeParse(request).success).toBe(true);
  expect(DisclosureRequestSchema.safeParse({ ...request, assisted: true }).success).toBe(false);
  expect(DisclosureRequestSchema.safeParse({ ...request, unfinishedSessionIds: [] }).success).toBe(false);
  expect(DisclosureDecisionSchema.safeParse({ decision: 'blocked', code: 'test_reference_locked', action: 'finishTest' }).success).toBe(true);
  expect(DisclosureDecisionSchema.safeParse({ decision: 'blocked', code: 'test_reference_locked', action: 'finishTest', answer: 'key' }).success).toBe(false);
});
it('recheck requests preserve origin references while internal projection retains separate ordinary due', () => {
  const decision = { decision: 'accept', originRef: { kind: 'repair', repairId: id }, itemId: id, ability: 'kana', itemRevisionId: id, sourceRevisionIds: [id], requestedNotBefore: '2026-10-30T10:00:00Z', policyVersion: 1 };
  expect(RecheckDecisionSchema.safeParse(decision).success).toBe(true);
  expect(RecheckDecisionSchema.safeParse({ ...decision, ownerId: id }).success).toBe(false);
  expect(RecheckDecisionSchema.safeParse({ ...decision, requestedNotBefore: 'tomorrow' }).success).toBe(false);
  expect(TargetedRecheckProjectionInputSchema.safeParse({ ownerId: id, datasetEpoch: id, intents: [], ordinaryDue: [{ itemId: id, ability: 'kana', dueAt: '2026-11-01T10:00:00Z' }] }).success).toBe(true);
});
