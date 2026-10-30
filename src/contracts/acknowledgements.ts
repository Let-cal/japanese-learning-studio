import { z } from 'zod';
import { ManualDraftReceiptSchema } from './manualDrafts.ts';
import { RepairReceiptSchema } from './repair.ts';
import { RecheckReceiptSchema } from './rechecks.ts';
import { JobAcknowledgementSchema } from './jobs.ts';
import { SessionEventReceiptSchema } from './learning.ts';
import { MemoryNoteReceiptSchema } from './memoryNotes.ts';

/** Closed, lossless persisted vocabulary; no arbitrary body or answer-bearing fields. */
export const acknowledgementSchemas = {
  'manual-draft-batches.create': ManualDraftReceiptSchema,
  'guided-repairs.create': RepairReceiptSchema,
  'guided-repairs.events': RepairReceiptSchema,
  'targeted-rechecks.decide': RecheckReceiptSchema,
  'jobs.cancel': JobAcknowledgementSchema,
  'jobs.retry': JobAcknowledgementSchema,
  'sessions.events': SessionEventReceiptSchema,
  'memory-notes.save': MemoryNoteReceiptSchema,
} as const;
export type AcknowledgementKind = keyof typeof acknowledgementSchemas;
export type DomainAcknowledgement = z.infer<(typeof acknowledgementSchemas)[AcknowledgementKind]>;
export const commandKindByOperationId = {
  createManualDraftBatch: 'manual-draft-batches.create', startGuidedRepair: 'guided-repairs.create', executeRepairEvent: 'guided-repairs.events',
  acceptTargetedRecheck: 'targeted-rechecks.decide', cancelJob: 'jobs.cancel', retryJob: 'jobs.retry',
  executeSessionEvent: 'sessions.events', saveMemoryNote: 'memory-notes.save',
} as const;
export function isAcknowledgementKind(value: string): value is AcknowledgementKind { return Object.hasOwn(acknowledgementSchemas, value); }

// Only run after a closed acknowledgement schema has excluded free-form learner content.
function canonicalIds(input: unknown): unknown {
  if (typeof input === 'string') return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(input) ? input.toLowerCase() : input;
  if (Array.isArray(input)) return input.map(canonicalIds);
  if (input !== null && typeof input === 'object') return Object.fromEntries(Object.entries(input).map(([key, value]) => [key, canonicalIds(value)]));
  return input;
}
export function domainAcknowledgement(kind: AcknowledgementKind, input: unknown): DomainAcknowledgement {
  const schema = acknowledgementSchemas[kind];
  return schema.parse(canonicalIds(schema.parse(input)));
}
