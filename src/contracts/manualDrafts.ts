import { z } from 'zod';
import { StoredVersionSchema, UuidSchema, VersionSchema } from './learning.ts';
const nonblank = z.string().regex(/\S/u, 'Expected nonblank text.');
export const ManualDraftRowSchema = z.strictObject({ clientRowId: UuidSchema, writtenForm: nonblank, kana: nonblank, vietnameseSense: nonblank, context: z.string().optional() });
const rows = z.array(ManualDraftRowSchema).min(1).max(10).refine(values => new Set(values.map(row => row.clientRowId.toLowerCase())).size === values.length, 'Duplicate client row ID.').meta({ 'x-runtimeValidation': 'clientRowId must be unique ignoring UUID letter case; checked by runtime schema and existing manual parser.' });
/** HTTP body excludes lessonBaseVersion; If-Match maps to the existing confirmed domain input. */
export const ManualDraftBatchBodySchema = z.strictObject({ source: z.literal('manualEntry'), lessonId: UuidSchema, rows });
export const ConfirmedManualDraftBatchSchema = ManualDraftBatchBodySchema.extend({ lessonBaseVersion: VersionSchema });
export const ManualDraftReceiptSchema = z.strictObject({ batchId: UuidSchema, lessonId: UuidSchema, lessonVersion: StoredVersionSchema, createdRows: z.array(z.strictObject({ clientRowId: UuidSchema, draftId: UuidSchema })).min(1).max(10).refine(values => new Set(values.map(row => row.clientRowId.toLowerCase())).size === values.length && new Set(values.map(row => row.draftId.toLowerCase())).size === values.length, 'Receipt row and draft IDs must each be unique.').meta({ 'x-runtimeValidation': 'clientRowId and draftId are each unique ignoring UUID letter case; mapping must equal the committed confirmed rows.' }) });
export type ManualDraftReceipt = z.infer<typeof ManualDraftReceiptSchema>;
