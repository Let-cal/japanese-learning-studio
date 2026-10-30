import { z } from 'zod';
import { StoredVersionSchema, UuidSchema } from './learning.ts';

const NoteTextSchema = z.string().refine(value => {
  let count = 0;
  for (const point of value) { void point; if (++count > 2000) return false; }
  return true;
}, 'At most 2000 Unicode code points.').meta({ maxLength: 2000 });

export const MemoryNoteBodySchema = z.strictObject({ body: NoteTextSchema, anchoredItemRevisionId: UuidSchema });
export const MemoryNoteSchema = z.discriminatedUnion('state', [
  z.strictObject({ state: z.literal('absent'), itemId: UuidSchema, body: z.literal(''), anchoredItemRevisionId: z.null(), noteVersion: z.literal(0) }),
  z.strictObject({ state: z.literal('existing'), itemId: UuidSchema, body: NoteTextSchema, anchoredItemRevisionId: UuidSchema, noteVersion: StoredVersionSchema }),
]);
export const MemoryNoteReceiptSchema = z.strictObject({ itemId: UuidSchema, anchoredItemRevisionId: UuidSchema, noteVersion: StoredVersionSchema });
