import { createHash } from 'node:crypto';
import { parseCommandContext, parseUuid } from '../../contracts/common';
import { CommandExecutionError } from '../../contracts/commands';
import type { CommandContext } from '../../contracts/common';
import type { CommandFingerprint, CommandInput } from '../../contracts/commands';

export const COMMAND_HASH_POLICY = 'jls-command-json-v1' as const;
const MAX_BYTES = 1024 * 1024;
const MAX_DEPTH = 32;
const MAX_NODES = 10_000;

function invalid(message: string): never { throw new TypeError(message); }

/** Versioned application JSON encoding, not a claim to implement RFC 8785/JCS. */
export function canonicalCommandJson(input: unknown): string {
  const ancestors = new Set<object>();
  const chunks: string[] = [];
  let bytes = 0;
  let nodes = 0;
  function emit(text: string) {
    bytes += Buffer.byteLength(text, 'utf8');
    if (bytes > MAX_BYTES) invalid('Command JSON byte limit exceeded.');
    chunks.push(text);
  }
  function quoted(text: string) {
    if (Buffer.byteLength(text, 'utf8') > MAX_BYTES) invalid('Command JSON byte limit exceeded.');
    emit(JSON.stringify(text));
  }
  function visit(value: unknown, depth: number): void {
    if (++nodes > MAX_NODES || depth > MAX_DEPTH) invalid('Command JSON structure limit exceeded.');
    if (value === null) { emit('null'); return; }
    if (typeof value === 'string') { quoted(value); return; }
    if (typeof value === 'boolean') { emit(value ? 'true' : 'false'); return; }
    if (typeof value === 'number' && Number.isFinite(value)) { emit(JSON.stringify(value)); return; }
    if (typeof value !== 'object') invalid('Command requires JSON data values.');
    const array = Array.isArray(value);
    const prototype = Object.getPrototypeOf(value);
    if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) invalid('Command requires plain JSON containers.');
    if (ancestors.has(value)) invalid('Command JSON cycle rejected.');
    ancestors.add(value);
    try {
      if (array && value.length > MAX_NODES) invalid('Command JSON structure limit exceeded.');
      const keys = Reflect.ownKeys(value);
      if (keys.length > MAX_NODES + 1) invalid('Command JSON structure limit exceeded.');
      const descriptors = Object.getOwnPropertyDescriptors(value);
      for (const key of keys) {
        if (array && key === 'length') continue;
        if (typeof key !== 'string') invalid('Command requires string data properties.');
        const descriptor = descriptors[key];
        if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) invalid('Command requires enumerable data properties.');
      }
      if (array) {
        if (keys.length !== value.length + 1) invalid('Command requires dense JSON arrays without extra fields.');
        emit('[');
        for (let i = 0; i < value.length; i++) {
          const descriptor = descriptors[String(i)];
          if (!descriptor || !Object.hasOwn(descriptor, 'value')) invalid('Command requires dense JSON arrays.');
          if (i) emit(',');
          visit(descriptor.value, depth + 1);
        }
        emit(']');
      } else {
        emit('{');
        const names = (keys as string[]).sort();
        names.forEach((key, index) => {
          if (index) emit(',');
          quoted(key); emit(':'); visit(descriptors[key].value, depth + 1);
        });
        emit('}');
      }
    } finally { ancestors.delete(value); }
  }
  visit(input, 0);
  return chunks.join('');
}

export function canonicalCommandContext(context: CommandContext): CommandContext {
  const parsed = parseCommandContext(context);
  if (!parsed.ok) throw new CommandExecutionError('invalid_command', 422);
  return Object.freeze({ ...parsed.value, ownerId: parsed.value.ownerId.toLowerCase(), datasetEpoch: parsed.value.datasetEpoch.toLowerCase(), operationId: parsed.value.operationId.toLowerCase() });
}

function freezeJson<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freezeJson(child);
    Object.freeze(value);
  }
  return value;
}

export function prepareCommandInput(context: CommandContext, input: unknown): { command: CommandInput; fingerprint: CommandFingerprint } {
  const current = canonicalCommandContext(context);
  let command: CommandInput;
  let encoded: string;
  try {
    // Copy from validated JSON before the next await; never read accessor-backed input fields.
    const copy: unknown = JSON.parse(canonicalCommandJson(input));
    if (copy === null || typeof copy !== 'object' || Array.isArray(copy)) throw new TypeError('Expected a command object.');
    const record = copy as Record<string, unknown>;
    const keys = Object.keys(record);
    if (keys.length !== 3 || !keys.every(key => ['kind', 'targetId', 'body'].includes(key)) ||
        typeof record.kind !== 'string' || !/^[a-z][a-z0-9_.-]{0,95}$/.test(record.kind) ||
        !parseUuid(record.targetId).ok || record.body === null || typeof record.body !== 'object' || Array.isArray(record.body)) {
      throw new TypeError('Invalid command envelope.');
    }
    command = freezeJson({ kind: record.kind, targetId: (record.targetId as string).toLowerCase(), body: record.body as Record<string, unknown> });
    encoded = canonicalCommandJson({
      policy: COMMAND_HASH_POLICY, ownerId: current.ownerId, datasetEpoch: current.datasetEpoch,
      expectedVersion: current.expectedVersion ?? null, kind: command.kind, targetId: command.targetId, body: command.body,
    });
  } catch (cause) {
    throw new CommandExecutionError('invalid_command', 422, { cause });
  }
  return { command, fingerprint: { policy: COMMAND_HASH_POLICY, hash: createHash('sha256').update(encoded, 'utf8').digest('hex') } };
}

export function hashCommandInput(context: CommandContext, input: unknown): CommandFingerprint {
  return prepareCommandInput(context, input).fingerprint;
}
