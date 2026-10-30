import { describe, expect, it } from 'vitest';
import { canonicalCommandJson, hashCommandInput } from '../../src/application/commands/commandFingerprint';

const context = { ownerId: '10000000-0000-4000-8000-000000000001', datasetEpoch: '20000000-0000-4000-8000-000000000001', operationId: '30000000-0000-4000-8000-000000000001', expectedVersion: 7 };
const command = { kind: 'note.save', targetId: '40000000-0000-4000-8000-000000000001', body: { kana: 'じゅんび', meaning: 'sự chuẩn bị' } };

describe('server-derived command fingerprints', () => {
  it('is independent of object insertion order, but preserves array order', () => {
    expect(canonicalCommandJson({ b: 2, a: [1, '日本語'] })).toBe('{"a":[1,"日本語"],"b":2}');
    expect(hashCommandInput(context, command)).toEqual(hashCommandInput(context, { ...command, body: { meaning: 'sự chuẩn bị', kana: 'じゅんび' } }));
    expect(canonicalCommandJson([1, 2])).not.toBe(canonicalCommandJson([2, 1]));
  });
  it('uses a versioned SHA256 fingerprint without storing the payload', () => {
    expect(hashCommandInput(context, command)).toEqual({ policy: 'jls-command-json-v1', hash: expect.stringMatching(/^[a-f0-9]{64}$/) });
  });
  it('excludes operation identity while binding owner, dataset, target, kind and original precondition', () => {
    const original = hashCommandInput(context, command);
    expect(hashCommandInput({ ...context, operationId: '30000000-0000-4000-8000-000000000002' }, command)).toEqual(original);
    for (const change of [ { ownerId: '10000000-0000-4000-8000-000000000002' }, { datasetEpoch: '20000000-0000-4000-8000-000000000002' }, { expectedVersion: 8 } ]) {
      expect(hashCommandInput({ ...context, ...change }, command)).not.toEqual(original);
    }
    expect(hashCommandInput(context, { ...command, kind: 'note.clear' })).not.toEqual(original);
    expect(hashCommandInput(context, { ...command, targetId: '40000000-0000-4000-8000-000000000002' })).not.toEqual(original);
  });
  it('does not normalize kana, whitespace or canonically equivalent Unicode', () => {
    const first = hashCommandInput(context, command);
    for (const kana of ['ぢゅんび', 'じゆんび', ' じゅんび ', 'し\u3099ゅんび']) {
      expect(hashCommandInput(context, { ...command, body: { ...command.body, kana } })).not.toEqual(first);
    }
  });
  it('canonicalizes UUID identity metadata without rewriting body text', () => {
    const id = 'abcdefab-cdef-4abc-8abc-abcdefabcdef';
    const lower = { ...context, ownerId: id, datasetEpoch: id };
    const lowerCommand = { ...command, targetId: id };
    expect(hashCommandInput({ ...lower, ownerId: id.toUpperCase(), datasetEpoch: id.toUpperCase() }, { ...lowerCommand, targetId: id.toUpperCase() })).toEqual(hashCommandInput(lower, lowerCommand));
    expect(hashCommandInput(lower, { ...lowerCommand, body: { note: id } })).not.toEqual(hashCommandInput(lower, { ...lowerCommand, body: { note: id.toUpperCase() } }));
  });
  it.each([undefined, NaN, Infinity, 1n, new Date(), new Map(), () => 1, Symbol('x')])('rejects non-JSON values without coercion: %s', value => {
    expect(() => canonicalCommandJson({ value })).toThrow();
  });
  it('rejects cycles, sparse arrays, hidden fields and getters without executing them', () => {
    const cyclic: Record<string, unknown> = {}; cyclic.self = cyclic;
    expect(() => canonicalCommandJson(cyclic)).toThrow();
    expect(() => canonicalCommandJson(new Array(1))).toThrow();
    const getter = Object.defineProperty({}, 'secret', { enumerable: true, get() { throw new Error('getter executed'); } });
    expect(() => canonicalCommandJson(getter)).toThrow(/data properties/);
    expect(() => canonicalCommandJson(Object.defineProperty({}, 'hidden', { value: 1 }))).toThrow();
    expect(() => canonicalCommandJson({ [Symbol('hidden')]: 1 })).toThrow();
  });
  it('bounds canonicalization and rejects extra command fields or caller-provided hashes', () => {
    let deep: unknown = null; for (let i = 0; i < 34; i++) deep = [deep];
    expect(() => canonicalCommandJson(deep)).toThrow(/limit/);
    expect(() => canonicalCommandJson('x'.repeat(1024 * 1024 + 1))).toThrow(/limit/);
    expect(() => hashCommandInput(context, { ...command, hash: 'caller supplied' })).toThrow();
  });
});
