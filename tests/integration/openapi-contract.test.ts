import { readFile } from 'node:fs/promises';
import { expect, it } from 'vitest';
import { buildOpenApiDocument, MemoryNoteBodySchema, MemoryNoteSchema, problemStatus } from '../../src/contracts/apiSchemas';
import { validateApiDocument, checkApiDocument } from '../../scripts/check-api.mjs';
import { parseMemoryNoteWrite } from '../../src/contracts/notes';
import { ProblemSchema } from '../../src/contracts/problems';
import { ManualDraftBatchBodySchema } from '../../src/contracts/manualDrafts';
it('validates the generated core slice and checks freshness without modifying the artifact', async () => {
  const text = await readFile(new URL('../../docs/api/openapi.yaml', import.meta.url), 'utf8');
  await expect(validateApiDocument(JSON.parse(text))).resolves.toBeDefined();
  expect(checkApiDocument(text)).toBe(true);
  expect(checkApiDocument(text.replace('M1 core API contract slice', 'stale'))).toBe(false);
  const document = buildOpenApiDocument();
  for (const [path, item] of Object.entries(document.paths)) {
    expect(path.startsWith('/api/v1/')).toBe(true);
    for (const [method, operation] of Object.entries(item)) {
      expect(operation['x-implementationStatus']).toBe('planned');
      expect(operation.security).toEqual([{ OwnerSession: [] }]);
      expect(operation.parameters.some(p => p.$ref === '#/components/parameters/DatasetEpoch')).toBe(true);
      if (method !== 'get') {
        for (const name of ['IdempotencyKey', 'Origin', 'CsrfToken']) expect(operation.parameters.some(p => p.$ref === `#/components/parameters/${name}`)).toBe(true);
        expect(operation.requestBody?.content['application/json'].schema.$ref).toMatch(/^#\/components\/schemas\//);
      }
      for (const [status, response] of Object.entries(operation.responses)) {
        if (status === '201' || status === '202') expect(response.headers?.Location).toBeDefined();
        if (Number(status) >= 400) expect(response.content?.['application/problem+json']).toBeDefined();
      }
    }
  }
  const create = document.paths['/api/v1/guided-repairs'].post;
  expect(create.parameters.some(p => p.$ref === '#/components/parameters/IfMatch')).toBe(false);
  expect(document.paths['/api/v1/guided-repairs/{id}/events'].post.parameters.some(p => p.$ref === '#/components/parameters/IfMatch')).toBe(true);
});
it('rejects broken internal references and refuses HTTP/file refs before any resolver can fetch', async () => {
  for (const ref of ['#/components/schemas/Missing', 'https://127.0.0.1:1/secret', 'file:///secret']) {
    const broken = buildOpenApiDocument();
    broken.components.schemas.Broken = { $ref: ref };
    await expect(validateApiDocument(broken)).rejects.toThrow(ref.startsWith('#') ? /Missing|pointer|reference/i : /external reference/i);
  }
});
it('retains note code-point bounds and absent version zero consistently', () => {
  const id = '11111111-1111-4111-8111-111111111111';
  for (const [body, accepted] of [['𠮷'.repeat(2000), true], ['𠮷'.repeat(2001), false]] as const) {
    expect(MemoryNoteBodySchema.safeParse({ body, anchoredItemRevisionId: id }).success).toBe(accepted);
    expect(parseMemoryNoteWrite({ itemId: id, body, anchoredItemRevisionId: id, expectedNoteVersion: 0 }).ok).toBe(accepted);
  }
  expect(MemoryNoteSchema.safeParse({ state: 'absent', itemId: id, body: '', anchoredItemRevisionId: null, noteVersion: 0 }).success).toBe(true);
  expect(MemoryNoteSchema.safeParse({ state: 'existing', itemId: id, body: '', anchoredItemRevisionId: id, noteVersion: 0 }).success).toBe(false);
  expect(problemStatus.version_conflict).toBe(412);
  expect(problemStatus.repair_origin_affected).toBe(409);
});
it('rejects leaked problem details, wrong status codes and invalid confirmed rows', () => {
  const id = '11111111-1111-4111-8111-111111111111';
  const problem = { type: 'urn:japanese-learning-studio:problem:version_conflict', title: 'Resource version changed.', detail: 'Resource version changed.', code: 'version_conflict', status: 412, requestId: id };
  expect(ProblemSchema.safeParse(problem).success).toBe(true);
  expect(ProblemSchema.safeParse({ ...problem, status: 409 }).success).toBe(false);
  expect(ProblemSchema.safeParse({ ...problem, detail: 'provider token: secret' }).success).toBe(false);
  const body = { source: 'manualEntry', lessonId: id, rows: [{ clientRowId: id, writtenForm: '今日', kana: 'きょう', vietnameseSense: 'hôm nay' }] };
  expect(ManualDraftBatchBodySchema.safeParse(body).success).toBe(true);
  expect(ManualDraftBatchBodySchema.safeParse({ ...body, rows: [...body.rows, ...body.rows] }).success).toBe(false);
  expect(ManualDraftBatchBodySchema.safeParse({ ...body, rows: [{ ...body.rows[0], kana: '  ' }] }).success).toBe(false);
});
