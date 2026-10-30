import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import SwaggerParser from '@apidevtools/swagger-parser';
import { serializeOpenApiDocument } from '../src/contracts/apiSchemas.ts';

/** Reject external references before invoking a parser; resolvers are also disabled. */
export async function validateApiDocument(document) {
  function inspect(value) {
    if (value === null || typeof value !== 'object') return;
    if (Object.hasOwn(value, '$ref') && (typeof value.$ref !== 'string' || !value.$ref.startsWith('#/'))) throw new Error('External reference denied.');
    for (const child of Object.values(value)) inspect(child);
  }
  inspect(document);
  return SwaggerParser.validate(structuredClone(document), { resolve: { external: false, file: false, http: false }, dereference: { circular: false } });
}
export function checkApiDocument(text) { return text === serializeOpenApiDocument(); }
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const text = await readFile(new URL('../docs/api/openapi.yaml', import.meta.url), 'utf8');
  await validateApiDocument(JSON.parse(text));
  if (!checkApiDocument(text)) throw new Error('OpenAPI artifact is stale. Run pnpm api:generate and review the diff.');
  console.log('Core OpenAPI syntax, internal references and generated freshness pass; operations remain planned.');
}
