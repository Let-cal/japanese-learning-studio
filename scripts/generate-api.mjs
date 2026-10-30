import { writeFile } from 'node:fs/promises';
import { serializeOpenApiDocument } from '../src/contracts/apiSchemas.ts';
await writeFile(new URL('../docs/api/openapi.yaml', import.meta.url), serializeOpenApiDocument(), 'utf8');
console.log('Generated planned core OpenAPI 3.1 slice.');
