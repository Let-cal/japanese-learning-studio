import { defineConfig, globalIgnores } from 'eslint/config';
// TS 7 currently exceeds typescript-eslint's documented <6.1 peer range.
// ESLint covers JavaScript config and local API scripts; TypeScript is checked separately.
export default defineConfig([
  { files: ['**/*.mjs'], rules: { 'no-unused-vars': 'error', 'no-undef': 'error' } },
  { files: ['scripts/*.mjs'], languageOptions: { globals: { console: 'readonly', process: 'readonly', structuredClone: 'readonly', URL: 'readonly' } } },
  globalIgnores(['.next/**', 'tools/**', 'node_modules/**', 'playwright-report/**', 'test-results/**']),
]);
