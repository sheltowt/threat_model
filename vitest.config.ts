import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

const r = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@tmc/core/browser': r('./packages/core/src/browser.ts'),
      '@tmc/core': r('./packages/core/src/index.ts'),
      '@tmc/rules/browser': r('./packages/rules/src/browser.ts'),
      '@tmc/rules': r('./packages/rules/src/index.ts'),
      '@tmc/render': r('./packages/render/src/index.ts'),
      '@tmc/report': r('./packages/report/src/index.ts'),
      '@tmc/importers': r('./packages/importers/src/index.ts'),
    },
  },
  test: {
    include: ['packages/**/test/**/*.test.ts', 'apps/**/test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['packages/*/src/**/*.ts'],
      exclude: ['**/index.ts'],
      thresholds: { lines: 80, functions: 80, branches: 75, statements: 80 },
    },
  },
});
