import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

const r = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      'tmac-core/browser': r('./packages/core/src/browser.ts'),
      'tmac-core': r('./packages/core/src/index.ts'),
      'tmac-rules/browser': r('./packages/rules/src/browser.ts'),
      'tmac-rules': r('./packages/rules/src/index.ts'),
      'tmac-render/svg-text': r('./packages/render/src/svg-text.ts'),
      'tmac-render/browser': r('./packages/render/src/browser.ts'),
      'tmac-render': r('./packages/render/src/index.ts'),
      'tmac-report/browser': r('./packages/report/src/browser.ts'),
      'tmac-report': r('./packages/report/src/index.ts'),
      'tmac-importers': r('./packages/importers/src/index.ts'),
    },
  },
  test: {
    include: [
      'packages/**/test/**/*.test.ts',
      'apps/**/test/**/*.test.ts',
      'apps/**/test/**/*.test.tsx',
    ],
    coverage: {
      provider: 'v8',
      include: ['packages/*/src/**/*.ts'],
      exclude: ['**/index.ts'],
      thresholds: { lines: 80, functions: 80, branches: 75, statements: 80 },
    },
  },
});
