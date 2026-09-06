import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

const r = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  plugins: [react()],
  // Relative, so a built bundle works from a file:// path or any subdirectory.
  base: './',
  resolve: {
    alias: {
      // The editor runs the real core and engine, not a second implementation.
      // These are the filesystem-free entries; ADR 0006 explains why they exist and
      // a test asserts no `node:` import is reachable from them.
      'tmac-core/browser': r('../../packages/core/src/browser.ts'),
      'tmac-rules/browser': r('../../packages/rules/src/browser.ts'),
      'tmac-render/svg-text': r('../../packages/render/src/svg-text.ts'),
      'tmac-render/browser': r('../../packages/render/src/browser.ts'),
      'tmac-report/browser': r('../../packages/report/src/browser.ts'),
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    // The Graphviz WASM payload is large and inlining it would be worse.
    assetsInlineLimit: 4096,
  },
  server: { port: 7300, strictPort: false },
});
