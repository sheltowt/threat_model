#!/usr/bin/env node
/**
 * Copy the built editor into the CLI package, so `tmac serve` works from an
 * install and not only from a checkout.
 *
 * `serve.ts` looks for `<cli>/web/index.html` first, which is what this produces.
 * Run as the CLI's `prepack`, so publishing cannot forget it.
 */
import { cpSync, existsSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const from = join(ROOT, 'apps/web/dist');
const to = join(ROOT, 'apps/cli/web');

if (!existsSync(join(from, 'index.html'))) {
  console.error(
    'tmac: the editor is not built, so `tmac serve` would not work in this package.\n' +
      '      Run `npm run build` before packing.',
  );
  process.exit(1);
}

rmSync(to, { recursive: true, force: true });
cpSync(from, to, { recursive: true });
console.log(`bundled the editor into ${to.replace(ROOT + '/', '')}`);
