#!/usr/bin/env node
/**
 * Write the JSON Schema to `schema/`, so the URL used as its own `$id` resolves.
 *
 * Checked in rather than generated on demand because editors point at the raw URL,
 * and a link in someone's settings should not depend on a release having run.
 */
import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { modelJsonSchema } from '../packages/core/dist/index.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const target = join(ROOT, 'schema/tmac-1.0.schema.json');
const next = `${JSON.stringify(modelJsonSchema(), null, 2)}\n`;
const current = existsSync(target) ? readFileSync(target, 'utf8') : '';

if (current === next) {
  console.log('schema/tmac-1.0.schema.json is current');
} else {
  writeFileSync(target, next, 'utf8');
  console.log('wrote schema/tmac-1.0.schema.json');
  if (process.argv.includes('--check')) {
    console.error('\nThe committed schema was stale. Run `npm run schema` and commit it.');
    process.exit(1);
  }
}
