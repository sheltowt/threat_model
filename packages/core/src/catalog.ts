import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import {
  builtinCatalog,
  createCatalog,
  mergeCatalogData,
  type Catalog,
  type RawCatalogData,
} from './catalog-core.js';
import { BUILTIN_CATALOG_DATA } from './generated/catalog-data.js';

export * from './catalog-core.js';

/**
 * The built-in catalogue plus any `technologies.yaml` / `protocols.yaml` found in
 * the given project directories, later directories winning.
 *
 * This is the only part of the catalogue that needs a filesystem, which is why it
 * lives here and not in `catalog-core.ts`.
 */
export function loadCatalog(projectDirs: readonly string[] = []): Catalog {
  if (projectDirs.length === 0) return builtinCatalog();

  const catalog = createCatalog([
    { data: BUILTIN_CATALOG_DATA, where: 'the built-in catalogue', requireSections: true },
  ]);

  for (const dir of projectDirs) {
    for (const name of ['technologies.yaml', 'protocols.yaml']) {
      const file = resolve(dir, name);
      if (!existsSync(file)) continue;
      const raw = parseYaml(readFileSync(file, 'utf8')) as RawCatalogData | null;
      if (raw) mergeCatalogData(catalog, raw, file);
    }
  }
  return catalog;
}
