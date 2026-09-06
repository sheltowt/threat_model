/**
 * Everything in `tmac-core` that does not touch the filesystem.
 *
 * The browser editor imports this, so it runs the same schema, the same graph
 * construction and the same cross-reference checks as the CLI. Anything that reads a
 * file (`loadModel`, `loadCatalog`) lives only in the default entry point, and
 * `test/browser.test.ts` asserts that none of it is reachable from here.
 */
export * from './enums.js';
export * from './schema.js';
export * from './catalog-core.js';
export * from './diagnostics.js';
export * from './parse.js';
export * from './graph.js';
export * from './ids.js';
export * from './diff.js';
export * from './jsonschema.js';
export { BUILTIN_CATALOG_DATA } from './generated/catalog-data.js';
