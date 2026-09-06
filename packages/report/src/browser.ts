/**
 * Reporting has no filesystem dependency: every reporter takes the analysis and
 * returns a string, so the same code renders a report in CI and in the editor.
 */
export * from './common.js';
export * from './json.js';
export * from './sarif.js';
export * from './markdown.js';
export * from './html.js';
