/**
 * Diagram generation with no filesystem. Graphviz here is WASM, so rendering works
 * unchanged in a browser; only writing the result to a file needs Node.
 */
export * from './dot.js';
export * from './svg-text.js';
export * from './svg.js';
