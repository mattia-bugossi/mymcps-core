// purpose: Umbrella barrel for the top-level 'mymcps-core' import. Most
// consumers should import from the narrower subpath exports
// ('mymcps-core/auth', 'mymcps-core/cache', …) declared in package.json so
// bundlers can tree-shake; this barrel exists for code that needs several
// areas at once and for ergonomic one-line imports in tests/scripts.

export * as auth from './auth/index.js';
export * as aws from './aws/index.js';
export * as cache from './cache/index.js';
export * as errors from './errors/index.js';
export * as tools from './tools/index.js';
export * as transport from './transport/index.js';
