import type { EnrichedExtra } from '../../src/index.ts';

/**
 * Create a test EnrichedExtra object for unit tests
 * @param overrides - Optional overrides for specific fields
 * @returns EnrichedExtra object with test defaults
 */
export function createTestExtra(overrides?: Partial<EnrichedExtra>): EnrichedExtra {
  return {
    requestInfo: {
      headers: {},
      url: 'http://test.local',
      method: 'POST',
      ...overrides?.requestInfo,
    },
    _meta: overrides?._meta || {},
    ...overrides,
  } as EnrichedExtra;
}

/**
 * Silent test logger that doesn't output to console
 */
export const logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};
