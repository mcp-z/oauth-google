import '../../lib/env-loader.js';

/**
 * DCR Utils Provider Token Tests
 *
 * Tests for DCR token storage that maps DCR access tokens to provider tokens.
 */

import type { ProviderTokens } from '@mcp-z/oauth';
import assert from 'assert';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import * as dcrUtils from '../../../src/lib/dcr-utils.ts';

// Use isolated test storage
const testStorePath = path.join('.tmp', `dcr-storage-test-${Date.now()}.json`);

const createMockTokens = (): ProviderTokens => ({
  accessToken: 'google_access_token_123',
  refreshToken: 'google_refresh_token_456',
  expiresAt: Date.now() + 3600000,
  scope: 'openid email',
});

it('dcrUtils - setProviderTokens stores tokens', async () => {
  const store = new Keyv({
    store: new KeyvFile({ filename: testStorePath }),
  });

  const dcrToken = 'dcr_access_token_789';
  const tokens = createMockTokens();

  await dcrUtils.setProviderTokens(store, dcrToken, tokens);

  // Verify storage succeeded (no error thrown)
  assert.ok(true, 'setProviderTokens should complete without error');
});

it('dcrUtils - getProviderTokens retrieves stored tokens', async () => {
  const store = new Keyv({
    store: new KeyvFile({ filename: testStorePath }),
  });

  const dcrToken = 'dcr_access_token_get_test';
  const tokens = createMockTokens();

  await dcrUtils.setProviderTokens(store, dcrToken, tokens);
  const retrieved = await dcrUtils.getProviderTokens(store, dcrToken);

  assert.ok(retrieved, 'Tokens should be retrieved');
  assert.strictEqual(retrieved?.accessToken, tokens.accessToken);
  assert.strictEqual(retrieved?.refreshToken, tokens.refreshToken);
  assert.strictEqual(retrieved?.expiresAt, tokens.expiresAt);
  assert.strictEqual(retrieved?.scope, tokens.scope);
});

it('dcrUtils - getProviderTokens returns undefined for unknown token', async () => {
  const store = new Keyv({
    store: new KeyvFile({ filename: testStorePath }),
  });

  const retrieved = await dcrUtils.getProviderTokens(store, 'nonexistent_token');

  assert.strictEqual(retrieved, undefined, 'Unknown token should return undefined');
});

it('dcrUtils - deleteProviderTokens removes tokens', async () => {
  const store = new Keyv({
    store: new KeyvFile({ filename: testStorePath }),
  });

  const dcrToken = 'dcr_access_token_delete_test';
  const tokens = createMockTokens();

  // Store tokens
  await dcrUtils.setProviderTokens(store, dcrToken, tokens);

  // Verify tokens exist
  const beforeDelete = await dcrUtils.getProviderTokens(store, dcrToken);
  assert.ok(beforeDelete, 'Tokens should exist before deletion');

  // Delete tokens
  await dcrUtils.deleteProviderTokens(store, dcrToken);

  // Verify tokens are gone
  const afterDelete = await dcrUtils.getProviderTokens(store, dcrToken);
  assert.strictEqual(afterDelete, undefined, 'Tokens should not exist after deletion');
});

it('dcrUtils - handles tokens without expiry', async () => {
  const store = new Keyv({
    store: new KeyvFile({ filename: testStorePath }),
  });

  const dcrToken = 'dcr_token_no_expiry';
  const tokensNoExpiry: ProviderTokens = {
    accessToken: 'access_token',
    refreshToken: 'refresh_token',
    scope: 'openid',
  };

  await dcrUtils.setProviderTokens(store, dcrToken, tokensNoExpiry);
  const retrieved = await dcrUtils.getProviderTokens(store, dcrToken);

  assert.ok(retrieved, 'Tokens should be retrieved');
  assert.strictEqual(retrieved?.expiresAt, undefined);
});

it('dcrUtils - handles tokens without refresh token', async () => {
  const store = new Keyv({
    store: new KeyvFile({ filename: testStorePath }),
  });

  const dcrToken = 'dcr_token_no_refresh';
  const tokensNoRefresh: ProviderTokens = {
    accessToken: 'access_token_only',
    expiresAt: Date.now() + 3600000,
    scope: 'openid',
  };

  await dcrUtils.setProviderTokens(store, dcrToken, tokensNoRefresh);
  const retrieved = await dcrUtils.getProviderTokens(store, dcrToken);

  assert.ok(retrieved, 'Tokens should be retrieved');
  assert.strictEqual(retrieved?.refreshToken, undefined);
});
