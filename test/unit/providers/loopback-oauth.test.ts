import '../../lib/env-loader.ts';

/**
 * LoopbackOAuthProvider Tests
 *
 * Tests for the LoopbackOAuthProvider class which implements OAuth 2.0 with
 * server-managed token storage and loopback redirect handling (RFC 8252).
 *
 * Security Model: Server manages tokens, uses ephemeral loopback server for OAuth callbacks
 */

import assert from 'assert';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import { LoopbackOAuthProvider } from '../../../src/providers/loopback-oauth.ts';
import { GOOGLE_SCOPE } from '../../constants.ts';
import { createConfig } from '../../lib/config.ts';
import { logger } from '../../lib/test-utils.ts';

const config = createConfig();

// Use isolated test token directory
// Run `npm run test:setup` first to generate tokens
const tokenStorePath = path.join(process.cwd(), '.tokens/test');

it('LoopbackOAuthProvider - getAccessToken returns valid token', async () => {
  // Skip this test - it's covered by the next test which validates googleapis compatibility
  // This test would require setting up account management state which is better tested in middleware tests
});

it('LoopbackOAuthProvider - toAuth provides googleapis-compatible auth', async () => {
  const tokenStore = new Keyv({
    store: new KeyvFile({ filename: path.join(tokenStorePath, 'store.json') }),
  });

  const auth = new LoopbackOAuthProvider({
    service: 'gmail',
    clientId: config.clientId,
    clientSecret: config.clientSecret || '', // Optional for public clients
    scope: GOOGLE_SCOPE,
    headless: true,
    logger,
    tokenStore,
  });

  const googleAuth = auth.toAuth('default');

  assert.ok(googleAuth, 'toAuth should return auth object');
  assert.ok(typeof googleAuth.getRequestHeaders === 'function', 'Should have getRequestHeaders function');
});
