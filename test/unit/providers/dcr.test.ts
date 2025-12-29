import '../../lib/env-loader.js';

/**
 * DcrOAuthProvider Tests
 *
 * Tests for the DcrOAuthProvider class which implements stateless OAuth 2.0 for
 * Dynamic Client Registration scenarios.
 *
 * Security Model: Stateless provider receives tokens from context (HTTP bearer auth)
 */

import type { ProviderTokens } from '@mcp-z/oauth';
import assert from 'assert';
import { DcrOAuthProvider } from '../../../src/providers/dcr.ts';
import { createConfig } from '../../lib/config.ts';
import { logger } from '../../lib/test-utils.ts';

const config = createConfig();

const GOOGLE_SCOPE = 'openid https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/gmail.readonly';

// Mock provider tokens for testing
const createMockTokens = (): ProviderTokens => ({
  accessToken: 'mock_access_token_12345',
  refreshToken: 'mock_refresh_token_67890',
  expiresAt: Date.now() + 3600000, // 1 hour from now
  scope: GOOGLE_SCOPE,
});

it('DcrOAuthProvider - toAuth creates functional OAuth2Client', () => {
  const provider = new DcrOAuthProvider({
    clientId: config.clientId,
    ...(config.clientSecret && { clientSecret: config.clientSecret }),
    scope: GOOGLE_SCOPE,
    verifyEndpoint: 'http://test.invalid/oauth/verify', // Not used in these tests
    logger,
  });

  const tokens = createMockTokens();
  const auth = provider.toAuth(tokens);

  assert.ok(auth, 'OAuth2Client should be created');
  assert.ok(auth.credentials, 'Credentials should be set');
  assert.strictEqual(auth.credentials.access_token, tokens.accessToken, 'Access token should match');
  assert.strictEqual(auth.credentials.refresh_token, tokens.refreshToken, 'Refresh token should match');
});

it('DcrOAuthProvider - toAuth handles tokens without expiry', () => {
  const provider = new DcrOAuthProvider({
    clientId: config.clientId,
    ...(config.clientSecret && { clientSecret: config.clientSecret }),
    scope: GOOGLE_SCOPE,
    verifyEndpoint: 'http://test.invalid/oauth/verify', // Not used in these tests
    logger,
  });

  const tokensWithoutExpiry: ProviderTokens = {
    accessToken: 'mock_access_token',
    refreshToken: 'mock_refresh_token',
    scope: GOOGLE_SCOPE,
  };

  const auth = provider.toAuth(tokensWithoutExpiry);

  assert.ok(auth, 'OAuth2Client should be created');
  assert.ok(auth.credentials, 'Credentials should be set');
  assert.strictEqual(auth.credentials.access_token, tokensWithoutExpiry.accessToken);
});

it('DcrOAuthProvider - toAuth handles tokens without refresh token', () => {
  const provider = new DcrOAuthProvider({
    clientId: config.clientId,
    ...(config.clientSecret && { clientSecret: config.clientSecret }),
    scope: GOOGLE_SCOPE,
    verifyEndpoint: 'http://test.invalid/oauth/verify', // Not used in these tests
    logger,
  });

  const tokensWithoutRefresh: ProviderTokens = {
    accessToken: 'mock_access_token',
    expiresAt: Date.now() + 3600000,
    scope: GOOGLE_SCOPE,
  };

  const auth = provider.toAuth(tokensWithoutRefresh);

  assert.ok(auth, 'OAuth2Client should be created');
  assert.ok(auth.credentials, 'Credentials should be set');
  assert.strictEqual(auth.credentials.access_token, tokensWithoutRefresh.accessToken);
  assert.strictEqual(auth.credentials.refresh_token, null);
});

// Integration tests with real Google endpoints (require tokens from test-setup)
describe('DcrOAuthProvider - Integration with Google APIs', () => {
  it('should refresh provider tokens with real Google endpoint', async function () {
    this.timeout(30000);

    // Load stored DCR tokens from test-setup
    const path = await import('path');
    const Keyv = (await import('keyv')).default;
    const { KeyvFile } = await import('keyv-file');

    const dcrTokenPath = path.join(process.cwd(), '.tokens/dcr.json');
    const dcrStore = new Keyv({
      store: new KeyvFile({ filename: dcrTokenPath }),
    });

    interface DcrTokenData {
      clientId: string;
      clientSecret: string;
      providerRefreshToken: string;
      providerAccessToken: string;
      providerExpiresAt: number;
    }

    const storedTokens = (await dcrStore.get('google')) as DcrTokenData | undefined;
    if (!storedTokens || !storedTokens.providerRefreshToken) {
      throw new Error('No stored DCR tokens found. Run npm run test:setup first to create test tokens.');
    }

    // Use DCR test credentials (these match the tokens in .tokens/dcr.json)
    // DCR uses a separate Web app client, NOT the loopback Desktop app client
    const dcrClientId = process.env.GOOGLE_TEST_DCR_CLIENT_ID;
    const dcrClientSecret = process.env.GOOGLE_TEST_DCR_CLIENT_SECRET;
    if (!dcrClientId) {
      throw new Error('GOOGLE_TEST_DCR_CLIENT_ID environment variable required. Configure in .env.test');
    }

    const provider = new DcrOAuthProvider({
      clientId: dcrClientId,
      ...(dcrClientSecret && { clientSecret: dcrClientSecret }),
      scope: GOOGLE_SCOPE,
      verifyEndpoint: 'http://test.invalid/oauth/verify',
      logger,
    });

    // Test refresh with real Google endpoint
    console.log('🔄 Refreshing tokens with real Google endpoint...');
    const refreshedTokens = await provider.refreshAccessToken(storedTokens.providerRefreshToken);

    assert.ok(refreshedTokens.accessToken, 'Should return new access token');
    assert.ok(refreshedTokens.accessToken !== storedTokens.providerAccessToken || refreshedTokens.expiresAt, 'Should have new token or fresh expiry');
    console.log(`✅ Refreshed token: ${refreshedTokens.accessToken.substring(0, 20)}...`);

    // Verify the refreshed token works by calling getUserEmail
    console.log('🔍 Verifying refreshed token with Google userinfo API...');
    const email = await provider.getUserEmail(refreshedTokens);
    assert.ok(email, 'Should get user email with refreshed token');
    assert.ok(email.includes('@'), 'Email should be valid format');
    console.log(`✅ Verified - user email: ${email}`);
  });

  it('should fail refresh with invalid token', async function () {
    this.timeout(10000);

    // Use DCR test credentials
    const dcrClientId = process.env.GOOGLE_CLIENT_ID;
    const dcrClientSecret = process.env.GOOGLE_TEST_DCR_CLIENT_SECRET;
    if (!dcrClientId) {
      throw new Error('GOOGLE_CLIENT_ID environment variable required. Configure in .env.test');
    }

    const provider = new DcrOAuthProvider({
      clientId: dcrClientId,
      ...(dcrClientSecret && { clientSecret: dcrClientSecret }),
      scope: GOOGLE_SCOPE,
      verifyEndpoint: 'http://test.invalid/oauth/verify',
      logger,
    });

    // Test refresh with invalid token
    await assert.rejects(
      async () => {
        await provider.refreshAccessToken('invalid_refresh_token_12345');
      },
      /Token refresh failed/,
      'Should throw error for invalid refresh token'
    );
    console.log('✅ Invalid refresh token correctly rejected by Google');
  });
});
