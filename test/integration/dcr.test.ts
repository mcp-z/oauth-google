/**
 * DCR Integration Test
 * Validates complete DCR + OAuth + MCP flow using safe CLI APIs
 * No dangerous internal store manipulation helpers used
 */

import '../lib/env-loader.ts';
import { createServerRegistry } from '@mcp-z/client';
import assert from 'assert';
import { startDcrTestServer } from '../lib/servers/dcr-test-server.ts';
import { logger } from '../lib/test-utils.ts';

// Check if manual mode is enabled (for OAuth flow tests only)
const MANUAL_MODE = process.env.TEST_INCLUDE_MANUAL === 'true';

// Read scope from environment variable (set in .env.test)
function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} environment variable is required. Check .env.test`);
  }
  return value;
}

const GOOGLE_SCOPE = requireEnv('GOOGLE_SCOPE');

describe('DCR Integration Test (Google)', () => {
  it('should validate Google DCR auth using registry.connect()', async function () {
    if (!MANUAL_MODE) {
      console.log('\n⚠️  Skipped: Set TEST_INCLUDE_MANUAL=true to run Google DCR integration test\n');
      this.skip();
    }

    this.timeout(120000); // 2 minutes for manual OAuth flow

    // DCR credentials - completely separate from loopback credentials
    // Google Web app clients require client_secret for non-loopback redirect URIs
    const clientId = process.env.GOOGLE_TEST_DCR_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_TEST_DCR_CLIENT_SECRET;
    const redirectUri = process.env.GOOGLE_TEST_DCR_REDIRECT_URI;

    if (!clientId || !clientSecret || !redirectUri) {
      throw new Error('Google DCR integration test requires GOOGLE_TEST_DCR_CLIENT_ID, GOOGLE_TEST_DCR_CLIENT_SECRET, and GOOGLE_TEST_DCR_REDIRECT_URI environment variables.\n' + 'Configure DCR credentials in .env.test to run integration tests.');
    }

    // Parse redirect URI to get base URL (strip /oauth/callback path)
    const redirectUrl = new URL(redirectUri);
    const port = parseInt(redirectUrl.port, 10);
    const baseUrl = `${redirectUrl.protocol}//${redirectUrl.host}`;

    let dcrCleanup: (() => Promise<void>) | undefined;
    try {
      // Note: CLI uses isolated token store per test - no production files touched

      // Start DCR test server
      console.log('🔧 Starting Google DCR test server...');
      const serverResult = await startDcrTestServer({
        port,
        baseUrl,
        scopes: [GOOGLE_SCOPE],
        clientId,
        clientSecret,
      });
      dcrCleanup = serverResult.close;
      console.log(`✅ Google DCR server running at ${serverResult.url}`);

      console.log('\n🚀 Testing Google DCR authentication using registry.connect()...');

      const registry = createServerRegistry({
        'test-dcr': {
          type: 'http',
          url: `${baseUrl}/mcp`,
          env: {
            AUTH_MODE: 'dcr',
            DCR_MODE: 'self-hosted',
            GOOGLE_CLIENT_ID: clientId,
            GOOGLE_CLIENT_SECRET: clientSecret,
          },
        },
      });

      try {
        // connect should automatically handle self-hosted DCR authentication
        // Use in-memory token store for this test
        const Keyv = (await import('keyv')).default;
        const testTokenStore = new Keyv();

        const client = await registry.connect('test-dcr', {
          dcrAuthenticator: { tokenStore: testTokenStore },
          logger,
        });
        console.log('✅ Connected to MCP server with Google DCR authentication');

        // Verify we can list tools (proves DCR authentication worked)
        const toolsResponse = await client.listTools();
        const tools = toolsResponse.tools || [];
        assert.ok(Array.isArray(tools), 'Should return tools array after Google DCR auth');
        assert.ok(tools.length > 0, 'Should have at least one tool');
        console.log(`✅ Found ${tools.length} tools via authenticated connection`);

        // Call echo tool to trigger auth middleware (which calls getUserEmail() to validate provider tokens)
        // This proves the Google access tokens are actually valid and usable
        const echoResult = await client.callTool({ name: 'echo', arguments: { message: 'token-validation-test' } });
        const echoContent = echoResult.json<{ accountId?: string }>();
        assert.ok(echoContent.accountId, 'Should have accountId from Google userinfo API call');
        console.log(`✅ Provider tokens validated - user email: ${echoContent.accountId}`);

        console.log('✅ Google DCR integration test passed!');
      } catch (error) {
        console.error('❌ Google DCR test failed:', error instanceof Error ? error.message : String(error));
        console.error('This may be expected - Google credentials may not be properly configured');
        throw error;
      } finally {
        await registry.close();
      }
    } finally {
      if (dcrCleanup) {
        await dcrCleanup();
        console.log('🔒 Google DCR test server closed');
      }
    }
  });

  it('should re-authenticate when tokens are expired (triggers browser)', async function () {
    if (!MANUAL_MODE) {
      console.log('\n⚠️  Skipped: Set TEST_INCLUDE_MANUAL=true to run expired token re-auth test\n');
      this.skip();
    }

    this.timeout(120000); // 2 minutes for manual OAuth flow

    // DCR credentials - completely separate from loopback credentials
    const clientId = process.env.GOOGLE_TEST_DCR_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_TEST_DCR_CLIENT_SECRET;
    const redirectUri = process.env.GOOGLE_TEST_DCR_REDIRECT_URI;
    if (!clientId || !clientSecret || !redirectUri) {
      throw new Error('GOOGLE_TEST_DCR_CLIENT_ID, GOOGLE_TEST_DCR_CLIENT_SECRET, and GOOGLE_TEST_DCR_REDIRECT_URI required');
    }

    // Parse redirect URI to get base URL
    const redirectUrl = new URL(redirectUri);
    const port = parseInt(redirectUrl.port, 10);
    const baseUrl = `${redirectUrl.protocol}//${redirectUrl.host}`;

    let dcrCleanup: (() => Promise<void>) | undefined;
    try {
      console.log('🔧 Starting Google DCR test server...');
      const serverResult = await startDcrTestServer({
        port,
        baseUrl,
        scopes: [GOOGLE_SCOPE],
        clientId,
        clientSecret,
      });
      dcrCleanup = serverResult.close;

      const registry = createServerRegistry({
        'test-dcr': {
          type: 'http',
          url: `${baseUrl}/mcp`,
          env: {
            AUTH_MODE: 'dcr',
            DCR_MODE: 'self-hosted',
            GOOGLE_CLIENT_ID: clientId,
            GOOGLE_CLIENT_SECRET: clientSecret,
          },
        },
      });

      try {
        // Create token store with EXPIRED tokens to simulate stale state
        const Keyv = (await import('keyv')).default;
        const testTokenStore = new Keyv();

        // Pre-populate with expired tokens (simulates stale cache)
        await testTokenStore.set(`dcr-tokens:${baseUrl}`, {
          accessToken: 'expired_access_token',
          refreshToken: 'invalid_refresh_token',
          expiresAt: Date.now() - 3600000, // Expired 1 hour ago
          clientId: 'old_client',
          clientSecret: 'old_secret',
        });

        console.log('\n🔄 Testing re-authentication with expired tokens...');
        console.log('   (Browser should open for fresh authorization)');

        // This should detect expired tokens and trigger full re-auth flow
        const client = await registry.connect('test-dcr', {
          dcrAuthenticator: { tokenStore: testTokenStore },
          logger,
        });

        // Verify connection works with fresh tokens
        const toolsResponse = await client.listTools();
        assert.ok((toolsResponse.tools?.length ?? 0) > 0, 'Should have tools after re-auth');

        // Verify provider tokens work
        const echoResult = await client.callTool({ name: 'echo', arguments: { message: 're-auth-test' } });
        const echoContent = echoResult.json<{ accountId?: string }>();
        assert.ok(echoContent.accountId, 'Should have accountId after re-authentication');

        console.log(`✅ Re-authenticated successfully - user: ${echoContent.accountId}`);
      } finally {
        await registry.close();
      }
    } finally {
      if (dcrCleanup) {
        await dcrCleanup();
      }
    }
  });
});
