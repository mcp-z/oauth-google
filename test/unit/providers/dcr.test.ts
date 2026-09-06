import '../../lib/env-loader.ts';

/**
 * DcrOAuthProvider Tests
 *
 * Tests for the DcrOAuthProvider class which implements stateless OAuth 2.0 for
 * Dynamic Client Registration scenarios, and for authMiddleware() which validates
 * bearer token extraction, token verification, auth context enrichment, and error handling.
 *
 * Security Model: Stateless provider receives tokens from context (HTTP bearer auth):
 * - Receives bearer tokens from HTTP Authorization header
 * - Validates tokens via /oauth/verify endpoint
 * - Enriches extra with auth context from provider tokens
 */

import type { ProviderTokens } from '@mcp-z/oauth';
import { DcrOAuthProvider, type EnrichedExtra, type ToolModule } from '@mcp-z/oauth-google';
import type { CallToolResult } from '@modelcontextprotocol/server';
import assert from 'assert';
import express from 'express';
import type { Server } from 'http';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import { z } from 'zod';
import { createConfig } from '../../lib/config.ts';
import { GOOGLE_SCOPE } from '../../lib/constants.ts';
import { createTestExtra, logger } from '../../lib/test-utils.ts';

const config = createConfig();

// Mock provider tokens for testing
const createMockTokens = (): ProviderTokens => ({
  accessToken: 'mock_access_token_12345',
  refreshToken: 'mock_refresh_token_67890',
  expiresAt: Date.now() + 3600000, // 1 hour from now
  scope: GOOGLE_SCOPE,
});

const TEST_PORT = 9877;
const BASE_URL = `http://localhost:${TEST_PORT}`;
const VERIFY_ENDPOINT = `${BASE_URL}/oauth/verify`;

// Mock provider tokens for testing
const mockProviderTokens: ProviderTokens = {
  accessToken: 'mock_provider_access_token',
  refreshToken: 'mock_provider_refresh_token',
  expiresAt: Date.now() + 3600000,
  scope: 'https://www.googleapis.com/auth/gmail.readonly',
};

// The provider reads the bearer token off the web Request the v2 context carries.
const extraWithAuth = (authorization?: string) =>
  createTestExtra({
    http: { req: new Request(BASE_URL, { method: 'POST', ...(authorization ? { headers: { authorization } } : {}) }) },
  });

// Simple test tool for middleware validation
const testTool = {
  name: 'test-tool',
  config: {
    title: 'Test Tool',
    description: 'Tool for testing authMiddleware',
    inputSchema: z.object({ message: z.string() }),
    outputSchema: z.object({ result: z.string() }),
  },
  handler: async (_args: unknown, extra: unknown) => {
    // Handler expects authContext to be present
    assert.ok((extra as EnrichedExtra).authContext, 'authContext should be present');
    assert.ok((extra as EnrichedExtra).authContext.auth, 'auth should be present');

    return {
      content: [{ type: 'text', text: JSON.stringify({ result: 'success' }) }],
      structuredContent: { result: 'success' },
    };
  },
} satisfies ToolModule;

// Create minimal HTTP server for verify endpoint
let testServer: Server | undefined;
const validBearerToken = 'valid_dcr_token';

function startTestServer(): Promise<void> {
  const app = express();
  app.use(express.json());

  // Mock /oauth/verify endpoint
  app.get('/oauth/verify', (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ error: 'missing_token' });
    }

    const token = authHeader.replace(/^Bearer\s+/i, '');

    if (token === validBearerToken) {
      return res.json({ providerTokens: mockProviderTokens });
    }

    return res.status(401).json({ error: 'invalid_token' });
  });

  return new Promise((resolve) => {
    testServer = app.listen(TEST_PORT, () => {
      resolve();
    });
  });
}

function stopTestServer(): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!testServer) {
      resolve();
      return;
    }

    testServer.close((err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

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

describe('DcrOAuthProvider.authMiddleware()', () => {
  let provider: DcrOAuthProvider;
  let originalGetUserEmail: (tokens: ProviderTokens) => Promise<string>;

  before(async () => {
    await startTestServer();

    provider = new DcrOAuthProvider({
      clientId: 'test-client-id',
      clientSecret: 'test-client-secret',
      scope: 'https://www.googleapis.com/auth/gmail.readonly',
      verifyEndpoint: VERIFY_ENDPOINT,
      logger,
    });

    // Save original getUserEmail method
    originalGetUserEmail = provider.getUserEmail.bind(provider);
  });

  after(async () => {
    await stopTestServer();
  });

  beforeEach(() => {
    // Stub getUserEmail to avoid real API calls in tests
    provider.getUserEmail = async (_tokens) => 'test@example.com';
  });

  afterEach(() => {
    // Restore original method after each test
    provider.getUserEmail = originalGetUserEmail;
  });

  it('throws error when Authorization header missing', async () => {
    const middleware = provider.authMiddleware();
    const wrappedTool = middleware.withToolAuth(testTool);

    const extra = extraWithAuth(); // No Authorization header

    try {
      await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extra);
      assert.fail('Should have thrown error');
    } catch (error) {
      assert.ok(error instanceof Error);
      assert.ok(error.message.includes('Authorization') || error.message.includes('bearer'), `Expected auth error, got: ${error.message}`);
    }
  });

  it('throws error when bearer token is invalid', async () => {
    const middleware = provider.authMiddleware();
    const wrappedTool = middleware.withToolAuth(testTool);

    const extra = extraWithAuth('Bearer invalid_token_12345');

    try {
      await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extra);
      assert.fail('Should have thrown error');
    } catch (error) {
      assert.ok(error instanceof Error);
      assert.ok(error.message.includes('verification failed') || error.message.includes('401'), `Expected verification error, got: ${error.message}`);
    }
  });

  it('enriches extra with authContext when token is valid', async () => {
    const middleware = provider.authMiddleware();
    const wrappedTool = middleware.withToolAuth(testTool);

    const extra = extraWithAuth(`Bearer ${validBearerToken}`);

    // Tool handler validates authContext presence (will throw if missing)
    const result = await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extra);

    assert.ok(result);
    assert.strictEqual((result.structuredContent as { result?: string }).result, 'success');
  });

  it('extracts bearer token from authInfo when present', async () => {
    const middleware = provider.authMiddleware();
    const wrappedTool = middleware.withToolAuth(testTool);

    // SDK already extracted and validated the token; no Authorization header to fall back to
    const extra = createTestExtra({ http: { authInfo: { token: validBearerToken, clientId: 'test-client', scopes: [] } } });

    // Tool handler validates authContext presence (will throw if missing)
    const result = await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extra);

    assert.ok(result);
    assert.strictEqual((result.structuredContent as { result?: string }).result, 'success');
  });

  it('handles case-insensitive Bearer prefix', async () => {
    const middleware = provider.authMiddleware();
    const wrappedTool = middleware.withToolAuth(testTool);

    // Test lowercase 'bearer'
    const extraLower = extraWithAuth(`bearer ${validBearerToken}`);

    const resultLower = await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extraLower);
    assert.ok(resultLower);

    // Test mixed case 'BeArEr'
    const extraMixed = extraWithAuth(`BeArEr ${validBearerToken}`);

    const resultMixed = await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extraMixed);
    assert.ok(resultMixed);
  });

  it('auth provider can get access token from provider tokens', async () => {
    const auth = provider.toAuth(mockProviderTokens);

    // Get credentials to access the access token
    const { token } = await auth.getAccessToken();

    assert.ok(token);
    assert.strictEqual(token, mockProviderTokens.accessToken);
  });

  it('sets accountId to user email from getUserEmail()', async () => {
    const testEmail = 'user@gmail.com';

    // Override the beforeEach stub with a specific email
    provider.getUserEmail = async (_tokens) => testEmail;

    const middleware = provider.authMiddleware();

    // Create tool that captures accountId
    let capturedAccountId: string | undefined;
    const captureTool = {
      name: 'capture-tool',
      config: testTool.config,
      handler: async (_args: unknown, extra: unknown) => {
        capturedAccountId = (extra as EnrichedExtra).authContext.accountId;
        return { content: [], structuredContent: { result: 'ok' } };
      },
    } satisfies ToolModule;

    const wrappedTool = middleware.withToolAuth(captureTool);

    const extra = extraWithAuth(`Bearer ${validBearerToken}`);

    await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({ message: 'test' }, extra);

    assert.strictEqual(capturedAccountId, testEmail, 'accountId should be user email');
  });
});
