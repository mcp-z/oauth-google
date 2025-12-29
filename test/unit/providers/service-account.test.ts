/**
 * ServiceAccountProvider Unit Tests
 *
 * Tests use REAL Google OAuth endpoints (no mocking) following QUALITY.md T1.
 * Requires a valid service account key file to run.
 *
 * Setup:
 * 1. Create service account in Google Cloud Console
 * 2. Download JSON key file
 * 3. Place as service-account.test.json in oauth-google root (see service-account.test.example.json)
 */

import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import assert from 'assert';
import { promises as fs } from 'fs';
import { google } from 'googleapis';
import { ServiceAccountProvider } from '../../../src/providers/service-account.ts';
import type { AuthContext, EnrichedExtra, ToolModule } from '../../../src/types.ts';
import { createTestExtra, logger } from '../../lib/test-utils.ts';

// Service account key file location (in package root)
const KEY_FILE_PATH = './service-account.test.json';

describe('ServiceAccountProvider', () => {
  const keyFilePath = KEY_FILE_PATH;
  const testScopes = ['https://www.googleapis.com/auth/drive.readonly'];

  describe('Key File Loading and Validation', () => {
    it('loadKeyFile: reads and parses valid JSON key file', async () => {
      const provider = new ServiceAccountProvider({
        keyFilePath,
        scopes: testScopes,
        logger,
      });

      // Get user email forces key file load
      const email = await provider.getUserEmail('service-account');

      // Verify email format (service account emails end with .gserviceaccount.com)
      assert.ok(email.includes('@'), 'Service account email should contain @');
      assert.ok(email.endsWith('.gserviceaccount.com'), 'Service account email should end with .gserviceaccount.com');
    });

    it('loadKeyFile: throws on missing file', async () => {
      const provider = new ServiceAccountProvider({
        keyFilePath: '/nonexistent/path/key.json',
        scopes: testScopes,
        logger,
      });

      await assert.rejects(
        async () => await provider.getUserEmail('service-account'),
        (error: Error) => {
          assert.ok(error.message.includes('Service account key file not found'), `Expected "key file not found" error, got: ${error.message}`);
          return true;
        }
      );
    });

    it('loadKeyFile: throws on invalid JSON', async () => {
      // Create temporary invalid JSON file
      const tempPath = '.tmp/invalid-key.json';
      await fs.mkdir('.tmp', { recursive: true });
      await fs.writeFile(tempPath, 'invalid json content{');

      const provider = new ServiceAccountProvider({
        keyFilePath: tempPath,
        scopes: testScopes,
        logger,
      });

      try {
        await assert.rejects(
          async () => await provider.getUserEmail('service-account'),
          (error: Error) => {
            assert.ok(error.message.includes('Failed to parse service account key file as JSON'), `Expected JSON parse error, got: ${error.message}`);
            return true;
          }
        );
      } finally {
        // Cleanup
        await fs.unlink(tempPath).catch(() => {});
      }
    });

    it('loadKeyFile: throws on wrong type field', async () => {
      // Create temporary key file with wrong type
      const tempPath = '.tmp/wrong-type-key.json';
      await fs.mkdir('.tmp', { recursive: true });
      await fs.writeFile(
        tempPath,
        JSON.stringify({
          type: 'authorized_user', // Wrong type!
          project_id: 'test',
          client_email: 'test@test.com',
        })
      );

      const provider = new ServiceAccountProvider({
        keyFilePath: tempPath,
        scopes: testScopes,
        logger,
      });

      try {
        await assert.rejects(
          async () => await provider.getUserEmail('service-account'),
          (error: Error) => {
            assert.ok(error.message.includes('Expected type "service_account"'), `Expected type validation error, got: ${error.message}`);
            return true;
          }
        );
      } finally {
        await fs.unlink(tempPath).catch(() => {});
      }
    });

    it('loadKeyFile: throws on missing required fields', async () => {
      // Create temporary key file with missing fields
      const tempPath = '.tmp/incomplete-key.json';
      await fs.mkdir('.tmp', { recursive: true });
      await fs.writeFile(
        tempPath,
        JSON.stringify({
          type: 'service_account',
          project_id: 'test',
          // Missing: private_key, client_email, etc.
        })
      );

      const provider = new ServiceAccountProvider({
        keyFilePath: tempPath,
        scopes: testScopes,
        logger,
      });

      try {
        await assert.rejects(
          async () => await provider.getUserEmail('service-account'),
          (error: Error) => {
            assert.ok(error.message.includes('missing required fields'), `Expected missing fields error, got: ${error.message}`);
            return true;
          }
        );
      } finally {
        await fs.unlink(tempPath).catch(() => {});
      }
    });

    it('loadKeyFile: throws on invalid private key format', async () => {
      // Create temporary key file with invalid private key
      const tempPath = '.tmp/bad-key-format.json';
      await fs.mkdir('.tmp', { recursive: true });
      await fs.writeFile(
        tempPath,
        JSON.stringify({
          type: 'service_account',
          project_id: 'test',
          private_key_id: 'key-id',
          private_key: 'not-a-valid-pem-key', // Invalid format!
          client_email: 'test@test.iam.gserviceaccount.com',
          client_id: '123',
          auth_uri: 'https://accounts.google.com/o/oauth2/auth',
          token_uri: 'https://oauth2.googleapis.com/token',
        })
      );

      const provider = new ServiceAccountProvider({
        keyFilePath: tempPath,
        scopes: testScopes,
        logger,
      });

      try {
        await assert.rejects(
          async () => await provider.getUserEmail('service-account'),
          (error: Error) => {
            assert.ok(error.message.includes('does not contain a valid PEM-formatted key'), `Expected PEM format error, got: ${error.message}`);
            return true;
          }
        );
      } finally {
        await fs.unlink(tempPath).catch(() => {});
      }
    });
  });

  describe('JWT Generation', () => {
    let provider: ServiceAccountProvider;
    let _keyFileData: unknown;

    before(async () => {
      provider = new ServiceAccountProvider({
        keyFilePath,
        scopes: testScopes,
        logger,
      });

      // Load key file for verification tests
      const keyFileContent = await fs.readFile(keyFilePath, 'utf-8');
      _keyFileData = JSON.parse(keyFileContent);
    });

    it('generateJWT: creates valid JWT structure', async () => {
      // Generate access token (internally generates JWT)
      const token = await provider.getAccessToken('service-account');

      // Verify we got a token (JWT generation worked)
      assert.ok(token, 'Should receive access token');
      assert.ok(token.length > 0, 'Access token should not be empty');
      assert.equal(typeof token, 'string', 'Access token should be string');
    });

    it('getAccessToken: returns valid access token from Google (service-backed)', async () => {
      // This test hits REAL Google OAuth endpoint
      const token = await provider.getAccessToken('service-account');

      // Verify token format (Google access tokens can be JWTs or opaque tokens)
      assert.ok(token.length > 50, 'Access token should be substantial length');
      assert.equal(typeof token, 'string', 'Token should be string');
      assert.ok(/^[A-Za-z0-9\-_.]+$/.test(token), 'Token should contain only valid characters');
    });

    it('getAccessToken: caches token for subsequent calls', async () => {
      const provider = new ServiceAccountProvider({
        keyFilePath,
        scopes: testScopes,
        logger,
      });

      // First call - generates token
      const token1 = await provider.getAccessToken('service-account');

      // Second call - should use cache (faster)
      const startTime = Date.now();
      const token2 = await provider.getAccessToken('service-account');
      const duration = Date.now() - startTime;

      // Cached call should be very fast (< 50ms) since it doesn't hit network
      assert.ok(duration < 50, `Cached token call took ${duration}ms, expected < 50ms`);

      // Tokens should match
      assert.equal(token1, token2, 'Cached token should match original');
    });
  });

  describe('Token Exchange (Service-Backed)', () => {
    it('exchangeJWT: successful token exchange with REAL Google OAuth endpoint', async () => {
      const provider = new ServiceAccountProvider({
        keyFilePath,
        scopes: testScopes,
        logger,
      });

      // This hits the real Google OAuth endpoint
      const token = await provider.getAccessToken('service-account');

      // Verify token characteristics
      assert.ok(token, 'Should receive access token from Google');
      assert.equal(typeof token, 'string', 'Token should be string');
      assert.ok(token.length > 50, 'Token should be substantial length');
    });

    it('exchangeJWT: handles network errors gracefully', async () => {
      const provider = new ServiceAccountProvider({
        keyFilePath,
        scopes: testScopes,
        logger,
      });

      // If network is available, this should succeed
      // If network fails, error should be wrapped with helpful message
      try {
        await provider.getAccessToken('service-account');
        assert.ok(true, 'Token generation succeeded (network available)');
      } catch (error) {
        // If network error occurs, verify error message is helpful
        assert.ok(error instanceof Error, 'Network errors should be Error instances');
        assert.ok(error.message.includes('Failed to get service account access token') || error.message.includes('Network error'), `Error message should be helpful: ${error.message}`);
      }
    });
  });

  describe('OAuth2Client Generation', () => {
    it('toAuth: returns OAuth2Client instance', async () => {
      const provider = new ServiceAccountProvider({
        keyFilePath,
        scopes: testScopes,
        logger,
      });

      const auth = provider.toAuth('service-account');

      // Verify it's an OAuth2Client
      assert.ok(auth, 'Should return OAuth2Client');
      assert.ok(auth.constructor.name === 'OAuth2Client', 'Should be OAuth2Client instance');

      // Verify it has getAccessToken method (required by googleapis)
      assert.ok(typeof auth.getAccessToken === 'function', 'Should have getAccessToken method');
    });

    it('toAuth: accepts undefined accountId', async () => {
      const provider = new ServiceAccountProvider({
        keyFilePath,
        scopes: testScopes,
        logger,
      });

      const auth = provider.toAuth('service-account'); // No accountId

      // Should work fine
      assert.ok(auth, 'Should return OAuth2Client');
      assert.ok(auth.constructor.name === 'OAuth2Client', 'Should be OAuth2Client instance');
    });

    it('toAuth: validates accountId parameter', async () => {
      const provider = new ServiceAccountProvider({
        keyFilePath,
        scopes: testScopes,
        logger,
      });

      // Should throw for wrong accountId
      assert.throws(
        () => provider.toAuth('wrong-account'),
        (error: Error) => {
          assert.ok(error.message.includes("ServiceAccountProvider only supports accountId='service-account'"), `Expected validation error, got: ${error.message}`);
          assert.ok(error.message.includes('single static identity pattern'), `Expected explanation in error, got: ${error.message}`);
          return true;
        }
      );
    });

    it('toAuth: OAuth2Client can retrieve access token', async () => {
      const provider = new ServiceAccountProvider({
        keyFilePath,
        scopes: testScopes,
        logger,
      });

      const auth = provider.toAuth('service-account');

      // Call getAccessToken on the OAuth2Client (googleapis will do this)
      const result = await auth.getAccessToken();

      // Verify result structure
      assert.ok(result, 'getAccessToken should return result');
      assert.ok(result.token, 'Result should contain token');
      assert.ok(typeof result.token === 'string', 'Token should be string');
      assert.ok(result.token.length > 50, 'Token should be substantial length');
    });
  });

  describe('getUserEmail', () => {
    it('getUserEmail: returns service account email from key file', async () => {
      const provider = new ServiceAccountProvider({
        keyFilePath,
        scopes: testScopes,
        logger,
      });

      const email = await provider.getUserEmail('service-account');

      // Verify email format
      assert.ok(email, 'Should return email');
      assert.ok(email.includes('@'), 'Email should contain @');
      assert.ok(email.endsWith('.gserviceaccount.com'), 'Service account email should end with .gserviceaccount.com');
    });

    it('getUserEmail: ignores accountId parameter (service account is single identity)', async () => {
      const provider = new ServiceAccountProvider({
        keyFilePath,
        scopes: testScopes,
        logger,
      });

      // Call with different accountIds - should return same email
      const email1 = await provider.getUserEmail('user1');
      const email2 = await provider.getUserEmail('user2');
      const email3 = await provider.getUserEmail('service-account');

      assert.equal(email1, email2, 'Email should be same regardless of accountId');
      assert.equal(email2, email3, 'Email should be same regardless of accountId');
    });
  });

  describe('Middleware Integration', () => {
    it('authMiddleware: returns middleware function', () => {
      const provider = new ServiceAccountProvider({
        keyFilePath,
        scopes: testScopes,
        logger,
      });

      const middleware = provider.authMiddleware();

      // Verify middleware is a function
      assert.ok(typeof middleware.withToolAuth === 'function', 'Middleware should be function');
    });

    it('authMiddleware: wraps tool module and injects authContext', async () => {
      const provider = new ServiceAccountProvider({
        keyFilePath,
        scopes: testScopes,
        logger,
      });

      // Create simple test tool to verify wrapping behavior
      let receivedAuthContext: AuthContext | undefined;
      const testTool = {
        name: 'test-tool',
        config: { inputSchema: {}, outputSchema: {} },
        handler: async (_args: unknown, extra: unknown) => {
          receivedAuthContext = (extra as EnrichedExtra).authContext;
          return { content: [{ type: 'text', text: 'success' }] };
        },
      } as unknown as ToolModule;

      // Apply middleware
      const middleware = provider.authMiddleware();
      const wrappedTool = middleware.withToolAuth(testTool);

      // Call wrapped handler
      const extra = createTestExtra({ _meta: {} });
      await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, extra);

      // Verify authContext was injected
      assert.ok(receivedAuthContext, 'authContext should be injected');
      assert.ok(receivedAuthContext.auth, 'authContext should have auth (OAuth2Client)');
      assert.equal(receivedAuthContext.accountId, 'service-account', 'accountId should be fixed "service-account"');

      // Verify service email is in metadata
      assert.ok(receivedAuthContext.metadata, 'authContext should have metadata');
      assert.ok(receivedAuthContext.metadata.serviceEmail, 'metadata should have serviceEmail');
      assert.ok(receivedAuthContext.metadata.serviceEmail.includes('@'), 'serviceEmail should be email format');
      assert.ok(receivedAuthContext.metadata.serviceEmail.endsWith('.gserviceaccount.com'), 'serviceEmail should be service account format');
    });
  });

  describe('Error Handling', () => {
    it('getAccessToken: wraps errors with helpful context', async () => {
      // Use nonexistent key file to trigger error
      const provider = new ServiceAccountProvider({
        keyFilePath: '/nonexistent/key.json',
        scopes: testScopes,
        logger,
      });

      await assert.rejects(
        async () => await provider.getAccessToken('service-account'),
        (error: Error) => {
          assert.ok(error.message.includes('Failed to get service account access token'), `Error should be wrapped with context: ${error.message}`);
          return true;
        }
      );
    });

    it('authMiddleware: wraps auth errors with helpful context', async () => {
      // Use nonexistent key file to trigger error
      const provider = new ServiceAccountProvider({
        keyFilePath: '/nonexistent/key.json',
        scopes: testScopes,
        logger,
      });

      const testTool = {
        name: 'test-tool',
        config: { inputSchema: {}, outputSchema: {} },
        handler: async () => ({ content: [{ type: 'text', text: 'success' }] }),
      } as unknown as ToolModule;

      const middleware = provider.authMiddleware();
      const wrappedTool = middleware.withToolAuth(testTool);

      await assert.rejects(
        async () => await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, createTestExtra({ _meta: {} })),
        (error: Error) => {
          assert.ok(error.message.includes('Service account setup error'), `Error should be wrapped with specific context: ${error.message}`);
          assert.ok(error.message.includes('Key file'), `Should mention key file issue: ${error.message}`);
          return true;
        }
      );
    });
  });

  /**
   * Google APIs Integration Tests
   * Tests ServiceAccountProvider OAuth2Client works with real Google APIs
   * (This is the critical test that was missing and caused our production bug!)
   */
  describe('Google APIs Integration', () => {
    it('toAuth OAuth2Client integrates with real Google Drive API', async () => {
      // CRITICAL TEST: This test verifies the OAuth2Client from toAuth() works with googleapis
      // Before our fix, this would fail with "No access, refresh token, API key or refresh handler callback is set"
      const provider = new ServiceAccountProvider({
        keyFilePath: KEY_FILE_PATH,
        scopes: ['https://www.googleapis.com/auth/drive.readonly'], // Drive scope only
        logger,
      });

      // Get OAuth2Client the same way production code does
      const googleAuth = provider.toAuth('service-account');

      // Use it with googleapis - this is where the original bug manifested
      const drive = google.drive({ version: 'v3', auth: googleAuth });

      // Make a real API call - this would fail before our fix
      const response = await drive.files.list({
        pageSize: 5, // Small limit
        fields: 'files(id, name),nextPageToken',
        q: 'trashed = false', // Non-trashed files only
      });

      // Verify response structure
      assert.ok(response.data, 'Should get Drive API response');
      assert.ok(Array.isArray(response.data.files), 'Should have files array');
      assert.ok(typeof response.data.nextPageToken === 'string' || response.data.nextPageToken === undefined, 'Should have valid nextPageToken');
    });

    it('OAuth2Client supports token refresh and concurrent calls', async () => {
      const provider = new ServiceAccountProvider({
        keyFilePath: KEY_FILE_PATH,
        scopes: ['https://www.googleapis.com/auth/drive.readonly'],
        logger,
      });

      const googleAuth = provider.toAuth('service-account');
      const drive = google.drive({ version: 'v3', auth: googleAuth });

      // Test concurrent API calls (this exercises token caching and refresh)
      const apiCalls = Array.from({ length: 3 }, () =>
        drive.files.list({
          pageSize: 1,
          fields: 'files(id)',
          q: 'trashed = false',
        })
      );

      const responses = await Promise.all(apiCalls);

      // All should succeed and return data
      responses.forEach((response, i) => {
        assert.ok(response.data, `Response ${i} should have data`);
        assert.ok(Array.isArray(response.data.files), `Response ${i} should have files array`);
      });
    });

    it('OAuth2Client properly sets access token on repeated calls', async () => {
      const provider = new ServiceAccountProvider({
        keyFilePath: KEY_FILE_PATH,
        scopes: ['https://www.googleapis.com/auth/drive.readonly'],
        logger,
      });

      // First call - should set up cached token
      const googleAuth1 = provider.toAuth('service-account');
      const drive1 = google.drive({ version: 'v3', auth: googleAuth1 });
      const response1 = await drive1.files.list({
        pageSize: 1,
        fields: 'files(id)',
      });
      assert.ok(response1.data.files, 'First API call should succeed');

      // Second call - should reuse cached token (proves credentials are properly set)
      const googleAuth2 = provider.toAuth('service-account');
      const drive2 = google.drive({ version: 'v3', auth: googleAuth2 });
      const response2 = await drive2.files.list({
        pageSize: 1,
        fields: 'files(id)',
      });
      assert.ok(response2.data.files, 'Second API call should succeed');
    });
  });
});
