/**
 * LoopbackOAuthProvider Integration Tests
 *
 * Comprehensively tests LoopbackOAuthProvider across all scenarios:
 * - Google APIs integration (Drive, Gmail, Sheets)
 * - Single-user middleware functionality
 * - Multi-account support with backchannel overrides
 *
 * Uses real OAuth tokens (run npm run test:setup first)
 */

import '../lib/env-loader.ts';

import { addAccount, type CachedToken, createAccountKey, setActiveAccount, type ToolModule } from '@mcp-z/oauth';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
/**
 * Single-User Mode Integration Tests
 * Tests authMiddleware() with real Google API calls
 */
import assert from 'assert';
import * as fs from 'fs';
import { google } from 'googleapis';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import { LoopbackOAuthProvider } from '../../src/index.ts';
import type { EnrichedExtra } from '../../src/types.ts';
import { AuthRequiredError } from '../../src/types.ts';
import { GOOGLE_SCOPE } from '../constants.ts';
import { createConfig } from '../lib/config.ts';
import { createTestExtra, logger } from '../lib/test-utils.ts';

const config = createConfig();

// Use isolated test token directory
const tokenStorePath = path.join(process.cwd(), '.tokens/test');

// Test-only provider to force auth_required without interactive OAuth.
// Exception to no-mocks rule: this isolates middleware error handling deterministically.
class AuthRequiredLoopbackProvider extends LoopbackOAuthProvider {
  async getAccessToken(): Promise<string> {
    throw new AuthRequiredError({
      kind: 'auth_url',
      provider: 'service-a',
      url: 'https://example.test/auth',
    });
  }
}

describe('LoopbackOAuthProvider Integration Tests', () => {
  describe('Google APIs Integration', () => {
    it('OAuth2Client works with Google Drive API', async () => {
      const tokenStore = new Keyv({
        store: new KeyvFile({ filename: path.join(tokenStorePath, 'store.json') }),
      });

      const auth = new LoopbackOAuthProvider({
        service: 'gmail', // Reuse gmail token (same scopes)
        clientId: config.clientId,
        clientSecret: config.clientSecret || '',
        scope: GOOGLE_SCOPE,
        headless: true,
        logger,
        tokenStore,
      });

      const googleAuth = auth.toAuth(); // Use active account (set by test:setup)
      const drive = google.drive({ version: 'v3', auth: googleAuth });

      const response = await drive.files.list({
        pageSize: 10,
        fields: 'files(id, name)',
      });

      assert.ok(response.data, 'Should get drive data');
      assert.ok(Array.isArray(response.data.files), 'Should have files array');
    });

    it('OAuth2Client works with Google Gmail API', async () => {
      const tokenStore = new Keyv({
        store: new KeyvFile({ filename: path.join(tokenStorePath, 'store.json') }),
      });

      const auth = new LoopbackOAuthProvider({
        service: 'gmail',
        clientId: config.clientId,
        clientSecret: config.clientSecret || undefined,
        scope: GOOGLE_SCOPE,
        headless: true,
        logger,
        tokenStore,
      });

      const googleAuth = auth.toAuth(); // Use active account (set by test:setup)
      const gmail = google.gmail({ version: 'v1', auth: googleAuth });

      const response = await gmail.users.getProfile({ userId: 'me' });

      assert.ok(response.data, 'Should get profile data');
      assert.ok(response.data.emailAddress, 'Should have email address');
      assert.ok(response.data.messagesTotal !== undefined, 'Should have message count');
    });

    it('OAuth2Client works with Google Sheets API', async () => {
      const tokenStore = new Keyv({
        store: new KeyvFile({ filename: path.join(tokenStorePath, 'store.json') }),
      });

      const auth = new LoopbackOAuthProvider({
        service: 'gmail', // Reuse gmail token (same scopes)
        clientId: config.clientId,
        clientSecret: config.clientSecret || '', // Optional for public clients
        scope: GOOGLE_SCOPE,
        headless: true,
        logger,
        tokenStore,
      });

      const googleAuth = auth.toAuth(); // Use active account (set by test:setup)
      const sheets = google.sheets({ version: 'v4', auth: googleAuth });

      // Create a test spreadsheet
      const createResponse = await sheets.spreadsheets.create({
        requestBody: {
          properties: {
            title: 'OAuth Test Spreadsheet',
          },
        },
      });

      assert.ok(createResponse.data.spreadsheetId, 'Should create spreadsheet');

      const spreadsheetId = createResponse.data.spreadsheetId;
      if (!spreadsheetId) {
        throw new Error('Expected spreadsheetId in create response');
      }

      try {
        // Verify we can read it back
        const getResponse = await sheets.spreadsheets.get({
          spreadsheetId,
        });

        assert.ok(getResponse.data, 'Should get spreadsheet data');
        assert.strictEqual(getResponse.data.properties?.title, 'OAuth Test Spreadsheet');
      } finally {
        // Clean up - delete the test spreadsheet
        const drive = google.drive({ version: 'v3', auth: googleAuth });
        await drive.files.delete({ fileId: spreadsheetId });
      }
    });
  });

  /**
   * Middleware Functionality Tests
   * Tests auth middleware and backchannel overrides behavior
   */
  describe('Middleware Functionality', () => {
    let testAccountId: string;
    let authProvider: LoopbackOAuthProvider;
    let middleware: ReturnType<typeof authProvider.authMiddleware>;

    before(async () => {
      const tokenStore = new Keyv({
        store: new KeyvFile({ filename: path.join(tokenStorePath, 'store.json') }),
      });

      authProvider = new LoopbackOAuthProvider({
        service: 'gmail',
        clientId: config.clientId,
        clientSecret: config.clientSecret || undefined,
        scope: 'https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/drive',
        headless: true,
        logger,
        tokenStore,
      });

      testAccountId = await authProvider.getUserEmail();
      await setActiveAccount(tokenStore, { service: 'gmail', accountId: testAccountId });
      middleware = authProvider.authMiddleware();
    });

    // Helper to wrap handler with new ToolModule API
    // Uses double assertion because test tools use minimal mock schemas, not full Zod schemas
    type TestHandler = (args: unknown, extra: unknown) => Promise<{ content: unknown[]; structuredContent?: unknown }>;
    function wrapHandlerWithAuth(handler: unknown, operation: string, schema: unknown): TestHandler {
      const toolModule = {
        name: operation,
        config: { outputSchema: schema },
        handler,
      } as unknown as ToolModule;
      const enhancedToolModule = middleware.withToolAuth(toolModule);
      return enhancedToolModule.handler as TestHandler;
    }

    describe('Single-Account Mode', () => {
      it('uses fixed account for auth context (no override)', async () => {
        let capturedAccountId: string | undefined;
        const testHandler = async (_args: unknown, extra: EnrichedExtra) => {
          capturedAccountId = extra.authContext.accountId;
          return { content: [] };
        };

        const testSchema = { result: {} };
        const wrappedHandler = wrapHandlerWithAuth(testHandler, 'test operation', testSchema);

        await wrappedHandler({}, createTestExtra());
        assert.strictEqual(capturedAccountId, testAccountId, 'Should use fixed account');
      });

      it('supports account override via _meta.accountId', async () => {
        let capturedAccountId: string | undefined;
        const testHandler = async (_args: unknown, extra: EnrichedExtra) => {
          capturedAccountId = extra.authContext.accountId;
          return { content: [] };
        };

        const testSchema = { result: {} };
        const wrappedHandler = wrapHandlerWithAuth(testHandler, 'test operation', testSchema);

        await wrappedHandler({}, createTestExtra({ _meta: { accountId: testAccountId } }));
        assert.strictEqual(capturedAccountId, testAccountId, 'Should allow override');
      });

      it('makes real Google API calls with auth context', async () => {
        let userEmail: string | undefined;
        const testHandler = async (_args: unknown, extra: EnrichedExtra) => {
          const auth = extra.authContext.auth;
          const oauth2 = google.oauth2({ version: 'v2', auth });
          const response = await oauth2.userinfo.get();
          userEmail = response.data.email ?? undefined;
          return { content: [] };
        };

        const testSchema = { result: {} };
        const wrappedHandler = wrapHandlerWithAuth(testHandler, 'get user email', testSchema);

        await wrappedHandler({}, createTestExtra());
        assert.ok(userEmail, 'Should return user email from API');
        assert.ok(userEmail.includes('@'), 'Email should contain @ symbol');
      });

      it('handles concurrent requests consistently', async () => {
        const capturedAccounts: string[] = [];
        const testHandler = async (_args: unknown, extra: EnrichedExtra) => {
          capturedAccounts.push(extra.authContext.accountId);
          return { content: [] };
        };

        const testSchema = { result: {} };
        const wrappedHandler = wrapHandlerWithAuth(testHandler, 'test operation', testSchema);

        await Promise.all(Array.from({ length: 5 }, () => wrappedHandler({}, createTestExtra())));
        assert.equal(capturedAccounts.length, 5, 'Should have 5 results');
        assert.ok(
          capturedAccounts.every((id) => id === testAccountId),
          'All calls should use same account'
        );
      });

      it('handles backchannel overrides consistently', async () => {
        const capturedAccounts: string[] = [];
        const testHandler = async (_args: unknown, extra: EnrichedExtra) => {
          capturedAccounts.push(extra.authContext.accountId);
          return { content: [] };
        };

        const testSchema = { result: {} };
        const wrappedHandler = wrapHandlerWithAuth(testHandler, 'test operation', testSchema);

        await Promise.all([wrappedHandler({}, createTestExtra()), wrappedHandler({}, createTestExtra({ _meta: { accountId: testAccountId } })), wrappedHandler({}, createTestExtra())]);

        assert.equal(capturedAccounts.length, 3, 'Should have 3 results');
        const accountIds = new Set(capturedAccounts);
        assert.equal(accountIds.size, 1, 'All should use the same account');
      });
    });

    describe('Error Handling', () => {
      it('handles missing tokens gracefully (auth_required)', async () => {
        // Create provider with empty token store
        const tokenStore = new Keyv(); // In-memory empty store
        const invalidAuthProvider = new AuthRequiredLoopbackProvider({
          service: 'service-a',
          clientId: config.clientId,
          clientSecret: config.clientSecret || undefined,
          scope: 'https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/drive',
          headless: true,
          logger,
          tokenStore,
        });

        const invalidMiddleware = invalidAuthProvider.authMiddleware();
        const testHandler = async (_args: unknown, extra: EnrichedExtra) => {
          const auth = extra.authContext.auth; // This should fail
          const oauth2 = google.oauth2({ version: 'v2', auth });
          await oauth2.userinfo.get();
          return { content: [] };
        };

        const testSchema = { result: {} };
        // Uses double assertion because test tools use minimal mock schemas
        const toolModule = {
          name: 'test operation',
          config: { outputSchema: testSchema },
          handler: testHandler,
        } as unknown as ToolModule;
        const enhancedToolModule = invalidMiddleware.withToolAuth(toolModule);
        const wrappedHandler = enhancedToolModule.handler as TestHandler;

        const result = await wrappedHandler({}, createTestExtra());
        assert.ok((result as { structuredContent?: unknown }).structuredContent, 'Should return structuredContent');
        assert.strictEqual(((result as { structuredContent?: { result?: { type?: string } } }).structuredContent as { result?: { type: string } }).result?.type, 'auth_required', 'Should return auth_required');
      });

      it('handles backchannel override with missing account (auth_required)', async () => {
        const testHandler = async (_args: unknown, _extra: EnrichedExtra) => {
          // This shouldn't be reached for invalid account
          return { content: [] };
        };

        const testSchema = { result: {} };
        // Uses double assertion because test tools use minimal mock schemas
        const toolModule = {
          name: 'test operation',
          config: { outputSchema: testSchema },
          handler: testHandler,
        } as unknown as ToolModule;
        const enhancedToolModule = new AuthRequiredLoopbackProvider({
          service: 'service-a',
          clientId: config.clientId,
          clientSecret: config.clientSecret || undefined,
          scope: 'https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/drive',
          headless: true,
          logger,
          tokenStore: new Keyv(),
        })
          .authMiddleware()
          .withToolAuth(toolModule);
        const wrappedHandler = enhancedToolModule.handler as TestHandler;

        const result = await wrappedHandler({}, createTestExtra({ _meta: { accountId: 'nonexistent@gmail.com' } }));
        assert.ok((result as { structuredContent?: unknown }).structuredContent, 'Should return structuredContent');
        assert.strictEqual(((result as { structuredContent?: { result?: { type?: string } } }).structuredContent as { result?: { type: string } }).result?.type, 'auth_required', 'Should return auth_required for missing account');
      });
    });
  });

  /**
   * Multi-Account Mode Tests (formerly service-account.test.ts)
   */
  describe('Multi-Account Mode', () => {
    let sharedTokenStore: Keyv;
    let sharedAuthProvider: LoopbackOAuthProvider;
    let realTokenData: CachedToken;

    before(async () => {
      const tokenStorePath = path.join(process.cwd(), '.tokens/test/store.json');
      if (!fs.existsSync(tokenStorePath)) {
        throw new Error(`Token file not found at ${tokenStorePath}. Run \`npm run test:setup\` to generate OAuth token.`);
      }

      const testTokenStore = new Keyv({
        store: new KeyvFile({ filename: tokenStorePath }),
      });

      const allKeys: string[] = [];
      const iterator = testTokenStore.iterator?.(undefined);
      if (iterator) {
        for await (const [key] of iterator) {
          allKeys.push(key);
        }
      }

      const gmailTokenKey = allKeys.find((k) => k.includes(':gmail:token') && !k.includes('user-'));
      if (!gmailTokenKey) {
        throw new Error('No Gmail test token found. Run `npm run test:setup` to generate OAuth token.');
      }

      const tokenData = await testTokenStore.get(gmailTokenKey);
      if (!tokenData?.accessToken) {
        throw new Error('Token found but missing accessToken field. Run `npm run test:setup` to regenerate.');
      }
      realTokenData = tokenData;

      sharedTokenStore = new Keyv();
      sharedAuthProvider = new LoopbackOAuthProvider({
        service: 'gmail',
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        scope: 'https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/drive',
        headless: true,
        logger,
        tokenStore: sharedTokenStore,
      });
    });

    // Clear token store before each test for isolation
    beforeEach(async () => {
      const iterator = sharedTokenStore.iterator?.(undefined);
      if (iterator) {
        for await (const [key] of iterator) {
          await sharedTokenStore.delete(key);
        }
      }
    });

    const testOutputSchema = {
      result: {
        type: 'object',
        properties: {
          message: { type: 'string' },
        },
      },
    } as const;

    it('supports account creation and switching', async () => {
      const tokenStore = sharedTokenStore;

      await sharedTokenStore.set(createAccountKey('token', { accountId: 'alice@gmail.com', service: 'gmail' }), realTokenData);
      await addAccount(tokenStore, { service: 'gmail', accountId: 'alice@gmail.com' });

      const middleware = sharedAuthProvider.authMiddleware();

      let capturedAccountId: string | null = null;
      const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
        capturedAccountId = extra.authContext.accountId;
        return { content: [{ type: 'text', text: 'success' }] };
      };

      const toolModule = middleware.withToolAuth({
        name: 'test-tool',
        config: { inputSchema: {}, outputSchema: testOutputSchema },
        handler: testHandler,
      } as unknown as ToolModule);
      await (toolModule.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, createTestExtra({ _meta: {} }));

      assert.strictEqual(capturedAccountId, 'alice@gmail.com');
    });

    it('supports account switching during runtime', async () => {
      const tokenStore = sharedTokenStore;

      await sharedTokenStore.set(createAccountKey('token', { accountId: 'alice@gmail.com', service: 'gmail' }), realTokenData);
      await sharedTokenStore.set(createAccountKey('token', { accountId: 'bob@gmail.com', service: 'gmail' }), realTokenData);

      await addAccount(tokenStore, { service: 'gmail', accountId: 'alice@gmail.com' });
      await addAccount(tokenStore, { service: 'gmail', accountId: 'bob@gmail.com' });

      const middleware = sharedAuthProvider.authMiddleware();

      const accountIds: string[] = [];

      const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
        accountIds.push(extra.authContext.accountId);
        return { content: [{ type: 'text', text: 'success' }] };
      };

      const toolModule = middleware.withToolAuth({
        name: 'test-tool',
        config: { inputSchema: {}, outputSchema: testOutputSchema },
        handler: testHandler,
      } as unknown as ToolModule);

      // First call with alice
      await (toolModule.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, createTestExtra());

      // Switch to bob
      await setActiveAccount(tokenStore, { service: 'gmail', accountId: 'bob@gmail.com' });

      // Second call with bob
      await (toolModule.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, createTestExtra());

      assert.strictEqual(accountIds.length, 2);
      assert.strictEqual(accountIds[0], 'alice@gmail.com');
      assert.strictEqual(accountIds[1], 'bob@gmail.com');
    });

    it('backs up account switching with _meta.accountId overrides', async () => {
      const tokenStore = sharedTokenStore;

      await sharedTokenStore.set(createAccountKey('token', { accountId: 'alice@gmail.com', service: 'gmail' }), realTokenData);
      await sharedTokenStore.set(createAccountKey('token', { accountId: 'bob@gmail.com', service: 'gmail' }), realTokenData);

      // Alice is active
      await addAccount(tokenStore, { service: 'gmail', accountId: 'alice@gmail.com' });

      const middleware = sharedAuthProvider.authMiddleware();

      let capturedAccountId: string | null = null;

      const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
        capturedAccountId = extra.authContext.accountId;
        return { content: [{ type: 'text', text: 'success' }] };
      };

      const toolModule = middleware.withToolAuth({
        name: 'test-tool',
        config: { inputSchema: {}, outputSchema: testOutputSchema },
        handler: testHandler,
      } as unknown as ToolModule);

      // Override to bob via backchannel
      await (toolModule.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, createTestExtra({ _meta: { accountId: 'bob@gmail.com' } }));

      // Should use bob, not alice
      assert.strictEqual(capturedAccountId, 'bob@gmail.com');
    });
  });
});
