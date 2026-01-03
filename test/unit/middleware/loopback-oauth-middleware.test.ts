/**
 * LoopbackOAuthProvider Middleware Tests
 *
 * Tests for authMiddleware() behavior across different account scenarios.
 * Validates auth client creation, context injection, and account switching.
 *
 * Security Model: Loopback OAuth with server-managed token storage
 */

import '../../lib/env-loader.ts';
import { addAccount, type CachedToken, createAccountKey, createServiceKey, getActiveAccount, getToken, removeAccount, setActiveAccount } from '@mcp-z/oauth';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import assert from 'assert';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as os from 'os';
import * as path from 'path';
import { z } from 'zod';
import { type EnrichedExtra, LoopbackOAuthProvider, type ToolModule } from '../../../src/index.ts';
import { AuthRequiredError } from '../../../src/types.ts';
import { GOOGLE_SCOPE } from '../../constants.ts';
import { createConfig } from '../../lib/config.ts';
import { createTestExtra, logger } from '../../lib/test-utils.ts';

const config = createConfig();

let sharedTokenStore: Keyv;
let sharedAuthProvider: LoopbackOAuthProvider;
let realTokenData: CachedToken;

const resetServiceState = async (service: string): Promise<void> => {
  await sharedTokenStore.delete(createServiceKey('active', { service }));
  await sharedTokenStore.delete(createServiceKey('linked', { service }));
};

before(async () => {
  // Load real token from test setup (package-local)
  const tokenStorePath = path.join(process.cwd(), '.tokens/test/store.json');

  const testTokenStore = new Keyv({
    store: new KeyvFile({ filename: tokenStorePath }),
  });

  // Find test account
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

  // Clone real token store to avoid mutating .tokens during tests.
  const tempTokenStorePath = path.join(os.tmpdir(), `oauth-google-loopback-${Date.now()}.json`);
  const tempTokenStore = new Keyv({
    store: new KeyvFile({ filename: tempTokenStorePath }),
  });
  // Copy token keys from real store into temp store (avoid active/linked keys).
  const testIterator = testTokenStore.iterator?.(undefined);
  if (testIterator) {
    for await (const [key, value] of testIterator) {
      const keyString = String(key);
      if (keyString.includes(':token')) {
        await tempTokenStore.set(keyString, value);
      }
    }
  }
  sharedTokenStore = tempTokenStore;

  // Create production LoopbackOAuthProvider
  sharedAuthProvider = new LoopbackOAuthProvider({
    service: 'gmail',
    clientId: config.clientId,
    clientSecret: config.clientSecret || undefined,
    scope: GOOGLE_SCOPE,
    headless: true,
    logger,
    tokenStore: sharedTokenStore,
  });
});

beforeEach(async () => {
  await resetServiceState('gmail');
  await resetServiceState('service-a');
  await resetServiceState('service-b');
});

// Simple output schema for testing
const testOutputSchema = {
  result: z.discriminatedUnion('type', [
    z.object({
      type: z.literal('success'),
      message: z.string(),
    }),
  ]),
} as const;

// ============================================================================
// Test Helpers
// ============================================================================

// Helper: Setup test context with accounts
async function setupTestContext(accounts: string[]): Promise<{ middleware: ReturnType<typeof sharedAuthProvider.authMiddleware> }> {
  for (const account of accounts) {
    await sharedTokenStore.set(createAccountKey('token', { accountId: account, service: 'gmail' }), realTokenData);
    await addAccount(sharedTokenStore, { service: 'gmail', accountId: account });
  }
  if (accounts.length > 0) {
    // Simulate account tool selection to avoid OAuth during middleware tests.
    await setActiveAccount(sharedTokenStore, { service: 'gmail', accountId: accounts[0] });
  }
  return { middleware: sharedAuthProvider.authMiddleware() };
}

// Helper: Create tool that captures extra fields
function createCapturingTool<T>(capture: (extra: EnrichedExtra) => T): { captured: T[]; toolModule: ToolModule } {
  const captured: T[] = [];
  const handler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
    captured.push(capture(extra));
    return { content: [{ type: 'text', text: 'success' }] };
  };
  return {
    captured,
    toolModule: { name: 'test-tool', config: { inputSchema: {}, outputSchema: testOutputSchema }, handler } as unknown as ToolModule,
  };
}

// Type aliases for handler functions
type Handler = (args: unknown, extra: unknown) => Promise<unknown>;
type AuthRequiredHandler = (args: unknown, extra: unknown) => Promise<{ structuredContent?: { result?: { type?: string } } }>;

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

// ============================================================================
// Basic Functionality Tests
// ============================================================================

describe('LoopbackOAuthProvider Middleware - Basic Functionality', () => {
  it('creates middleware wrapper function', async () => {
    const { middleware } = await setupTestContext(['alice@gmail.com']);
    assert.strictEqual(typeof middleware.withToolAuth, 'function');
  });

  it('creates auth client for account', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'alice@gmail.com',
        service: 'gmail',
      }),
      realTokenData
    );
    await addAccount(sharedTokenStore, {
      service: 'gmail',
      accountId: 'alice@gmail.com',
    });

    const middleware = sharedAuthProvider.authMiddleware();

    let capturedExtra: EnrichedExtra | null = null;

    const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      capturedExtra = extra;
      return {
        content: [{ type: 'text', text: 'success' }],
      };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);

    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, { ...createTestExtra(), _meta: { accountId: 'alice@gmail.com' } });

    assert.ok(capturedExtra, 'Extra should be captured');
    const extra = capturedExtra as EnrichedExtra;
    assert.ok(extra.authContext, 'Auth context should exist');
    assert.strictEqual(extra.authContext.accountId, 'alice@gmail.com');
    assert.ok(extra.authContext.auth, 'Auth client should exist');
  });

  it('enriches extra with auth context', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'bob@gmail.com',
        service: 'gmail',
      }),
      realTokenData
    );
    await addAccount(sharedTokenStore, {
      service: 'gmail',
      accountId: 'bob@gmail.com',
    });

    const middleware = sharedAuthProvider.authMiddleware();

    let capturedExtra: EnrichedExtra | null = null;

    const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      capturedExtra = extra;
      return {
        content: [{ type: 'text', text: 'success' }],
      };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);
    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, { ...createTestExtra(), _meta: { accountId: 'bob@gmail.com' } });

    assert.ok(capturedExtra, 'Extra should be captured');
    const extra = capturedExtra as EnrichedExtra;
    assert.ok(extra.authContext, 'Auth context should exist');
  });

  it('preserves account ID in auth context', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'charlie@gmail.com',
        service: 'gmail',
      }),
      realTokenData
    );
    await addAccount(sharedTokenStore, {
      service: 'gmail',
      accountId: 'charlie@gmail.com',
    });
    await setActiveAccount(sharedTokenStore, {
      service: 'gmail',
      accountId: 'charlie@gmail.com',
    });

    const middleware = sharedAuthProvider.authMiddleware();

    let capturedAccountId: string | null = null;

    const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      capturedAccountId = extra.authContext.accountId;
      return {
        content: [{ type: 'text', text: 'success' }],
      };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);
    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, createTestExtra());

    assert.strictEqual(capturedAccountId, 'charlie@gmail.com');
  });

  it('handler receives guaranteed auth (middleware catches errors)', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'valid@gmail.com',
        service: 'gmail',
      }),
      realTokenData
    );
    await addAccount(sharedTokenStore, {
      service: 'gmail',
      accountId: 'valid@gmail.com',
    });
    await setActiveAccount(sharedTokenStore, {
      service: 'gmail',
      accountId: 'valid@gmail.com',
    });

    const middleware = sharedAuthProvider.authMiddleware();

    let handlerCalled = false;

    const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      handlerCalled = true;
      assert.ok(extra.authContext.auth);
      return {
        content: [{ type: 'text', text: 'success' }],
      };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);
    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, createTestExtra());

    assert.ok(handlerCalled, 'Handler should have been called');
  });

  it('handles arg-less tools correctly', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'argless@gmail.com',
        service: 'gmail',
      }),
      realTokenData
    );
    await addAccount(sharedTokenStore, {
      service: 'gmail',
      accountId: 'argless@gmail.com',
    });
    await setActiveAccount(sharedTokenStore, {
      service: 'gmail',
      accountId: 'argless@gmail.com',
    });

    const middleware = sharedAuthProvider.authMiddleware();

    let capturedArgs: unknown = null;
    let capturedExtra: EnrichedExtra | null = null;

    const testHandler = async (args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      capturedArgs = args;
      capturedExtra = extra;
      return {
        content: [{ type: 'text', text: 'success' }],
      };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);

    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, createTestExtra());

    assert.deepStrictEqual(capturedArgs, {});
    assert.ok(capturedExtra, 'Extra should be captured');
    const extra = capturedExtra as EnrichedExtra;
    assert.ok(extra.authContext);
  });

  it('handles special characters in account ID', async () => {
    const specialAccount = 'user+test@gmail.com';
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: specialAccount,
        service: 'gmail',
      }),
      realTokenData
    );
    await addAccount(sharedTokenStore, {
      service: 'gmail',
      accountId: specialAccount,
    });
    await setActiveAccount(sharedTokenStore, {
      service: 'gmail',
      accountId: specialAccount,
    });

    const middleware = sharedAuthProvider.authMiddleware();

    let capturedAccountId: string | null = null;

    const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      capturedAccountId = extra.authContext.accountId;
      return {
        content: [{ type: 'text', text: 'success' }],
      };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);
    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, createTestExtra());

    assert.strictEqual(capturedAccountId, specialAccount);
  });
});

// ============================================================================
// Multi-Account Switching Tests
// ============================================================================

describe('LoopbackOAuthProvider Middleware - Multi-Account Switching', () => {
  it('uses active account from tokenStore', async () => {
    const { middleware } = await setupTestContext(['alice@gmail.com']);
    const { captured, toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);
    await (wrapped.handler as Handler)({}, createTestExtra());
    assert.strictEqual(captured[0], 'alice@gmail.com');
  });

  it('switches accounts when active account changes', async () => {
    const { middleware } = await setupTestContext(['alice@gmail.com', 'bob@gmail.com']);
    const { captured, toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    await (wrapped.handler as Handler)({}, createTestExtra());
    await setActiveAccount(sharedTokenStore, { service: 'gmail', accountId: 'bob@gmail.com' });
    await (wrapped.handler as Handler)({}, createTestExtra());

    assert.deepStrictEqual(captured, ['alice@gmail.com', 'bob@gmail.com']);
  });

  it('supports backchannel override via _meta.accountId', async () => {
    const { middleware } = await setupTestContext(['alice@gmail.com']);
    await sharedTokenStore.set(createAccountKey('token', { accountId: 'bob@gmail.com', service: 'gmail' }), realTokenData);

    const { captured, toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);
    await (wrapped.handler as Handler)({}, { ...createTestExtra(), _meta: { accountId: 'bob@gmail.com' } });
    assert.strictEqual(captured[0], 'bob@gmail.com');
  });

  it('backchannel override takes precedence over active account', async () => {
    const { middleware } = await setupTestContext(['alice@gmail.com']);
    await sharedTokenStore.set(createAccountKey('token', { accountId: 'bob@gmail.com', service: 'gmail' }), realTokenData);
    await sharedTokenStore.set(createAccountKey('token', { accountId: 'charlie@gmail.com', service: 'gmail' }), realTokenData);

    const { captured, toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    await (wrapped.handler as Handler)({}, createTestExtra());
    await (wrapped.handler as Handler)({}, { ...createTestExtra(), _meta: { accountId: 'bob@gmail.com' } });
    await (wrapped.handler as Handler)({}, { ...createTestExtra(), _meta: { accountId: 'charlie@gmail.com' } });
    await (wrapped.handler as Handler)({}, createTestExtra());

    assert.deepStrictEqual(captured, ['alice@gmail.com', 'bob@gmail.com', 'charlie@gmail.com', 'alice@gmail.com']);
  });

  it('handles multiple services independently', async () => {
    // Seed two independent services in the same store
    await sharedTokenStore.set(createAccountKey('token', { accountId: 'service-a-user@example.com', service: 'service-a' }), realTokenData);
    await addAccount(sharedTokenStore, { service: 'service-a', accountId: 'service-a-user@example.com' });
    await setActiveAccount(sharedTokenStore, { service: 'service-a', accountId: 'service-a-user@example.com' });

    await sharedTokenStore.set(createAccountKey('token', { accountId: 'service-b-user@example.com', service: 'service-b' }), realTokenData);
    await addAccount(sharedTokenStore, { service: 'service-b', accountId: 'service-b-user@example.com' });
    await setActiveAccount(sharedTokenStore, { service: 'service-b', accountId: 'service-b-user@example.com' });

    const serviceAProvider = new LoopbackOAuthProvider({
      service: 'service-a',
      clientId: config.clientId,
      clientSecret: config.clientSecret || undefined,
      scope: GOOGLE_SCOPE,
      headless: true,
      logger,
      tokenStore: sharedTokenStore,
    });
    const serviceBProvider = new LoopbackOAuthProvider({
      service: 'service-b',
      clientId: config.clientId,
      clientSecret: config.clientSecret || undefined,
      scope: GOOGLE_SCOPE,
      headless: true,
      logger,
      tokenStore: sharedTokenStore,
    });

    const serviceAAuth = serviceAProvider.authMiddleware();
    const serviceBAuth = serviceBProvider.authMiddleware();

    const { captured: serviceACaptured, toolModule: serviceATool } = createCapturingTool((e) => e.authContext.accountId);
    const { captured: serviceBCaptured, toolModule: serviceBTool } = createCapturingTool((e) => e.authContext.accountId);

    const wrappedServiceA = serviceAAuth.withToolAuth(serviceATool);
    const wrappedServiceB = serviceBAuth.withToolAuth(serviceBTool);

    await (wrappedServiceA.handler as Handler)({}, createTestExtra());
    await (wrappedServiceB.handler as Handler)({}, createTestExtra());

    assert.strictEqual(serviceACaptured[0], 'service-a-user@example.com');
    assert.strictEqual(serviceBCaptured[0], 'service-b-user@example.com');
  });

  it('preserves _meta fields other than accountId', async () => {
    const { middleware } = await setupTestContext(['alice@gmail.com']);
    const { captured, toolModule } = createCapturingTool((e) => e._meta);
    const wrapped = middleware.withToolAuth(toolModule);

    await (wrapped.handler as Handler)({}, { ...createTestExtra(), _meta: { accountId: 'alice@gmail.com', customField: 'test-value' } });

    assert.ok(captured[0]);
    assert.strictEqual((captured[0] as { accountId?: string; customField?: string }).accountId, 'alice@gmail.com');
    assert.strictEqual((captured[0] as { accountId?: string; customField?: string }).customField, 'test-value');
  });

  it('enriches extra with authContext (logger added by separate middleware)', async () => {
    const { middleware } = await setupTestContext(['alice@gmail.com']);
    const { captured, toolModule } = createCapturingTool((e) => e.authContext);
    const wrapped = middleware.withToolAuth(toolModule);

    await (wrapped.handler as Handler)({}, { ...createTestExtra(), _meta: { accountId: 'alice@gmail.com' } });

    // Verify authContext was injected
    assert.ok(captured[0], 'authContext should be present');
    assert.ok(captured[0].auth, 'authContext should have auth client');
    assert.strictEqual(captured[0].accountId, 'alice@gmail.com');

    // Note: logger is NOT injected by auth middleware - that's done by separate logging middleware
  });

  it('handles account switching with null intermediate state', async () => {
    class ConditionalAuthProvider extends LoopbackOAuthProvider {
      async getAccessToken(accountId?: string): Promise<string> {
        const effectiveAccountId = accountId ?? (await getActiveAccount(sharedTokenStore, { service: 'service-a' }));
        if (effectiveAccountId) {
          const token = await getToken<CachedToken>(sharedTokenStore, { accountId: effectiveAccountId, service: 'service-a' });
          if (token?.accessToken) {
            return token.accessToken;
          }
        }
        throw new AuthRequiredError({
          kind: 'auth_url',
          provider: 'service-a',
          url: 'https://example.test/auth',
        });
      }
    }

    const middleware = new ConditionalAuthProvider({
      service: 'service-a',
      clientId: config.clientId,
      clientSecret: config.clientSecret || undefined,
      scope: GOOGLE_SCOPE,
      headless: true,
      logger,
      tokenStore: sharedTokenStore,
    }).authMiddleware();

    await sharedTokenStore.set(createAccountKey('token', { accountId: 'user-a@example.com', service: 'service-a' }), realTokenData);
    await addAccount(sharedTokenStore, { service: 'service-a', accountId: 'user-a@example.com' });
    await sharedTokenStore.set(createAccountKey('token', { accountId: 'user-b@example.com', service: 'service-a' }), realTokenData);

    const { toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    await (wrapped.handler as Handler)({}, { ...createTestExtra(), _meta: { accountId: 'user-a@example.com' } });
    await removeAccount(sharedTokenStore, { service: 'service-a', accountId: 'user-a@example.com' });

    const resultNoAccount = await (wrapped.handler as AuthRequiredHandler)({}, createTestExtra());
    assert.strictEqual(resultNoAccount.structuredContent?.result?.type, 'auth_required');

    await addAccount(sharedTokenStore, { service: 'service-a', accountId: 'user-b@example.com' });
    await (wrapped.handler as Handler)({}, { ...createTestExtra(), _meta: { accountId: 'user-b@example.com' } });
  });

  it('supports rapid account switching without state pollution', async () => {
    const { middleware } = await setupTestContext(['alice@gmail.com', 'bob@gmail.com', 'charlie@gmail.com']);
    const { captured, toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    await (wrapped.handler as Handler)({}, createTestExtra());
    await setActiveAccount(sharedTokenStore, { service: 'gmail', accountId: 'bob@gmail.com' });
    await (wrapped.handler as Handler)({}, createTestExtra());
    await setActiveAccount(sharedTokenStore, { service: 'gmail', accountId: 'charlie@gmail.com' });
    await (wrapped.handler as Handler)({}, createTestExtra());
    await setActiveAccount(sharedTokenStore, { service: 'gmail', accountId: 'alice@gmail.com' });
    await (wrapped.handler as Handler)({}, createTestExtra());

    assert.deepStrictEqual(captured, ['alice@gmail.com', 'bob@gmail.com', 'charlie@gmail.com', 'alice@gmail.com']);
  });

  it('concurrent requests with different overrides use correct accounts', async () => {
    const { middleware } = await setupTestContext(['alice@gmail.com']);
    await sharedTokenStore.set(createAccountKey('token', { accountId: 'bob@gmail.com', service: 'gmail' }), realTokenData);

    const { captured, toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    await Promise.all([(wrapped.handler as Handler)({}, createTestExtra()), (wrapped.handler as Handler)({}, { ...createTestExtra(), _meta: { accountId: 'bob@gmail.com' } }), (wrapped.handler as Handler)({}, createTestExtra())]);

    assert.strictEqual(captured.length, 3);
    const aliceCount = captured.filter((id) => id === 'alice@gmail.com').length;
    const bobCount = captured.filter((id) => id === 'bob@gmail.com').length;
    assert.strictEqual(aliceCount, 2);
    assert.strictEqual(bobCount, 1);
  });

  it('multiple tool calls use same account when not switching', async () => {
    await sharedTokenStore.set(
      createAccountKey('token', {
        accountId: 'fixed@gmail.com',
        service: 'gmail',
      }),
      realTokenData
    );
    await addAccount(sharedTokenStore, {
      service: 'gmail',
      accountId: 'fixed@gmail.com',
    });
    await setActiveAccount(sharedTokenStore, {
      service: 'gmail',
      accountId: 'fixed@gmail.com',
    });

    const middleware = sharedAuthProvider.authMiddleware();

    const accountIds: string[] = [];

    const testHandler = async (_args: unknown, extra: EnrichedExtra): Promise<CallToolResult> => {
      accountIds.push(extra.authContext.accountId);
      return {
        content: [{ type: 'text', text: 'success' }],
      };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);

    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, { ...createTestExtra(), _meta: { accountId: 'fixed@gmail.com' } });
    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, { ...createTestExtra(), _meta: { accountId: 'fixed@gmail.com' } });
    await (toolModule.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, { ...createTestExtra(), _meta: { accountId: 'fixed@gmail.com' } });

    assert.strictEqual(accountIds.length, 3);
    assert.ok(accountIds.every((id) => id === 'fixed@gmail.com'));
  });
});

// ============================================================================
// Error Handling Tests
// ============================================================================

describe('LoopbackOAuthProvider Middleware - Error Handling', () => {
  const createAuthRequiredProvider = () =>
    new AuthRequiredLoopbackProvider({
      service: 'service-a',
      clientId: config.clientId,
      clientSecret: config.clientSecret || undefined,
      scope: GOOGLE_SCOPE,
      headless: true,
      logger,
      tokenStore: sharedTokenStore,
    });

  it('throws error for missing token when handler is called', async () => {
    const middleware = createAuthRequiredProvider().authMiddleware();

    const testHandler = async (_args: unknown, _extra: EnrichedExtra): Promise<CallToolResult> => {
      return { content: [{ type: 'text', text: 'should not reach here' }] };
    };

    const toolModule = middleware.withToolAuth({
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: testOutputSchema },
      handler: testHandler,
    } as unknown as ToolModule);

    const result = await (toolModule.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, createTestExtra());
    assert.ok(result.structuredContent);
    assert.strictEqual((result.structuredContent as { result?: { type: string } }).result?.type, 'auth_required', 'Should return auth_required when token is missing');
  });

  it('throws error when no active account is set', async () => {
    const middleware = createAuthRequiredProvider().authMiddleware();
    const { toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    const result = await (wrapped.handler as AuthRequiredHandler)({}, createTestExtra());
    assert.ok(result.structuredContent);
    assert.strictEqual(result.structuredContent.result?.type, 'auth_required');
  });

  it('throws error when active account has no token', async () => {
    await addAccount(sharedTokenStore, { service: 'service-a', accountId: 'missing@example.com' });

    const middleware = createAuthRequiredProvider().authMiddleware();
    const { toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    const result = await (wrapped.handler as AuthRequiredHandler)({}, createTestExtra());
    assert.ok(result.structuredContent);
    assert.strictEqual(result.structuredContent.result?.type, 'auth_required');
  });

  it('backchannel override with invalid account fails gracefully', async () => {
    const { middleware } = { middleware: createAuthRequiredProvider().authMiddleware() };
    const { toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = middleware.withToolAuth(toolModule);

    const result = await (wrapped.handler as AuthRequiredHandler)({}, { ...createTestExtra(), _meta: { accountId: 'invalid@example.com' } });
    assert.strictEqual(result.structuredContent?.result?.type, 'auth_required');
  });

  it('rejects unauthorized account access (security)', async () => {
    const { toolModule } = createCapturingTool((e) => e.authContext.accountId);
    const wrapped = createAuthRequiredProvider().authMiddleware().withToolAuth(toolModule);

    const bobResult = await (wrapped.handler as AuthRequiredHandler)({}, { ...createTestExtra(), _meta: { accountId: 'user-b@example.com' } });
    assert.strictEqual(bobResult.structuredContent?.result?.type, 'auth_required');

    const aliceResult = await (wrapped.handler as AuthRequiredHandler)({}, { ...createTestExtra(), _meta: { accountId: 'user-a@example.com' } });
    assert.strictEqual(aliceResult.structuredContent?.result?.type, 'auth_required');
  });
});
