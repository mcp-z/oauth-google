// Calls Google's OAuth token endpoint and the Drive API with the configured service account key.
import '../lib/env-loader.ts';
import type { AuthContext, EnrichedExtra, ToolModule } from '@mcp-z/oauth-google';
import { ServiceAccountProvider } from '@mcp-z/oauth-google';
import type { CallToolResult } from '@modelcontextprotocol/server';
import assert from 'assert';
import { requiredEnv } from 'portable-env';
import { driveFor } from '../lib/google-clients.ts';
import { createTestExtra, logger } from '../lib/test-utils.ts';

describe('ServiceAccountProvider (live)', () => {
  const scopes = ['https://www.googleapis.com/auth/drive.readonly'];
  let keyFilePath: string;

  before(() => {
    keyFilePath = requiredEnv('GOOGLE_SERVICE_ACCOUNT_KEY_FILE');
  });

  it('mints an access token and reuses it on the same provider', async () => {
    const provider = new ServiceAccountProvider({ keyFilePath, scopes, logger });

    const token1 = await provider.getAccessToken('service-account');
    const token2 = await provider.getAccessToken('service-account');

    assert.ok(token1.length > 0, 'Google should return an access token');
    assert.strictEqual(token2, token1, 'A cached token should be reused until it expires');
  });

  it('toAuthProvider token is accepted by the Drive API', async () => {
    const provider = new ServiceAccountProvider({ keyFilePath, scopes, logger });
    const token = await provider.toAuthProvider('service-account').getAccessToken();

    const { data } = await driveFor(token).files.list({ pageSize: 5, fields: 'files(id, name),nextPageToken', q: 'trashed = false' });

    assert.ok(Array.isArray(data.files), 'Drive should return a files array');
  });

  it('serves concurrent Drive calls from one provider', async () => {
    const auth = new ServiceAccountProvider({ keyFilePath, scopes, logger }).toAuthProvider('service-account');

    const responses = await Promise.all(
      Array.from({ length: 3 }, async () =>
        driveFor(await auth.getAccessToken())
          .files.list({ pageSize: 1, fields: 'files(id)', q: 'trashed = false' })
          .then((response) => response.data)
      )
    );

    for (const data of responses) assert.ok(Array.isArray(data.files), 'Each concurrent call should return a files array');
  });

  it('authMiddleware injects the service-account auth context', async () => {
    const provider = new ServiceAccountProvider({ keyFilePath, scopes, logger });
    let received: AuthContext | undefined;
    const testTool = {
      name: 'test-tool',
      config: { inputSchema: {}, outputSchema: {} },
      handler: async (_args: unknown, extra: unknown) => {
        received = (extra as EnrichedExtra).authContext;
        return { content: [{ type: 'text', text: 'success' }] };
      },
    } as unknown as ToolModule;

    const wrappedTool = provider.authMiddleware().withToolAuth(testTool);
    await (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, createTestExtra({ _meta: {} }));

    assert.ok(received, 'authContext should be injected');
    assert.strictEqual(received.accountId, 'service-account');
    assert.strictEqual(received.metadata?.serviceEmail, await provider.getUserEmail());
    assert.ok((await received.auth.getAccessToken()).length > 0, 'Injected auth should provide a token');
  });
});
