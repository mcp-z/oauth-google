import '../../lib/env-loader.ts';
import { setToken } from '@mcp-z/oauth';
import { LoopbackOAuthProvider } from '@mcp-z/oauth-google';
import assert from 'assert';
import type { Server } from 'http';
import { createServer } from 'http';
import type { AddressInfo } from 'net';
import { createFailingStore } from '../../lib/failing-store.ts';
import { redirectFetch } from '../../lib/redirect-fetch.ts';
import { logger } from '../../lib/test-utils.ts';

const baseConfig = { service: 'gmail' as const, clientId: 'test-client', scope: 'openid', headless: false };

describe('unit/loopback-oauth-store-failures', () => {
  // The abandoned-sign-in timer calls this with `void`; a rejection there was an unhandled rejection that ends the process.
  it('discardAbandonedPendingAuth resolves and logs a warning when the store delete fails', async () => {
    const { store, fail } = createFailingStore();
    fail();
    const warnings: unknown[][] = [];
    const provider = new LoopbackOAuthProvider({ ...baseConfig, logger: { ...logger, warn: (...args: unknown[]) => void warnings.push(args) }, tokenStore: store });

    await (provider as unknown as { discardAbandonedPendingAuth(stateId: string): Promise<void> }).discardAbandonedPendingAuth('state-1');

    assert.strictEqual(warnings.length, 1);
    assert.match(String(warnings[0]?.[0]), /abandoned pending OAuth state/);
  });

  describe('refresh then save', () => {
    let tokenServer: Server;
    let restoreFetch: () => void;

    before(async () => {
      // Controlled token endpoint answering a successful refresh (RFC 6749 section 5.1).
      tokenServer = createServer((_req, res) => {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ access_token: 'fresh-access', expires_in: 3600, token_type: 'Bearer' }));
      });
      await new Promise<void>((resolve) => tokenServer.listen(0, '127.0.0.1', resolve));
      restoreFetch = redirectFetch('oauth2.googleapis.com', `http://127.0.0.1:${(tokenServer.address() as AddressInfo).port}`);
    });

    after(() => {
      restoreFetch();
      tokenServer.close();
    });

    // A save that fails after a good refresh used to be reported as "Token refresh failed, starting new OAuth flow"
    // and fell through to a new sign-in; the storage error must come out as itself.
    it('surfaces a storage failure as itself, not as a failed refresh', async () => {
      const { store, fail } = createFailingStore();
      const infos: string[] = [];
      await setToken(store, { accountId: 'a@example.com', service: 'gmail' }, { accessToken: 'old', refreshToken: 'r', expiresAt: Date.now() - 1000 });
      fail();
      const provider = new LoopbackOAuthProvider({ ...baseConfig, logger: { ...logger, info: (message: unknown) => void infos.push(String(message)) }, tokenStore: store });

      await assert.rejects(provider.getAccessToken('a@example.com'), /store write failed/);
      assert.ok(!infos.some((message) => message.includes('Token refresh failed')), 'must not be reported as a refresh failure');
    });
  });
});
