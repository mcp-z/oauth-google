// Calls Google's token endpoint and userinfo with the existing loopback test account.
// A successful renewal is saved to the original store before any assertion so the credential survives the run.
import '../lib/env-loader.ts';
import { type CachedToken, getActiveAccount, getToken, listAccountIds, setToken } from '@mcp-z/oauth';
import assert from 'assert';
import { mkdir, mkdtemp, rmdir, unlink } from 'fs/promises';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import path from 'path';
import { LoopbackOAuthProvider } from '../../src/providers/loopback-oauth.ts';
import { createConfig } from '../lib/config.ts';
import { GOOGLE_SCOPE } from '../lib/constants.ts';
import { userinfo } from '../lib/google-rest.ts';
import { logger } from '../lib/test-utils.ts';
import { throwFailures } from '../lib/throw-failures.ts';

const config = createConfig();
const SERVICE = 'gmail';

function createProvider(tokenStore: Keyv): LoopbackOAuthProvider {
  return new LoopbackOAuthProvider({ service: SERVICE, clientId: config.clientId, clientSecret: config.clientSecret, scope: GOOGLE_SCOPE, headless: true, logger, tokenStore });
}

/** The configured TEST_ACCOUNT_ID, else the active account, else the only account in the store. */
async function selectTestAccount(store: Keyv): Promise<string> {
  const accounts = await listAccountIds(store, SERVICE);
  const configured = process.env.TEST_ACCOUNT_ID;
  if (configured) {
    assert.ok(accounts.includes(configured), 'TEST_ACCOUNT_ID has no gmail token in .tokens/test/store.json; run npm run test:setup');
    return configured;
  }
  const active = await getActiveAccount(store, { service: SERVICE });
  if (active) return active;
  if (accounts.length === 1 && accounts[0]) return accounts[0];
  throw new Error(`Found ${accounts.length} gmail test accounts and no active account; set TEST_ACCOUNT_ID or run npm run test:setup`);
}

describe('Google unattended token renewal (live)', () => {
  it('fails an invalid loopback refresh in headless mode without requesting consent', async () => {
    const store = new Keyv();
    const params = { accountId: 'invalid-test-account', service: SERVICE };
    const failures: unknown[] = [];
    try {
      await setToken(store, params, { accessToken: 'expired', refreshToken: 'invalid-refresh-token', expiresAt: 1 });
      await assert.rejects(() => createProvider(store).getAccessToken(params.accountId), /Token refresh failed in headless mode/);
      assert.strictEqual((await getToken<CachedToken>(store, params))?.refreshToken, 'invalid-refresh-token');
    } catch (error) {
      failures.push(error);
    }
    await store.disconnect().catch((error: unknown) => failures.push(error));
    throwFailures('Invalid refresh test failed', failures);
  });

  it('renews an expired credential and reuses the persisted value after reopening', async () => {
    const original = new Keyv({ store: new KeyvFile({ filename: path.resolve('.tokens/test/store.json') }) });
    const stores: Keyv[] = [original];
    const owned: { filename?: string; directory?: string } = {};
    let bodyError: unknown;

    try {
      const accountId = await selectTestAccount(original);
      const params = { accountId, service: SERVICE };
      const initial = await getToken<CachedToken>(original, params);
      assert.ok(initial?.refreshToken, 'Test account needs a refresh token; run npm run test:setup');

      await mkdir(path.resolve('.tmp'), { recursive: true });
      owned.directory = await mkdtemp(path.resolve('.tmp/token-renewal-'));
      owned.filename = path.join(owned.directory, 'store.json');
      const scratch = new Keyv({ store: new KeyvFile({ filename: owned.filename }) });
      stores.push(scratch);
      await setToken(scratch, params, { ...initial, expiresAt: 1 });

      const accessToken = await createProvider(scratch).getAccessToken(accountId);
      const refreshed = await getToken<CachedToken>(scratch, params);
      if (refreshed) await setToken(original, params, refreshed);

      assert.ok(refreshed, 'Renewal must persist a credential');
      assert.strictEqual(refreshed.accessToken, accessToken, 'Returned access token must match the stored credential');
      assert.ok(refreshed.refreshToken, 'Renewal must keep a refresh credential');
      assert.ok(refreshed.expiresAt !== undefined && refreshed.expiresAt > Date.now(), 'Renewal must advance expiry');

      await scratch.disconnect();
      stores.splice(stores.indexOf(scratch), 1);
      const reopened = new Keyv({ store: new KeyvFile({ filename: owned.filename }) });
      stores.push(reopened);
      assert.strictEqual(await createProvider(reopened).getAccessToken(accountId), accessToken, 'Reopened store must reuse the persisted credential');

      const { email } = await userinfo(accessToken);
      assert.strictEqual(email, accountId, 'Renewed credential must identify the test account');
    } catch (error) {
      bodyError = error;
    }

    const cleanupErrors: unknown[] = [];
    for (const store of stores) await store.disconnect().catch((error: unknown) => cleanupErrors.push(error));
    if (owned.filename) await unlink(owned.filename).catch((error: unknown) => cleanupErrors.push(error));
    if (owned.directory) await rmdir(owned.directory).catch((error: unknown) => cleanupErrors.push(error));
    throwFailures('Token renewal test and cleanup failed', bodyError === undefined ? cleanupErrors : [bodyError, ...cleanupErrors]);
  });
});
