/**
 * DCR Router Refresh Tests (Google)
 *
 * Tests the /oauth/token endpoint with grant_type=refresh_token
 * Calls Google's real token endpoint and checks both DCR and provider-token persistence.
 */

import '../lib/env-loader.ts';
import assert from 'assert';
import { randomUUID } from 'crypto';
import { mkdir, unlink } from 'fs/promises';
import getPort from 'get-port';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import * as dcrUtils from '../../src/lib/dcr-utils.ts';
import type { AccessToken } from '../../src/types.ts';
import { GOOGLE_SCOPE } from '../lib/constants.ts';
import { startDcrTestServer } from '../lib/servers/dcr-test-server.ts';

interface DcrTokenData {
  clientId: string;
  clientSecret: string;
  providerRefreshToken: string;
  providerAccessToken: string;
  providerExpiresAt: number;
}

/**
 * Load stored DCR tokens from test-setup
 */
async function loadDcrTokens(): Promise<DcrTokenData | undefined> {
  const dcrTokenPath = path.join(process.cwd(), '.tokens/dcr.json');
  const dcrStore = new Keyv({
    store: new KeyvFile({ filename: dcrTokenPath }),
  });
  try {
    return (await dcrStore.get('google')) as DcrTokenData | undefined;
  } finally {
    await dcrStore.disconnect();
  }
}

describe('DCR Router Refresh Tests (Google)', () => {
  let dcrCleanup: (() => Promise<void>) | undefined;
  let serverStore: Keyv;
  let activeServerStore: Keyv | undefined;
  let serverStorePath: string | undefined;

  afterEach(async () => {
    if (dcrCleanup) {
      await dcrCleanup();
      dcrCleanup = undefined;
    }
    if (activeServerStore) {
      await activeServerStore.disconnect();
      activeServerStore = undefined;
    }
    if (serverStorePath) {
      try {
        await unlink(serverStorePath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      serverStorePath = undefined;
    }
  });

  it('should refresh DCR token and return new access token', async function () {
    this.timeout(30000);

    // Load stored tokens from test-setup
    const storedTokens = await loadDcrTokens();
    if (!storedTokens) {
      throw new Error('No stored DCR tokens found. Run npm run test:setup first to create test tokens.');
    }

    // DCR credentials - completely separate from loopback credentials
    const clientId = process.env.GOOGLE_TEST_DCR_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_TEST_DCR_CLIENT_SECRET;
    if (!clientId || !clientSecret) {
      throw new Error('GOOGLE_TEST_DCR_CLIENT_ID and GOOGLE_TEST_DCR_CLIENT_SECRET environment variables required. Configure in .env.test');
    }

    // Get dynamic port to avoid conflicts
    const port = await getPort();
    const baseUrl = `http://127.0.0.1:${port}`;
    await mkdir(path.resolve('.tmp'), { recursive: true });
    serverStorePath = path.resolve('.tmp', `dcr-refresh-${randomUUID()}.json`);
    const persistentStore = new Keyv({ store: new KeyvFile({ filename: serverStorePath }) });

    // Start DCR test server
    const serverResult = await startDcrTestServer({
      port,
      baseUrl,
      scopes: [GOOGLE_SCOPE],
      clientId,
      clientSecret,
      store: persistentStore,
    });
    dcrCleanup = serverResult.close;
    serverStore = serverResult.store;
    activeServerStore = serverStore;

    // Register a client in the server's store (client_id and client_secret are generated)
    const registeredClient = await dcrUtils.registerClient(serverStore, {
      client_name: 'Test Refresh Client',
      redirect_uris: ['http://localhost:9999/callback'],
    });
    const testClientId = registeredClient.client_id;
    const testClientSecret = registeredClient.client_secret;
    if (!testClientSecret) throw new Error('registerClient must return client_secret');

    // Create initial access token with provider tokens in server store
    const initialAccessToken = `initial-access-token-${Date.now()}`;
    const refreshToken = `dcr-refresh-token-${Date.now()}`;
    const initialTokenData: AccessToken = {
      access_token: initialAccessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: refreshToken,
      scope: GOOGLE_SCOPE,
      client_id: testClientId,
      providerTokens: {
        accessToken: storedTokens.providerAccessToken,
        refreshToken: storedTokens.providerRefreshToken,
        expiresAt: storedTokens.providerExpiresAt,
      },
      created_at: Date.now(),
    };

    await dcrUtils.setAccessToken(serverStore, initialAccessToken, initialTokenData);
    await dcrUtils.setRefreshToken(serverStore, refreshToken, initialTokenData);
    await dcrUtils.setProviderTokens(serverStore, initialAccessToken, initialTokenData.providerTokens);

    console.log('✅ Initial tokens set up in server store');

    // Call /oauth/token with grant_type=refresh_token
    const tokenResponse = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: testClientId,
        client_secret: testClientSecret,
      }).toString(),
    });

    assert.ok(tokenResponse.ok, `Token refresh should succeed, got ${tokenResponse.status}`);

    const tokenData = (await tokenResponse.json()) as {
      access_token: string;
      token_type: string;
      expires_in: number;
      scope?: string;
    };

    assert.ok(tokenData.access_token, 'Should return new access token');
    assert.ok(tokenData.access_token !== initialAccessToken, 'New access token must differ from the previous token');
    assert.strictEqual(tokenData.token_type, 'Bearer', 'Token type should be Bearer');
    console.log('✅ New DCR access token received');

    const refreshedProviderTokens = await dcrUtils.getProviderTokens(serverStore, tokenData.access_token);
    if (!refreshedProviderTokens?.accessToken) throw new Error('Refreshed provider tokens were not stored for the new DCR access token');

    // Save the provider credentials before later checks.
    // This keeps any returned refresh replacement available for the next run.
    storedTokens.providerAccessToken = refreshedProviderTokens.accessToken;
    storedTokens.providerRefreshToken = refreshedProviderTokens.refreshToken ?? storedTokens.providerRefreshToken;
    storedTokens.providerExpiresAt = refreshedProviderTokens.expiresAt ?? storedTokens.providerExpiresAt;
    const dcrTokenPath = path.join(process.cwd(), '.tokens/dcr.json');
    const dcrStore = new Keyv({ store: new KeyvFile({ filename: dcrTokenPath }) });
    const persistedRefreshToken = refreshedProviderTokens.refreshToken ?? storedTokens.providerRefreshToken;
    try {
      await dcrStore.set('google', storedTokens);
    } finally {
      await dcrStore.disconnect();
    }
    const reopenedDcrStore = new Keyv({ store: new KeyvFile({ filename: dcrTokenPath }) });
    try {
      const persisted = (await reopenedDcrStore.get('google')) as DcrTokenData | undefined;
      assert.ok(persisted?.providerAccessToken === refreshedProviderTokens.accessToken, 'Refreshed provider access token must persist');
      assert.ok(persisted?.providerRefreshToken === persistedRefreshToken, 'Any provider refresh replacement must persist');
    } finally {
      await reopenedDcrStore.disconnect();
    }

    const accessBeforeVerify = await dcrUtils.getAccessToken(serverStore, tokenData.access_token);
    if (!accessBeforeVerify) throw new Error('DCR access record was not persisted');
    const expiringTokenData = {
      ...accessBeforeVerify,
      providerTokens: { ...accessBeforeVerify.providerTokens, expiresAt: Date.now() - 1000 },
    };
    await dcrUtils.setAccessToken(serverStore, tokenData.access_token, expiringTokenData);
    await dcrUtils.setRefreshToken(serverStore, refreshToken, expiringTokenData);
    await dcrUtils.setProviderTokens(serverStore, tokenData.access_token, expiringTokenData.providerTokens);
    const accessExpiryBefore = (await serverStore.get<AccessToken>(`dcr:access:${tokenData.access_token}`, { raw: true }))?.expires;
    const refreshExpiryBefore = (await serverStore.get<AccessToken>(`dcr:refresh:${refreshToken}`, { raw: true }))?.expires;
    const providerExpiryBefore = (await serverStore.get(`dcr:provider:${tokenData.access_token}`, { raw: true }))?.expires;
    if (accessExpiryBefore === undefined || refreshExpiryBefore === undefined || providerExpiryBefore === undefined) {
      throw new Error('Expected file-backed DCR records to include expiry metadata');
    }

    // Verify refreshes and persists provider credentials before returning them.
    const verifyResponse = await fetch(`${baseUrl}/oauth/verify`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    assert.ok(verifyResponse.ok, 'New token should be verifiable');
    const verifyData = (await verifyResponse.json()) as {
      token: string;
      providerTokens: { accessToken: string; refreshToken?: string; expiresAt?: number };
    };

    const renewed = await dcrUtils.getRefreshToken(serverStore, refreshToken);
    if (!renewed) throw new Error('DCR refresh record was not persisted after provider refresh');
    storedTokens.providerAccessToken = renewed.providerTokens.accessToken;
    storedTokens.providerRefreshToken = renewed.providerTokens.refreshToken ?? storedTokens.providerRefreshToken;
    storedTokens.providerExpiresAt = renewed.providerTokens.expiresAt ?? storedTokens.providerExpiresAt;
    const sourceStore = new Keyv({ store: new KeyvFile({ filename: dcrTokenPath }) });
    try {
      await sourceStore.set('google', storedTokens);
    } finally {
      await sourceStore.disconnect();
    }

    const accessAfter = await serverStore.get<AccessToken>(`dcr:access:${tokenData.access_token}`, { raw: true });
    const refreshAfter = await serverStore.get<AccessToken>(`dcr:refresh:${refreshToken}`, { raw: true });
    const providerAfter = await serverStore.get(`dcr:provider:${tokenData.access_token}`, { raw: true });
    if (accessAfter?.expires === undefined || refreshAfter?.expires === undefined || providerAfter?.expires === undefined) {
      throw new Error('Refreshed file-backed DCR records must retain expiry metadata');
    }

    assert.ok(verifyData.token === tokenData.access_token, 'Verification must return the submitted DCR access token');
    assert.ok(verifyData.providerTokens.accessToken, 'Should have provider access token');
    assert.ok(renewed.created_at === accessBeforeVerify.created_at, 'Provider refresh must preserve DCR token created_at');
    assert.ok(renewed.expires_in === accessBeforeVerify.expires_in, 'Provider refresh must preserve DCR token expires_in');
    assert.ok(accessAfter.expires <= accessExpiryBefore + 500, 'Verification must not extend the access-token store expiry');
    assert.ok(refreshAfter.expires <= refreshExpiryBefore + 500, 'Verification must not extend the refresh-token store expiry');
    assert.ok(providerAfter.expires <= providerExpiryBefore + 500, 'Verification must not extend the provider-token index expiry');
    const renewedAccess = await dcrUtils.getAccessToken(serverStore, tokenData.access_token);
    assert.ok(renewedAccess?.providerTokens.accessToken === renewed.providerTokens.accessToken, 'Access record must persist the refreshed provider access token');
    assert.ok(renewedAccess?.providerTokens.refreshToken === renewed.providerTokens.refreshToken, 'Access record must persist the provider refresh token');
    assert.ok(renewedAccess?.providerTokens.expiresAt === renewed.providerTokens.expiresAt, 'Access record must persist the provider expiry');
    assert.ok(verifyData.providerTokens.accessToken === renewed.providerTokens.accessToken, 'Verification must return the persisted provider access token');
    assert.ok(verifyData.providerTokens.refreshToken === renewed.providerTokens.refreshToken, 'Verification must return the persisted provider refresh token');
    assert.ok(verifyData.providerTokens.expiresAt === renewed.providerTokens.expiresAt, 'Verification must return the persisted provider expiry');

    const nextVerifyResponse = await fetch(`${baseUrl}/oauth/verify`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    assert.ok(nextVerifyResponse.ok, 'The next request must verify successfully');
    const nextVerifyData = (await nextVerifyResponse.json()) as { providerTokens: { accessToken: string; refreshToken?: string } };
    assert.ok(nextVerifyData.providerTokens.accessToken === verifyData.providerTokens.accessToken, 'The next request must reuse the persisted provider access token');
    assert.ok(nextVerifyData.providerTokens.refreshToken === verifyData.providerTokens.refreshToken, 'The next request must reuse the persisted provider refresh token');
    console.log('✅ New token verified successfully');
    console.log('✅ Router refresh test passed!');
  });

  it('should fail refresh with invalid refresh_token', async function () {
    this.timeout(10000);

    // DCR credentials - completely separate from loopback credentials
    const clientId = process.env.GOOGLE_TEST_DCR_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_TEST_DCR_CLIENT_SECRET;
    if (!clientId || !clientSecret) {
      throw new Error('GOOGLE_TEST_DCR_CLIENT_ID and GOOGLE_TEST_DCR_CLIENT_SECRET environment variables required. Configure in .env.test');
    }

    // Get dynamic port to avoid conflicts
    const port = await getPort();
    const baseUrl = `http://127.0.0.1:${port}`;

    // Start DCR test server
    const serverResult = await startDcrTestServer({
      port,
      baseUrl,
      scopes: [GOOGLE_SCOPE],
      clientId,
      clientSecret,
    });
    dcrCleanup = serverResult.close;
    serverStore = serverResult.store;
    activeServerStore = serverStore;

    // Register a client (client_id and client_secret are generated)
    const registeredClient = await dcrUtils.registerClient(serverStore, {
      client_name: 'Test Invalid Refresh Client',
      redirect_uris: ['http://localhost:9999/callback'],
    });
    const testClientId = registeredClient.client_id;
    const testClientSecret = registeredClient.client_secret;
    if (!testClientSecret) throw new Error('registerClient must return client_secret');

    // Call /oauth/token with invalid refresh_token
    const tokenResponse = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: 'invalid-refresh-token',
        client_id: testClientId,
        client_secret: testClientSecret,
      }).toString(),
    });

    assert.strictEqual(tokenResponse.status, 400, 'Should return 400 for invalid refresh token');

    const errorData = (await tokenResponse.json()) as { error: string; error_description?: string };
    assert.strictEqual(errorData.error, 'invalid_grant', 'Should return invalid_grant error');
    console.log('✅ Invalid refresh token correctly rejected');
  });
});
