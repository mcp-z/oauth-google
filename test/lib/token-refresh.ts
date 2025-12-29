/**
 * Token Refresh Utilities for Integration Tests
 *
 * Provides automatic token refresh for MCP OAuth integration tests.
 * Prevents test failures due to expired tokens by checking expiry and
 * refreshing when needed.
 *
 * Design:
 * - Checks token expiry before returning (< 5 min threshold)
 * - Auto-refreshes using Google OAuth API
 * - FAILS FAST with clear error if refresh fails (no silent fallback)
 * - Updates token store with refreshed tokens
 */

import { createAccountKey } from '@mcp-z/oauth';
import type Keyv from 'keyv';

/**
 * Cached token format matching LoopbackOAuthProvider
 */
export interface CachedToken {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
  scope?: string;
}

/**
 * Token response from Google OAuth API
 */
interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
}

/**
 * Refresh Google OAuth access token
 *
 * Calls Google's token endpoint to exchange refresh token for new access token.
 * This mimics the refresh logic from LoopbackOAuthProvider.
 *
 * @param refreshToken - Valid Google refresh token
 * @param clientId - Google OAuth client ID
 * @param clientSecret - Google OAuth client secret (optional for public clients)
 * @returns Refreshed token with new access token and expiry
 * @throws Error if refresh fails (revoked token, invalid credentials, network error)
 *
 * Common failure reasons:
 * - Refresh token expired (inactive for 90+ days)
 * - User revoked app access
 * - Client credentials changed
 * - Network connectivity issues
 * - Google OAuth API issues
 */
export async function refreshGoogleToken(refreshToken: string, clientId: string, clientSecret?: string): Promise<CachedToken> {
  const tokenUrl = 'https://oauth2.googleapis.com/token';
  const params: Record<string, string> = {
    refresh_token: refreshToken,
    client_id: clientId,
    grant_type: 'refresh_token',
  };

  // Client secret is optional for public clients (desktop/mobile/SPA)
  if (clientSecret) {
    params.client_secret = clientSecret;
  }

  const body = new URLSearchParams(params);

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: body.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Token refresh failed: ${response.status} ${errorText}`);
  }

  const tokenResponse = (await response.json()) as TokenResponse;

  return {
    accessToken: tokenResponse.access_token,
    refreshToken: refreshToken, // Keep original refresh token (Google doesn't always return new one)
    ...(tokenResponse.expires_in !== undefined && { expiresAt: Date.now() + tokenResponse.expires_in * 1000 }),
    ...(tokenResponse.scope !== undefined && { scope: tokenResponse.scope }),
  };
}

/**
 * Get access token with automatic refresh if expired
 *
 * Checks if token is expired or expires soon (< 5 minutes) and automatically
 * refreshes it using Google OAuth API. Updates token store with refreshed token.
 *
 * FAIL FAST Philosophy:
 * - If token not found: throw error with setup instructions
 * - If refresh fails: throw error with actionable guidance (NO silent fallback)
 * - If no refresh token: throw error (can't refresh)
 *
 * @param tokenStore - Keyv token store
 * @param accountId - Account identifier (email or 'default')
 * @param service - Service name (gmail, drive, sheets)
 * @param clientId - Google OAuth client ID
 * @param clientSecret - Google OAuth client secret (optional)
 * @returns Fresh access token (refreshed if needed)
 * @throws Error if token not found, refresh fails, or no refresh token available
 *
 * @example
 * ```typescript
 * const tokenStore = new Keyv({ store: new KeyvFile({ filename: '.tokens/test/store.json' }) });
 * const token = await getRefreshedToken(tokenStore, 'default', 'gmail', CLIENT_ID, CLIENT_SECRET);
 * // Returns fresh token, automatically refreshed if expired
 * ```
 */
export async function getRefreshedToken(tokenStore: Keyv, accountId: string, service: string, clientId: string, clientSecret?: string): Promise<string> {
  // Use createAccountKey('token', { accountId: accountId, service: service }) to generate key: {accountId}:{service}:token
  const key = createAccountKey('token', { accountId: accountId, service: service });
  const storedToken = await tokenStore.get(key);

  if (!storedToken?.accessToken) {
    throw new Error(`Token not found for ${accountId}:${service}.\n\nRun \`npm run test:setup\` in libs/oauth-google/ to generate OAuth token.`);
  }

  // Check if token is expired or expires soon (< 5 min)
  // 5-minute threshold prevents race conditions during test execution
  const expiresAt = storedToken.expiresAt;
  const expirationThreshold = Date.now() + 5 * 60 * 1000; // 5 minutes
  const isExpiringSoon = expiresAt && expiresAt < expirationThreshold;

  if (isExpiringSoon && storedToken.refreshToken) {
    try {
      // Refresh token using Google OAuth API
      const refreshedToken = await refreshGoogleToken(storedToken.refreshToken, clientId, clientSecret);

      // Update store with refreshed token
      await tokenStore.set(key, refreshedToken);

      return refreshedToken.accessToken;
    } catch (error) {
      // FAIL FAST - no graceful fallback
      // Tests should fail loudly when configuration is broken
      throw new Error(
        `Token refresh failed: ${error instanceof Error ? error.message : String(error)}\n\n` +
          'This usually means:\n' +
          '  1. Refresh token expired (inactive for 90+ days)\n' +
          '  2. App access was revoked by user\n' +
          '  3. Client credentials changed in .env.test\n' +
          '  4. Network connectivity issues\n\n' +
          'To fix: Run `npm run test:setup` in libs/oauth-google/ to generate a new token.'
      );
    }
  }

  // Token expires soon but no refresh token available
  if (isExpiringSoon && !storedToken.refreshToken) {
    throw new Error('Token expires soon (< 5 minutes) but no refresh token available.\n\n' + 'Run `npm run test:setup` in libs/oauth-google/ to generate a new token with refresh capability.');
  }

  return storedToken.accessToken;
}
