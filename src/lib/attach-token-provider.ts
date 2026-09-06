/**
 * Adapter between this package's token providers and Google's API clients.
 *
 * `googleapis` clients take an auth object; this package mints tokens and knows
 * nothing else about the SDK. `refreshHandler` is the SDK's documented hook for
 * exactly that split (google-auth-library README, "token broker"), so the two
 * meet here and nowhere else.
 */

import type { GoogleAuthProvider } from '../types.ts';

/**
 * The one member of Google's `OAuth2Client` this package depends on.
 *
 * Structural rather than imported: it keeps `google-auth-library` out of this
 * package's dependencies, and keeps the client a server passes in type-identical
 * to the one its own `googleapis` expects.
 *
 * @public
 */
export interface RefreshHandlerClient {
  refreshHandler?: () => Promise<{ access_token: string; expiry_date: number }>;
}

/**
 * Point a Google API client at a token provider.
 *
 * @example
 * ```ts
 * google.gmail({ version: 'v1', auth: attachTokenProvider(new google.auth.OAuth2(), extra.authContext.auth) })
 * ```
 *
 * @public
 */
export function attachTokenProvider<T extends RefreshHandlerClient>(client: T, auth: GoogleAuthProvider): T {
  client.refreshHandler = async () => ({
    access_token: await auth.getAccessToken(),
    // `expiry_date: Date.now()` is deliberate and load-bearing: it makes the client
    // treat the token as always expiring, so it re-asks the provider on every request
    // and the provider's own store and refresh logic decides what is current.
    //
    // Do not "fix" this to a real-looking expiry. The providers return a bare string
    // with no expiry, so any value here is invented; the client trusts it blindly
    // (processAndValidateRefreshHandler checks only that access_token is present) and
    // caches until it passes. Every request after the true expiry then 401s, and the
    // client does not retry, because it only retries a handler token when expiry_date
    // is unset. It fails only for tokens near expiry, so tests mostly pass.
    expiry_date: Date.now(),
  });
  return client;
}
