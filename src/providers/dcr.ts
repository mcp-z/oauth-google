/**
 * DCR Provider - Stateless Dynamic Client Registration Provider
 *
 * Implements stateless provider pattern where provider tokens are received from
 * token verification context rather than managed by the provider itself.
 *
 * Use case: MCP HTTP servers with DCR authentication where client manages tokens
 * and provider only handles Google API calls with provided credentials.
 */

import type { ProviderTokens } from '@mcp-z/oauth';
import { ProtocolError, ProtocolErrorCode } from '@modelcontextprotocol/server';
import type { AuthContext, EnrichedExtra, GoogleAuthProvider, Logger } from '../types.ts';

/**
 * DCR Provider configuration
 */
export interface DcrOAuthProviderConfig {
  /** Google application client ID */
  clientId: string;

  /** Google application client secret (optional for public clients) */
  clientSecret?: string;

  /** OAuth scopes */
  scope: string;

  /** DCR token verification endpoint URL (e.g., http://localhost:3000/oauth/verify) */
  verifyEndpoint: string;

  /** Logger for auth operations */
  logger: Logger;
}

/**
 * Google TokenResponse
 */
interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
}

/**
 * DCR Provider - Stateless OAuth provider for Dynamic Client Registration
 *
 * Unlike LoopbackOAuthProvider which manages token storage, DcrOAuthProvider is stateless:
 * - Receives provider tokens from verification context (HTTP bearer auth)
 * - Creates auth providers on-demand from tokens
 * - Handles token refresh using Google OAuth 2.0
 * - No token storage dependency
 *
 * Pattern:
 * ```typescript
 * const provider = new DcrOAuthProvider(config);
 * const auth = provider.toAuthProvider(providerTokens);  // pass to attachTokenProvider
 * const accessToken = await getAccessToken(auth);
 * ```
 */
export class DcrOAuthProvider {
  private config: DcrOAuthProviderConfig;
  private emailCache = new Map<string, { email: string; expiresAt: number }>();

  constructor(config: DcrOAuthProviderConfig) {
    this.config = config;
  }

  /**
   * Token provider built from verification-supplied tokens.
   *
   * This is the core stateless pattern - the provider receives tokens from
   * context (token verification, HTTP request) rather than owning a store.
   *
   * @param tokens - Provider tokens (Google access/refresh tokens)
   */
  toAuthProvider(tokens: ProviderTokens): GoogleAuthProvider {
    // The tokens arrive from token verification and are refreshed in place, so the
    // provider closes over them rather than re-reading a store it does not own.
    let current = tokens;

    return {
      getAccessToken: async () => {
        if (!this.needsRefresh(current.expiresAt)) {
          return current.accessToken;
        }

        // Expired - refresh if we can
        if (current.refreshToken) {
          try {
            current = await this.refreshAccessToken(current.refreshToken);
            return current.accessToken;
          } catch (error) {
            throw new Error(`Token refresh failed: ${error instanceof Error ? error.message : String(error)}`);
          }
        }

        // Handing back a token we know is expired only turns a clear failure into a
        // 401 from Google that points nowhere near the cause.
        throw new Error('Access token expired and no refresh token available');
      },
    };
  }

  /**
   * Check if token needs refresh (with 1 minute buffer)
   */
  private needsRefresh(expiryDate: number | null | undefined): boolean {
    if (!expiryDate) return false; // No expiry = no refresh needed
    return Date.now() >= expiryDate - 60000; // 1 minute buffer
  }

  /**
   * Refresh Google access token using refresh token
   *
   * @param refreshToken - Google refresh token
   * @returns New provider tokens
   */
  async refreshAccessToken(refreshToken: string): Promise<ProviderTokens> {
    const { clientId, clientSecret } = this.config;

    const tokenUrl = 'https://oauth2.googleapis.com/token';
    const params: Record<string, string> = {
      refresh_token: refreshToken,
      client_id: clientId,
      grant_type: 'refresh_token',
    };

    // Only include client_secret for confidential clients
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

    const result: ProviderTokens = {
      accessToken: tokenResponse.access_token,
      refreshToken: refreshToken, // Keep original refresh token
    };

    // Only add optional fields if they have values
    if (tokenResponse.expires_in !== undefined) {
      result.expiresAt = Date.now() + tokenResponse.expires_in * 1000;
    }
    if (tokenResponse.scope !== undefined) {
      result.scope = tokenResponse.scope;
    }

    return result;
  }

  /**
   * Get user email from Google userinfo API (with caching)
   *
   * @param tokens - Provider tokens to use for API call
   * @returns User's email address
   */
  async getUserEmail(tokens: ProviderTokens): Promise<string> {
    const cacheKey = tokens.accessToken;
    const cached = this.emailCache.get(cacheKey);

    // Check cache (with same expiry as access token)
    if (cached && Date.now() < cached.expiresAt) {
      return cached.email;
    }

    const accessToken = await this.toAuthProvider(tokens).getAccessToken();

    const response = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
      throw new Error(`Failed to get user info: ${response.status} ${await response.text()}`);
    }

    const userInfo = (await response.json()) as { email: string };
    const email = userInfo.email;

    // Cache with token expiration (default 1 hour if not specified)
    this.emailCache.set(cacheKey, {
      email,
      expiresAt: tokens.expiresAt ?? Date.now() + 3600000,
    });

    return email;
  }

  /**
   * Auth middleware for HTTP servers with DCR bearer auth
   * Validates bearer tokens and enriches extra with provider tokens
   *
   * Pattern:
   * ```typescript
   * const provider = new DcrOAuthProvider({ ..., verifyEndpoint: 'http://localhost:3000/oauth/verify' });
   * const authMiddleware = provider.authMiddleware();
   * const tools = toolFactories.map(f => f()).map(authMiddleware.withToolAuth);
   * const resources = resourceFactories.map(f => f()).map(authMiddleware.withResourceAuth);
   * const prompts = promptFactories.map(f => f()).map(authMiddleware.withPromptAuth);
   * ```
   */
  authMiddleware() {
    // Shared wrapper logic - extracts extra parameter from specified position
    // Generic T captures the actual module type; handler is cast from unknown to callable
    const wrapAtPosition = <T extends { name: string; handler: unknown; [key: string]: unknown }>(module: T, extraPosition: number): T => {
      const originalHandler = module.handler as (...args: unknown[]) => Promise<unknown>;

      const wrappedHandler = async (...allArgs: unknown[]) => {
        // Extract extra from the correct position
        const extra = allArgs[extraPosition] as EnrichedExtra;

        // Extract DCR bearer token from SDK's authInfo (if present) or request headers
        let bearerToken: string | undefined;

        // Option 1: Token already verified by SDK's bearerAuth middleware
        if (extra.http?.authInfo && typeof extra.http.authInfo === 'object') {
          // authInfo contains the validated token - extract it
          // The SDK's bearerAuth middleware already validated it, but we need the raw token for /oauth/verify
          // Check if authInfo has the token directly, otherwise extract from headers
          const authInfo = extra.http.authInfo as unknown as Record<string, unknown>;
          bearerToken = (typeof authInfo.accessToken === 'string' ? authInfo.accessToken : undefined) ?? (typeof authInfo.token === 'string' ? authInfo.token : undefined);
        }

        // Option 2: Extract from Authorization header
        if (!bearerToken) {
          const authHeader = extra.http?.req?.headers.get('authorization');
          if (authHeader) {
            const match = /^Bearer\s+(.+)$/i.exec(authHeader);
            if (match) {
              bearerToken = match[1];
            }
          }
        }

        if (!bearerToken) {
          throw new ProtocolError(ProtocolErrorCode.InvalidRequest, 'Missing Authorization header. DCR mode requires bearer token.');
        }

        // Call /oauth/verify to validate DCR token and get provider tokens
        const verifyResponse = await fetch(this.config.verifyEndpoint, {
          headers: { Authorization: `Bearer ${bearerToken}` },
        });

        if (!verifyResponse.ok) {
          throw new ProtocolError(ProtocolErrorCode.InvalidRequest, `Token verification failed: ${verifyResponse.status}`);
        }

        const verifyData = (await verifyResponse.json()) as {
          providerTokens: ProviderTokens;
        };

        // Fetch user email to use as accountId (with caching)
        let accountId: string;
        try {
          accountId = await this.getUserEmail(verifyData.providerTokens);
        } catch (error) {
          throw new ProtocolError(ProtocolErrorCode.InternalError, `Failed to get user email for DCR authentication: ${error instanceof Error ? error.message : String(error)}`);
        }

        // Create auth client from provider tokens
        const auth = this.toAuthProvider(verifyData.providerTokens);

        // Inject authContext and logger into extra
        (extra as { authContext?: AuthContext }).authContext = {
          auth,
          accountId, // User's email address
        };
        (extra as { logger?: unknown }).logger = this.config.logger;

        // Call original handler with all args
        return await originalHandler(...allArgs);
      };

      return {
        ...module,
        handler: wrappedHandler,
      } as T;
    };

    return {
      // Use structural constraints to avoid contravariance check on handler type.
      // wrapAtPosition is now generic and returns T directly.
      withToolAuth: <T extends { name: string; config: unknown; handler: unknown }>(module: T) => wrapAtPosition(module, 1),
      withResourceAuth: <T extends { name: string; template?: unknown; config?: unknown; handler: unknown }>(module: T) => wrapAtPosition(module, 2),
      withPromptAuth: <T extends { name: string; config: unknown; handler: unknown }>(module: T) => wrapAtPosition(module, 0),
    };
  }
}
