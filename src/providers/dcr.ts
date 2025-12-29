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
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { OAuth2Client } from 'google-auth-library';
import type { AuthContext, EnrichedExtra, Logger } from '../types.ts';

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
 * const auth = provider.toAuth(providerTokens);
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
   * Create Google OAuth2Client from provider tokens
   *
   * This is the core stateless pattern - provider receives tokens from context
   * (token verification, HTTP request) and creates OAuth2Client on-demand.
   *
   * @param tokens - Provider tokens (Google access/refresh tokens)
   * @returns Google OAuth2Client configured with credentials
   */
  toAuth(tokens: ProviderTokens): OAuth2Client {
    const { clientId, clientSecret } = this.config;

    // Create OAuth2Client with credentials
    const client = new OAuth2Client({
      clientId,
      ...(clientSecret && { clientSecret }),
    });

    // Set initial credentials (convert undefined to null for Google's Credentials type)
    client.credentials = {
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken ?? null,
      expiry_date: tokens.expiresAt ?? null,
      token_type: 'Bearer',
    };

    // Override getRequestMetadataAsync to handle token refresh
    // @ts-expect-error - Access protected method for token refresh
    const originalGetMetadata = client.getRequestMetadataAsync.bind(client);

    // @ts-expect-error - Override protected method for token refresh
    client.getRequestMetadataAsync = async (url?: string) => {
      // Check if token needs refresh
      if (this.needsRefresh(client.credentials.expiry_date)) {
        try {
          // Use built-in refresh mechanism
          const refreshedTokens = await client.refreshAccessToken();
          client.credentials = refreshedTokens.credentials;
        } catch (error) {
          throw new Error(`Token refresh failed: ${error instanceof Error ? error.message : String(error)}`);
        }
      }

      return originalGetMetadata(url);
    };

    return client;
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

    const auth = this.toAuth(tokens);

    // Use OAuth2Client to make authenticated request
    const response = await auth.request({
      url: 'https://www.googleapis.com/oauth2/v2/userinfo',
      method: 'GET',
    });

    const userInfo = response.data as { email: string };
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
        if (extra.authInfo && typeof extra.authInfo === 'object') {
          // authInfo contains the validated token - extract it
          // The SDK's bearerAuth middleware already validated it, but we need the raw token for /oauth/verify
          // Check if authInfo has the token directly, otherwise extract from headers
          const authInfo = extra.authInfo as unknown as Record<string, unknown>;
          bearerToken = (typeof authInfo.accessToken === 'string' ? authInfo.accessToken : undefined) ?? (typeof authInfo.token === 'string' ? authInfo.token : undefined);
        }

        // Option 2: Extract from Authorization header
        if (!bearerToken && extra.requestInfo?.headers) {
          const authHeader = extra.requestInfo.headers.authorization || extra.requestInfo.headers.Authorization;
          if (authHeader) {
            // Handle both string and string[] types
            const headerValue = Array.isArray(authHeader) ? authHeader[0] : authHeader;
            if (headerValue) {
              const match = /^Bearer\s+(.+)$/i.exec(headerValue);
              if (match) {
                bearerToken = match[1];
              }
            }
          }
        }

        if (!bearerToken) {
          throw new McpError(ErrorCode.InvalidRequest, 'Missing Authorization header. DCR mode requires bearer token.');
        }

        // Call /oauth/verify to validate DCR token and get provider tokens
        const verifyResponse = await fetch(this.config.verifyEndpoint, {
          headers: { Authorization: `Bearer ${bearerToken}` },
        });

        if (!verifyResponse.ok) {
          throw new McpError(ErrorCode.InvalidRequest, `Token verification failed: ${verifyResponse.status}`);
        }

        const verifyData = (await verifyResponse.json()) as {
          providerTokens: ProviderTokens;
        };

        // Fetch user email to use as accountId (with caching)
        let accountId: string;
        try {
          accountId = await this.getUserEmail(verifyData.providerTokens);
        } catch (error) {
          throw new McpError(ErrorCode.InternalError, `Failed to get user email for DCR authentication: ${error instanceof Error ? error.message : String(error)}`);
        }

        // Create auth client from provider tokens
        const auth = this.toAuth(verifyData.providerTokens);

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
