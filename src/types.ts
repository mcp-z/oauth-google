/**
 * Standalone types for Google OAuth
 * No dependencies on other @mcp-z packages except @mcp-z/oauth
 */

// Shared types from base @mcp-z/oauth package
import type { AuthFlowDescriptor, CachedToken, DcrClientInformation, DcrClientMetadata, Logger, OAuth2TokenStorageProvider, ProviderTokens, ToolHandler, ToolModule, UserAuthProvider } from '@mcp-z/oauth';
import type { ServerContext } from '@modelcontextprotocol/server';
import type { Keyv } from 'keyv';

// Re-export error class
export { AuthRequiredError } from '@mcp-z/oauth';
// Re-export only essential shared types for public API
// Re-export additional types for internal package use
export type { AuthFlowDescriptor, CachedToken, DcrClientInformation, DcrClientMetadata, Logger, OAuth2TokenStorageProvider, ProviderTokens, ServerContext, ToolHandler, ToolModule, UserAuthProvider };

/**
 * Google service types that support OAuth
 * OAuth clients support all Google services provided by googleapis
 * @public
 */
export type GoogleService = string;

// =============================================================================
// Configuration Types
// =============================================================================

/**
 * OAuth client configuration for upstream provider
 * @public
 */
export interface OAuthClientConfig {
  /** OAuth client ID for upstream provider */
  clientId: string;
  /** OAuth client secret (optional for some flows) */
  clientSecret?: string;
}

/**
 * Google OAuth configuration interface.
 * @public
 */
export interface OAuthConfig {
  clientId: string;
  /** Optional for public clients */
  clientSecret?: string;
  auth: 'loopback-oauth' | 'service-account' | 'dcr';
  /** No browser interaction when true */
  headless: boolean;
  /** Defaults to ephemeral loopback */
  redirectUri?: string;
  /** Required when auth === 'service-account' */
  serviceAccountKeyFile?: string;
}

/**
 * DCR configuration for dynamic client registration
 * @public
 */
export interface DcrConfig {
  /** DCR mode: self-hosted (runs own OAuth server) or external (uses Auth0/Stitch) */
  mode: 'self-hosted' | 'external';
  /** External verification endpoint URL (required for external mode) */
  verifyUrl?: string;
  /** DCR client storage URI (required for self-hosted mode) */
  storeUri?: string;
  /** OAuth client ID for Google APIs */
  clientId: string;
  /** OAuth client secret (optional for public clients) */
  clientSecret?: string;
  /** OAuth scopes to request */
  scope: string;
  /** Logger instance */
  logger?: Logger;
}

/**
 * Configuration for loopback OAuth client
 * @public
 */
export interface LoopbackOAuthConfig {
  service: GoogleService;
  clientId: string;
  /** Optional for public clients */
  clientSecret?: string | undefined;
  scope: string;
  /** No browser interaction when true */
  headless: boolean;
  logger: Logger;
  tokenStore: Keyv<unknown>;
  /** Defaults to ephemeral loopback */
  redirectUri?: string;
}

// =============================================================================
// Middleware Types
// =============================================================================

/**
 * Supplies Google access tokens on demand.
 *
 * The whole contract between this package and a Google API client. It mirrors
 * `@mcp-z/oauth-microsoft`, whose providers satisfy Graph's
 * `AuthenticationProvider` with the same single method, and it is why this
 * package needs no Google SDK of its own.
 *
 * @public
 */
export interface GoogleAuthProvider {
  /** Resolves a currently-valid access token, refreshing if the provider needs to. */
  getAccessToken: () => Promise<string>;
}

/**
 * Auth context injected into extra by middleware
 * @public
 */
export interface AuthContext {
  /**
   * Mints access tokens for this account. Pass it to a Google API client with
   * `attachTokenProvider`; this package does not build the client itself.
   * GUARANTEED to exist when handler runs
   */
  auth: GoogleAuthProvider;

  /**
   * Account being used (for logging, debugging)
   */
  accountId: string;

  /**
   * User ID (multi-tenant only)
   */

  /**
   * Additional metadata (e.g., service account email)
   */
  metadata?: {
    serviceEmail?: string;
    [key: string]: unknown;
  };
}

/**
 * Enriched extra with guaranteed auth context and logger
 * Handlers receive this type - never plain ServerContext
 *
 * Extending `ServerContext` is deliberate: this is middleware, so it adds to the
 * SDK's request context rather than replacing it. A handler is still an SDK
 * handler and may need what the SDK put there - `signal` to honour cancellation,
 * `mcpReq._meta.progressToken` and notifications to report progress, `mcpReq.id`
 * to correlate logs. Narrowing this to `{ authContext, logger }` would read as a
 * simplification, because the servers in this workspace happen to use none of it,
 * and would silently remove those capabilities from every other consumer.
 *
 * @public
 */
export interface EnrichedExtra extends ServerContext {
  /**
   * Auth context injected by middleware
   * GUARANTEED to exist (middleware catches auth failures)
   */
  authContext: AuthContext;

  /**
   * Logger injected by middleware
   * GUARANTEED to exist
   */
  logger: Logger;

  // Preserve backchannel support
  _meta?: {
    accountId?: string;
    [key: string]: unknown;
  };
}

// =============================================================================
// DCR Internal Types
// =============================================================================

/**
 * Registered client with full metadata
 * Extends DcrClientInformation with internal timestamps
 * @internal
 */
export interface RegisteredClient extends DcrClientInformation {
  /** Creation timestamp (milliseconds since epoch) */
  created_at: number;
}

/**
 * Authorization code data structure
 * @public
 */
export interface AuthorizationCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  code_challenge?: string;
  code_challenge_method?: string;
  /** Google provider tokens obtained during authorization */
  providerTokens: ProviderTokens;
  created_at: number;
  expires_at: number;
}

/**
 * Access token data structure
 * @public
 */
export interface AccessToken {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  scope: string;
  client_id: string;
  /** Google provider tokens */
  providerTokens: ProviderTokens;
  created_at: number;
}

// =============================================================================
// Schema Types
// =============================================================================

/**
 * Authentication required response type
 * Re-exported from @mcp-z/oauth for consistency
 * @public
 */
export type { AuthRequired, AuthRequiredBranch } from './schemas/index.ts';
