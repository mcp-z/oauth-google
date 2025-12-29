/**
 * Standalone types for Google OAuth
 * No dependencies on other @mcp-z packages except @mcp-z/oauth
 */

// Shared types from base @mcp-z/oauth package
import type { AuthFlowDescriptor, CachedToken, DcrClientInformation, DcrClientMetadata, Logger, OAuth2TokenStorageProvider, ProviderTokens, ToolHandler, ToolModule, UserAuthProvider } from '@mcp-z/oauth';
import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type { ServerNotification, ServerRequest } from '@modelcontextprotocol/sdk/types.js';
import type { OAuth2Client } from 'google-auth-library';
import type { Keyv } from 'keyv';

// Re-export only essential shared types for public API
export type { Logger, CachedToken, ToolModule, ProviderTokens, DcrClientMetadata, DcrClientInformation };

// Re-export error class
export { AuthRequiredError } from '@mcp-z/oauth';

// Re-export additional types for internal package use
export type { ToolHandler, AuthFlowDescriptor, OAuth2TokenStorageProvider, UserAuthProvider, RequestHandlerExtra, ServerRequest, ServerNotification };

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
 * Auth context injected into extra by middleware
 * @public
 */
export interface AuthContext {
  /**
   * OAuth2Client ready for googleapis
   * GUARANTEED to exist when handler runs
   */
  auth: OAuth2Client;

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
 * Handlers receive this type - never plain RequestHandlerExtra
 * @public
 */
export interface EnrichedExtra extends RequestHandlerExtra<ServerRequest, ServerNotification> {
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
