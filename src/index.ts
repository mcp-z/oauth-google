/**
 * @mcp-z/oauth-google - Shared Google OAuth implementation
 *
 * Provides OAuth authentication:
 * - Loopback OAuth (RFC 8252) - Server-managed, file-based tokens
 * - Service Account authentication for server-to-server scenarios
 */

export { createDcrRouter, type DcrRouterConfig } from './lib/dcr-router.ts';
export { type VerificationResult, verifyBearerToken } from './lib/dcr-verify.ts';
export { type AuthInfo, DcrTokenVerifier } from './lib/token-verifier.ts';
export { DcrOAuthProvider, type DcrOAuthProviderConfig } from './providers/dcr.ts';
export { LoopbackOAuthProvider } from './providers/loopback-oauth.ts';
export { type ServiceAccountConfig, ServiceAccountProvider } from './providers/service-account.ts';
export * as schemas from './schemas/index.ts';
export { createConfig, parseConfig, parseDcrConfig } from './setup/config.ts';
export * from './types.ts';
