import { promises as fs } from 'fs';
import { OAuth2Client } from 'google-auth-library';
import { importPKCS8, SignJWT } from 'jose';
import type { AuthContext, EnrichedExtra, Logger, OAuth2TokenStorageProvider } from '../types.ts';

/**
 * Service Account Key File Structure
 * Standard Google Cloud service account JSON key format
 */
interface ServiceAccountKey {
  type: 'service_account';
  project_id: string;
  private_key_id: string;
  private_key: string;
  client_email: string;
  client_id: string;
  auth_uri: string;
  token_uri: string;
  auth_provider_x509_cert_url?: string;
  client_x509_cert_url?: string;
}

/**
 * Service Account Provider Configuration
 */
export interface ServiceAccountConfig {
  /** Path to Google Cloud service account JSON key file */
  keyFilePath: string;
  /** OAuth scopes to request (e.g., ['https://www.googleapis.com/auth/gmail.readonly']) */
  scopes: string[];
  /** Logger for auth operations */
  logger: Logger;
}

/**
 * Token Exchange Response from Google OAuth endpoint
 */
interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

/**
 * ServiceAccountProvider implements OAuth2TokenStorageProvider using Google Service Accounts
 * with JWT-based (2-legged OAuth) authentication.
 *
 * This provider:
 * - Loads service account key file from disk
 * - Generates self-signed JWTs using RS256 algorithm
 * - Exchanges JWTs for access tokens at Google's token endpoint
 * - Does NOT store tokens (regenerates on each request)
 * - Provides single static identity (no account management)
 *
 * @example
 * ```typescript
 * const provider = new ServiceAccountProvider({
 *   keyFilePath: '/path/to/service-account-key.json',
 *   scopes: ['https://www.googleapis.com/auth/drive.readonly'],
 * });
 *
 * // Get authenticated OAuth2Client for googleapis
 * const auth = provider.toAuth('default');
 * const drive = google.drive({ version: 'v3', auth });
 * ```
 */
export class ServiceAccountProvider implements OAuth2TokenStorageProvider {
  private config: ServiceAccountConfig;
  private keyFilePath: string;
  private scopes: string[];
  private keyData?: ServiceAccountKey;
  private cachedToken?: { token: string; expiry: number };

  constructor(config: ServiceAccountConfig) {
    this.config = config;
    this.keyFilePath = config.keyFilePath;
    this.scopes = config.scopes;
  }

  /**
   * Load and parse service account key file from disk
   * Validates structure and caches for subsequent calls
   */
  private async loadKeyFile(): Promise<ServiceAccountKey> {
    // Return cached key data if already loaded
    if (this.keyData) {
      return this.keyData;
    }

    try {
      // Read key file from disk
      const fileContent = await fs.readFile(this.keyFilePath, 'utf-8');

      // Parse JSON
      let keyData: unknown;
      try {
        keyData = JSON.parse(fileContent);
      } catch (parseError) {
        throw new Error(`Failed to parse service account key file as JSON: ${this.keyFilePath}\n` + `Error: ${parseError instanceof Error ? parseError.message : String(parseError)}`);
      }

      // Validate structure
      this.keyData = this.validateKeyFile(keyData);
      return this.keyData;
    } catch (error) {
      // Handle file not found
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new Error(`Service account key file not found: ${this.keyFilePath}\nMake sure GOOGLE_SERVICE_ACCOUNT_KEY_FILE points to a valid file path.`);
      }

      // Handle permission errors
      if ((error as NodeJS.ErrnoException).code === 'EACCES') {
        throw new Error(`Permission denied reading service account key file: ${this.keyFilePath}\nCheck file permissions (should be readable by current user).`);
      }

      // Re-throw other errors
      throw error;
    }
  }

  /**
   * Validate service account key file structure
   * Ensures all required fields are present and correctly typed
   */
  private validateKeyFile(data: unknown): ServiceAccountKey {
    if (!data || typeof data !== 'object') {
      throw new Error('Service account key file must contain a JSON object');
    }

    const obj = data as Record<string, unknown>;

    // Validate type field
    if (obj.type !== 'service_account') {
      throw new Error(`Invalid service account key file: Expected type "service_account", got "${obj.type}"\nMake sure you downloaded a service account key, not an OAuth client credential.`);
    }

    // Validate required string fields
    const requiredFields: Array<keyof ServiceAccountKey> = ['project_id', 'private_key_id', 'private_key', 'client_email', 'client_id', 'auth_uri', 'token_uri'];

    const missingFields = requiredFields.filter((field) => typeof obj[field] !== 'string' || !obj[field]);

    if (missingFields.length > 0) {
      throw new Error(`Service account key file is missing required fields: ${missingFields.join(', ')}\nMake sure you downloaded a complete service account key file from Google Cloud Console.`);
    }

    // Validate private key format
    const privateKey = obj.private_key as string;
    if (!privateKey.includes('BEGIN PRIVATE KEY') || !privateKey.includes('END PRIVATE KEY')) {
      throw new Error('Service account private_key field does not contain a valid PEM-formatted key.\n' + 'Expected format: -----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----');
    }

    return obj as unknown as ServiceAccountKey;
  }

  /**
   * Generate signed JWT (JSON Web Token) for service account authentication
   * Uses RS256 algorithm with private key from key file
   */
  private async generateJWT(): Promise<string> {
    const keyData = await this.loadKeyFile();

    // Import private key using jose
    const privateKey = await importPKCS8(keyData.private_key, 'RS256');

    // Current time
    const now = Math.floor(Date.now() / 1000);

    // Create JWT with required claims for Google OAuth
    const jwt = await new SignJWT({
      iss: keyData.client_email, // Issuer: service account email
      scope: this.scopes.join(' '), // Scopes: space-separated
      aud: 'https://oauth2.googleapis.com/token', // Audience: token endpoint
      exp: now + 3600, // Expiration: 1 hour from now
      iat: now, // Issued at: current time
    })
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
      .sign(privateKey);

    return jwt;
  }

  /**
   * Exchange signed JWT for access token at Google OAuth endpoint
   * POST to https://oauth2.googleapis.com/token with grant_type=jwt-bearer
   */
  private async exchangeJWT(jwt: string): Promise<{ token: string; expiry: number }> {
    const tokenEndpoint = 'https://oauth2.googleapis.com/token';

    try {
      const response = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          assertion: jwt,
        }),
      });

      // Handle non-2xx responses
      if (!response.ok) {
        const errorText = await response.text();
        let errorMessage: string;

        try {
          const errorJson = JSON.parse(errorText);
          errorMessage = errorJson.error_description || errorJson.error || errorText;
        } catch {
          errorMessage = errorText;
        }

        // 400: Invalid JWT (malformed claims, expired, etc.)
        if (response.status === 400) {
          throw new Error(`Invalid service account JWT: ${errorMessage}\nThis usually means the JWT claims are malformed or the key file is invalid.`);
        }

        // 401: Unauthorized (revoked service account, wrong scopes, etc.)
        if (response.status === 401) {
          throw new Error(`Service account authentication failed: ${errorMessage}\nThe service account may have been disabled or deleted. Check Google Cloud Console.`);
        }

        // Other errors
        throw new Error(`Token exchange failed (HTTP ${response.status}): ${errorMessage}`);
      }

      // Parse successful response
      const tokenData = (await response.json()) as TokenResponse;

      // Calculate expiry timestamp (token expires in ~1 hour)
      const expiry = Date.now() + (tokenData.expires_in - 60) * 1000; // Subtract 60s for safety margin

      return {
        token: tokenData.access_token,
        expiry,
      };
    } catch (error) {
      // Network errors
      if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new Error('Network error connecting to Google OAuth endpoint. Check internet connection.');
      }

      // Re-throw other errors
      throw error;
    }
  }

  /**
   * Get access token for Google APIs
   * Generates fresh JWT and exchanges for access token on each call
   *
   * Note: accountId parameter is ignored for service accounts (service account is single static identity)
   */
  async getAccessToken(_accountId?: string): Promise<string> {
    // Check if we have a valid cached token (optional optimization)
    if (this.cachedToken && this.cachedToken.expiry > Date.now()) {
      return this.cachedToken.token;
    }

    try {
      // Generate JWT
      const jwt = await this.generateJWT();

      // Exchange for access token
      const { token, expiry } = await this.exchangeJWT(jwt);

      // Cache token for subsequent calls (optional optimization)
      this.cachedToken = { token, expiry };

      return token;
    } catch (error) {
      // Add context to errors
      throw new Error(`Failed to get service account access token: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Get OAuth2Client with service account credentials for googleapis
   * This is the CRITICAL method that servers use to get authenticated API clients
   *
   * Service account ONLY works with accountId='service-account' (single static identity)
   *
    @param accountId - Account identifier (must be 'service-account' or undefined)
   * @returns OAuth2Client instance with access token credentials set
   */
  toAuth(accountId?: string): OAuth2Client {
    // Service account ONLY works with 'service-account' account ID
    if (accountId !== undefined && accountId !== 'service-account') {
      throw new Error(`ServiceAccountProvider only supports accountId='service-account', got '${accountId}'. Service account uses a single static identity pattern.`);
    }

    // Create OAuth2Client instance (no client ID/secret needed for service accounts)
    const client = new OAuth2Client();

    // Override getRequestMetadataAsync to provide authentication headers for each request
    // This is the method googleapis calls to get auth headers - can be async and fetch tokens on-demand
    (
      client as OAuth2Client & {
        getRequestMetadataAsync: (url?: string) => Promise<{ headers: Headers | Map<string, string> }>;
      }
    ).getRequestMetadataAsync = async (_url?: string) => {
      try {
        // Get fresh access token (can be async, will trigger JWT generation if needed)
        const token = await this.getAccessToken();

        // Update client credentials for consistency (other googleapis methods might check these)
        client.credentials = {
          access_token: token,
          token_type: 'Bearer',
        };

        // Return headers as Headers instance for proper TypeScript types
        const headers = new Headers();
        headers.set('authorization', `Bearer ${token}`);
        return { headers };
      } catch (error) {
        this.config.logger?.error('Failed to get service account access token for API request', { error });
        throw error;
      }
    };

    // Override getAccessToken to support googleapis client API and direct token access
    client.getAccessToken = async () => {
      try {
        const token = await this.getAccessToken();
        return { token };
      } catch (error) {
        this.config.logger?.error('Failed to get service account access token', { error });
        throw error;
      }
    };

    this.config.logger?.debug(`ServiceAccountProvider: OAuth2Client created for ${accountId}`);
    return client;
  }

  /**
   * Get service account email address
   * Used for account registration and display
   *
   * Note: accountId parameter is ignored for service accounts
   * @returns Service account email from key file (e.g., "service-account@project.iam.gserviceaccount.com")
   */
  async getUserEmail(_accountId?: string): Promise<string> {
    const keyData = await this.loadKeyFile();
    return keyData.client_email;
  }

  /**
   * Create middleware wrapper for single-user authentication
   * This is the CRITICAL method that integrates service account auth into MCP servers
   *
   * Middleware wraps tool, resource, and prompt handlers and injects authContext into extra parameter.
   * Handlers receive OAuth2Client via extra.authContext.auth for API calls.
   *
   * @returns Object with withToolAuth, withResourceAuth, withPromptAuth methods
   *
   * @example
   * ```typescript
   * // Server registration
   * const authMiddleware = provider.authMiddleware();
   * const tools = toolFactories.map(f => f()).map(authMiddleware.withToolAuth);
   * const resources = resourceFactories.map(f => f()).map(authMiddleware.withResourceAuth);
   * const prompts = promptFactories.map(f => f()).map(authMiddleware.withPromptAuth);
   *
   * // Tool handler receives auth
   * async function handler({ id }: In, extra: EnrichedExtra) {
   *   // extra.authContext.auth is OAuth2Client (from middleware)
   *   const gmail = google.gmail({ version: 'v1', auth: extra.authContext.auth });
   * }
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

        try {
          // Use fixed accountId for storage isolation (like device-code pattern)
          const accountId = 'service-account';

          // Get service account email for logging/display
          const serviceEmail = await this.getUserEmail();

          // Get access token (generates JWT and exchanges if needed)
          await this.getAccessToken();

          // Create OAuth2Client with service account credentials
          const auth = this.toAuth(accountId);

          // Inject authContext and logger into extra parameter
          (extra as { authContext?: AuthContext }).authContext = {
            auth, // OAuth2Client for googleapis
            accountId, // 'service-account' (fixed, not service email)
            metadata: { serviceEmail }, // Keep email for logging/reference
          };
          (extra as { logger?: unknown }).logger = this.config.logger;

          // Call original handler with all args
          return await originalHandler(...allArgs);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);

          // Provide specific, actionable error messages based on error type
          if (message.includes('key file not found')) {
            throw new Error(`Service account setup error: Key file '${this.keyFilePath}' not found.\n• Set GOOGLE_SERVICE_ACCOUNT_KEY_FILE environment variable\n• Or ensure the file path exists and is accessible`);
          }
          if (message.includes('Forbidden') || message.includes('access_denied')) {
            throw new Error(
              'Service account permission error: The service account does not have required permissions.\n' + '• Ensure the service account has been granted the necessary roles\n' + '• Check that required API scopes are enabled in Google Cloud Console\n' + '• Verify the service account is active (not disabled)'
            );
          }
          if (message.includes('invalid_grant') || message.includes('JWT')) {
            throw new Error('Service account authentication error: Invalid credentials or expired tokens.\n' + '• Verify your service account key file is valid and not expired\n' + '• Check that the service account email and project match your GCP setup\n' + '• Try regenerating the key file in Google Cloud Console');
          }
          if (message.includes('Network error') || message.includes('fetch')) {
            throw new Error('Service account connection error: Unable to reach Google authentication services.\n' + '• Check your internet connection\n' + '• Verify firewall/proxy settings allow HTTPS to oauth2.googleapis.com\n' + '• Try again in a few moments (may be temporary service issue)');
          }
          // Generic fallback with original error
          throw new Error(`Service account authentication failed: ${message}`);
        }
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
