import '../lib/env-loader.ts';

import assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { type DcrConfig, type OAuthConfig, parseConfig, parseDcrConfig } from '../../src/setup/config.ts';

describe('parseConfig', () => {
  describe('Environment variables', () => {
    it('parses config with all environment variables', () => {
      const env = {
        GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
        GOOGLE_CLIENT_SECRET: 'test-client-secret',
      };

      const config = parseConfig([], env);

      assert.strictEqual(config.clientId, 'test-client-id.apps.googleusercontent.com');
      assert.strictEqual(config.clientSecret, 'test-client-secret');
    });

    it('parses config with optional client secret omitted', () => {
      const env = {
        GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
      };

      const config = parseConfig([], env);

      assert.strictEqual(config.clientId, 'test-client-id.apps.googleusercontent.com');
      assert.strictEqual(config.clientSecret, undefined);
    });

    it('throws error when GOOGLE_CLIENT_ID is missing', () => {
      const env = {
        GOOGLE_CLIENT_SECRET: 'test-client-secret',
      };

      assert.throws(() => parseConfig([], env), {
        name: 'Error',
        message: 'Environment variable GOOGLE_CLIENT_ID is required for Google OAuth',
      });
    });

    it('throws error when GOOGLE_CLIENT_ID is empty string', () => {
      const env = {
        GOOGLE_CLIENT_ID: '',
        GOOGLE_CLIENT_SECRET: 'test-client-secret',
      };

      assert.throws(() => parseConfig([], env), {
        name: 'Error',
        message: 'Environment variable GOOGLE_CLIENT_ID is required for Google OAuth',
      });
    });

    it('handles undefined environment variables correctly', () => {
      const env = {
        GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
        GOOGLE_CLIENT_SECRET: undefined,
      };

      const config = parseConfig([], env);

      assert.strictEqual(config.clientId, 'test-client-id.apps.googleusercontent.com');
      assert.strictEqual(config.clientSecret, undefined);
    });
  });

  describe('Default values', () => {
    it('defaults to loopback-oauth auth mode', () => {
      const env = { GOOGLE_CLIENT_ID: 'test-id' };
      const config = parseConfig([], env);

      assert.strictEqual(config.auth, 'loopback-oauth');
    });

    it('defaults headless to false when not specified', () => {
      const env = { GOOGLE_CLIENT_ID: 'test-id' };
      const config = parseConfig([], env);

      assert.strictEqual(config.headless, false);
    });
  });

  describe('CLI arguments', () => {
    it('parses --headless flag', () => {
      const env = { GOOGLE_CLIENT_ID: 'test-id' };
      const config = parseConfig(['--headless'], env);

      assert.strictEqual(config.headless, true);
    });

    it('parses --redirect-uri', () => {
      const env = { GOOGLE_CLIENT_ID: 'test-id' };
      const config = parseConfig(['--redirect-uri=https://api.example.com/callback'], env);

      assert.strictEqual(config.redirectUri, 'https://api.example.com/callback');
    });

    it('CLI --headless overrides env HEADLESS', () => {
      const env = { GOOGLE_CLIENT_ID: 'test-id', HEADLESS: 'false' };
      const config = parseConfig(['--headless'], env);

      assert.strictEqual(config.headless, true);
    });

    it('CLI --redirect-uri overrides env REDIRECT_URI', () => {
      const env = { GOOGLE_CLIENT_ID: 'test-id', REDIRECT_URI: 'http://localhost:3000/old' };
      const config = parseConfig(['--redirect-uri=http://localhost:8080/oauth/callback'], env);

      assert.strictEqual(config.redirectUri, 'http://localhost:8080/oauth/callback');
    });
  });

  describe('Environment variable fallbacks', () => {
    it('uses HEADLESS env var', () => {
      const env = { GOOGLE_CLIENT_ID: 'test-id', HEADLESS: 'true' };
      const config = parseConfig([], env);

      assert.strictEqual(config.headless, true);
    });

    it('uses REDIRECT_URI env var', () => {
      const env = { GOOGLE_CLIENT_ID: 'test-id', REDIRECT_URI: 'http://localhost:8080/oauth/callback' };
      const config = parseConfig([], env);

      assert.strictEqual(config.redirectUri, 'http://localhost:8080/oauth/callback');
    });
  });

  describe('--auth argument', () => {
    describe('Valid modes', () => {
      it('parses --auth=loopback-oauth', () => {
        const env = { GOOGLE_CLIENT_ID: 'test-id' };
        const config = parseConfig(['--auth=loopback-oauth'], env);

        assert.strictEqual(config.auth, 'loopback-oauth');
      });

      it('parses --auth=service-account', () => {
        const env = { GOOGLE_CLIENT_ID: 'test-id', GOOGLE_SERVICE_ACCOUNT_KEY_FILE: '/path/to/key.json' };
        const config = parseConfig(['--auth=service-account'], env);

        assert.strictEqual(config.auth, 'service-account');
      });
    });

    describe('Invalid modes', () => {
      it('throws error for invalid auth mode', () => {
        const env = { GOOGLE_CLIENT_ID: 'test-id' };

        assert.throws(() => parseConfig(['--auth=invalid'], env), {
          message: /Invalid --auth value: "invalid"/,
        });
      });
    });

    describe('AUTH_MODE environment variable', () => {
      it('uses AUTH_MODE env var', () => {
        const env = { GOOGLE_CLIENT_ID: 'test-id', AUTH_MODE: 'loopback-oauth' };
        const config = parseConfig([], env);

        assert.strictEqual(config.auth, 'loopback-oauth');
      });

      it('CLI --auth overrides AUTH_MODE env var', () => {
        const env = { GOOGLE_CLIENT_ID: 'test-id', AUTH_MODE: 'loopback-oauth', GOOGLE_SERVICE_ACCOUNT_KEY_FILE: '/path/to/key.json' };
        const config = parseConfig(['--auth=service-account'], env);

        assert.strictEqual(config.auth, 'service-account');
      });
    });
  });

  describe('Type structure', () => {
    it('returns correct type structure', () => {
      const env = {
        GOOGLE_CLIENT_ID: 'test-client-id',
        GOOGLE_CLIENT_SECRET: 'test-secret',
      };

      const config: OAuthConfig = parseConfig([], env);

      // Type assertions - should compile without errors
      assert.ok(typeof config.clientId === 'string');
      assert.ok(typeof config.clientSecret === 'string' || config.clientSecret === undefined);
      assert.ok(config.auth === 'loopback-oauth' || config.auth === 'service-account' || config.auth === 'dcr');
      assert.ok(typeof config.headless === 'boolean');
      assert.ok(typeof config.redirectUri === 'string' || config.redirectUri === undefined);
    });
  });

  describe('Transport validation', () => {
    it('allows DCR mode with HTTP transport', () => {
      const env = { GOOGLE_CLIENT_ID: 'test-id' };
      const config = parseConfig(['--auth=dcr'], env, 'http');

      assert.strictEqual(config.auth, 'dcr');
    });

    it('allows DCR mode when transport not specified', () => {
      const env = { GOOGLE_CLIENT_ID: 'test-id' };
      const config = parseConfig(['--auth=dcr'], env);

      assert.strictEqual(config.auth, 'dcr');
    });

    it('throws error for DCR mode with stdio transport', () => {
      const env = { GOOGLE_CLIENT_ID: 'test-id' };

      assert.throws(() => parseConfig(['--auth=dcr'], env, 'stdio'), {
        name: 'Error',
        message: 'DCR authentication mode requires HTTP transport. DCR is not supported with stdio transport.',
      });
    });

    it('throws error for DCR mode via AUTH_MODE env var with stdio transport', () => {
      const env = { GOOGLE_CLIENT_ID: 'test-id', AUTH_MODE: 'dcr' };

      assert.throws(() => parseConfig([], env, 'stdio'), {
        name: 'Error',
        message: 'DCR authentication mode requires HTTP transport. DCR is not supported with stdio transport.',
      });
    });

    it('allows loopback-oauth mode with stdio transport', () => {
      const env = { GOOGLE_CLIENT_ID: 'test-id' };
      const config = parseConfig(['--auth=loopback-oauth'], env, 'stdio');

      assert.strictEqual(config.auth, 'loopback-oauth');
    });

    it('allows service-account mode with stdio transport', () => {
      const env = { GOOGLE_CLIENT_ID: 'test-id', GOOGLE_SERVICE_ACCOUNT_KEY_FILE: '/path/to/key.json' };
      const config = parseConfig(['--auth=service-account'], env, 'stdio');

      assert.strictEqual(config.auth, 'service-account');
    });
  });

  describe('Service account key file path resolution', () => {
    it('resolves relative service account key file paths at config parse time', async () => {
      // Store original cwd
      const originalCwd = process.cwd();

      // Create temp directory structure (using absolute paths)
      const tempRoot = path.resolve('.tmp', `test-config-${Date.now()}`);
      const configDir = path.join(tempRoot, 'config');
      const keyFileDir = path.join(tempRoot, 'keys');

      await fs.promises.mkdir(configDir, { recursive: true });
      await fs.promises.mkdir(keyFileDir, { recursive: true });

      // Create a minimal service account key file
      const keyFilePath = path.join(keyFileDir, 'service-account.json');
      const serviceAccountKey = {
        type: 'service_account',
        project_id: 'test-project',
        private_key_id: 'test-key-id',
        private_key: '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----',
        client_email: 'test@test-project.iam.gserviceaccount.com',
        client_id: '123456789',
        auth_uri: 'https://accounts.google.com/o/oauth2/auth',
        token_uri: 'https://oauth2.googleapis.com/token',
      };
      await fs.promises.writeFile(keyFilePath, JSON.stringify(serviceAccountKey), 'utf-8');

      try {
        // Parse config from keys directory with relative path
        process.chdir(keyFileDir);
        const env = {
          GOOGLE_CLIENT_ID: 'test-client-id',
          GOOGLE_SERVICE_ACCOUNT_KEY_FILE: './service-account.json',
        };
        const config = parseConfig(['--auth=service-account'], env);

        // Config should have the key file path
        assert.ok(config.serviceAccountKeyFile, 'serviceAccountKeyFile should be present');

        // Store the key file path before changing directory
        const resolvedKeyFilePath = config.serviceAccountKeyFile;

        // Now change to a different directory
        process.chdir(configDir);

        // Try to use the service account provider
        // The relative path should have been resolved at parse time,
        // so this should still work even though we changed directories
        const { ServiceAccountProvider } = await import('../../src/providers/service-account.ts');
        const provider = new ServiceAccountProvider({
          keyFilePath: resolvedKeyFilePath,
          scopes: ['https://www.googleapis.com/auth/drive.readonly'],
          logger: console,
        });

        // This should succeed if the path was resolved at config parse time
        // It will fail if the path is still relative
        const email = await provider.getUserEmail();
        assert.strictEqual(email, 'test@test-project.iam.gserviceaccount.com');
      } finally {
        // Always restore cwd and close, regardless of test outcome
        process.chdir(originalCwd);
        await fs.promises.rm(tempRoot, { recursive: true, force: true });
      }
    });
  });
});

describe('parseDcrConfig', () => {
  const testScope = 'https://www.googleapis.com/auth/spreadsheets';

  describe('Valid configurations', () => {
    it('parses valid self-hosted mode with all environment variables', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://.dcr.json',
        GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
        GOOGLE_CLIENT_SECRET: 'test-client-secret',
      };

      const config = parseDcrConfig([], env, testScope);

      assert.strictEqual(config.mode, 'self-hosted');
      assert.strictEqual(config.storeUri, 'file://.dcr.json');
      assert.strictEqual(config.clientId, 'test-client-id.apps.googleusercontent.com');
      assert.strictEqual(config.clientSecret, 'test-client-secret');
      assert.strictEqual(config.scope, testScope);
      assert.strictEqual(config.verifyUrl, undefined);
    });

    it('parses valid external mode with verifyUrl', () => {
      const env = {
        DCR_MODE: 'external',
        DCR_VERIFY_URL: 'https://auth.example.com/oauth/verify',
        GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
        GOOGLE_CLIENT_SECRET: 'test-client-secret',
      };

      const config = parseDcrConfig([], env, testScope);

      assert.strictEqual(config.mode, 'external');
      assert.strictEqual(config.verifyUrl, 'https://auth.example.com/oauth/verify');
      assert.strictEqual(config.clientId, 'test-client-id.apps.googleusercontent.com');
      assert.strictEqual(config.clientSecret, 'test-client-secret');
      assert.strictEqual(config.scope, testScope);
      assert.strictEqual(config.storeUri, undefined);
    });

    it('parses config with optional client secret omitted', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://.dcr.json',
        GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
      };

      const config = parseDcrConfig([], env, testScope);

      assert.strictEqual(config.clientId, 'test-client-id.apps.googleusercontent.com');
      assert.strictEqual(config.clientSecret, undefined);
    });
  });

  describe('Default values', () => {
    it('defaults to self-hosted mode when DCR_MODE not specified', () => {
      const env = {
        DCR_STORE_URI: 'file://.dcr.json',
        GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
      };

      const config = parseDcrConfig([], env, testScope);

      assert.strictEqual(config.mode, 'self-hosted');
      assert.strictEqual(config.storeUri, 'file://.dcr.json');
    });
  });

  describe('CLI arguments override environment variables', () => {
    it('CLI --dcr-mode overrides DCR_MODE env var', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://.dcr.json',
        DCR_VERIFY_URL: 'https://auth.example.com/oauth/verify',
        GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
      };

      const config = parseDcrConfig(['--dcr-mode=external'], env, testScope);

      assert.strictEqual(config.mode, 'external');
      assert.strictEqual(config.verifyUrl, 'https://auth.example.com/oauth/verify');
    });

    it('CLI --dcr-verify-url overrides DCR_VERIFY_URL env var', () => {
      const env = {
        DCR_MODE: 'external',
        DCR_VERIFY_URL: 'https://old.example.com/verify',
        GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
      };

      const config = parseDcrConfig(['--dcr-verify-url=https://new.example.com/verify'], env, testScope);

      assert.strictEqual(config.verifyUrl, 'https://new.example.com/verify');
    });

    it('CLI --dcr-store-uri overrides DCR_STORE_URI env var', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://old-path/store.json',
        GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
      };

      const config = parseDcrConfig(['--dcr-store-uri=file://new-path/store.json'], env, testScope);

      assert.strictEqual(config.storeUri, 'file://new-path/store.json');
    });
  });

  describe('Invalid mode value', () => {
    it('throws error for invalid --dcr-mode value', () => {
      const env = {
        GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
      };

      assert.throws(() => parseDcrConfig(['--dcr-mode=invalid'], env, testScope), {
        name: 'Error',
        message: 'Invalid --dcr-mode value: "invalid". Valid values: self-hosted, external',
      });
    });

    it('throws error for invalid DCR_MODE env var', () => {
      const env = {
        DCR_MODE: 'invalid',
        GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
      };

      assert.throws(() => parseDcrConfig([], env, testScope), {
        name: 'Error',
        message: 'Invalid --dcr-mode value: "invalid". Valid values: self-hosted, external',
      });
    });
  });

  describe('Mode-specific required field validation', () => {
    it('throws error when verifyUrl missing in external mode', () => {
      const env = {
        DCR_MODE: 'external',
        GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com',
      };

      assert.throws(() => parseDcrConfig([], env, testScope), {
        name: 'Error',
        message: 'DCR external mode requires --dcr-verify-url or DCR_VERIFY_URL environment variable',
      });
    });

    it('throws error when GOOGLE_CLIENT_ID is missing', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://.dcr.json',
      };

      assert.throws(() => parseDcrConfig([], env, testScope), {
        name: 'Error',
        message: 'Environment variable GOOGLE_CLIENT_ID is required for DCR configuration',
      });
    });

    it('throws error when GOOGLE_CLIENT_ID is empty string', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://.dcr.json',
        GOOGLE_CLIENT_ID: '',
      };

      assert.throws(() => parseDcrConfig([], env, testScope), {
        name: 'Error',
        message: 'Environment variable GOOGLE_CLIENT_ID is required for DCR configuration',
      });
    });
  });

  describe('Type structure', () => {
    it('returns correct type structure for self-hosted mode', () => {
      const env = {
        DCR_MODE: 'self-hosted',
        DCR_STORE_URI: 'file://.dcr.json',
        GOOGLE_CLIENT_ID: 'test-client-id',
        GOOGLE_CLIENT_SECRET: 'test-secret',
      };

      const config: DcrConfig = parseDcrConfig([], env, testScope);

      // Type assertions - should compile without errors
      assert.ok(config.mode === 'self-hosted' || config.mode === 'external');
      assert.ok(typeof config.verifyUrl === 'string' || config.verifyUrl === undefined);
      assert.ok(typeof config.storeUri === 'string' || config.storeUri === undefined);
      assert.ok(typeof config.clientId === 'string');
      assert.ok(typeof config.clientSecret === 'string' || config.clientSecret === undefined);
      assert.ok(typeof config.scope === 'string');
    });

    it('returns correct type structure for external mode', () => {
      const env = {
        DCR_MODE: 'external',
        DCR_VERIFY_URL: 'https://auth.example.com/oauth/verify',
        GOOGLE_CLIENT_ID: 'test-client-id',
      };

      const config: DcrConfig = parseDcrConfig([], env, testScope);

      assert.strictEqual(config.mode, 'external');
      assert.strictEqual(typeof config.verifyUrl, 'string');
      assert.strictEqual(config.storeUri, undefined);
    });
  });
});
