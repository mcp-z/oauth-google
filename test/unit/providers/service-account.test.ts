/**
 * ServiceAccountProvider local behavior: key file loading and validation, the fixed
 * service-account identity, and error mapping. Live token exchange is covered in
 * test/integration/service-account.test.ts.
 */

import type { ToolModule } from '@mcp-z/oauth-google';
import { ServiceAccountProvider } from '@mcp-z/oauth-google';
import type { CallToolResult } from '@modelcontextprotocol/server';
import assert from 'assert';
import { generateKeyPairSync, randomUUID } from 'crypto';
import { promises as fs } from 'fs';
import * as path from 'path';
import { createTestExtra, logger } from '../../lib/test-utils.ts';
import { throwFailures } from '../../lib/throw-failures.ts';

describe('ServiceAccountProvider', () => {
  const scopes = ['https://www.googleapis.com/auth/drive.readonly'];
  const fixtureDir = path.resolve('.tmp', `service-account-${randomUUID()}`);
  const fixtureEmail = 'fixture@test-project.iam.gserviceaccount.com';
  const written: string[] = [];
  const missingKeyFile = path.join(fixtureDir, 'missing.json');

  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  const validKey = {
    type: 'service_account',
    project_id: 'test-project',
    private_key_id: 'fixture-key-id',
    private_key: privateKey,
    client_email: fixtureEmail,
    client_id: '123',
    auth_uri: 'https://accounts.google.com/o/oauth2/auth',
    token_uri: 'https://oauth2.googleapis.com/token',
  };

  async function writeKeyFile(name: string, content: string): Promise<string> {
    const filePath = path.join(fixtureDir, name);
    await fs.writeFile(filePath, content);
    written.push(filePath);
    return filePath;
  }

  const provider = (keyFilePath: string) => new ServiceAccountProvider({ keyFilePath, scopes, logger });

  before(async () => {
    await fs.mkdir(fixtureDir, { recursive: true });
  });

  after(async () => {
    const failures: unknown[] = [];
    for (const filePath of written) await fs.unlink(filePath).catch((error: unknown) => failures.push(error));
    await fs.rmdir(fixtureDir).catch((error: unknown) => failures.push(error));
    throwFailures('Service account fixture cleanup failed', failures);
  });

  describe('key file loading and validation', () => {
    it('reads client_email from a valid key file for any account id', async () => {
      const keyFile = await writeKeyFile('valid.json', JSON.stringify(validKey));
      const sa = provider(keyFile);

      assert.strictEqual(await sa.getUserEmail('service-account'), fixtureEmail);
      assert.strictEqual(await sa.getUserEmail('user1'), fixtureEmail);
      assert.strictEqual(await sa.getUserEmail(), fixtureEmail);
    });

    it('throws on missing file', async () => {
      await assert.rejects(() => provider(missingKeyFile).getUserEmail('service-account'), /Service account key file not found/);
    });

    it('throws on invalid JSON', async () => {
      const keyFile = await writeKeyFile('invalid.json', 'invalid json content{');
      await assert.rejects(() => provider(keyFile).getUserEmail('service-account'), /Failed to parse service account key file as JSON/);
    });

    it('throws on wrong type field', async () => {
      const keyFile = await writeKeyFile('wrong-type.json', JSON.stringify({ ...validKey, type: 'authorized_user' }));
      await assert.rejects(() => provider(keyFile).getUserEmail('service-account'), /Expected type "service_account"/);
    });

    it('throws on missing required fields', async () => {
      const keyFile = await writeKeyFile('incomplete.json', JSON.stringify({ type: 'service_account', project_id: 'test-project' }));
      await assert.rejects(() => provider(keyFile).getUserEmail('service-account'), /missing required fields/);
    });

    it('throws on invalid private key format', async () => {
      const keyFile = await writeKeyFile('bad-pem.json', JSON.stringify({ ...validKey, private_key: 'not-a-valid-pem-key' }));
      await assert.rejects(() => provider(keyFile).getUserEmail('service-account'), /does not contain a valid PEM-formatted key/);
    });
  });

  describe('fixed service-account identity', () => {
    it('toAuthProvider accepts the service-account id or none', () => {
      const sa = provider(missingKeyFile);
      assert.strictEqual(typeof sa.toAuthProvider('service-account').getAccessToken, 'function');
      assert.strictEqual(typeof sa.toAuthProvider(undefined).getAccessToken, 'function');
    });

    it('toAuthProvider rejects any other account id', () => {
      assert.throws(() => provider(missingKeyFile).toAuthProvider('wrong-account'), /ServiceAccountProvider only supports accountId='service-account'.*single static identity pattern/);
    });

    it('authMiddleware exposes tool wrapping', () => {
      assert.strictEqual(typeof provider(missingKeyFile).authMiddleware().withToolAuth, 'function');
    });
  });

  describe('error handling', () => {
    it('getAccessToken wraps errors with context', async () => {
      await assert.rejects(() => provider(missingKeyFile).getAccessToken('service-account'), /Failed to get service account access token/);
    });

    it('authMiddleware maps a missing key file to a setup error', async () => {
      const testTool = {
        name: 'test-tool',
        config: { inputSchema: {}, outputSchema: {} },
        handler: async () => ({ content: [{ type: 'text', text: 'success' }] }),
      } as unknown as ToolModule;
      const wrappedTool = provider(missingKeyFile).authMiddleware().withToolAuth(testTool);

      await assert.rejects(
        () => (wrappedTool.handler as (args: unknown, extra: unknown) => Promise<CallToolResult>)({}, createTestExtra({ _meta: {} })),
        (error: Error) => {
          assert.ok(error.message.includes('Service account setup error'), error.message);
          assert.ok(error.message.includes('Key file'), error.message);
          return true;
        }
      );
    });
  });
});
