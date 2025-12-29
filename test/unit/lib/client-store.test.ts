import '../../lib/env-loader.js';

/**
 * DCR Utils Tests
 *
 * Tests for RFC 7591 Dynamic Client Registration client management.
 * Tests client registration, validation, and lifecycle management.
 */

import type { DcrClientMetadata } from '@mcp-z/oauth';
import assert from 'assert';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import * as dcrUtils from '../../../src/lib/dcr-utils.ts';

// Use isolated test storage
const testStorePath = path.join('.tmp', `client-store-test-${Date.now()}.json`);

it('dcrUtils - registerClient creates valid client', async () => {
  const store = new Keyv({
    store: new KeyvFile({ filename: testStorePath }),
  });

  const metadata: DcrClientMetadata = {
    redirect_uris: ['http://localhost:3000/callback'],
    client_name: 'Test Client',
    scope: 'openid email',
  };

  const client = await dcrUtils.registerClient(store, metadata);

  assert.ok(client.client_id, 'Client ID should be generated');
  assert.ok(client.client_secret, 'Client secret should be generated');
  assert.ok(client.client_id.startsWith('dcr_'), 'Client ID should have dcr_ prefix');
  assert.strictEqual(client.client_name, 'Test Client');
  assert.deepStrictEqual(client.redirect_uris, metadata.redirect_uris);
});

it('dcrUtils - getClient retrieves registered client', async () => {
  const store = new Keyv({
    store: new KeyvFile({ filename: testStorePath }),
  });

  const metadata: DcrClientMetadata = {
    redirect_uris: ['http://localhost:3000/callback'],
    client_name: 'Get Test Client',
  };

  const registered = await dcrUtils.registerClient(store, metadata);
  const retrieved = await dcrUtils.getClient(store, registered.client_id);

  assert.ok(retrieved, 'Client should be retrieved');
  assert.strictEqual(retrieved?.client_id, registered.client_id);
  assert.strictEqual(retrieved?.client_secret, registered.client_secret);
});

it('dcrUtils - validateClient checks credentials correctly', async () => {
  const store = new Keyv({
    store: new KeyvFile({ filename: testStorePath }),
  });

  const metadata: DcrClientMetadata = {
    redirect_uris: ['http://localhost:3000/callback'],
  };

  const client = await dcrUtils.registerClient(store, metadata);

  // Valid credentials
  const validResult = await dcrUtils.validateClient(store, client.client_id, client.client_secret as string);
  assert.strictEqual(validResult, true, 'Valid credentials should pass');

  // Invalid secret
  const invalidResult = await dcrUtils.validateClient(store, client.client_id, 'wrong_secret');
  assert.strictEqual(invalidResult, false, 'Invalid secret should fail');

  // Unknown client
  const unknownResult = await dcrUtils.validateClient(store, 'unknown_client', 'any_secret');
  assert.strictEqual(unknownResult, false, 'Unknown client should fail');
});

it('dcrUtils - validateRedirectUri checks URIs correctly', async () => {
  const store = new Keyv({
    store: new KeyvFile({ filename: testStorePath }),
  });

  const metadata: DcrClientMetadata = {
    redirect_uris: ['http://localhost:3000/callback', 'http://localhost:3001/oauth'],
  };

  const client = await dcrUtils.registerClient(store, metadata);

  // Valid redirect URIs
  const validResult1 = await dcrUtils.validateRedirectUri(store, client.client_id, 'http://localhost:3000/callback');
  assert.strictEqual(validResult1, true, 'Registered redirect URI should be valid');

  const validResult2 = await dcrUtils.validateRedirectUri(store, client.client_id, 'http://localhost:3001/oauth');
  assert.strictEqual(validResult2, true, 'Second redirect URI should be valid');

  // Invalid redirect URI
  const invalidResult = await dcrUtils.validateRedirectUri(store, client.client_id, 'http://evil.com/callback');
  assert.strictEqual(invalidResult, false, 'Unregistered redirect URI should be invalid');
});

it('dcrUtils - listClients returns all registered clients', async () => {
  const store = new Keyv({
    store: new KeyvFile({ filename: testStorePath }),
  });

  // Register multiple clients
  await dcrUtils.registerClient(store, {
    redirect_uris: ['http://localhost:3000/callback'],
    client_name: 'Client 1',
  });

  await dcrUtils.registerClient(store, {
    redirect_uris: ['http://localhost:3001/callback'],
    client_name: 'Client 2',
  });

  const clients = await dcrUtils.listClients(store);

  assert.ok(clients.length >= 2, 'Should return at least 2 clients');
  assert.ok(
    clients.every((c) => c.client_id.startsWith('dcr_')),
    'All clients should have dcr_ prefix'
  );
});

it('dcrUtils - deleteClient removes client', async () => {
  const store = new Keyv({
    store: new KeyvFile({ filename: testStorePath }),
  });

  const metadata: DcrClientMetadata = {
    redirect_uris: ['http://localhost:3000/callback'],
    client_name: 'To Be Deleted',
  };

  const client = await dcrUtils.registerClient(store, metadata);

  // Verify client exists
  const beforeDelete = await dcrUtils.getClient(store, client.client_id);
  assert.ok(beforeDelete, 'Client should exist before deletion');

  // Delete client
  await dcrUtils.deleteClient(store, client.client_id);

  // Verify client is gone
  const afterDelete = await dcrUtils.getClient(store, client.client_id);
  assert.strictEqual(afterDelete, undefined, 'Client should not exist after deletion');
});

it('dcrUtils - registerClient requires redirect_uris', async () => {
  const store = new Keyv({
    store: new KeyvFile({ filename: testStorePath }),
  });

  const invalidMetadata = {
    client_name: 'Invalid Client',
    // Missing redirect_uris
  } as DcrClientMetadata;

  await assert.rejects(async () => {
    await dcrUtils.registerClient(store, invalidMetadata);
  }, /redirect_uris is required/);
});
