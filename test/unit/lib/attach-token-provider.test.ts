import { attachTokenProvider, type RefreshHandlerClient } from '@mcp-z/oauth-google';
import assert from 'assert';

describe('unit/lib/attach-token-provider', () => {
  it('points the client at the provider', async () => {
    const client: RefreshHandlerClient = {};
    attachTokenProvider(client, { getAccessToken: async () => 'token-1' });

    assert.ok(client.refreshHandler, 'should set a refreshHandler');
    assert.strictEqual((await client.refreshHandler()).access_token, 'token-1');
  });

  it('returns the client it was given, for inline use', () => {
    const client: RefreshHandlerClient = {};
    assert.strictEqual(attachTokenProvider(client, { getAccessToken: async () => 't' }), client);
  });

  // The invariant: expiry_date must keep the token permanently "expiring" so the
  // client re-asks on every request and the provider decides what is current. A
  // plausible-looking future expiry makes the client cache until it passes, and
  // every request after the real expiry then 401s with no retry.
  it('asks the provider again on every request', async () => {
    let calls = 0;
    const client: RefreshHandlerClient = {};
    attachTokenProvider(client, {
      getAccessToken: async () => {
        calls++;
        return `token-${calls}`;
      },
    });

    const first = await client.refreshHandler?.();
    const second = await client.refreshHandler?.();

    assert.strictEqual(calls, 2, 'handler must run per request, not once');
    assert.strictEqual(first?.access_token, 'token-1');
    assert.strictEqual(second?.access_token, 'token-2');
  });

  it('reports an expiry the client always treats as expiring', async () => {
    const client: RefreshHandlerClient = {};
    attachTokenProvider(client, { getAccessToken: async () => 't' });

    const before = Date.now();
    const { expiry_date } = (await client.refreshHandler?.()) ?? { expiry_date: Number.NaN };

    // google-auth-library caches while `expiry_date > now + 5min`; anything at or
    // behind now fails that check on the next call. Asserting the bound rather than
    // equality keeps this true if the value ever becomes `now - 1`.
    assert.ok(expiry_date <= Date.now(), 'must not be in the future');
    assert.ok(expiry_date >= before, 'should be derived from the current time');
  });
});
