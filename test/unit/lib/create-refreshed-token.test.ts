import '../../lib/env-loader.ts';
import assert from 'assert';
import { createRefreshedToken } from '../../../src/lib/create-refreshed-token.ts';

describe('createRefreshedToken', () => {
  it('uses a replacement refresh token and converts expiry to an absolute time', () => {
    const before = Date.now();
    const token = createRefreshedToken({ access_token: 'new-access', refresh_token: 'new-refresh', expires_in: 3600, scope: 'openid email' }, 'old-refresh');

    assert.strictEqual(token.accessToken, 'new-access');
    assert.strictEqual(token.refreshToken, 'new-refresh');
    assert.strictEqual(token.scope, 'openid email');
    assert.ok(token.expiresAt !== undefined && token.expiresAt >= before + 3600000 && token.expiresAt <= Date.now() + 3600000);
  });

  it('preserves the previous refresh token when the response omits one', () => {
    assert.deepStrictEqual(createRefreshedToken({ access_token: 'new-access' }, 'old-refresh'), { accessToken: 'new-access', refreshToken: 'old-refresh' });
    assert.strictEqual(createRefreshedToken({ access_token: 'new-access', refresh_token: '' }, 'old-refresh').refreshToken, 'old-refresh');
  });

  it('preserves a zero expiry as already expiring', () => {
    const before = Date.now();
    const token = createRefreshedToken({ access_token: 'expired', expires_in: 0 }, 'refresh');
    assert.ok(token.expiresAt !== undefined && token.expiresAt >= before && token.expiresAt <= Date.now());
  });
});
