import '../../lib/env-loader.ts';
import assert from 'assert';
import { isRevokedRefreshToken, ProviderRefreshError } from '../../../src/lib/provider-refresh-error.ts';

describe('provider-refresh-error', () => {
  // Body shape: Google's token endpoint answers a revoked or expired refresh token with
  // HTTP 400 and an RFC 6749 section 5.2 body; google-auth-library reads the same body
  // (node_modules/google-auth-library/build/src/auth/oauth2client.js:263).
  it('classifies a Google invalid_grant response as a revoked refresh token', () => {
    const error = new ProviderRefreshError(400, JSON.stringify({ error: 'invalid_grant', error_description: 'Token has been expired or revoked.' }));
    assert.strictEqual(error.oauthError, 'invalid_grant');
    assert.strictEqual(isRevokedRefreshToken(error), true);
    assert.match(error.message, /^Token refresh failed: 400 /);
  });

  it('does not classify other failures as revoked', () => {
    assert.strictEqual(isRevokedRefreshToken(new ProviderRefreshError(400, JSON.stringify({ error: 'invalid_client' }))), false);
    assert.strictEqual(isRevokedRefreshToken(new ProviderRefreshError(503, 'upstream unavailable')), false);
    assert.strictEqual(isRevokedRefreshToken(new Error('Token refresh failed: 400 {"error":"invalid_grant"}')), false);
    assert.strictEqual(isRevokedRefreshToken(undefined), false);
  });
});
