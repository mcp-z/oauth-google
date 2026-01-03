#!/usr/bin/env node

/**
 * Minimal OAuth token setup for oauth-google library tests
 *
 * Self-contained test utility with minimal dependencies.
 * Just pure OAuth flow → Keyv/KeyvFile for validating googleapis integration.
 *
 * Usage:
 *   node test/lib/setup-token.ts
 */

import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';
import * as path from 'path';
import { LoopbackOAuthProvider } from '../../src/providers/loopback-oauth.ts';
import { createConfig } from '../../src/setup/config.ts';
import { GOOGLE_SCOPE } from '../constants.ts';
import { logger } from './test-utils.ts';

const config = createConfig();

async function setupToken(): Promise<void> {
  console.log('🔐 Google OAuth Test Token Setup');
  console.log('This script will generate tokens for BOTH loopback and DCR flows.');
  console.log('');

  // Use package-local .tokens directory (standardized path)
  const tokenStorePath = path.join(process.cwd(), '.tokens/test/store.json');
  const tokenStore = new Keyv({
    store: new KeyvFile({ filename: tokenStorePath }),
  });

  // Step 1: Generate loopback token
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('Step 1/2: Loopback OAuth Flow');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');

  const auth = new LoopbackOAuthProvider({
    service: 'gmail',
    clientId: config.clientId,
    clientSecret: config.clientSecret || undefined,
    scope: GOOGLE_SCOPE,
    headless: false,
    logger,
    tokenStore,
  });

  console.log('Starting loopback OAuth flow...');
  console.log('');

  // Trigger OAuth flow - will open browser or print URL
  await auth.getAccessToken();

  // Get user email for confirmation
  const email = await auth.getUserEmail();

  console.log('');
  console.log('✅ Loopback token generated successfully!');
  console.log(`📧 Authenticated as: ${email}`);
  console.log(`📁 Token saved to: ${tokenStorePath}`);
  console.log('');

  // Step 2: Generate DCR token
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('Step 2/2: DCR OAuth Flow');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');

  // Get DCR-specific credentials from environment
  // DCR uses a DIFFERENT client (Web app with confidential client) than loopback (Desktop app)
  const dcrClientId = process.env.GOOGLE_TEST_DCR_CLIENT_ID;
  const dcrClientSecret = process.env.GOOGLE_TEST_DCR_CLIENT_SECRET;

  if (!dcrClientId) {
    console.log('⚠️  Skipping DCR token setup - GOOGLE_TEST_DCR_CLIENT_ID not set');
    console.log('   Set GOOGLE_TEST_DCR_CLIENT_ID and GOOGLE_TEST_DCR_CLIENT_SECRET in .env.test to enable DCR testing');
    console.log('');
  } else {
    // Check for existing DCR tokens
    const { loadDcrTokens } = await import('./dcr-token-helper.ts');
    let existingDcrToken = await loadDcrTokens('google');

    // Try to refresh if token exists but is expired
    if (existingDcrToken && existingDcrToken.providerExpiresAt <= Date.now()) {
      console.log('⚠️  Existing DCR token expired. Attempting to refresh...');
      console.log('');

      try {
        // Refresh the Google access token
        const tokenUrl = 'https://oauth2.googleapis.com/token';
        const params: Record<string, string> = {
          refresh_token: existingDcrToken.providerRefreshToken,
          client_id: dcrClientId,
          grant_type: 'refresh_token',
        };
        if (dcrClientSecret) {
          params.client_secret = dcrClientSecret;
        }

        const response = await fetch(tokenUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams(params).toString(),
        });

        if (response.ok) {
          const tokenResponse = (await response.json()) as {
            access_token: string;
            expires_in?: number;
          };

          // Update stored token with refreshed access token
          const dcrTokenPath = path.join(process.cwd(), '.tokens/dcr.json');
          const dcrStore = new Keyv({
            store: new KeyvFile({ filename: dcrTokenPath }),
          });

          existingDcrToken.providerAccessToken = tokenResponse.access_token;
          existingDcrToken.providerExpiresAt = Date.now() + (tokenResponse.expires_in ?? 3600) * 1000;

          await dcrStore.set('google', existingDcrToken);

          console.log('✅ DCR token refreshed successfully!');
          console.log(`   Access Token: ${existingDcrToken.providerAccessToken.substring(0, 20)}...`);
          console.log('');
        } else {
          console.log('⚠️  Token refresh failed. Starting new OAuth flow...');
          console.log('');
          existingDcrToken = undefined; // Force new OAuth flow
        }
      } catch (error) {
        console.log('⚠️  Token refresh error:', error instanceof Error ? error.message : String(error));
        console.log('   Starting new OAuth flow...');
        console.log('');
        existingDcrToken = undefined; // Force new OAuth flow
      }
    }

    if (existingDcrToken && existingDcrToken.providerExpiresAt > Date.now()) {
      console.log('✅ Valid DCR token available!');
      console.log(`   Client ID: ${existingDcrToken.clientId}`);
      console.log(`   Access Token: ${existingDcrToken.providerAccessToken.substring(0, 20)}...`);
      console.log(`   Refresh Token: ${existingDcrToken.providerRefreshToken.substring(0, 20)}...`);
      console.log('');
    } else {
      // Import DCR setup helper
      const { setupDcrToken } = await import('./setup-dcr-token.ts');

      const dcrOptions: Parameters<typeof setupDcrToken>[0] = {
        clientId: dcrClientId,
        scope: GOOGLE_SCOPE,
        logger,
      };
      if (dcrClientSecret) {
        dcrOptions.clientSecret = dcrClientSecret;
      }
      await setupDcrToken(dcrOptions);
    }
  }

  console.log('');

  // Final summary
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('✅ All tokens generated successfully!');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');
  console.log(`📧 Loopback: ${email}`);
  console.log(`📁 Loopback tokens: ${tokenStorePath}`);
  console.log('📁 DCR tokens: .tokens/dcr.json');
  console.log('');
  console.log('Run `npm run test:unit` to verify googleapis integration');
  console.log('Run `npm run test:integration` to verify DCR flow');
}

// Run if executed directly
if (import.meta.main) {
  setupToken()
    .then(() => {
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n❌ Token setup failed:', error.message);
      process.exit(1);
    });
}
