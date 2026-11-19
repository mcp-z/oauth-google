import type { CiConfig } from './lib/ci-setup.ts';

export const config = {
  provider: 'google',
  flows: [
    {
      id: 'loopback-google',
      refreshTokenSecret: 'TEST_REFRESH_TOKEN',
      scopeSecret: 'TEST_SCOPE',
      clientIdSecret: 'GOOGLE_CLIENT_ID',
      clientSecretSecret: 'GOOGLE_CLIENT_SECRET',
      clientSecretRequired: false,
      tenantSecret: null,
      storage: {
        kind: 'account',
        path: '.tokens/test/store.json',
        service: 'gmail',
        accountId: {
          env: 'TEST_ACCOUNT_ID',
        },
      },
    },
    {
      id: 'dcr-google',
      refreshTokenSecret: 'TEST_DCR_REFRESH_TOKEN',
      scopeSecret: 'TEST_DCR_SCOPE',
      clientIdSecret: 'GOOGLE_TEST_DCR_CLIENT_ID',
      clientSecretSecret: 'GOOGLE_TEST_DCR_CLIENT_SECRET',
      clientSecretRequired: true,
      tenantSecret: null,
      storage: {
        kind: 'dcr',
        path: '.tokens/dcr.json',
        key: 'google',
        registration: {
          clientIdSecret: 'TEST_DCR_CLIENT_ID',
          clientSecretSecret: 'TEST_DCR_CLIENT_SECRET',
        },
      },
    },
  ],
  requiredTestSecrets: [],
  serviceAccount: {
    output: 'service-account.test.json',
    secrets: {
      private_key: 'GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY',
      private_key_id: 'GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY_ID',
      client_email: 'GOOGLE_SERVICE_ACCOUNT_CLIENT_EMAIL',
      client_id: 'GOOGLE_SERVICE_ACCOUNT_CLIENT_ID',
      project_id: 'GOOGLE_SERVICE_ACCOUNT_PROJECT_ID',
      auth_uri: 'GOOGLE_SERVICE_ACCOUNT_AUTH_URI',
      token_uri: 'GOOGLE_SERVICE_ACCOUNT_TOKEN_URI',
    },
  },
} as const satisfies CiConfig;
