# @mcp-z/oauth-google

OAuth 2.0 client for Google APIs with multi-account support, PKCE security, and swappable storage backends

## Common uses

- Gmail/Drive/Sheets OAuth in MCP servers
- CLI and desktop OAuth flows
- Service account auth for server-to-server access
- DCR and Client ID Metadata Documents (self-hosted) for shared HTTP servers

## Install

```bash
npm install @mcp-z/oauth-google keyv keyv-file
```

## Create a Google Cloud app

1. Go to [Google Cloud Console](https://console.cloud.google.com/).
2. Create or select a project.
3. Enable the API you need (Gmail, Drive, or Sheets).
4. Create OAuth 2.0 credentials (Desktop app).
5. Copy the Client ID and Client Secret.
6. Select the credential type that matches your deployment:
   - For a local stdio client, create a "Desktop app" OAuth client.
   - For an HTTP server, create a "Web application" client and add its public `/oauth/callback` URL. Local HTTP uses the port configured by the server.
   - For local hosting, add `http://127.0.0.1` for the [ephemeral redirect URL](https://en.wikipedia.org/wiki/Ephemeral_port).

## OAuth modes

### Redirect URI modes (loopback)
- No REDIRECT_URI: ephemeral loopback (random port), works for stdio and http.
- REDIRECT_URI set: persistent callback /oauth/callback (HTTP only).

### Loopback OAuth (interactive)

```ts
import { LoopbackOAuthProvider } from '@mcp-z/oauth-google';
import Keyv from 'keyv';
import { KeyvFile } from 'keyv-file';

const provider = new LoopbackOAuthProvider({
  service: 'gmail',
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  scope: 'https://www.googleapis.com/auth/gmail.modify',
  tokenStore: new Keyv({ store: new KeyvFile({ filename: '.tokens/google.json' }) })
});

const accessToken = await provider.getAccessToken();
// Opens the browser for consent when no valid token is stored, then returns a token.
```

### Service account

```ts
import { ServiceAccountProvider } from '@mcp-z/oauth-google';

const provider = new ServiceAccountProvider({
  keyFilePath: '/path/to/service-account.json',
  scopes: ['https://www.googleapis.com/auth/drive']
});

const accessToken = await provider.getAccessToken();
```

The service-account key file must exist and be readable by the process, and the APIs in `scopes` must be enabled for the Google Cloud project. Loopback OAuth opens a browser for consent (or returns an authorization URL in headless mode) and stores the resulting token.

### DCR and CIMD (self-hosted)

Use `DcrOAuthProvider` for bearer validation and `createDcrRouter` to host DCR endpoints and accept CIMD clients.
The router uses a secure CIMD resolver by default. Pass an optional `cimdResolver` from
`@mcp-z/oauth` when local development needs an explicit loopback policy.

```ts
import { DcrOAuthProvider, createDcrRouter } from '@mcp-z/oauth-google';

const provider = new DcrOAuthProvider({
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  scope: 'openid email profile',
  verifyEndpoint: 'https://your-host.com/oauth/verify'
});

const router = createDcrRouter({
  store,
  issuerUrl: 'https://your-host.com',
  baseUrl: 'https://your-host.com',
  scopesSupported: ['openid', 'email', 'profile'],
  clientConfig: {
    clientId: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!
  }
});
```

For local development only, create a resolver with an explicit HTTP loopback opt-in and pass it
as `cimdResolver` in the router configuration:

```ts
import { createCimdResolver } from '@mcp-z/oauth';

const cimdResolver = createCimdResolver({ allowHttpLoopback: true });
```

## Config helpers

Use `parseConfig()` and `parseDcrConfig()` to load CLI + env settings for servers.

## Schemas and handler types

- `schemas` - Shared Zod schemas used by tools
- `EnrichedExtra` - Handler extra type with auth context

## Requirements

- Node.js >= 18

## Documentation

[API Docs](https://mcp-z.github.io/oauth-google)
