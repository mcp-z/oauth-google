# @mcp-z/oauth-google

Docs: https://mcp-z.github.io/oauth-google
OAuth client for Google APIs with multi-account support and PKCE.

## Common uses

- Gmail/Drive/Sheets OAuth in MCP servers
- CLI and desktop OAuth flows
- Service account auth for server-to-server access
- DCR (self-hosted) for shared HTTP servers

## Install

```bash
npm install @mcp-z/oauth-google keyv
```

## Create a Google Cloud app

1. Go to [Google Cloud Console](https://console.cloud.google.com/).
2. Create or select a project.
3. Enable the API you need (Gmail, Drive, or Sheets).
4. Create OAuth 2.0 credentials (Desktop app).
5. Copy the Client ID and Client Secret.
6. Select your MCP transport (stdio for local and http for remote) and platform
- For stdio, choose "APIs & Services", + Create client, "Desktop app" type
- For http, choose "APIs & Services", + Create client, "Web application" type, add your URL (default is http://localhost:3000/oauth/callback based on the --port or PORT)
- For local hosting, add "http://127.0.0.1" for [Ephemeral redirect URL](https://en.wikipedia.org/wiki/Ephemeral_port)

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
```

### Service account

```ts
import { ServiceAccountProvider } from '@mcp-z/oauth-google';

const provider = new ServiceAccountProvider({
  keyFilePath: '/path/to/service-account.json',
  scopes: ['https://www.googleapis.com/auth/drive']
});
```

### DCR (self-hosted)

Use `DcrOAuthProvider` for bearer validation and `createDcrRouter` to host the DCR endpoints.

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

## Config helpers

Use `parseConfig()` and `parseDcrConfig()` to load CLI + env settings for servers.

## Schemas and handler types

- `schemas` - Shared Zod schemas used by tools
- `EnrichedExtra` - Handler extra type with auth context

## Requirements

- Node.js >= 22
