# @mcp-z/oauth-google Architecture

> Technical architecture documentation for the Google OAuth library used by MCP servers

---

## Overview

This library provides Google OAuth 2.0 authentication with multi-account support for MCP (Model Context Protocol) servers. It implements two complementary OAuth patterns: **Loopback OAuth** for desktop/CLI apps and **MCP SDK OAuth** for web-based stateless deployments.

**Core Design Principles**:
- **SOLID compliance**: Single Responsibility, Dependency Inversion, Inversion of Control
- **Middleware-based architecture**: Tools focus on business logic, middleware handles auth
- **Multi-account orchestration**: Service-level isolation with independent active accounts
- **Swappable storage**: Keyv interface with FileStore, Redis, DuckDB, PostgreSQL backends

---

## OAuth Provider Comparison

### LoopbackOAuthProvider

**Purpose**: Interactive OAuth flow for desktop/CLI applications using RFC 8252 loopback pattern.

**Characteristics**:
- Ephemeral local HTTP server on OS-assigned port
- Browser-based user authentication
- PKCE (Proof Key for Code Exchange) for security
- Server-side token storage (FileStore, DuckDB, Redis, PostgreSQL)
- Supports multi-account via token store + accountId
- Works with stdio and HTTP transports

**Use Cases**:
- Desktop applications
- CLI tools
- MCP servers with local execution
- Development and testing

**Security Features**:
- Binds to `127.0.0.1` only (localhost isolation)
- OS-assigned ports (eliminates port conflicts)
- PKCE prevents authorization code interception
- No redirect URI conflicts across instances

### McpOAuthProvider

**Purpose**: Stateless OAuth for web-based MCP clients where client manages auth flow.

**Characteristics**:
- Client-initiated OAuth flow
- Tokens transmitted in request metadata (`extra.authInfo.token`)
- No server-side token storage (stateless)
- **REQUIRES HTTPS in production** (tokens in HTTP headers)
- HTTP transport only (no stdio)
- Client manages multi-account, token refresh, expiration

**Use Cases**:
- Web-based MCP clients (like Claude Web)
- Multi-tenant SaaS applications
- Shared server instances with many clients
- Client-side token management

**Security Requirements**:
- **HTTPS mandatory** for network-accessible deployments
- Token validation on every request
- Client responsible for secure token storage
- Server never logs tokens (auto-sanitized)

**Comparison Table**:

| Feature | Loopback OAuth | MCP SDK OAuth |
|---------|----------------|---------------|
| Token Storage | Server (FileStore/DuckDB/Redis) | Client |
| OAuth Flow | Server initiates | Client initiates |
| Browser Required | Yes (server-side) | Yes (client-side) |
| Transport Support | stdio, HTTP | HTTP only |
| Multi-Account | Server manages via tokenStore | Client manages |
| Token Refresh | Server handles | Client handles |
| HTTPS Required | No (localhost only) | **Yes (production)** |
| Use Case | Desktop/CLI tools | Web applications |

---

## Three OAuth Deployment Modes

The library supports distinct deployment patterns through the LoopbackOAuthProvider.

### Mode 1: Single-User (Desktop/CLI)

**Use Case**: Single user runs the process locally (desktop apps, CLI tools).

**Configuration**:
```typescript
const loopback = new LoopbackOAuthProvider({
  tokenStore,
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  scopes: ['https://www.googleapis.com/auth/gmail.modify'],
  logger,
});

const middleware = loopback.authMiddleware();
```

**Behavior**:
- All API calls use the single user's authenticated account
- **accountId is the user's email address** fetched from Google OAuth2 API
- Token storage: `user:default:{email}:{service}:token`
- Interactive OAuth flow via ephemeral loopback server
- Email automatically retrieved during first OAuth flow

**Use Cases**: Personal CLI tools, desktop applications, development environments.

### Mode 2: Service Account

**Use Case**: Server-to-server authentication without user interaction (automation, monitoring).

**Configuration**:
```typescript
import { ServiceAccountProvider } from '@mcp-z/oauth-google';

const serviceAccount = new ServiceAccountProvider({
  keyFile: '/path/to/service-account-key.json',
  scopes: ['https://www.googleapis.com/auth/gmail.readonly'],
  subject: 'user@domain.com',  // Optional: impersonate user (domain-wide delegation)
});

// Use service account auth directly in tools
const auth = await serviceAccount.getAuthClient();
```

**Behavior**:
- No interactive OAuth flow required
- Uses service account credentials (JSON key file)
- Optional domain-wide delegation for user impersonation
- Suitable for automated/headless environments

**Security**: Service account keys must be protected - they provide direct API access.

### Mode 3: Stateless (MCP OAuth)

**Use Case**: Web-based MCP clients where client manages OAuth flow and tokens.

**Configuration**:
```typescript
import { setupMcpOAuth, McpOAuthProvider } from '@mcp-z/oauth-google';

const app = express();

// Setup MCP OAuth endpoints
const mcpOAuthAdapter = setupMcpOAuth(app, {
  clientId: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  scopes: ['https://www.googleapis.com/auth/gmail.modify'],
  redirectUri: 'https://example.com/oauth/callback',  // HTTPS required
  logger,
});

// Stateless middleware - token extracted from request
const mcpOAuthProvider = new McpOAuthProvider(mcpOAuthAdapter);
const middleware = mcpOAuthProvider.authMiddleware();
```

**Behavior**:
- Extracts token from `extra.authInfo.token` (MCP protocol)
- No server-side token storage (client manages tokens)
- Each request must include valid token
- Only works with HTTP transport (not stdio)
- **HTTPS required in production**

**Client Request Example**:
```typescript
const result = await client.callTool('gmail-message-search',
  { query: 'important' },
  {
    authInfo: {
      token: 'ya29.a0AfB_...'  // Client-provided access token
    }
  }
);
```

**OAuth Endpoints Installed**:
- `GET /.well-known/oauth-authorization-server` - OAuth metadata
- `GET /oauth/authorize` - Start OAuth flow
- `POST /oauth/token` - Exchange code for token
- `POST /oauth/revoke` - Revoke token
- `POST /oauth/register` - Dynamic client registration

---

## Server-Level Middleware Architecture

### SOLID Principles Compliance

The middleware pattern follows SOLID principles for clean separation of concerns:

**1. Single Responsibility Principle (SRP)**:
- **Tools**: Define business operations (inputs, outputs, logic)
- **Middleware**: Handle authentication (token retrieval, error handling)
- **Server**: Coordinate integration (middleware application, registration)

**2. Open/Closed Principle (OCP)**:
- Adding new middleware (logging, metrics) requires only server changes
- Tools remain unchanged when adding cross-cutting concerns
```typescript
registerTools(mcpServer,
  tools
    .map(authMiddleware.withToolAuth)
    .map(toolMiddleware.withToolLogging)
    .map(metricsMiddleware.withToolMetrics)
);
```

**3. Dependency Inversion Principle (DIP)**:
- Tools don't depend on auth infrastructure
- High-level (business logic) doesn't depend on low-level (auth)
- Server mediates dependencies

**4. Inversion of Control (IoC)**:
- Server controls when/how middleware is applied
- Tools are passive (just define operations)
- Proper container pattern

### Tool Factory Pattern (No Middleware Knowledge)

Tools define pure business logic without auth dependencies:

```typescript
// Example tool implementation
import type { ToolModule } from '@mcp-z/server';
import type { EnrichedExtra } from '@mcp-z/oauth-google';

const config = {
  name: 'gmail-message-get',
  description: 'Get a Gmail message by ID',
  inputSchema: {
    id: z.string().min(1).describe('Gmail message ID')
  },
  outputSchema: {
    result: z.discriminatedUnion('type', [
      z.object({ type: z.literal('success'), item: MessageSchema }),
      z.object({ type: z.literal('error'), error: z.string(), code: ErrorCodeSchema }),
    ])
  }
} as const;

async function handler(args: In, extra: EnrichedExtra): Promise<CallToolResult> {
  try {
    // extra.authContext.auth is guaranteed to exist (middleware ensures auth succeeded)
    const gmail = google.gmail({ version: 'v1', auth: extra.authContext.auth });
    const response = await gmail.users.messages.get({ userId: 'me', id: args.id });

    const result = {
      type: 'success' as const,
      item: response.data,
    };

    return {
      content: [{ type: 'text', text: JSON.stringify(result) }],
      structuredContent: result,
    };
  } catch (error) {
    if (error instanceof McpError) {
      throw error;
    }
    const message = error instanceof Error ? error.message : String(error);
    throw new McpError(ErrorCode.InternalError, `Error: ${message}`, {
      stack: error instanceof Error ? error.stack : undefined,
    });
  }
}

// Tool factory has NO auth middleware parameter
export default function createTool(): ToolModule {
  return { name: 'gmail-message-get', config, handler };
}
```

**Key Points**:
- Tool imports `EnrichedExtra` type (provides IntelliSense)
- Handler receives guaranteed `authContext.auth` (middleware ensures this)
- Tool never imports auth providers or token stores
- No error handling for auth failures (middleware handles)

### Server Registration (Middleware Application)

Server applies middleware to business tools at registration time:

```typescript
// Example server implementation
import { LoopbackOAuthProvider } from '@mcp-z/oauth-google';
import * as toolFactories from './mcp/tools/index.ts';

// Create loopback OAuth provider (configured at server startup)
const loopback = new LoopbackOAuthProvider({
  tokenStore,
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  scopes: ['https://www.googleapis.com/auth/gmail.modify'],
  logger,
});

// Create middleware based on deployment mode
const middleware = loopback.authMiddleware();

// Create business tools (no auth knowledge)
const tools = Object.values(toolFactories).map(factory => factory());

// Register with middleware
registerTools(mcpServer, tools.map(middleware.withToolAuth));  // Auth middleware applied
```

**Separation of Concerns**:
- Business tools get auth middleware (need OAuth2Client)
- Server decides middleware application strategy
- Middleware handles all auth concerns (token retrieval, refresh, errors)

### Error Handling Pattern

**Current Standard**: All errors use McpError from the MCP SDK.

**Tool Definition**:
```typescript
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';

const config = {
  inputSchema: z.object({ id: z.string().min(1) }) as const,
  outputSchema: z.object({
    type: z.literal('success'),
    item: MessageSchema,
  }),
} as const;
```

**Handler Pattern**:
```typescript
type In = z.infer<typeof config.inputSchema>;
type Out = z.infer<typeof config.outputSchema>;

async function handler(args: In, extra: EnrichedExtra): Promise<CallToolResult> {
  try {
    const gmail = google.gmail({ version: 'v1', auth: extra.authContext.auth });
    const response = await gmail.users.messages.get({ userId: 'me', id: args.id });

    const result: Out = {
      type: 'success' as const,
      item: response.data,
    };

    return {
      content: [{ type: 'text', text: JSON.stringify(result) }],
      structuredContent: result,
    };
  } catch (error) {
    // Re-throw McpError as-is
    if (error instanceof McpError) {
      throw error;
    }

    // Wrap other errors in McpError
    const message = error instanceof Error ? error.message : String(error);
    throw new McpError(ErrorCode.InternalError, `Error: ${message}`, {
      stack: error instanceof Error ? error.stack : undefined,
    });
  }
}
```

**Why This Works**:
- Handlers receive `EnrichedExtra` with guaranteed auth context
- Middleware catches auth errors BEFORE handler runs
- Handlers never execute if auth fails
- MCP SDK provides standard error types
- Type-safe: TypeScript enforces result matches schema

**Benefits**:
- MCP compliant - uses official SDK error types
- Simple - no helper function dependencies
- Explicit - clear, self-contained error handling
- Type safe - TypeScript enforces schema compliance

### EnrichedExtra Type

Middleware enriches request context with guaranteed auth:

```typescript
export interface EnrichedExtra extends RequestHandlerExtra {
  authContext: {
    auth: OAuth2Client;    // googleapis-compatible client
    accountId: string;     // Account being used
  };
  logger: Logger;          // Injected logger
  _meta?: {
    accountId?: string;    // Backchannel account override (multi-account mode only)
  };
}
```

**Guarantee**: If handler runs, `authContext` exists. Middleware catches auth failures before handler execution.

**IntelliSense Benefits**:
- TypeScript autocomplete for `extra.authContext.auth`
- Compile-time errors if accessing non-existent properties
- Clear type documentation for tool developers

---

## Multi-Account Token Storage

### Storage Key Format

Compound keys enable O(1) direct lookups:

```
{accountId}:{service}:{type}
```

**Parameters**:
- `accountId`: **Email address** of the authenticated Google account
- `service`: Service identifier (e.g., `'gmail'`, `'drive'`, `'sheets'`)
- `type`: Token type suffix (e.g., `'token'`, `'refresh'`)

**Examples**:
```
user@gmail.com:gmail:token
user@gmail.com:drive:token
work@company.com:sheets:token
```

**accountId Design**:
- **Always uses email address** fetched from Google OAuth2 API (`/oauth2/v2/userinfo` endpoint)
- Never uses `'default'` fallback - email is mandatory
- Provides human-readable account identification
- Enables easy account selection and management
- Retrieved via `email` field from Google userinfo

**Benefits**:
- Direct O(1) access without scanning
- Human-readable account identification (email addresses)
- Service-level isolation (Gmail, Drive, Sheets independent)
- Multi-account support via accountId
- Same email can have tokens for multiple services
- Different accounts can use same service

### Storage Backends (Keyv Interface)

The library uses the `keyv` interface for swappable storage backends:

**Development (FileStore)**:
```typescript
import { KeyvFile } from 'keyv-file';
const tokenStore = new Keyv({
  store: new KeyvFile({ filename: '.tokens/google.json' })
});
```

**Production (Redis)**:
```typescript
import KeyvRedis from '@keyv/redis';
const tokenStore = new Keyv({
  store: new KeyvRedis('redis://localhost:6379')
});
```

**Production (PostgreSQL)**:
```typescript
import KeyvPostgres from '@keyv/postgres';
const tokenStore = new Keyv({
  store: new KeyvPostgres('postgresql://localhost/mydb')
});
```

**Production (Encrypted DuckDB)**:
```typescript
import { DuckDBStore } from '@mcp-z/keyv-duckdb';
const tokenStore = new Keyv({
  store: new DuckDBStore('./store.duckdb', {
    encryptionKey: process.env.ENCRYPTION_KEY
  })
});
```

**Key Principle**: All backends implement the same `keyv` interface - change storage without changing auth code.

### Account Management Pattern

Users manage accounts via MCP tools:

- `gmail-account-current` - Show active account
- `gmail-account-list` - List all authorized accounts
- `gmail-account-switch` - Change active account
- `gmail-account-add` - Add new account via OAuth
- `gmail-account-remove` - Remove account and tokens

**Implementation**:
- Account tools access tokenStore directly (no middleware)
- Active account stored in config (`.tokens/config.json`)
- Service-level isolation (Gmail active != Drive active)
- Multi-tenant: Per-user active account isolation

---

## Security Architecture

### PKCE (Proof Key for Code Exchange)

All OAuth flows use PKCE (RFC 7636) to prevent authorization code interception:

1. Client generates random `code_verifier`
2. Creates `code_challenge` = BASE64URL(SHA256(code_verifier))
3. Authorization request includes `code_challenge`
4. Token exchange requires original `code_verifier`
5. Google validates SHA256(code_verifier) matches code_challenge

**Benefits**:
- Prevents authorization code interception attacks
- No client secret required for public clients
- Recommended by OAuth 2.1 for all clients

### Ephemeral Server (RFC 8252)

Loopback server implementation:

- Binds to `127.0.0.1` only (localhost isolation)
- OS-assigned ports (eliminates port conflicts)
- Server lifetime: OAuth flow duration only
- Single authorization code handled, then shutdown

**Redirect URI Pattern**:
```
http://127.0.0.1:{port}/callback
```

**Security**:
- No port conflicts across multiple OAuth instances
- Localhost-only (no network exposure)
- Temporary (not persistent server)

### Token Storage Security

**Responsibilities**:
- Implement encryption at rest in storage backend
- Use secure file permissions (FileStore)
- Use database access controls (Redis/PostgreSQL)
- Enable encryption for DuckDBStore (AES-256-GCM)

**Token Sanitization**:
- Tokens never logged (auto-sanitized from log output)
- Secrets redacted in error messages
- Stack traces scrubbed of sensitive data

**Keyv Backends Security**:
- FileStore: Use secure file permissions (`chmod 600`)
- Redis: Use authentication + TLS
- PostgreSQL: Use SSL connections + role-based access
- DuckDB: Enable AES-256-GCM encryption

### HTTPS Requirement for MCP OAuth

**CRITICAL**: MCP SDK OAuth **REQUIRES HTTPS in production**.

**Why**:
- Access tokens transmitted in HTTP headers (`Authorization: Bearer ...`)
- Plain HTTP exposes tokens to network interception
- Man-in-the-middle attacks can steal tokens

**When HTTPS is NOT Required**:
- Loopback OAuth (localhost 127.0.0.1 only)
- Development/testing on localhost
- Stdio transport (no network)

**When HTTPS IS Required**:
- MCP SDK OAuth on network-accessible servers
- Any production deployment accepting remote connections
- Multi-tenant SaaS applications

**Enforcement**:
- Server should reject HTTP requests with tokens in production
- Client must only send tokens over HTTPS
- Use reverse proxy (nginx, Caddy) for TLS termination if needed

---

## Migration Guide

### From Old Pattern (Pre-Middleware)

**Old Pattern** (tools have auth dependencies):
```typescript
async function handler(args, ctx) {
  const auth = await ctx.getAuth();  // Tool handles auth
  const gmail = google.gmail({ version: 'v1', auth });
  // business logic
}
```

**New Pattern** (middleware handles auth):
```typescript
async function handler(args, extra: EnrichedExtra) {
  // extra.authContext.auth guaranteed by middleware
  const gmail = google.gmail({ version: 'v1', auth: extra.authContext.auth });
  // business logic only
}
```

**Why Breaking Change**:
- SRP: Tools shouldn't handle auth (cross-cutting concern)
- DIP: Tools shouldn't depend on auth infrastructure
- Testability: Tools easier to test without auth mocking
- Consistency: All tools use same auth pattern

**Migration Steps**:
1. Change handler signature: `(args, ctx)` → `(args, extra: EnrichedExtra)`
2. Remove `ctx.getAuth()` calls
3. Use `extra.authContext.auth` directly
4. Remove auth error handling from tools
5. Update tool factory to return `ToolModule` (no middleware param)
6. Let server apply middleware at registration

**No Backward Compatibility**: Old pattern not supported. Clean break for better architecture.

---

## References

- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8252 - OAuth for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252)
- [MCP Specification](https://modelcontextprotocol.io/)
- [Keyv Storage Interface](https://github.com/jaredwray/keyv)
