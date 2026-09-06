# Changelog

## [2.0.2] - 2026-09-06

### Fixed

- An abandoned OAuth flow no longer keeps the host process alive. `startEphemeralOAuthFlow` starts an HTTP server for the callback and arms a 5-minute safety-net timer; neither was `unref`'d, so a flow that never completed — a headless caller, or a user who closes the browser — held an open socket and a live timer for up to five minutes. Both are `unref`'d now. A running server stays alive on its own transport as before.

## [2.0.1] - 2026-09-06

### Changed

- `toAuth()` is now `toAuthProvider()` and returns a `GoogleAuthProvider` — one `getAccessToken()` method — instead of a `google-auth-library` `OAuth2Client`. `AuthContext.auth` is that provider. Build your API client in your own package and bind it with `attachTokenProvider(new google.auth.OAuth2(), auth)`; this matches `@mcp-z/oauth-microsoft`, whose providers have always had this shape.
- This package no longer depends on `google-auth-library` or `googleapis`. Its public contract names no third-party class, so it can never drift out of type identity with the `googleapis` a consumer installs.

### Added

- `GoogleAuthProvider`, `attachTokenProvider`, `RefreshHandlerClient`.

### Fixed

- The DCR provider now fails with `Access token expired and no refresh token available` instead of handing back a token it knows is dead, which surfaced as an unexplained 401 from Google.

## [2.0.0] - 2026-09-06

### Changed

- Migrated to the v2 MCP SDK. `McpError`/`ErrorCode` are `ProtocolError`/`ProtocolErrorCode`, reached through `@mcp-z/server`; wire codes are unchanged.
- The 1.x line is maintained on `support/1.x` and published under the `support-1` dist-tag.

## [1.2.2] - 2026-09-05

### Fixed

- Rejects PKCE `plain`; only `S256` is accepted. CORS moved to an explicit allow-list.

## [1.2.0] - 2026-08-29

### Changed

- Dependency refresh; exports smoke tests added for the `.mjs`, `.cjs` and `.ts` entry points.

## [1.1.0] - 2026-08-09

### Changed

- `google-auth-library` and `googleapis` pinned exactly, so the copy this package resolved stayed type-identical to a consumer's.

## [1.0.0] - 2025-12-28

Initial release.
