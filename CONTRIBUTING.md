# Contributing to @mcp-z/oauth-google

## Before Starting

**MUST READ**:
- [QUALITY.MD](QUALITY.md) - Quality principles (summarize before starting work)

## Pre-Commit Commands

Install ts-dev-stack globally if not already installed:
```bash
npm install -g ts-dev-stack
```

Run before committing:
```bash
tsds validate
```

## Test Setup

### Google OAuth App Configuration

All tests (including DCR integration tests) use a single OAuth app. Configure it as a **Desktop app** in Google Cloud Console:

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create OAuth 2.0 Client ID with **Application type: Desktop app**
3. Desktop apps support RFC 8252 loopback (`127.0.0.1` with any port) - no redirect URI registration needed

### Environment Variables

Copy `.env.test.example` to `.env.test` and configure:

```bash
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret

# Enable manual OAuth tests (requires browser interaction)
TEST_INCLUDE_MANUAL=true
```

### Running Tests

```bash
npm run test:setup    # Generate OAuth tokens (interactive)
npm run test:unit     # Unit tests only
npm run test:integration  # Integration tests (some require browser)
npm test              # All tests
```

## Package Development

See package documentation:
- `README.md` - Package overview and usage
- `QUALITY.md` - Quality principles and standards
- `CLAUDE.md` - Development patterns and architecture guidance
