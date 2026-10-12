# Contributing to @mcp-z/oauth-google

OAuth 2.0 client for Google APIs with multi-account support, PKCE security, and swappable storage backends

## Before Starting

A few conventions here differ from what you might expect:

- **Breaking changes over compatibility.** This project has no compatibility burden yet. Do not add back-compat layers, migration utilities, or wrappers for deprecated APIs - change the API cleanly and bump the major.
- **Keep it approachable.** This is a small community project, not an enterprise codebase. Prefer the simplest solution that fits in the existing files over new abstractions, frameworks, or shared infrastructure.
- **Tests run against real services, not mocks.** Suites call live provider APIs with real credentials, so you need your own test account configured (see Test Setup below). A test that fails on credentials is reported, not skipped or loosened.
- **Test scratch goes in the package's gitignored `.tmp/`**, never `os.tmpdir()`.

## Branches

`master` is the only maintained release line. The 1.x line is retired and receives no fixes. All changes target `master`.

## Pre-Commit Commands

Install ts-dev-stack globally if not already installed:

```bash
npm install -g ts-dev-stack
```

Run before committing - this builds, type-checks, lints, and tests:

```bash
tsds validate
```

`tsds validate` also runs automatically on `npm publish` via the `prepublishOnly` hook; a failure blocks the publish.

## Testing

```bash
npm run test:setup    # Generate OAuth tokens (interactive, run once)
npm test              # Run the test suite
npm run test:engines  # Run the suite across every supported Node version
```

Specs live in `test/unit/`, mirroring `src/`. Cross-service specs live in `test/integration/`. Both run under `npm test`.

## Test Setup

### Google OAuth App Configuration

Loopback tests use a **Desktop app**. DCR tests use a separate **Web application** client with its own client ID and required secret.

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create OAuth 2.0 Client ID with **Application type: Desktop app**
3. Desktop apps support RFC 8252 loopback (`127.0.0.1` with any port) - no redirect URI registration needed

For DCR tests, create a separate Web application client and supply `GOOGLE_TEST_DCR_CLIENT_ID` and `GOOGLE_TEST_DCR_CLIENT_SECRET`. Manual DCR integration tests also require `GOOGLE_TEST_DCR_REDIRECT_URI`, registered as an authorized redirect URI on that client. `npm run test:setup` generates loopback tokens and, when the DCR client ID is configured, separate DCR tokens.

### Environment Variables

Supply these values through the shell or CI, or copy `.env.test.example` to `.env.test` for local configuration. Tests optionally load the file through `portable-env`; file values override matching inherited values. Enabled live tests require their necessary values, not the file itself.

```bash
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
# Optional for public loopback clients
GOOGLE_CLIENT_SECRET=your-client-secret

# Enable manual OAuth tests (requires browser interaction)
TEST_INCLUDE_MANUAL=true
```

## Package Development

See `README.md` for package overview and usage.

## GitHub Actions

Trusted pushes to master and manual CI runs call this commit's Tests workflow on Ubuntu, then Windows. Each platform uses Node 26 for installation and validation, runs the full unattended suite with `npm test -- --bail`, then runs every admitted Node engine with `npm run test:engines -- --bail`. The package currently admits Node 18, 20, 22, 24 and 26; current-runtime execution is additional to that sweep. `test:ci` and `test:ci:engines` also retain full discovery. Environment-aware test entrypoints load their existing environment helper before dependent imports; package scripts do not preload it. Missing or invalid enabled credentials fail the trusted job.

Pull requests receive no provider credentials and select exports, unit lib/setup, unit service-account, and integration PKCE files explicitly through the same canonical commands. This preserves the ten existing credential-free files. Mixed unit DCR and loopback files contain additional local cases whose current setup requires provider configuration or real token fixtures. Those local cases need a separate reviewed fixture correction before PR selection; their complete files run in trusted full discovery. A green PR check does not certify provider behavior.

`TEST_INCLUDE_MANUAL=false` leaves the two existing browser-consent tests pending. Those tests require a person and run locally with `TEST_INCLUDE_MANUAL=true`. Fresh browser consent is separate from unattended refresh-backed provider execution. Release evidence must include the configured live suites and relevant manual OAuth flows.

### Trusted tests

The Tests workflow is reusable by CI and retains its master-only manual dispatch with a Linux/Windows choice. The existing token owner seeds this repository's loopback and DCR stores and service-account key file, runs current and admitted-engine tests, persists updates, and removes private runner files. Ubuntu failure prevents the automatic Windows job. The shared repository job concurrency group queues automatic and manual entrypoints without cancelling active runs; the lock covers seed through persistence and cleanup. The 90-minute platform timeout is a budget, not measured Google full-suite timing.

This repository owns its `live-test` GitHub environment, restricted to master. There is no cross-repository coordinator. Concurrent repositories can share provider quotas or grants; the maintainer must coordinate those account users. Browser consent and local setup remain outside the GitHub job lock. Forced cancellation, timeout and runner loss can prevent finalization despite always steps; inspect seed, persistence and cleanup results. The canonical engine sweep runs serially but continues to later engines after a failed runtime; bail stops only the current runtime. No automatic retry is configured.

Configure these individual environment secrets from the existing test configuration and token stores:

- `CI_SECRETS_TOKEN`
- `TEST_ACCOUNT_ID`
- `TEST_REFRESH_TOKEN`
- `TEST_SCOPE`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `TEST_DCR_REFRESH_TOKEN`
- `TEST_DCR_SCOPE`
- `GOOGLE_TEST_DCR_CLIENT_ID`
- `GOOGLE_TEST_DCR_CLIENT_SECRET`
- `TEST_DCR_CLIENT_ID`
- `TEST_DCR_CLIENT_SECRET`
- `GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY`
- `GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY_ID`
- `GOOGLE_SERVICE_ACCOUNT_CLIENT_EMAIL`
- `GOOGLE_SERVICE_ACCOUNT_CLIENT_ID`
- `GOOGLE_SERVICE_ACCOUNT_PROJECT_ID`
- `GOOGLE_SERVICE_ACCOUNT_AUTH_URI`
- `GOOGLE_SERVICE_ACCOUNT_TOKEN_URI`

`CI_SECRETS_TOKEN` is a fine-grained GitHub PAT with this repository selected and **Environments: Read and write**. GitHub's default workflow token cannot update environment secrets; see the [environment-secret API permissions](https://docs.github.com/en/rest/actions/secrets#create-or-update-an-environment-secret). Keep the PAT's expiry visible to the maintainer; do not use the local broad GitHub login as a CI secret. Provider refresh tokens and GitHub authorization have separate lifetimes.

The seeder validates configuration, renews provider credentials, saves private runner files, and writes replacement refresh tokens back to environment secrets before tests run. An always-run finalizer saves subsequent replacements even when tests fail, then removes runner credential files. Credentials are not cached or uploaded as artifacts. Missing configuration, failed renewal and failed persistence fail the job; CI never opens a consent screen. After provider revocation or expiry, reauthorize locally with the existing setup command and reseed that repository's refresh-token secrets.

Google external apps in Testing can issue seven-day refresh tokens for these scopes; successful access-token renewal does not remove that policy. Confirm the existing project's consent publishing configuration before relying on long-term unattended runs. See [Google's token lifecycle documentation](https://developers.google.com/identity/protocols/oauth2).
