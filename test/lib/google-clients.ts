/**
 * Scoped Google API clients built from a raw access token.
 *
 * Used by the suites that prove a granted scope reaches its real API. They go
 * through the generated client a consumer would use, from the per-API packages
 * rather than the `googleapis` meta-package, so the assertion covers the same
 * path a server takes. Generic "is this token valid" checks use `fetch` — see
 * `google-rest.ts`.
 */

import { auth, drive as driveApi } from '@googleapis/drive';
import { gmail as gmailApi } from '@googleapis/gmail';
import { sheets as sheetsApi } from '@googleapis/sheets';

function clientFor(token: string) {
  const oauth2 = new auth.OAuth2();
  oauth2.setCredentials({ access_token: token });
  return oauth2;
}

export const driveFor = (token: string) => driveApi({ version: 'v3', auth: clientFor(token) });
export const gmailFor = (token: string) => gmailApi({ version: 'v1', auth: clientFor(token) });
export const sheetsFor = (token: string) => sheetsApi({ version: 'v4', auth: clientFor(token) });
