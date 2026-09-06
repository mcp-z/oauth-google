/**
 * Generic token checks over plain `fetch`.
 *
 * This is for asserting a token is valid at all, where no product API is
 * involved and a client would only add a layer between the token and the
 * assertion. Tests that exercise a real Drive/Gmail/Sheets operation use the
 * scoped `@googleapis/*` clients instead — the point there is that the granted
 * scope reaches the real API, so it should go through the same client a
 * consumer would use.
 */

export interface UserInfo {
  email?: string;
}

export async function userinfo(token: string): Promise<UserInfo> {
  const response = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    throw new Error(`GET userinfo -> ${response.status} ${await response.text()}`);
  }
  return (await response.json()) as UserInfo;
}
