/**
 * Minimal REST calls to the Google APIs these suites authenticate against.
 *
 * The package under test mints tokens and no longer depends on a Google SDK, so
 * its suites must not either: a test that proves the token through `googleapis`
 * proves the SDK's wiring as much as ours. These call the same endpoints the SDK
 * would, with the token in an Authorization header, which is the whole thing
 * being asserted.
 */

async function call<T>(token: string, url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, ...(init?.body ? { 'Content-Type': 'application/json' } : {}), ...init?.headers },
  });
  if (!response.ok) {
    throw new Error(`${init?.method ?? 'GET'} ${url} -> ${response.status} ${await response.text()}`);
  }
  return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
}

export interface DriveFileList {
  files?: { id?: string; name?: string }[];
  nextPageToken?: string;
}

export function driveFilesList(token: string, params: { pageSize?: number; fields?: string; q?: string } = {}): Promise<DriveFileList> {
  const query = new URLSearchParams();
  if (params.pageSize !== undefined) query.set('pageSize', String(params.pageSize));
  if (params.fields !== undefined) query.set('fields', params.fields);
  if (params.q !== undefined) query.set('q', params.q);
  return call<DriveFileList>(token, `https://www.googleapis.com/drive/v3/files?${query}`);
}

export function driveFilesDelete(token: string, fileId: string): Promise<void> {
  return call<void>(token, `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}`, { method: 'DELETE' });
}

export interface GmailProfile {
  emailAddress?: string;
  messagesTotal?: number;
}

export function gmailGetProfile(token: string): Promise<GmailProfile> {
  return call<GmailProfile>(token, 'https://gmail.googleapis.com/gmail/v1/users/me/profile');
}

export interface Spreadsheet {
  spreadsheetId?: string;
  properties?: { title?: string };
}

export function sheetsCreate(token: string, title: string): Promise<Spreadsheet> {
  return call<Spreadsheet>(token, 'https://sheets.googleapis.com/v4/spreadsheets', {
    method: 'POST',
    body: JSON.stringify({ properties: { title } }),
  });
}

export function sheetsGet(token: string, spreadsheetId: string): Promise<Spreadsheet> {
  return call<Spreadsheet>(token, `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}`);
}

export interface UserInfo {
  email?: string;
}

export function userinfo(token: string): Promise<UserInfo> {
  return call<UserInfo>(token, 'https://www.googleapis.com/oauth2/v2/userinfo');
}

export interface GmailMessageList {
  messages?: { id?: string }[];
}

export function gmailMessagesList(token: string, params: { q?: string; maxResults?: number } = {}): Promise<GmailMessageList> {
  const query = new URLSearchParams();
  if (params.q !== undefined) query.set('q', params.q);
  if (params.maxResults !== undefined) query.set('maxResults', String(params.maxResults));
  return call<GmailMessageList>(token, `https://gmail.googleapis.com/gmail/v1/users/me/messages?${query}`);
}

export interface GmailMessageMetadata {
  payload?: { headers?: { name?: string; value?: string }[] };
}

export function gmailMessageMetadata(token: string, id: string, metadataHeaders: string[]): Promise<GmailMessageMetadata> {
  const query = new URLSearchParams({ format: 'metadata' });
  for (const header of metadataHeaders) query.append('metadataHeaders', header);
  return call<GmailMessageMetadata>(token, `https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(id)}?${query}`);
}
