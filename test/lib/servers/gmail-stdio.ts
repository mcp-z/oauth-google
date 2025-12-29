#!/usr/bin/env node

/**
 * Minimal Gmail MCP stdio test server
 *
 * PURPOSE: Test Google OAuth stateless mode without cross-dependencies
 * FEATURES:
 * - Full MCP SDK (McpServer, StdioServerTransport)
 * - Stateless mode: extracts OAuth token from MCP context
 * - Minimal gmail-message-search and gmail-account-current tools
 * - Real Gmail API calls using Google API client
 * - Process-based communication (stdin/stdout)
 * - Graceful shutdown on SIGINT/SIGTERM
 *
 * USAGE: node test/lib/servers/gmail-stdio.ts
 * NOTE: This is a minimal test fixture - NOT a production Gmail server
 */

import type { ToolConfig } from '@mcp-z/oauth';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type { CallToolResult, ServerNotification, ServerRequest } from '@modelcontextprotocol/sdk/types.js';
import { google } from 'googleapis';
import { z } from 'zod';

/**
 * Extract OAuth token from MCP context (stateless mode)
 * MCP SDK provides tokens in extra._meta.oauth.token
 */
function extractTokenFromContext(extra: RequestHandlerExtra<ServerRequest, ServerNotification>): string {
  // Type-safe access to optional OAuth token in meta
  const token = (extra._meta as { oauth?: { token?: string } } | undefined)?.oauth?.token;
  if (!token || typeof token !== 'string') {
    throw new Error('No OAuth token provided in MCP context. Client must provide token via capabilities.experimental.oauth');
  }
  return token;
}

async function main() {
  const server = new McpServer({
    name: 'gmail-stdio-test',
    version: '1.0.0',
  });

  // Register gmail-message-search tool with explicit ToolConfig type
  const messageSearchConfig: ToolConfig = {
    title: 'Search Gmail Messages',
    description: 'Search messages in Gmail mailbox',
    inputSchema: {
      query: z.string().optional(),
    },
    outputSchema: {
      messages: z.array(
        z.object({
          id: z.string(),
          subject: z.string().optional(),
        })
      ),
    },
  };

  server.registerTool('gmail-message-search', messageSearchConfig, async (args: { query?: string }, extra: unknown): Promise<CallToolResult> => {
    try {
      // Extract token from MCP context (stateless mode)
      const accessToken = extractTokenFromContext(extra as RequestHandlerExtra<ServerRequest, ServerNotification>);

      // Create OAuth2Client with token
      const oauth2Client = new google.auth.OAuth2();
      oauth2Client.setCredentials({
        access_token: accessToken,
      });

      // Create Gmail API client
      const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

      // Search messages
      const response = await gmail.users.messages.list({
        userId: 'me',
        q: (args as { query?: string }).query || '',
        maxResults: 10,
      });

      const messages = response.data.messages || [];
      const messageDetails = [];

      // Get subject for each message
      for (const message of messages.slice(0, 5)) {
        if (message.id) {
          try {
            const messageResponse = await gmail.users.messages.get({
              userId: 'me',
              id: message.id,
              format: 'metadata',
              metadataHeaders: ['Subject'],
            });

            const headers = messageResponse.data.payload?.headers || [];
            const subjectHeader = headers.find((h) => h.name === 'Subject');

            messageDetails.push({
              id: message.id,
              subject: subjectHeader?.value || '',
            });
          } catch (_e) {
            // If we can't get the message details, continue with id only
            messageDetails.push({
              id: message.id,
              subject: '',
            });
          }
        }
      }

      return {
        content: [{ type: 'text', text: JSON.stringify({ messages: messageDetails }) }],
        structuredContent: { messages: messageDetails },
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      return {
        content: [{ type: 'text', text: JSON.stringify({ error: errorMessage }) }],
        isError: true,
      };
    }
  });

  // Register gmail-account-current tool with explicit ToolConfig type
  const accountCurrentConfig: ToolConfig = {
    title: 'Get Current Gmail Account',
    description: 'Get current authenticated Gmail account',
    outputSchema: {
      email: z.string(),
    },
  };

  server.registerTool('gmail-account-current', accountCurrentConfig, async (extra: unknown): Promise<CallToolResult> => {
    try {
      // Extract token from MCP context (stateless mode)
      const accessToken = extractTokenFromContext(extra as RequestHandlerExtra<ServerRequest, ServerNotification>);

      // Create OAuth2Client with token
      const oauth2Client = new google.auth.OAuth2();
      oauth2Client.setCredentials({
        access_token: accessToken,
      });

      // Get user profile using Google OAuth2 API
      const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
      const response = await oauth2.userinfo.get();

      const email = response.data.email || '';

      return {
        content: [{ type: 'text', text: JSON.stringify({ email }) }],
        structuredContent: { email },
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      return {
        content: [{ type: 'text', text: JSON.stringify({ error: errorMessage }) }],
        isError: true,
      };
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main();
