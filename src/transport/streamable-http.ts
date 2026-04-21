// purpose: Streamable-HTTP MCP request handler factory — provider-agnostic.

import type { IncomingMessage, ServerResponse } from 'node:http';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';

export interface McpTransportLogger {
  error(message: string, ...args: unknown[]): void;
}

export interface StreamableHttpHandlerConfig {
  serverInfo: { name: string; version: string };
  listTools: () => Promise<Tool[]> | Tool[];
  callTool: (name: string, args: Record<string, unknown>) => Promise<CallToolResult>;
  logger?: McpTransportLogger;
}

const defaultLogger: McpTransportLogger = {
  error: (message, ...args) => console.error(`[mymcps-core/transport] ${message}`, ...args),
};

function buildServer(config: StreamableHttpHandlerConfig): McpServer {
  const mcp = new McpServer(config.serverInfo, { capabilities: { tools: {} } });

  mcp.server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: await config.listTools(),
  }));

  mcp.server.setRequestHandler(CallToolRequestSchema, async (req): Promise<CallToolResult> => {
    return config.callTool(req.params.name, req.params.arguments ?? {});
  });

  return mcp;
}

// Factory over a plain handler so consumers can wire `callTool` / `listTools`
// once at boot and reuse the returned function per request. Works with any
// framework whose `req`/`res` extend Node's http primitives (express,
// serverless-express, raw http, …) — core never imports a web framework.
export function makeStreamableHttpHandler(config: StreamableHttpHandlerConfig) {
  const log = config.logger ?? defaultLogger;

  return async function handleMcpRequest(
    req: IncomingMessage,
    res: ServerResponse,
    body?: unknown,
  ): Promise<void> {
    const mcp = buildServer(config);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });

    res.on('close', () => {
      transport.close().catch((err) => log.error('Transport close error:', err));
      mcp.close().catch((err) => log.error('Server close error:', err));
    });

    try {
      await mcp.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (error) {
      log.error('MCP request error:', error);
      if (!res.headersSent) {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: null,
            error: {
              code: -32603,
              message: error instanceof Error ? error.message : 'Internal error',
            },
          }),
        );
      }
    }
  };
}
