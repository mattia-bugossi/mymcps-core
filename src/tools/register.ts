// purpose: Provider-agnostic tool registry. Each provider registers its Tool
// definitions + handlers once; the registry exposes { listTools, callTool }
// suitable for passing straight to makeStreamableHttpHandler.

import type { CallToolResult, Tool } from '@modelcontextprotocol/sdk/types.js';
import { NotFoundError } from '../errors/types.js';

export type ToolHandlerResult = string | CallToolResult;

export type ToolHandler = (args: Record<string, unknown>) => Promise<ToolHandlerResult>;

export interface ToolRegistration {
  tool: Tool;
  handler: ToolHandler;
}

export interface ToolRegistry {
  register(registration: ToolRegistration): ToolRegistry;
  listTools(): Tool[];
  callTool(name: string, args: Record<string, unknown>): Promise<CallToolResult>;
}

function wrap(result: ToolHandlerResult): CallToolResult {
  if (typeof result === 'string') {
    return { content: [{ type: 'text', text: result }] };
  }
  return result;
}

export function createToolRegistry(): ToolRegistry {
  const entries = new Map<string, ToolRegistration>();

  const registry: ToolRegistry = {
    register(registration) {
      if (entries.has(registration.tool.name)) {
        throw new Error(`Tool already registered: ${registration.tool.name}`);
      }
      entries.set(registration.tool.name, registration);
      return registry;
    },
    listTools() {
      return [...entries.values()].map((e) => e.tool);
    },
    async callTool(name, args) {
      const entry = entries.get(name);
      if (!entry) throw new NotFoundError(`Unknown tool: ${name}`);
      return wrap(await entry.handler(args));
    },
  };

  return registry;
}
