import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createToolRegistry } from '../../src/tools/index.js';
import { NotFoundError } from '../../src/errors/index.js';

const echoTool = {
  name: 'echo',
  description: 'echoes input',
  inputSchema: { type: 'object' as const, properties: {} },
};

describe('createToolRegistry', () => {
  it('listTools returns registered definitions in registration order', () => {
    const r = createToolRegistry();
    r.register({ tool: echoTool, handler: async () => 'hi' });
    r.register({
      tool: { name: 'ping', description: 'p', inputSchema: { type: 'object', properties: {} } },
      handler: async () => 'pong',
    });
    assert.deepEqual(
      r.listTools().map((t) => t.name),
      ['echo', 'ping'],
    );
  });

  it('wraps string handler results in a text CallToolResult', async () => {
    const r = createToolRegistry().register({
      tool: echoTool,
      handler: async (args) => `got:${JSON.stringify(args)}`,
    });
    const result = await r.callTool('echo', { a: 1 });
    assert.deepEqual(result, { content: [{ type: 'text', text: 'got:{"a":1}' }] });
  });

  it('passes through handler results that are already CallToolResult', async () => {
    const pre = { content: [{ type: 'text' as const, text: 'pre-shaped' }], isError: true };
    const r = createToolRegistry().register({ tool: echoTool, handler: async () => pre });
    const result = await r.callTool('echo', {});
    assert.equal(result, pre);
  });

  it('throws NotFoundError on unknown tool', async () => {
    const r = createToolRegistry();
    await assert.rejects(() => r.callTool('nope', {}), (err) => err instanceof NotFoundError);
  });

  it('rejects duplicate registration', () => {
    const r = createToolRegistry().register({ tool: echoTool, handler: async () => '' });
    assert.throws(() => r.register({ tool: echoTool, handler: async () => '' }), /already registered/);
  });
});
