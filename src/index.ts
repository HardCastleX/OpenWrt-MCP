import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { loadConfig } from './config.js';
import { runSshCommand } from './ssh.js';
import { isConfirmedCommand } from './safety.js';

const sections = {
  system: 'ubus call system board; printf "\\n"; uptime; printf "\\n"; cat /proc/loadavg',
  storage: 'df -h',
  interfaces: 'ubus call network.interface dump',
  wireless: 'iwinfo',
  clients: 'for iface in $(ubus list "hostapd.*"); do printf "\\n%s\\n" "$iface"; ubus call "$iface" get_clients; done',
  logs: 'logread -l 100',
} as const;

const monitorInput = z.object({
  section: z.enum(['system', 'storage', 'interfaces', 'wireless', 'clients', 'logs']),
});
const executeInput = z.object({
  command: z.string().min(1).max(4096),
  confirm: z.string().min(1).max(4096),
});

const server = new Server(
  { name: 'openwrt', version: '0.1.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'get_router_status',
      description: 'Read a fixed, non-mutating OpenWrt status section over SSH. Choose system, storage, interfaces, wireless, clients, or logs.',
      inputSchema: {
        type: 'object',
        properties: {
          section: { type: 'string', enum: Object.keys(sections) },
        },
        required: ['section'],
      },
    },
    {
      name: 'execute_command',
      description: 'Run one explicitly supplied command on the configured OpenWrt router as the configured SSH user. This can make system changes. Requires confirm to exactly repeat command; still configure Command Code to ask before every call.',
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
      inputSchema: {
        type: 'object',
        properties: {
          command: { type: 'string', minLength: 1, maxLength: 4096 },
          confirm: { type: 'string', minLength: 1, maxLength: 4096, description: 'Repeat the exact command string to confirm execution.' },
        },
        required: ['command', 'confirm'],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const config = loadConfig();
  if (request.params.name === 'get_router_status') {
    const input = monitorInput.parse(request.params.arguments);
    const result = await runSshCommand(config, sections[input.section]);
    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      isError: result.exitCode !== 0,
    };
  }
  if (request.params.name === 'execute_command') {
    const input = executeInput.parse(request.params.arguments);
    if (!isConfirmedCommand(input.command, input.confirm)) {
      return {
        content: [{ type: 'text', text: `No ejecutado. Para confirmar, vuelve a llamar y repite exactamente el comando en confirm: ${input.command}` }],
        isError: true,
      };
    }
    const result = await runSshCommand(config, input.command);
    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      isError: result.exitCode !== 0,
    };
  }
  throw new Error(`Unknown tool: ${request.params.name}`);
});

export { server };

const transport = new StdioServerTransport();
await server.connect(transport);
