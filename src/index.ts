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
import { getDeviceCapabilities } from './openwrt.js';
import { applyTailscalePlan, createTailscalePlan, getTailscaleStatus, verifyTailscale } from './tailscale-operations.js';
import type { TailscalePlan } from './tailscale.js';

const sections = {
  system: 'ubus call system board; printf "\\n"; uptime; printf "\\n"; cat /proc/loadavg',
  storage: 'df -h',
  interfaces: 'ubus call network.interface dump',
  wireless: 'iwinfo',
  clients: "for dev in $(iwinfo 2>/dev/null | awk '/^[^[:space:]]/{print $1}'); do printf '\\n%s\\n' \"$dev\"; iwinfo \"$dev\" assoclist 2>/dev/null; done",
  logs: 'logread -l 100',
} as const;

const monitorInput = z.object({
  section: z.enum(['system', 'storage', 'interfaces', 'wireless', 'clients', 'logs']),
});
const executeInput = z.object({
  command: z.string().min(1).max(4096),
  confirm: z.string().min(1).max(4096),
});
const applyTailscaleInput = z.object({ planId: z.string().uuid(), digest: z.string().regex(/^[a-f0-9]{64}$/) }).strict();
const verifyTailscaleInput = z.object({}).strict();
const tailscalePlans = new Map<string, TailscalePlan>();

const serverName = process.env.OPENWRT_MCP_NAME?.trim() || 'openwrt';

const server = new Server(
  { name: serverName, version: '0.1.0' },
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
      name: 'get_device_capabilities',
      description: 'Read OpenWrt release, available package manager, UCI/ubus/Tailscale tools, existing interface names and network routes. Makes no changes.',
      annotations: { readOnlyHint: true },
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    },
    {
      name: 'get_tailscale_status',
      description: `Read Tailscale state on ${serverName} without changing anything: installation, daemon state, backend state, node IPs, advertised routes, exit node, and peer counts.`,
      annotations: { readOnlyHint: true },
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    },
    {
      name: 'plan_tailscale_up',
      description: `Validate and preview a Tailscale node configuration for ${serverName}. Does not change the router. The optional auth key is accepted here but is never echoed back; prefer setting OPENWRT_TAILSCALE_AUTHKEY so the secret never appears in tool input.`,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
      inputSchema: {
        type: 'object',
        properties: {
          hostname: { type: 'string', pattern: '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$' },
          advertiseRoutes: { type: 'array', maxItems: 16, items: { type: 'string' }, default: [] },
          advertiseExitNode: { type: 'boolean', default: false },
          acceptRoutes: { type: 'boolean', default: false },
          acceptDns: { type: 'boolean', default: true },
          authKey: { type: 'string', description: 'Tailscale auth key (tskey-...). Prefer the OPENWRT_TAILSCALE_AUTHKEY environment variable.' },
        },
        additionalProperties: false,
      },
    },
    {
      name: 'apply_tailscale_up',
      description: `Apply a previously previewed Tailscale plan on ${serverName}. Runs tailscale up with only the planned flags and changes the router's Tailscale state. Requires the exact planId and digest. The auth key travels over SSH stdin and is never written to disk permanently.`,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
      inputSchema: { type: 'object', properties: { planId: { type: 'string' }, digest: { type: 'string' } }, required: ['planId', 'digest'], additionalProperties: false },
    },
    {
      name: 'verify_tailscale',
      description: `Open a fresh SSH connection to ${serverName} and verify the Tailscale node: daemon running, backend state, assigned IPs, advertised routes, exit node, and tailscale0 address. Independent post-apply check.`,
      annotations: { readOnlyHint: true },
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
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
  if (request.params.name === 'get_device_capabilities') {
    const capabilities = await getDeviceCapabilities(config);
    return { content: [{ type: 'text', text: JSON.stringify({
      release: capabilities.release,
      revision: capabilities.revision,
      target: capabilities.target,
      packageManager: capabilities.packageManager,
      tools: capabilities.tools,
      tailscaleAvailable: capabilities.tailscaleAvailable,
      pendingNetworkChanges: capabilities.pendingNetworkChanges,
      configuredInterfaces: capabilities.configuredInterfaces,
      interfaceAddresses: capabilities.interfaceAddresses,
    }, null, 2) }] };
  }
  if (request.params.name === 'get_tailscale_status') {
    const result = await getTailscaleStatus(config);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }], isError: result.exitCode !== 0 };
  }
  if (request.params.name === 'plan_tailscale_up') {
    const summary = await createTailscalePlan(
      config,
      tailscalePlans,
      request.params.arguments,
      process.env.OPENWRT_TAILSCALE_AUTHKEY?.trim() || undefined,
    );
    return { content: [{ type: 'text', text: JSON.stringify(summary, null, 2) }] };
  }
  if (request.params.name === 'apply_tailscale_up') {
    const input = applyTailscaleInput.parse(request.params.arguments);
    const result = await applyTailscalePlan(config, tailscalePlans, input.planId, input.digest);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  }
  if (request.params.name === 'verify_tailscale') {
    verifyTailscaleInput.parse(request.params.arguments ?? {});
    const result = await verifyTailscale(config);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }], isError: !result.up };
  }
  if (request.params.name === 'execute_command') {
    const input = executeInput.parse(request.params.arguments);
    if (!isConfirmedCommand(input.command, input.confirm)) {
      return {
        content: [{ type: 'text', text: 'No ejecutado. Para confirmar, vuelve a llamar con confirm idéntico a command.' }],
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
