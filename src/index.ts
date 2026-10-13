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
import { assertWireGuardReady, getDeviceCapabilities } from './openwrt.js';
import { applyWireGuardPlan, createWireGuardPlan, verifyWireGuardTunnel } from './wireguard-operations.js';
import { wireGuardInputSchema, type WireGuardPlan } from './wireguard.js';

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
const applyWireGuardInput = z.object({ planId: z.string().uuid(), digest: z.string().regex(/^[a-f0-9]{64}$/) }).strict();
const verifyWireGuardInput = z.object({ interfaceName: z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,14}$/) }).strict();
const wireGuardPlans = new Map<string, WireGuardPlan>();

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
      description: 'Read OpenWrt release, available package manager, UCI/ubus/WireGuard tools, existing interface names and network routes. Makes no changes.',
      annotations: { readOnlyHint: true },
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    },
    {
      name: 'plan_wireguard_tunnel',
      description: `Validate and preview a new isolated WireGuard tunnel on ${serverName}. Generates its key pair in MCP memory and does not change router configuration. The returned public key is the tunnel peer key; never returns the private key.`,
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
      inputSchema: {
        type: 'object',
        properties: {
          interfaceName: { type: 'string', pattern: '^[A-Za-z][A-Za-z0-9_]{0,14}$' },
          addresses: { type: 'array', minItems: 1, maxItems: 8, items: { type: 'string' } },
          listenPort: { type: 'integer', minimum: 1, maximum: 65535 },
          routeAllowedIps: { type: 'boolean', default: false },
          peers: { type: 'array', minItems: 1, maxItems: 8, items: {
            type: 'object', additionalProperties: false,
            properties: {
              publicKey: { type: 'string' },
              allowedIps: { type: 'array', minItems: 1, maxItems: 16, items: { type: 'string' } },
              endpointHost: { type: 'string' },
              endpointPort: { type: 'integer', minimum: 1, maximum: 65535 },
              persistentKeepalive: { type: 'integer', minimum: 0, maximum: 65535 },
            },
            required: ['publicKey', 'allowedIps'],
          } },
        },
        required: ['interfaceName', 'addresses', 'peers'],
        additionalProperties: false,
      },
    },
    {
      name: 'apply_wireguard_tunnel',
      description: `Apply a previously previewed isolated WireGuard plan on ${serverName}. This changes that router's network configuration. Requires the exact planId and digest returned by plan_wireguard_tunnel; only applies while this MCP process holding the private key remains running.`,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
      inputSchema: { type: 'object', properties: { planId: { type: 'string' }, digest: { type: 'string' } }, required: ['planId', 'digest'], additionalProperties: false },
    },
    {
      name: 'verify_wireguard_tunnel',
      description: `Open a fresh SSH connection to ${serverName} and verify the configured WireGuard interface, local up state, peer count, and recent handshake. This is an independent post-apply check.`,
      annotations: { readOnlyHint: true },
      inputSchema: { type: 'object', properties: { interfaceName: { type: 'string', pattern: '^[A-Za-z][A-Za-z0-9_]{0,14}$' } }, required: ['interfaceName'], additionalProperties: false },
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
      wireguardAvailable: capabilities.wireguardAvailable,
      pendingNetworkChanges: capabilities.pendingNetworkChanges,
      configuredInterfaces: capabilities.configuredInterfaces,
      wireguardInterfaces: capabilities.wireguardInterfaces,
      interfaceAddresses: capabilities.interfaceAddresses,
    }, null, 2) }] };
  }
  if (request.params.name === 'plan_wireguard_tunnel') {
    const parsed = wireGuardInputSchema.parse(request.params.arguments);
    const summary = await createWireGuardPlan(config, wireGuardPlans, parsed);
    return { content: [{ type: 'text', text: JSON.stringify(summary, null, 2) }] };
  }
  if (request.params.name === 'apply_wireguard_tunnel') {
    const input = applyWireGuardInput.parse(request.params.arguments);
    const result = await applyWireGuardPlan(config, wireGuardPlans, input.planId, input.digest);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  }
  if (request.params.name === 'verify_wireguard_tunnel') {
    const input = verifyWireGuardInput.parse(request.params.arguments);
    const result = await verifyWireGuardTunnel(config, input.interfaceName);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }], isError: !result.configured || !result.up };
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
