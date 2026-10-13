import { createHash, createPrivateKey, createPublicKey, randomBytes, randomUUID } from 'node:crypto';
import ipaddr from 'ipaddr.js';
import { z } from 'zod';
import type { DeviceCapabilities } from './openwrt.js';

const interfaceNameSchema = z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,14}$/);
const cidrSchema = z.string().max(64).refine((value) => {
  try { ipaddr.parseCIDR(value); return true; } catch { return false; }
}, 'Expected a valid IPv4 or IPv6 CIDR.');
const keySchema = z.string().regex(/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/).refine((value) => {
  try { return Buffer.from(value, 'base64').length === 32; } catch { return false; }
}, 'WireGuard keys must be base64-encoded 32-byte values.');
const endpointHostSchema = z.string().min(1).max(253).refine((value) =>
  ipaddr.isValid(value) || /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$/.test(value),
'Endpoint must be an IP address or DNS hostname.');

export const wireGuardInputSchema = z.object({
  interfaceName: interfaceNameSchema,
  addresses: z.array(cidrSchema).min(1).max(8),
  listenPort: z.number().int().min(1).max(65535).optional(),
  routeAllowedIps: z.boolean().default(false),
  peers: z.array(z.object({
    publicKey: keySchema,
    allowedIps: z.array(cidrSchema).min(1).max(16),
    endpointHost: endpointHostSchema.optional(),
    endpointPort: z.number().int().min(1).max(65535).optional(),
    persistentKeepalive: z.number().int().min(0).max(65535).optional(),
  }).strict().refine((peer) => Boolean(peer.endpointHost) === Boolean(peer.endpointPort), 'endpointHost and endpointPort must be provided together.')).max(8).default([]),
}).strict().refine((input) => new Set(input.peers.map((peer) => peer.publicKey)).size === input.peers.length, 'Peer public keys must be unique.')
  .refine((input) => input.peers.length > 0 || input.routeAllowedIps === false, 'Local-only tunnels cannot install routes.');

export type WireGuardInput = z.infer<typeof wireGuardInputSchema>;

export interface WireGuardPlan {
  planId: string;
  digest: string;
  createdAt: number;
  input: WireGuardInput;
  privateKey: string;
  publicKey: string;
  networkConfigDigest: string;
  capabilities: DeviceCapabilities;
}

export interface WireGuardPlanSummary {
  planId: string;
  digest: string;
  expiresInSeconds: number;
  interfaceName: string;
  addresses: string[];
  listenPort?: number;
  routeAllowedIps: boolean;
  peers: Array<Pick<WireGuardInput['peers'][number], 'publicKey' | 'allowedIps' | 'endpointHost' | 'endpointPort' | 'persistentKeepalive'>>;
  localPublicKey: string;
  configPreview: string[];
  warnings: string[];
}

const PRIVATE_KEY_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

export function generateWireGuardKeyPair(): { privateKey: string; publicKey: string } {
  const rawPrivateKey = randomBytes(32);
  rawPrivateKey[0] = rawPrivateKey[0]! & 248;
  rawPrivateKey[31] = (rawPrivateKey[31]! & 127) | 64;
  const privateObject = createPrivateKey({ key: Buffer.concat([PRIVATE_KEY_PKCS8_PREFIX, rawPrivateKey]), format: 'der', type: 'pkcs8' });
  const publicObject = createPublicKey(privateObject);
  const rawPublicKey = publicObject.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { privateKey: rawPrivateKey.toString('base64'), publicKey: rawPublicKey.toString('base64') };
}

function cidrRange(cidr: string): { family: number; start: bigint; end: bigint } {
  const [address, prefix] = ipaddr.parseCIDR(cidr);
  const bytes = address.toByteArray();
  const bits = bytes.length * 8;
  const value = bytes.reduce((result, byte) => (result << 8n) | BigInt(byte), 0n);
  const hostBits = BigInt(bits - prefix);
  const start = (value >> hostBits) << hostBits;
  const end = start + ((1n << hostBits) - 1n);
  return { family: bits, start, end };
}

function overlaps(left: string, right: string): boolean {
  const a = cidrRange(left);
  const b = cidrRange(right);
  return a.family === b.family && a.start <= b.end && b.start <= a.end;
}

function nonDefaultRoutes(routes: string[]): string[] {
  return routes.flatMap((route) => {
    const fields = route.trim().split(/\s+/);
    const destinationIndex = fields.findIndex((field) => field === 'default' || ipaddr.isValid(field) || /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(field) || field.includes(':') && field.includes('/'));
    const destination = destinationIndex >= 0 ? fields[destinationIndex] : undefined;
    if (!destination || destination === 'default') return [];
    try {
      const normalized = destination.includes('/') ? destination : `${destination}/${ipaddr.parse(destination).kind() === 'ipv4' ? 32 : 128}`;
      ipaddr.parseCIDR(normalized);
      return [normalized];
    } catch { return []; }
  });
}

export function validateWireGuardPlan(input: WireGuardInput, capabilities: DeviceCapabilities): void {
  if (capabilities.configuredInterfaces.includes(input.interfaceName)) throw new Error(`Interface ${input.interfaceName} already exists; only new interfaces can be created.`);
  const routeRanges = nonDefaultRoutes(capabilities.routes);
  for (const address of input.addresses) {
    if (routeRanges.some((route) => overlaps(address, route))) throw new Error(`Tunnel address ${address} overlaps an existing route; refusing to configure it.`);
  }
  for (const peer of input.peers) {
    if (peer.allowedIps.some((cidr) => cidr === '0.0.0.0/0' || cidr === '::/0')) throw new Error('Default routes are not allowed for isolated tunnels.');
    if (input.routeAllowedIps) {
      for (const allowedIp of peer.allowedIps) {
        if (routeRanges.some((route) => overlaps(allowedIp, route))) throw new Error(`Allowed IP ${allowedIp} overlaps an existing route; refusing to add routes.`);
      }
    }
  }
}

function uciQuote(value: string): string {
  if (!/^[A-Za-z0-9_+./:=@-]+$/.test(value)) throw new Error('Unsafe UCI value rejected.');
  return `'${value}'`;
}

export function makeWireGuardPlan(input: WireGuardInput, capabilities: DeviceCapabilities, now = Date.now()): { plan: WireGuardPlan; summary: WireGuardPlanSummary } {
  validateWireGuardPlan(input, capabilities);
  const keyPair = generateWireGuardKeyPair();
  const planId = randomUUID();
  const digest = createHash('sha256').update(JSON.stringify({ planId, input, publicKey: keyPair.publicKey, config: capabilities.networkConfigDigest })).digest('hex');
  const plan: WireGuardPlan = {
    planId,
    digest,
    createdAt: now,
    input,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    networkConfigDigest: capabilities.networkConfigDigest,
    capabilities,
  };
  const peerSections = input.peers.flatMap((_, index) => [
    `network.wgpeer_${input.interfaceName}_${index}=wireguard_${input.interfaceName}`,
    `network.wgpeer_${input.interfaceName}_${index}.public_key=<peer-${index + 1}-public-key>`,
  ]);
  const configPreview = [
    `network.${input.interfaceName}=interface`,
    `network.${input.interfaceName}.proto=wireguard`,
    `network.${input.interfaceName}.private_key=<generated; hidden>`,
    ...input.addresses.map((address) => `network.${input.interfaceName}.addresses=${address}`),
    ...peerSections,
    `route_allowed_ips=${input.routeAllowedIps}`,
  ];
  const summary: WireGuardPlanSummary = {
    planId,
    digest,
    expiresInSeconds: 600,
    interfaceName: input.interfaceName,
    addresses: input.addresses,
    listenPort: input.listenPort,
    routeAllowedIps: input.routeAllowedIps,
    peers: input.peers,
    localPublicKey: keyPair.publicKey,
    configPreview,
    warnings: [
      'Plan only; no router configuration has been changed.',
      'The tunnel private key is generated locally and is not included in this response.',
      'No firewall zone, LAN/WAN interface, existing tunnel, or default route will be modified.',
    ],
  };
  return { plan, summary };
}

export function buildUciBatch(plan: WireGuardPlan): string {
  const { input } = plan;
  const commands = [
    `set network.${input.interfaceName}='interface'`,
    `set network.${input.interfaceName}.proto='wireguard'`,
    `set network.${input.interfaceName}.private_key=${uciQuote(plan.privateKey)}`,
    ...input.addresses.map((address) => `add_list network.${input.interfaceName}.addresses=${uciQuote(address)}`),
  ];
  if (input.listenPort !== undefined) commands.push(`set network.${input.interfaceName}.listen_port='${input.listenPort}'`);
  for (const [index, peer] of input.peers.entries()) {
    const section = `wgpeer_${input.interfaceName}_${index}`;
    commands.push(`set network.${section}='wireguard_${input.interfaceName}'`);
    commands.push(`set network.${section}.public_key=${uciQuote(peer.publicKey)}`);
    commands.push(`set network.${section}.route_allowed_ips='${input.routeAllowedIps ? 1 : 0}'`);
    for (const allowedIp of peer.allowedIps) commands.push(`add_list network.${section}.allowed_ips=${uciQuote(allowedIp)}`);
    if (peer.endpointHost !== undefined) commands.push(`set network.${section}.endpoint_host=${uciQuote(peer.endpointHost)}`);
    if (peer.endpointPort !== undefined) commands.push(`set network.${section}.endpoint_port='${peer.endpointPort}'`);
    if (peer.persistentKeepalive !== undefined) commands.push(`set network.${section}.persistent_keepalive='${peer.persistentKeepalive}'`);
  }
  return `${commands.join('\n')}\n`;
}

export function redactWireGuardSecrets(text: string, plan: WireGuardPlan): string {
  return text.split(plan.privateKey).join('<redacted>');
}

export function planExpired(plan: WireGuardPlan, now = Date.now()): boolean {
  return now - plan.createdAt > 10 * 60 * 1000;
}
