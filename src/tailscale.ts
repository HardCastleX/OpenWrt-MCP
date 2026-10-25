import { createHash, randomUUID } from 'node:crypto';
import ipaddr from 'ipaddr.js';
import { z } from 'zod';
import { assertTailscaleReady, type DeviceCapabilities } from './openwrt.js';

const TAILNET_V4 = '100.64.0.0/10';
const TAILNET_V6 = 'fd7a:115c:a1e0::/48';
const PLAN_TTL_MS = 10 * 60 * 1000;

const cidrSchema = z.string().max(64).refine((value) => {
  try { ipaddr.parseCIDR(value); return true; } catch { return false; }
}, 'Expected a valid IPv4 or IPv6 CIDR.');

const hostnameSchema = z.string().min(1).max(63).regex(
  /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/,
  'Hostname must be a valid DNS label.',
);

const authKeySchema = z.string().min(20).max(200).regex(
  /^tskey-[A-Za-z0-9_-]+$/,
  'Expected a Tailscale auth key (tskey-...).',
);

function isDefaultRoute(cidr: string): boolean {
  return cidr === '0.0.0.0/0' || cidr === '::/0';
}

function cidrRange(cidr: string): { bits: number; start: bigint; end: bigint } {
  const [address, prefix] = ipaddr.parseCIDR(cidr);
  const value = address.toByteArray().reduce((result, byte) => (result << 8n) | BigInt(byte), 0n);
  const bits = address.toByteArray().length * 8;
  const hostBits = BigInt(bits - prefix);
  const start = (value >> hostBits) << hostBits;
  return { bits, start, end: start + ((1n << hostBits) - 1n) };
}

function overlaps(left: string, right: string): boolean {
  const a = cidrRange(left);
  const b = cidrRange(right);
  return a.bits === b.bits && a.start <= b.end && b.start <= a.end;
}

export const tailscaleUpInputSchema = z.object({
  hostname: hostnameSchema.optional(),
  advertiseRoutes: z.array(cidrSchema).max(16).default([]),
  advertiseExitNode: z.boolean().default(false),
  acceptRoutes: z.boolean().default(false),
  acceptDns: z.boolean().default(true),
  authKey: authKeySchema.optional(),
}).strict()
  .refine((input) => new Set(input.advertiseRoutes).size === input.advertiseRoutes.length, 'Advertised routes must be unique.')
  .refine((input) => input.advertiseRoutes.every((route) => !isDefaultRoute(route)), 'Use advertiseExitNode instead of advertising 0.0.0.0/0 or ::/0.')
  .refine((input) => input.advertiseRoutes.every((route) => !overlaps(route, TAILNET_V4) && !overlaps(route, TAILNET_V6)), 'Tailscale reserves 100.64.0.0/10 and fd7a:115c:a1e0::/48; they cannot be advertised.');

export type TailscaleUpInput = z.infer<typeof tailscaleUpInputSchema>;
export type TailscalePublicInput = Omit<TailscaleUpInput, 'authKey'>;

export interface TailscalePlan {
  planId: string;
  digest: string;
  createdAt: number;
  input: TailscalePublicInput;
  authKey?: string;
  networkConfigDigest: string;
  capabilities: DeviceCapabilities;
}

export interface TailscalePlanSummary {
  planId: string;
  digest: string;
  expiresInSeconds: number;
  hostname?: string;
  advertiseRoutes: string[];
  advertiseExitNode: boolean;
  acceptRoutes: boolean;
  acceptDns: boolean;
  authKeyProvided: boolean;
  configPreview: string[];
  warnings: string[];
}

export function buildTailscaleUpFlags(input: TailscalePublicInput): string[] {
  return [
    `--accept-dns=${input.acceptDns ? 'true' : 'false'}`,
    `--accept-routes=${input.acceptRoutes ? 'true' : 'false'}`,
    `--advertise-exit-node=${input.advertiseExitNode ? 'true' : 'false'}`,
    ...(input.hostname ? [`--hostname=${input.hostname}`] : []),
    ...(input.advertiseRoutes.length > 0 ? [`--advertise-routes=${input.advertiseRoutes.join(',')}`] : []),
  ];
}

export function makeTailscalePlan(
  input: TailscaleUpInput,
  capabilities: DeviceCapabilities,
  now = Date.now(),
  envAuthKey?: string,
): { plan: TailscalePlan; summary: TailscalePlanSummary } {
  assertTailscaleReady(capabilities);
  const { authKey: inputAuthKey, ...publicInput } = input;
  const authKey = inputAuthKey ?? envAuthKey;
  const planId = randomUUID();
  const authKeyDigest = authKey ? createHash('sha256').update(authKey).digest('hex') : null;
  const digest = createHash('sha256').update(JSON.stringify({
    planId,
    input: publicInput,
    authKeyDigest,
    config: capabilities.networkConfigDigest,
  })).digest('hex');
  const plan: TailscalePlan = {
    planId,
    digest,
    createdAt: now,
    input: publicInput,
    authKey,
    networkConfigDigest: capabilities.networkConfigDigest,
    capabilities,
  };
  const configPreview = [
    `tailscale up ${buildTailscaleUpFlags(publicInput).join(' ')}${authKey ? ' --auth-key=file:<temporary file, deleted after apply>' : ''}`,
  ];
  const summary: TailscalePlanSummary = {
    planId,
    digest,
    expiresInSeconds: PLAN_TTL_MS / 1000,
    hostname: publicInput.hostname,
    advertiseRoutes: publicInput.advertiseRoutes,
    advertiseExitNode: publicInput.advertiseExitNode,
    acceptRoutes: publicInput.acceptRoutes,
    acceptDns: publicInput.acceptDns,
    authKeyProvided: Boolean(authKey),
    configPreview,
    warnings: [
      'Plan only; no router configuration has been changed.',
      authKey
        ? 'The auth key is held only in MCP memory, sent over SSH stdin, and never included in this response.'
        : 'No auth key was provided; tailscale up will reuse an existing session on the router.',
      'The tailscaled service is started only if it is not already running.',
    ],
  };
  return { plan, summary };
}

export function buildTailscaleUpScript(plan: TailscalePlan): string {
  const flags = buildTailscaleUpFlags(plan.input);
  const lines = [
    'set -e',
    "if ! command -v tailscale >/dev/null 2>&1; then printf '%s\\n' TAILSCALE_NOT_INSTALLED; exit 30; fi",
    "if ! command -v tailscaled >/dev/null 2>&1; then printf '%s\\n' TAILSCALED_NOT_INSTALLED; exit 30; fi",
    'if ! tailscale status --json >/dev/null 2>&1; then',
    '  if [ -x /etc/init.d/tailscale ]; then /etc/init.d/tailscale start >/dev/null 2>&1 || true; fi',
    '  attempts=0',
    '  while [ "$attempts" -lt 10 ]; do',
    '    if tailscale status --json >/dev/null 2>&1; then break; fi',
    '    attempts=$((attempts + 1))',
    '    sleep 1',
    '  done',
    "  if ! tailscale status --json >/dev/null 2>&1; then printf '%s\\n' TAILSCALED_NOT_RUNNING; exit 31; fi",
    'fi',
    'umask 077',
    'key_file=',
    'cleanup() { if [ -n "$key_file" ]; then rm -f "$key_file"; fi; }',
    'trap cleanup EXIT HUP INT TERM',
  ];
  if (plan.authKey) {
    lines.push(
      'key_file="$(mktemp /tmp/openwrt-mcp-tailscale.XXXXXX)"',
      'chmod 600 "$key_file"',
      'cat > "$key_file"',
      `tailscale up ${flags.join(' ')} --auth-key="file:$key_file" --timeout=20s`,
    );
  } else {
    lines.push(`tailscale up ${flags.join(' ')} --timeout=20s`);
  }
  return lines.join('\n');
}

export function buildTailscaleApplyPayload(plan: TailscalePlan): { command: string; stdin?: string } {
  return {
    command: buildTailscaleUpScript(plan),
    stdin: plan.authKey ? `${plan.authKey}\n` : undefined,
  };
}

export function redactTailscaleSecrets(text: string, plan: TailscalePlan): string {
  const withoutPlanKey = plan.authKey ? text.split(plan.authKey).join('<redacted>') : text;
  return withoutPlanKey.replace(/tskey-[A-Za-z0-9_-]+/g, '<redacted-tskey>');
}

export function planExpired(plan: TailscalePlan, now = Date.now()): boolean {
  return now - plan.createdAt > PLAN_TTL_MS;
}

function markedSection(stdout: string, start: string, end: string): string {
  const from = stdout.indexOf(`${start}\n`);
  if (from < 0) return '';
  const contentStart = from + start.length + 1;
  const to = stdout.indexOf(`${end}\n`, contentStart);
  return (to < 0 ? stdout.slice(contentStart) : stdout.slice(contentStart, to)).trim();
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function parseJson(input: string): unknown {
  try { return JSON.parse(input); } catch { return undefined; }
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

export interface TailscaleStatus {
  installed: boolean;
  daemonRunning: boolean;
  version?: string;
  backendState?: string;
  up: boolean;
  online: boolean;
  hostname?: string;
  dnsName?: string;
  tailscaleIps: string[];
  magicDnsSuffix?: string;
  advertisedRoutes: string[];
  advertiseExitNode: boolean;
  usingExitNode?: string;
  acceptRoutes: boolean;
  acceptDns: boolean;
  peerCount: number;
  onlinePeerCount: number;
  interfaceAddress?: string;
  partial: boolean;
}

export function parseTailscaleStatus(stdout: string, truncated = false): TailscaleStatus {
  const binary = markedSection(stdout, '__TAILSCALE_BIN__', '__TAILSCALED_BIN__').split(/\r?\n/)[0]?.trim() ?? '';
  const daemonBinary = markedSection(stdout, '__TAILSCALED_BIN__', '__VERSION__').split(/\r?\n/)[0]?.trim() ?? '';
  const versionRaw = markedSection(stdout, '__VERSION__', '__STATUS__');
  const statusRaw = markedSection(stdout, '__STATUS__', '__PREFS__');
  const prefsRaw = markedSection(stdout, '__PREFS__', '__IP4__');
  const ip4Raw = markedSection(stdout, '__IP4__', '__IFACE__');
  const interfaceRaw = markedSection(stdout, '__IFACE__', '__END__');

  const status = asRecord(parseJson(statusRaw));
  const prefs = asRecord(parseJson(prefsRaw));
  const self = asRecord(status?.Self);
  const exitNodeStatus = asRecord(status?.ExitNodeStatus);
  const peers = asRecord(status?.Peer);
  const peerRecords = peers
    ? Object.values(peers).map(asRecord).filter((peer): peer is Record<string, unknown> => peer !== undefined)
    : [];
  const tailscaleIps = stringArray(self?.TailscaleIPs ?? status?.TailscaleIPs);
  const advertisedRoutes = stringArray(prefs?.AdvertiseRoutes);
  const interfaceAddress = interfaceRaw.split(/\r?\n/)
    .map((line) => line.match(/\binet\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\/\d{1,2})?/) ?.[1])
    .find((address): address is string => Boolean(address && ipaddr.isValid(address)));

  return {
    installed: binary.length > 0 && daemonBinary.length > 0,
    daemonRunning: status !== undefined,
    version: optionalString(status?.Version) ?? (versionRaw.split(/\r?\n/)[0]?.trim() || undefined),
    backendState: optionalString(status?.BackendState),
    up: status?.BackendState === 'Running' && tailscaleIps.length > 0,
    online: self?.Online === true,
    hostname: optionalString(self?.HostName),
    dnsName: optionalString(self?.DNSName),
    tailscaleIps,
    magicDnsSuffix: optionalString(status?.MagicDNSSuffix),
    advertisedRoutes,
    advertiseExitNode: advertisedRoutes.some(isDefaultRoute),
    usingExitNode: stringArray(exitNodeStatus?.TailscaleIPs)[0] ?? optionalString(prefs?.ExitNodeIP),
    acceptRoutes: prefs?.RouteAll === true,
    acceptDns: prefs?.CorpDNS !== false,
    peerCount: peerRecords.length,
    onlinePeerCount: peerRecords.filter((peer) => peer.Online === true).length,
    interfaceAddress,
    partial: truncated,
  };
}
