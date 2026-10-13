import { createHash } from 'node:crypto';
import type { SshConfig } from './config.js';
import { runSshCommand } from './ssh.js';

const CAPABILITIES_COMMAND = [
  "printf '%s\\n' '__RELEASE__'",
  'cat /etc/openwrt_release 2>/dev/null || true',
  "printf '%s\\n' '__TOOLS__'",
  'for tool in uci ubus wg apk opkg iwinfo sha256sum; do command -v "$tool" 2>/dev/null || true; done',
  "printf '%s\\n' '__UCI_CHANGES__'",
  'uci changes network 2>/dev/null || true',
  "printf '%s\\n' '__UCI_INTERFACES__'",
  "uci show network 2>/dev/null | while IFS= read -r line; do case \"$line\" in network.*=interface|network.*.proto='wireguard'|network.*=wireguard_*) printf '%s\\n' \"$line\";; esac; done",
  "printf '%s\\n' '__UCI_HASH__'",
  "uci show network 2>/dev/null | sha256sum | cut -d ' ' -f 1",
  "printf '%s\\n' '__ROUTES4__'",
  'ip -4 route show 2>/dev/null || true',
  "printf '%s\\n' '__ROUTES6__'",
  'ip -6 route show 2>/dev/null || true',
  "printf '%s\\n' '__INTERFACES__'",
  'ubus call network.interface dump 2>/dev/null || true',
  "printf '%s\\n' '__WG_INTERFACES__'",
  'wg show interfaces 2>/dev/null || true',
].join('; ');

export interface DeviceCapabilities {
  release: string;
  revision: string;
  target: string;
  packageManager: 'apk' | 'opkg' | 'ambiguous' | 'unknown';
  tools: string[];
  wireguardAvailable: boolean;
  pendingNetworkChanges: boolean;
  configuredInterfaces: string[];
  wireguardInterfaces: string[];
  routes: string[];
  interfaceAddresses: string[];
  networkConfigDigest: string;
}

function section(stdout: string, start: string, end: string): string {
  const from = stdout.indexOf(`${start}\n`);
  if (from < 0) return '';
  const contentStart = from + start.length + 1;
  const to = stdout.indexOf(`${end}\n`, contentStart);
  return (to < 0 ? stdout.slice(contentStart) : stdout.slice(contentStart, to)).trim();
}

function releaseValue(release: string, name: string): string {
  const match = release.match(new RegExp(`^${name}='([^']*)'$`, 'm'));
  return match?.[1] ?? 'unknown';
}

export function parseCapabilities(stdout: string): DeviceCapabilities {
  const release = section(stdout, '__RELEASE__', '__TOOLS__');
  const toolPaths = section(stdout, '__TOOLS__', '__UCI_CHANGES__').split(/\r?\n/).filter(Boolean);
  const tools = toolPaths.map((entry) => entry.split(/[\\/]/).at(-1)!).filter(Boolean);
  const uciChanges = section(stdout, '__UCI_CHANGES__', '__UCI_INTERFACES__');
  const uciNetwork = section(stdout, '__UCI_INTERFACES__', '__UCI_HASH__');
  const networkConfigDigest = section(stdout, '__UCI_HASH__', '__ROUTES4__').split(/\s+/)[0] ?? '';
  const routes4 = section(stdout, '__ROUTES4__', '__ROUTES6__');
  const routes6 = section(stdout, '__ROUTES6__', '__INTERFACES__');
  const interfacesRaw = section(stdout, '__INTERFACES__', '__WG_INTERFACES__');
  const wgInterfacesRaw = section(stdout, '__WG_INTERFACES__', '__END__').replace(/__END__$/, '').trim();

  const configuredInterfaces = [...uciNetwork.matchAll(/^network\.([A-Za-z0-9_]+)=interface$/gm)].map((match) => match[1]!);
  const configuredWireGuardInterfaces = [...uciNetwork.matchAll(/^network\.([A-Za-z0-9_]+)\.proto='wireguard'$/gm)].map((match) => match[1]!);
  const wireguardInterfaces = [...new Set(configuredWireGuardInterfaces)];
  const wgTools = tools.includes('wg');
  const hasApk = tools.includes('apk');
  const hasOpkg = tools.includes('opkg');
  let interfaces: Array<{ 'ipv4-address'?: Array<{ address: string; mask: number }>; 'ipv6-address'?: Array<{ address: string; mask: number }> }> = [];
  try {
    interfaces = (JSON.parse(interfacesRaw) as { interface?: typeof interfaces }).interface ?? [];
  } catch {
    interfaces = [];
  }
  const interfaceAddresses = interfaces.flatMap((item) => [
    ...(item['ipv4-address'] ?? []).map(({ address, mask }) => `${address}/${mask}`),
    ...(item['ipv6-address'] ?? []).map(({ address, mask }) => `${address}/${mask}`),
  ]);
  const routes = [...routes4.split(/\r?\n/), ...routes6.split(/\r?\n/)].filter(Boolean);

  return {
    release: releaseValue(release, 'DISTRIB_RELEASE'),
    revision: releaseValue(release, 'DISTRIB_REVISION'),
    target: releaseValue(release, 'DISTRIB_TARGET'),
    packageManager: hasApk === hasOpkg ? (hasApk ? 'ambiguous' : 'unknown') : hasApk ? 'apk' : 'opkg',
    tools,
    wireguardAvailable: wgTools && uciNetwork.includes("=interface") && release.length > 0,
    pendingNetworkChanges: uciChanges.length > 0,
    configuredInterfaces: [...new Set([...configuredInterfaces, ...wgInterfacesRaw.split(/\s+/).filter(Boolean)])],
    wireguardInterfaces: [...new Set([...wireguardInterfaces, ...wgInterfacesRaw.split(/\s+/).filter(Boolean)])],
    routes,
    interfaceAddresses,
    networkConfigDigest: /^[a-f0-9]{64}$/.test(networkConfigDigest) ? networkConfigDigest : '',
  };
}

export async function getDeviceCapabilities(config: SshConfig): Promise<DeviceCapabilities> {
  const result = await runSshCommand(config, CAPABILITIES_COMMAND);
  if (result.exitCode !== 0 || result.truncated) {
    throw new Error(`Could not read OpenWrt capabilities (exit code ${result.exitCode ?? 'unknown'}).`);
  }
  return parseCapabilities(`${result.stdout}\n__END__\n`);
}

export function assertWireGuardReady(capabilities: DeviceCapabilities): void {
  if (capabilities.release === 'unknown') throw new Error('Could not identify the OpenWrt release; refusing network changes.');
  if (!capabilities.tools.includes('uci') || !capabilities.tools.includes('ubus')) {
    throw new Error('This device is missing required UCI/ubus tools; refusing network changes.');
  }
  if (!capabilities.tools.includes('wg') || !capabilities.wireguardAvailable) {
    throw new Error('WireGuard tools are not available on this device. No packages were installed.');
  }
  if (capabilities.packageManager === 'unknown' || capabilities.packageManager === 'ambiguous') {
    throw new Error('Could not identify a unique package manager; refusing network changes.');
  }
  if (!capabilities.tools.includes('sha256sum')) {
    throw new Error('sha256sum is unavailable; cannot safely check for concurrent network configuration changes.');
  }
  if (!/^[a-f0-9]{64}$/.test(capabilities.networkConfigDigest)) {
    throw new Error('Could not obtain a safe network configuration fingerprint; refusing network changes.');
  }
  if (capabilities.pendingNetworkChanges) {
    throw new Error('The router has pending UCI network changes; apply or discard them manually before using this tool.');
  }
}
