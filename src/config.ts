import { readFileSync } from 'node:fs';
import ipaddr from 'ipaddr.js';

export interface SshConfig {
  host: string;
  port: number;
  username: string;
  privateKey: Buffer;
  passphrase?: string;
  hostFingerprint: string;
}

export function isPrivateAddress(host: string): boolean {
  if (!ipaddr.isValid(host)) return false;

  const address = ipaddr.parse(host);
  if (address.kind() === 'ipv4') {
    const range = address.range();
    return range === 'private' || range === 'carrierGradeNat';
  }
  if (address.range() === 'uniqueLocal') return true;
  if (ipaddr.IPv6.isIPv6(host)) {
    const ipv6 = ipaddr.IPv6.parse(host);
    if (!ipv6.isIPv4MappedAddress()) return false;
    const range = ipv6.toIPv4Address().range();
    return range === 'private' || range === 'carrierGradeNat';
  }
  return false;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): SshConfig {
  const host = env.OPENWRT_HOST?.trim();
  const username = env.OPENWRT_SSH_USER?.trim();
  const keyPath = env.OPENWRT_SSH_KEY_PATH?.trim();
  const hostFingerprint = env.OPENWRT_SSH_HOST_FINGERPRINT?.trim();
  const portValue = env.OPENWRT_SSH_PORT ?? '22';
  const port = Number(portValue);

  if (!host || !isPrivateAddress(host)) {
    throw new Error('OPENWRT_HOST must be a private LAN or Tailscale (CGNAT) IP address.');
  }
  if (!username) throw new Error('OPENWRT_SSH_USER is required.');
  if (!keyPath) throw new Error('OPENWRT_SSH_KEY_PATH is required.');
  if (!hostFingerprint || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(hostFingerprint)) {
    throw new Error('OPENWRT_SSH_HOST_FINGERPRINT must be a SHA256 SSH host-key fingerprint.');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('OPENWRT_SSH_PORT must be an integer between 1 and 65535.');
  }

  return {
    host,
    port,
    username,
    privateKey: readFileSync(keyPath),
    passphrase: env.OPENWRT_SSH_KEY_PASSPHRASE || undefined,
    hostFingerprint,
  };
}
