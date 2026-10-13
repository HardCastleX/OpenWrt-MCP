import { createHash } from 'node:crypto';
import type { SshConfig } from './config.js';
import { assertWireGuardReady, getDeviceCapabilities, type DeviceCapabilities } from './openwrt.js';
import { runSshCommand } from './ssh.js';
import { buildUciBatch, makeWireGuardPlan, planExpired, redactWireGuardSecrets, type WireGuardPlan, wireGuardInputSchema } from './wireguard.js';
import { parsePeerHandshakes } from './wireguard-verify.js';

export type WireGuardPlanStore = Map<string, WireGuardPlan>;

export function buildWireGuardApplyScript(plan: WireGuardPlan): string {
  const sections = [plan.input.interfaceName, ...plan.input.peers.map((_, index) => `wgpeer_${plan.input.interfaceName}_${index}`)];
  const cleanup = sections.map((section) => `uci revert network.${section} >/dev/null 2>&1 || true`).join('; ');
  return [
    'set -e',
    'lock_dir=/tmp/openwrt-mcp-network.lock',
    'batch_file=',
    'if ! mkdir "$lock_dir" 2>/dev/null; then echo NETWORK_OPERATION_LOCKED; exit 20; fi',
    `trap 'rmdir "$lock_dir" >/dev/null 2>&1 || true' EXIT HUP INT TERM`,
    'if [ -n "$(uci changes network)" ]; then echo PENDING_UCI_CHANGES; exit 21; fi',
    `if [ "$(uci show network | sha256sum | cut -d ' ' -f 1)" != '${plan.networkConfigDigest}' ]; then echo NETWORK_CONFIG_CHANGED; exit 23; fi`,
    `if uci show network | grep -q '^network\\.${plan.input.interfaceName}='; then echo INTERFACE_EXISTS; exit 22; fi`,
    'batch_file="$(mktemp /tmp/openwrt-mcp.XXXXXX)"',
    'chmod 600 "$batch_file"',
    `trap 'rm -f "$batch_file"; ${cleanup}; rmdir "$lock_dir" >/dev/null 2>&1 || true' EXIT HUP INT TERM`,
    'cat > "$batch_file"',
    'if ! uci batch < "$batch_file"; then echo UCI_BATCH_FAILED; exit 24; fi',
    'changes="$(uci changes network)"',
    `if [ -z "$changes" ]; then echo EMPTY_UCI_TRANSACTION; ${cleanup}; exit 24; fi`,
    `if ! printf '%s\\n' "$changes" | awk '{ section=$0; sub(/^.*network\\./, "", section); sub(/[. =].*$/, "", section); if (section !~ /^(${sections.join('|')})$/) exit 1 }'; then echo UNEXPECTED_UCI_SECTION; ${cleanup}; exit 25; fi`,
    'uci commit network',
    'rm -f "$batch_file"',
    'batch_file=',
    `trap 'rmdir "$lock_dir" >/dev/null 2>&1 || true' EXIT HUP INT TERM`,
    `ifup ${plan.input.interfaceName}`,
  ].join('\n');
}

export function hasOnlyExpectedWireGuardSections(changes: string, interfaceName: string, peerCount: number): boolean {
  const allowed = new Set([interfaceName, ...Array.from({ length: peerCount }, (_, index) => `wgpeer_${interfaceName}_${index}`)]);
  const lines = changes.trim().split(/\r?\n/).filter(Boolean);
  return lines.length > 0 && lines.every((line) => {
    const match = line.match(/(?:^|\s)network\.([A-Za-z0-9_]+)(?:\.|=)/);
    return Boolean(match && allowed.has(match[1]!));
  });
}

export async function createWireGuardPlan(config: SshConfig, store: WireGuardPlanStore, rawInput: unknown) {
  const input = wireGuardInputSchema.parse(rawInput);
  const capabilities = await getDeviceCapabilities(config);
  assertWireGuardReady(capabilities);
  for (const [id, existing] of store) if (planExpired(existing)) store.delete(id);
  if (store.size >= 8) throw new Error('Too many active plans; apply or discard an existing plan first.');
  const { plan, summary } = makeWireGuardPlan(input, capabilities);
  store.set(plan.planId, plan);
  return summary;
}

export async function applyWireGuardPlan(config: SshConfig, store: WireGuardPlanStore, planId: string, digest: string) {
  const plan = store.get(planId);
  if (!plan) throw new Error('Plan not found in this MCP process; create a new plan.');
  if (planExpired(plan)) {
    store.delete(planId);
    throw new Error('Plan expired after 10 minutes; create a new plan.');
  }
  if (plan.digest !== digest) throw new Error('Plan digest does not match; nothing was applied.');

  const current = await getDeviceCapabilities(config);
  assertWireGuardReady(current);
  if (current.networkConfigDigest !== plan.networkConfigDigest) throw new Error('Network configuration changed since planning; nothing was applied. Create a new plan.');
  if (current.configuredInterfaces.includes(plan.input.interfaceName)) throw new Error('The interface name now exists; nothing was applied. Create a new plan.');

  const batch = buildUciBatch(plan);
  const applyCommand = buildWireGuardApplyScript(plan);
  const result = await runSshCommand(config, applyCommand, 30_000, batch);
  if (result.exitCode !== 0 || result.truncated) {
    store.delete(planId);
    throw new Error('WireGuard apply failed before or during commit/activation. The UCI staging was reverted when possible; no rollback is guaranteed after commit.');
  }
  store.delete(planId);
  return {
    applied: true,
    interfaceName: plan.input.interfaceName,
    message: 'Only the new WireGuard interface and its peer configuration were committed. A fresh SSH verification is still required.',
  };
}

export async function verifyWireGuardTunnel(config: SshConfig, interfaceName: string) {
  if (!/^[A-Za-z][A-Za-z0-9_]{0,14}$/.test(interfaceName)) throw new Error('Invalid interface name.');
  const command = `printf '__PROTO__\\n'; uci -q get network.${interfaceName}.proto 2>&1; printf '\\n__STATUS__\\n'; ubus call network.interface.${interfaceName} status 2>&1; printf '\\n__WG__\\n'; wg show ${interfaceName} latest-handshakes 2>&1`;
  const result = await runSshCommand(config, command);
  const proto = result.stdout.split('__PROTO__')[1]?.split('__STATUS__')[0]?.trim() ?? '';
  const statusText = result.stdout.split('__STATUS__')[1]?.split('__WG__')[0]?.trim() ?? '';
  const wgText = result.stdout.split('__WG__')[1]?.trim() ?? '';
  let status: Record<string, unknown> | undefined;
  try { status = JSON.parse(statusText) as Record<string, unknown>; } catch { status = undefined; }
  const configured = proto === 'wireguard';
  const up = status?.up === true;
  const handshakes = parsePeerHandshakes(wgText);
  return {
    interfaceName,
    configured,
    up,
    device: typeof status?.device === 'string' ? status.device : undefined,
    peerCount: handshakes.peerCount,
    hasRecentHandshake: handshakes.hasRecentHandshake,
    status: !configured ? 'not-configured' : !up ? 'configured-but-down' : handshakes.hasRecentHandshake ? 'up-with-recent-handshake' : 'up-waiting-for-peer-handshake',
    details: result.exitCode === 0 ? undefined : result.stderr.trim() || `SSH command exited with ${result.exitCode}`,
  };
}
