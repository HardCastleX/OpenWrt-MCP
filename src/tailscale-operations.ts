import type { SshConfig } from './config.js';
import { assertTailscaleReady, getDeviceCapabilities } from './openwrt.js';
import { runSshCommand } from './ssh.js';
import {
  buildTailscaleApplyPayload,
  makeTailscalePlan,
  parseTailscaleStatus,
  planExpired,
  redactTailscaleSecrets,
  tailscaleUpInputSchema,
  type TailscalePlan,
} from './tailscale.js';

export type TailscalePlanStore = Map<string, TailscalePlan>;

const APPLY_TIMEOUT_MS = 60_000;

export const TAILSCALE_STATUS_COMMAND = [
  "printf '__TAILSCALE_BIN__\\n'",
  'command -v tailscale 2>/dev/null || true',
  "printf '\\n__TAILSCALED_BIN__\\n'",
  'command -v tailscaled 2>/dev/null || true',
  "printf '\\n__VERSION__\\n'",
  'tailscale version 2>&1 || true',
  "printf '\\n__STATUS__\\n'",
  'tailscale status --json 2>&1 || true',
  "printf '\\n__PREFS__\\n'",
  'tailscale debug prefs 2>&1 || true',
  "printf '\\n__IP4__\\n'",
  'tailscale ip -4 2>&1 || true',
  "printf '\\n__IFACE__\\n'",
  'ip -4 addr show tailscale0 2>&1 || true',
].join('; ');

async function readTailscaleStatus(config: SshConfig) {
  const result = await runSshCommand(config, TAILSCALE_STATUS_COMMAND);
  const status = parseTailscaleStatus(`${result.stdout}\n__END__\n`, result.truncated);
  return {
    ...status,
    exitCode: result.exitCode,
    error: result.exitCode === 0
      ? undefined
      : result.stderr.trim() || `SSH command exited with ${result.exitCode}`,
  };
}

export async function getTailscaleStatus(config: SshConfig) {
  return readTailscaleStatus(config);
}

export async function verifyTailscale(config: SshConfig) {
  return readTailscaleStatus(config);
}

export async function createTailscalePlan(
  config: SshConfig,
  store: TailscalePlanStore,
  rawInput: unknown,
  envAuthKey?: string,
) {
  const input = tailscaleUpInputSchema.parse(rawInput);
  const capabilities = await getDeviceCapabilities(config);
  assertTailscaleReady(capabilities);
  for (const [id, existing] of store) if (planExpired(existing)) store.delete(id);
  if (store.size >= 8) throw new Error('Too many active plans; apply or discard an existing plan first.');
  const { plan, summary } = makeTailscalePlan(input, capabilities, Date.now(), envAuthKey);
  store.set(plan.planId, plan);
  return summary;
}

export async function applyTailscalePlan(
  config: SshConfig,
  store: TailscalePlanStore,
  planId: string,
  digest: string,
) {
  const plan = store.get(planId);
  if (!plan) throw new Error('Plan not found in this MCP process; create a new plan.');
  if (planExpired(plan)) {
    store.delete(planId);
    throw new Error('Plan expired after 10 minutes; create a new plan.');
  }
  if (plan.digest !== digest) throw new Error('Plan digest does not match; nothing was applied.');

  const current = await getDeviceCapabilities(config);
  assertTailscaleReady(current);
  if (current.networkConfigDigest !== plan.networkConfigDigest) {
    throw new Error('Network configuration changed since planning; nothing was applied. Create a new plan.');
  }

  const payload = buildTailscaleApplyPayload(plan);
  const result = await runSshCommand(config, payload.command, APPLY_TIMEOUT_MS, payload.stdin);
  store.delete(planId);
  const output = redactTailscaleSecrets(`${result.stdout}\n${result.stderr}`, plan).trim();
  if (result.exitCode !== 0) {
    const exitCode = result.exitCode ?? 'unknown';
    throw new Error(`Tailscale apply failed (exit ${exitCode}). The auth key was not stored on the router.${output ? ` Output: ${output.slice(0, 2000)}` : ''}`);
  }
  return {
    applied: true,
    hostname: plan.input.hostname,
    advertiseRoutes: plan.input.advertiseRoutes,
    advertiseExitNode: plan.input.advertiseExitNode,
    output: output || undefined,
    message: 'tailscale up completed. A fresh verify_tailscale call is still required to confirm the node is Running and online.',
  };
}
