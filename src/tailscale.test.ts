import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { assertTailscaleReady, type DeviceCapabilities } from './openwrt.js';
import {
  buildTailscaleApplyPayload,
  buildTailscaleUpScript,
  makeTailscalePlan,
  parseTailscaleStatus,
  planExpired,
  redactTailscaleSecrets,
  tailscaleUpInputSchema,
} from './tailscale.js';

const fakeAuthKey = ['tskey', 'auth', 'fixture', '0'.repeat(24)].join('-');
const otherAuthKey = ['tskey', 'auth', 'fixture', '1'.repeat(24)].join('-');

const capabilities: DeviceCapabilities = {
  release: '25.12.5',
  revision: 'r-test',
  target: 'ramips/mt7621',
  packageManager: 'apk',
  tools: ['uci', 'ubus', 'sha256sum', 'tailscale', 'tailscaled'],
  tailscaleAvailable: true,
  pendingNetworkChanges: false,
  configuredInterfaces: ['lan', 'wan'],
  routes: ['192.168.10.0/24 dev br-lan proto kernel scope link'],
  interfaceAddresses: ['192.168.10.1/24'],
  networkConfigDigest: 'a'.repeat(64),
};

const statusJson = {
  Version: '1.78.1',
  BackendState: 'Running',
  MagicDNSSuffix: 'tailnet.ts.net',
  TailscaleIPs: ['100.64.1.2', 'fd7a:115c:a1e0::2'],
  Self: {
    HostName: 'router',
    DNSName: 'router.tailnet.ts.net.',
    Online: true,
    TailscaleIPs: ['100.64.1.2', 'fd7a:115c:a1e0::2'],
  },
  ExitNodeStatus: { TailscaleIPs: ['100.64.0.9'] },
  Peer: {
    'nodekey:one': { HostName: 'laptop', Online: true },
    'nodekey:two': { HostName: 'phone', Online: false },
  },
};

const prefsJson = {
  AdvertiseRoutes: ['192.168.10.0/24'],
  AdvertiseExitNode: false,
  RouteAll: true,
  CorpDNS: false,
  ExitNodeIP: '100.64.0.9',
};

const fixture = [
  '__TAILSCALE_BIN__',
  '/usr/sbin/tailscale',
  '__TAILSCALED_BIN__',
  '/usr/sbin/tailscaled',
  '__VERSION__',
  '1.78.1',
  '  go version: go1.23.4',
  '__STATUS__',
  JSON.stringify(statusJson),
  '__PREFS__',
  JSON.stringify(prefsJson),
  '__IP4__',
  '100.64.1.2',
  '__IFACE__',
  '7: tailscale0: <POINTOPOINT,UP,LOWER_UP> mtu 1280',
  '    inet 100.64.1.2/32 scope global tailscale0',
  '__END__',
].join('\n');

test('parses installed, running node state without leaking secrets', () => {
  const status = parseTailscaleStatus(fixture);
  assert.equal(status.installed, true);
  assert.equal(status.daemonRunning, true);
  assert.equal(status.version, '1.78.1');
  assert.equal(status.backendState, 'Running');
  assert.equal(status.up, true);
  assert.equal(status.online, true);
  assert.equal(status.hostname, 'router');
  assert.equal(status.dnsName, 'router.tailnet.ts.net.');
  assert.deepEqual(status.tailscaleIps, ['100.64.1.2', 'fd7a:115c:a1e0::2']);
  assert.equal(status.magicDnsSuffix, 'tailnet.ts.net');
  assert.deepEqual(status.advertisedRoutes, ['192.168.10.0/24']);
  assert.equal(status.advertiseExitNode, false);
  assert.equal(status.usingExitNode, '100.64.0.9');
  assert.equal(status.acceptRoutes, true);
  assert.equal(status.acceptDns, false);
  assert.equal(status.peerCount, 2);
  assert.equal(status.onlinePeerCount, 1);
  assert.equal(status.interfaceAddress, '100.64.1.2');
  assert.equal(status.partial, false);
});

test('reports a missing or broken Tailscale installation without throwing', () => {
  const missing = parseTailscaleStatus(['__TAILSCALE_BIN__', '__TAILSCALED_BIN__', '__VERSION__', '__STATUS__', 'tailscale: not found', '__PREFS__', '__IP4__', '__IFACE__', '__END__'].join('\n'));
  assert.equal(missing.installed, false);
  assert.equal(missing.daemonRunning, false);
  assert.equal(missing.up, false);
  const broken = parseTailscaleStatus(fixture.replace(JSON.stringify(statusJson), 'not-json'), true);
  assert.equal(broken.daemonRunning, false);
  assert.equal(broken.up, false);
  assert.equal(broken.partial, true);
});

test('validates plan input and refuses unsafe route advertisements', () => {
  const parsed = tailscaleUpInputSchema.parse({ hostname: 'router' });
  assert.deepEqual(parsed.advertiseRoutes, []);
  assert.equal(parsed.acceptDns, true);
  assert.throws(() => tailscaleUpInputSchema.parse({ advertiseRoutes: ['0.0.0.0/0'] }), /advertiseExitNode/);
  assert.throws(() => tailscaleUpInputSchema.parse({ advertiseRoutes: ['100.64.0.0/10'] }), /reserves/);
  assert.throws(() => tailscaleUpInputSchema.parse({ advertiseRoutes: ['192.168.10.0/24', '192.168.10.0/24'] }), /unique/);
  assert.throws(() => tailscaleUpInputSchema.parse({ advertiseRoutes: ['not-a-cidr'] }));
  assert.throws(() => tailscaleUpInputSchema.parse({ hostname: '-bad-' }));
  assert.throws(() => tailscaleUpInputSchema.parse({ authKey: 'not-a-valid-auth-key' }));
  assert.throws(() => tailscaleUpInputSchema.parse({ unexpected: true }));
});

test('refuses Tailscale changes when the device is not ready', () => {
  assert.throws(() => assertTailscaleReady({ ...capabilities, release: 'unknown' }), /release/);
  assert.throws(() => assertTailscaleReady({ ...capabilities, tools: capabilities.tools.filter((tool) => tool !== 'tailscale') }), /not installed/);
  assert.throws(() => assertTailscaleReady({ ...capabilities, tailscaleAvailable: false }), /binaries were not found/);
  assert.throws(() => assertTailscaleReady({ ...capabilities, tools: capabilities.tools.filter((tool) => tool !== 'sha256sum') }), /sha256sum/);
  assert.throws(() => assertTailscaleReady({ ...capabilities, pendingNetworkChanges: true }), /pending UCI/);
});

test('creates a secret-free plan and uses the environment auth key as a fallback', () => {
  const input = tailscaleUpInputSchema.parse({
    hostname: 'router', advertiseRoutes: ['192.168.20.0/24'], advertiseExitNode: false, acceptRoutes: true, acceptDns: false,
  });
  const envKey = fakeAuthKey;
  const { plan, summary } = makeTailscalePlan(input, capabilities, 1_000, envKey);
  assert.equal(JSON.stringify(summary).includes(envKey), false);
  assert.equal(summary.authKeyProvided, true);
  assert.equal(summary.configPreview.length, 1);
  assert.match(summary.configPreview[0]!, /--advertise-routes=192\.168\.20\.0\/24/);
  assert.match(summary.configPreview[0]!, /--auth-key=file:<temporary file, deleted after apply>/);
  assert.equal(plan.authKey, envKey);
  assert.equal('authKey' in plan.input, false);
  assert.equal(plan.digest, createHash('sha256').update(JSON.stringify({
    planId: plan.planId,
    input: plan.input,
    authKeyDigest: createHash('sha256').update(envKey).digest('hex'),
    config: capabilities.networkConfigDigest,
  })).digest('hex'));
  assert.equal(planExpired(plan, 1_000 + 10 * 60 * 1000), false);
  assert.equal(planExpired(plan, 1_000 + 10 * 60 * 1000 + 1), true);
});

test('builds an apply script that reads the key from stdin and never embeds it', () => {
  const input = tailscaleUpInputSchema.parse({ hostname: 'router', authKey: fakeAuthKey });
  const { plan } = makeTailscalePlan(input, capabilities, 1_000);
  const payload = buildTailscaleApplyPayload(plan);
  assert.equal(payload.stdin, `${plan.authKey}\n`);
  assert.equal(payload.command.includes(plan.authKey!), false);
  assert.match(payload.command, /--auth-key="file:\$key_file"/);
  assert.ok(payload.command.indexOf('cat > "$key_file"') < payload.command.indexOf('tailscale up'));
  assert.match(payload.command, /--accept-dns=true/);
  assert.match(payload.command, /--accept-routes=false/);
  assert.match(payload.command, /--advertise-exit-node=false/);
  assert.match(payload.command, /--hostname=router/);
  assert.match(payload.command, /--timeout=20s/);
  assert.match(payload.command, /TAILSCALED_NOT_RUNNING/);
  assert.match(payload.command, /trap cleanup EXIT/);
  const script = buildTailscaleUpScript(plan);
  assert.equal(script, payload.command);
});

test('omits the auth key file path when no key is provided', () => {
  const input = tailscaleUpInputSchema.parse({});
  const { plan, summary } = makeTailscalePlan(input, capabilities);
  const payload = buildTailscaleApplyPayload(plan);
  assert.equal(payload.stdin, undefined);
  assert.equal(payload.command.includes('cat > "$key_file"'), false);
  assert.equal(payload.command.includes('--auth-key'), false);
  assert.equal(summary.authKeyProvided, false);
  assert.match(summary.warnings.join(' '), /reuse an existing session/);
});

test('redacts auth keys from any router output', () => {
  const input = tailscaleUpInputSchema.parse({ authKey: fakeAuthKey });
  const { plan } = makeTailscalePlan(input, capabilities);
  const output = `up failed for ${plan.authKey} and ${otherAuthKey}`;
  const redacted = redactTailscaleSecrets(output, plan);
  assert.equal(redacted.includes(plan.authKey!), false);
  assert.equal(redacted.includes(otherAuthKey), false);
});
