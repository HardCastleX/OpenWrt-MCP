import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import test from 'node:test';
import { assertWireGuardReady, parseCapabilities } from './openwrt.js';
import {
  buildUciBatch,
  generateWireGuardKeyPair,
  makeWireGuardPlan,
  planExpired,
  redactWireGuardSecrets,
  validateWireGuardPlan,
  wireGuardInputSchema,
} from './wireguard.js';

const fixture = [
  '__RELEASE__',
  "DISTRIB_RELEASE='25.12.5'",
  "DISTRIB_REVISION='r-test'",
  "DISTRIB_TARGET='ramips/mt7621'",
  '__TOOLS__',
  '/sbin/uci',
  '/bin/ubus',
  '/usr/bin/wg',
  '/usr/bin/apk',
  '__UCI_CHANGES__',
  '__UCI_INTERFACES__',
  'network.lan=interface',
  'network.wg0=interface',
  "network.wg0.proto='wireguard'",
  '__UCI_HASH__',
  'a'.repeat(64),
  '__ROUTES4__',
  '192.168.10.0/24 dev br-lan proto kernel scope link',
  '__ROUTES6__',
  'fd00:10::/64 dev wg0 proto kernel',
  '__INTERFACES__',
  '{"interface":[{"ipv4-address":[{"address":"192.168.10.1","mask":24}]}]}',
  '__WG_INTERFACES__',
  'wg0',
  '__END__',
].join('\n');

const caps = parseCapabilities(fixture);
const peerPublicKey = generateWireGuardKeyPair().publicKey;
const input = wireGuardInputSchema.parse({
  interfaceName: 'wg1',
  addresses: ['10.88.0.1/24'],
  peers: [{ publicKey: peerPublicKey, allowedIps: ['10.88.0.2/32'] }],
});

test('detects firmware, apk, wireguard tools, and existing tunnel', () => {
  assert.equal(caps.release, '25.12.5');
  assert.equal(caps.packageManager, 'apk');
  assert.equal(caps.wireguardAvailable, true);
  assert.deepEqual(caps.wireguardInterfaces, ['wg0']);
  assert.equal(caps.pendingNetworkChanges, false);
  assert.equal(caps.networkConfigDigest, 'a'.repeat(64));
  const withSecret = parseCapabilities(fixture.replace('__UCI_INTERFACES__', "__UCI_INTERFACES__\\nnetwork.wg0.private_key='secret-value'"));
  assert.equal(JSON.stringify(withSecret).includes('secret-value'), false);
});

test('detects opkg, ambiguous package managers, and pending UCI changes', () => {
  const opkg = parseCapabilities(fixture.replace('/usr/bin/apk', '/bin/opkg'));
  assert.equal(opkg.packageManager, 'opkg');
  const ambiguous = parseCapabilities(fixture.replace('/usr/bin/apk', '/usr/bin/apk\n/bin/opkg'));
  assert.equal(ambiguous.packageManager, 'ambiguous');
  const pending = parseCapabilities(fixture.replace('__UCI_INTERFACES__', 'network.lan.ipaddr=192.168.1.1\n__UCI_INTERFACES__'));
  assert.equal(pending.pendingNetworkChanges, true);
});

test('refuses WireGuard changes if required tools are missing or package manager is unknown', () => {
  assert.throws(() => assertWireGuardReady({ ...caps, release: 'unknown' }), /identify the OpenWrt release/);
  assert.throws(() => assertWireGuardReady({ ...caps, packageManager: 'unknown' }), /package manager/);
  assert.throws(() => assertWireGuardReady({ ...caps, tools: caps.tools.filter((tool) => tool !== 'wg') }), /WireGuard tools/);
});

test('generates compatible X25519 key pair', () => {
  const pair = generateWireGuardKeyPair();
  const rawPrivate = Buffer.from(pair.privateKey, 'base64');
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), rawPrivate]), format: 'der', type: 'pkcs8' });
  const key = createPublicKey(privateKey);
  const derived = key.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
  assert.equal(rawPrivate.length, 32);
  assert.equal(pair.publicKey, derived);
});

test('normalizes OpenWrt route output including unreachable and default-from IPv6 routes', () => {
  const capabilities = parseCapabilities(fixture.replace('192.168.2.0/24 dev br-lan proto kernel scope link', [
    'default via 192.168.100.1 dev wan',
    'unreachable 2806:2f0:7101:f351::/64 dev lo',
    'default from 2806:2f0:7101:f351::2 via fe80::1 dev wan',
    'fd00:10:0:1::/64 dev wg0 proto kernel',
  ].join('\n')));
  assert.doesNotThrow(() => validateWireGuardPlan(input, capabilities));
});

test('rejects existing interfaces, default routes, and existing route overlaps', () => {
  assert.throws(() => validateWireGuardPlan({ ...input, interfaceName: 'wg0' }, caps), /already exists/);
  assert.throws(() => validateWireGuardPlan({ ...input, peers: [{ ...input.peers[0]!, allowedIps: ['0.0.0.0/0'] }], routeAllowedIps: true }, caps), /Default routes/);
  assert.throws(() => validateWireGuardPlan({ ...input, peers: [{ ...input.peers[0]!, allowedIps: ['::/0'] }], routeAllowedIps: false }, caps), /Default routes/);
  assert.throws(() => validateWireGuardPlan({ ...input, addresses: ['192.168.10.10/24'] }, caps), /overlaps an existing route/);
});

test('rejects invalid keys, endpoint mismatch, and unknown fields', () => {
  assert.throws(() => wireGuardInputSchema.parse({ ...input, unexpected: true }));
  assert.throws(() => wireGuardInputSchema.parse({ ...input, peers: [{ ...input.peers[0], endpointHost: 'vpn.example.net' }] }));
});

test('creates secret-free plan preview and UCI batch with private key only in apply payload', () => {
  const { plan, summary } = makeWireGuardPlan(input, caps, 1000);
  const batch = buildUciBatch(plan);
  assert.equal(summary.interfaceName, 'wg1');
  assert.equal(summary.configPreview.some((line) => line.includes(plan.privateKey)), false);
  assert.equal(summary.configPreview.some((line) => line.includes('private_key=<generated; hidden>')), true);
  assert.equal(batch.includes(`private_key='${plan.privateKey}'`), true);
  assert.equal(redactWireGuardSecrets(batch, plan).includes(plan.privateKey), false);
  assert.equal(planExpired(plan, 1000 + 10 * 60 * 1000 + 1), true);
  assert.equal(planExpired(plan, 1000 + 10 * 60 * 1000), false);
  assert.equal(plan.digest, createHash('sha256').update(JSON.stringify({ planId: plan.planId, input, publicKey: plan.publicKey, config: caps.networkConfigDigest })).digest('hex'));
});
