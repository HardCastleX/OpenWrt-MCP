import assert from 'node:assert/strict';
import test from 'node:test';
import { buildWireGuardApplyScript, hasOnlyExpectedWireGuardSections } from './wireguard-operations.js';
import { parseCapabilities } from './openwrt.js';
import { makeWireGuardPlan, wireGuardInputSchema } from './wireguard.js';

test('staged UCI change validation accepts only the new tunnel and its peers', () => {
  const staged = [
    "set network.wgnew.proto='wireguard'",
    "set network.wgnew.private_key='private-value'",
    "set network.wgpeer_wgnew_0='wireguard_wgnew'",
    "add_list network.wgpeer_wgnew_0.allowed_ips='10.99.0.2/32'",
  ].join('\n');
  assert.equal(hasOnlyExpectedWireGuardSections(staged, 'wgnew', 1), true);
});

test('staged UCI change validation rejects mutations to LAN, WAN, unknown peers, and empty input', () => {
  assert.equal(hasOnlyExpectedWireGuardSections("set network.lan.ipaddr='192.168.3.1'", 'wgnew', 1), false);
  assert.equal(hasOnlyExpectedWireGuardSections("set network.wgpeer_wgnew_2='wireguard_wgnew'", 'wgnew', 1), false);
  assert.equal(hasOnlyExpectedWireGuardSections('', 'wgnew', 1), false);
  assert.equal(hasOnlyExpectedWireGuardSections('unparseable output', 'wgnew', 1), false);
});

test('apply script stages, validates, commits, then activates only the new interface', () => {
  const fixture = [
    '__RELEASE__', "DISTRIB_RELEASE='25.12.5'", '__TOOLS__', '/sbin/uci', '/bin/ubus', '/usr/bin/wg', '/usr/bin/apk', '/usr/bin/sha256sum',
    '__UCI_CHANGES__', '__UCI_INTERFACES__', '__UCI_HASH__', 'a'.repeat(64), '__ROUTES4__', '__ROUTES6__', '__INTERFACES__', '{"interface":[]}', '__WG_INTERFACES__', '__END__',
  ].join('\n');
  const capabilities = parseCapabilities(fixture);
  const input = wireGuardInputSchema.parse({
    interfaceName: 'wgmcp_test', addresses: ['10.90.0.1/24'],
    peers: [{ publicKey: '0'.repeat(42) + 'A=', allowedIps: ['10.90.0.2/32'] }],
  });
  const { plan } = makeWireGuardPlan(input, capabilities, 1_000);
  const script = buildWireGuardApplyScript(plan);
  assert.ok(script.indexOf('cat > "$batch_file"') < script.indexOf('changes="$(uci changes network)"'));
  assert.ok(script.indexOf('UNEXPECTED_UCI_SECTION') < script.indexOf('uci commit network'));
  assert.ok(script.indexOf('uci commit network') < script.indexOf('ifup wgmcp_test'));
  assert.equal(script.includes('uci revert network.wgpeer_wgmcp_test_0'), true);
  assert.doesNotMatch(script, /firewall|network\.lan|network\.wan/);
  assert.equal(script.includes('\\nlock_dir='), false);
  const commitIndex = script.indexOf('uci commit network');
  assert.equal(script.slice(commitIndex).includes('uci revert'), false);
  assert.ok(script.indexOf('PENDING_UCI_CHANGES') < script.indexOf('uci revert'));
  assert.ok(script.includes('rmdir "$lock_dir"'));
});
