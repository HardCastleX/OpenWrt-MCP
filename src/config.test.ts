import assert from 'node:assert/strict';
import test from 'node:test';
import { isPrivateAddress, loadConfig } from './config.js';

test('accepts private LAN and Tailscale (CGNAT) addresses', () => {
  for (const host of ['10.0.0.1', '172.20.1.1', '192.168.1.1', '100.126.77.71', 'fd12:3456::1', '::ffff:192.168.1.1']) {
    assert.equal(isPrivateAddress(host), true, host);
  }
});

test('rejects public addresses and hostnames', () => {
  for (const host of ['8.8.8.8', '1.1.1.1', 'router.lan', 'localhost', '127.0.0.1']) {
    assert.equal(isPrivateAddress(host), false, host);
  }
});

test('requires private IP, key, user, and pinned host fingerprint', () => {
  assert.throws(() => loadConfig({}), /OPENWRT_HOST/);
  assert.throws(() => loadConfig({ OPENWRT_HOST: '192.168.1.1' }), /OPENWRT_SSH_USER/);
  assert.throws(() => loadConfig({
    OPENWRT_HOST: '192.168.1.1',
    OPENWRT_SSH_USER: 'root',
    OPENWRT_SSH_KEY_PATH: 'not-read-because-no-fingerprint',
  }), /OPENWRT_SSH_HOST_FINGERPRINT/);
});
