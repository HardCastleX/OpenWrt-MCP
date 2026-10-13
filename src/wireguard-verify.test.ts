import assert from 'node:assert/strict';
import test from 'node:test';
import { parsePeerHandshakes } from './wireguard-verify.js';

test('parses WireGuard latest-handshakes output without exposing keys', () => {
  const publicKey = 'jyJvcba/yfwIKV6x0L4mKbGzVZfVF5i5aosOzZZoRCM=';
  assert.deepEqual(parsePeerHandshakes(`${publicKey}\t0\n`, 1_800_000_000), { peerCount: 1, hasRecentHandshake: false });
  assert.deepEqual(parsePeerHandshakes(`${publicKey}\t1799999900\n`, 1_800_000_000), { peerCount: 1, hasRecentHandshake: true });
  assert.deepEqual(parsePeerHandshakes(''), { peerCount: 0, hasRecentHandshake: false });
});
