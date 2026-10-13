import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { Client } from 'ssh2';
import { runSshCommand } from './ssh.js';
import type { SshConfig } from './config.js';

test('uses the configured SSH destination, private key, and pinned fingerprint', async () => {
  const hostKey = Buffer.from('known host key');
  const expected = `SHA256:${createHash('sha256').update(hostKey).digest('base64').replace(/=+$/, '')}`;
  const config: SshConfig = {
    host: '192.168.1.1',
    port: 22,
    username: 'root',
    privateKey: Buffer.from('private key'),
    hostFingerprint: expected,
  };
  let connectionConfig: Record<string, unknown> | undefined;
  const originalConnect = Client.prototype.connect;
  const originalExec = Client.prototype.exec;
  const originalEnd = Client.prototype.end;
  Client.prototype.connect = function (options: Record<string, unknown>) {
    connectionConfig = options;
    const verifier = options.hostVerifier as (key: Buffer) => boolean;
    assert.equal(verifier(hostKey), true);
    assert.equal(verifier(Buffer.from('unexpected key')), false);
    queueMicrotask(() => this.emit('ready'));
    return this;
  };
  Client.prototype.exec = ((...args: unknown[]) => {
    const callback = args.find((arg) => typeof arg === 'function') as (error: Error | undefined, stream: never) => void;
    const stream = new EventEmitter() as EventEmitter & { stderr: EventEmitter };
    stream.stderr = new EventEmitter();
    callback(undefined, stream as never);
    queueMicrotask(() => stream.emit('close', 0));
    return Client.prototype;
  }) as typeof Client.prototype.exec;
  Client.prototype.end = function () { return this; };

  try {
    const result = await runSshCommand(config, 'ubus call system board');
    assert.deepEqual(result, { stdout: '', stderr: '', exitCode: 0, truncated: false });
    assert.equal(connectionConfig?.host, config.host);
    assert.equal(connectionConfig?.username, config.username);
    assert.deepEqual(connectionConfig?.privateKey, config.privateKey);
  } finally {
    Client.prototype.connect = originalConnect;
    Client.prototype.exec = originalExec;
    Client.prototype.end = originalEnd;
  }
});
