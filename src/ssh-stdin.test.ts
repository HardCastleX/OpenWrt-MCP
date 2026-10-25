import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { Client } from 'ssh2';
import type { SshConfig } from './config.js';
import { runSshCommand } from './ssh.js';

test('sends config batch through SSH stdin instead of the remote command string', async () => {
  const hostKey = Buffer.from('stdin test host key');
  const hostFingerprint = `SHA256:${createHash('sha256').update(hostKey).digest('base64').replace(/=+$/, '')}`;
  const config: SshConfig = {
    host: '192.168.10.1', port: 22, username: 'root', privateKey: Buffer.from('fake key'), hostFingerprint,
  };
  const expectedInput = "test-auth-key-value\n";
  let issuedCommand = '';
  let streamedInput = '';
  const originalConnect = Client.prototype.connect;
  const originalExec = Client.prototype.exec;
  const originalEnd = Client.prototype.end;
  Client.prototype.connect = function (options) {
    const verifier = options.hostVerifier as (key: Buffer) => boolean;
    assert.equal(verifier(hostKey), true);
    queueMicrotask(() => this.emit('ready'));
    return this;
  };
  Client.prototype.exec = ((command: string, optionsOrCallback: unknown, maybeCallback?: unknown) => {
    issuedCommand = command;
    const callback = (typeof optionsOrCallback === 'function' ? optionsOrCallback : maybeCallback) as (error: Error | undefined, stream: EventEmitter & { stderr: EventEmitter; end: (data?: string) => void }) => void;
    const stream = new EventEmitter() as EventEmitter & { stderr: EventEmitter; end: (data?: string) => void };
    stream.stderr = new EventEmitter();
    stream.end = (data) => { streamedInput = data ?? ''; queueMicrotask(() => stream.emit('close', 0)); };
    callback(undefined, stream);
    return Client.prototype;
  }) as typeof Client.prototype.exec;
  Client.prototype.end = function () { return this; };
  try {
    const result = await runSshCommand(config, 'sh -s', 1000, expectedInput);
    assert.equal(result.exitCode, 0);
    assert.equal(issuedCommand, 'sh -s');
    assert.equal(streamedInput, expectedInput);
    assert.equal(issuedCommand.includes(expectedInput.trim()), false);
  } finally {
    Client.prototype.connect = originalConnect;
    Client.prototype.exec = originalExec;
    Client.prototype.end = originalEnd;
  }
});
