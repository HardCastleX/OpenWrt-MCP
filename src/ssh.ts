import { createHash } from 'node:crypto';
import { Client } from 'ssh2';
import type { SshConfig } from './config.js';

const MAX_OUTPUT_BYTES = 32 * 1024;
const COMMAND_TIMEOUT_MS = 30_000;

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  truncated: boolean;
}

function fingerprint(key: Buffer): string {
  return `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/, '')}`;
}

export async function runSshCommand(
  config: SshConfig,
  command: string,
  timeoutMs = COMMAND_TIMEOUT_MS,
): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const connection = new Client();
    let settled = false;
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let truncated = false;
    const finish = (error?: Error, result?: CommandResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      connection.end();
      if (error) reject(error);
      else resolve(result!);
    };
    const timer = setTimeout(() => finish(new Error(`SSH command timed out after ${timeoutMs} ms.`)), timeoutMs);

    connection.on('ready', () => {
      connection.exec(command, (error, stream) => {
        if (error) return finish(error);
        stream.on('data', (chunk: Buffer) => {
          const remaining = MAX_OUTPUT_BYTES - stdout.length - stderr.length;
          if (remaining <= 0) {
            truncated = true;
            stream.close();
            return;
          }
          const data = Buffer.from(chunk);
          stdout = Buffer.concat([stdout, data.subarray(0, remaining)]);
          if (data.length > remaining) {
            truncated = true;
            stream.close();
          }
        });
        stream.stderr.on('data', (chunk: Buffer) => {
          const remaining = MAX_OUTPUT_BYTES - stdout.length - stderr.length;
          if (remaining <= 0) {
            truncated = true;
            stream.close();
            return;
          }
          const data = Buffer.from(chunk);
          stderr = Buffer.concat([stderr, data.subarray(0, remaining)]);
          if (data.length > remaining) {
            truncated = true;
            stream.close();
          }
        });
        stream.on('close', (code: number | null) => finish(undefined, {
          stdout: stdout.toString('utf8'),
          stderr: stderr.toString('utf8'),
          exitCode: code,
          truncated,
        }));
        stream.on('error', finish);
      });
    });
    connection.on('error', finish);
    connection.connect({
      host: config.host,
      port: config.port,
      username: config.username,
      privateKey: config.privateKey,
      passphrase: config.passphrase,
      readyTimeout: timeoutMs,
      hostVerifier: (key: Buffer) => fingerprint(key) === config.hostFingerprint,
    });
  });
}
