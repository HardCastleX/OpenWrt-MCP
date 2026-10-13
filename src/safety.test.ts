import assert from 'node:assert/strict';
import test from 'node:test';
import { isConfirmedCommand } from './safety.js';

test('requires exact command confirmation', () => {
  assert.equal(isConfirmedCommand('reboot', 'reboot'), true);
  assert.equal(isConfirmedCommand('reboot', 'ubus call system board'), false);
  assert.equal(isConfirmedCommand('reboot', 'reboot '), false);
});
