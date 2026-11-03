import assert from 'node:assert/strict';
import test from 'node:test';
import { nextServerSessionActive } from '../src/server-session-state.mjs';

test('server-session request sequence retains logout through denial and service errors', () => {
  let active = false;
  active = nextServerSessionActive(active, 200);
  assert.equal(active, true, 'successful session-backed response shows Sign out');

  active = nextServerSessionActive(active, 403);
  assert.equal(active, true, 'role denial does not hide Sign out');

  active = nextServerSessionActive(active, 503);
  assert.equal(active, true, 'dependency failure does not hide Sign out');

  active = nextServerSessionActive(active, 200);
  assert.equal(active, true, 'the same session can continue successfully');

  active = nextServerSessionActive(active, 401);
  assert.equal(active, false, 'authentication failure changes the control to Sign in');

  active = nextServerSessionActive(active, 201);
  assert.equal(active, true, 'a later authenticated success restores Sign out');
});

test('non-authentication errors do not invent an active session', () => {
  assert.equal(nextServerSessionActive(false, 403), false);
  assert.equal(nextServerSessionActive(false, 502), false);
});
