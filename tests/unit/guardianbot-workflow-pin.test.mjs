import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

test('GuardianBot configuration matches every pinned reusable workflow', () => {
  const config = readFileSync(new URL('../../.guardianbot/config.yml', import.meta.url), 'utf8');
  const workflow = readFileSync(new URL('../../.github/workflows/guardianbot.yml', import.meta.url), 'utf8');
  const configured = /^workflowVersion:\s*([a-f0-9]{40})\s*$/m.exec(config)?.[1];
  assert.ok(configured, 'workflowVersion must be a full commit SHA');
  const calls = [...workflow.matchAll(/^\s*uses:\s*Geekyshubham\/guardianbot\/.+@([^\s#]+)/gm)];
  assert.ok(calls.length > 0, 'GuardianBot reusable workflows must exist');
  for (const [, revision] of calls) {
    assert.equal(revision, configured, 'workflowVersion must match the called GuardianBot revision');
  }
});
